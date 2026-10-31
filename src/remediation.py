"""Apply an explicit, allowlisted property patch to a separate candidate only."""
import copy
import difflib
import json
import tempfile
from dataclasses import asdict
from pathlib import Path
from src.parser.cloudformation_parser import CloudFormationParser
from src.policies import load_policies, evaluate_policies
from src.scanning import Scanner


def remediate(source, patch_path, output, allowed_paths, reports_dir="reports", policy_path=None,
              environment="production", region=None, timeout=60, scanner=None, linter=None):
    source, output = Path(source).resolve(), Path(output).resolve()
    root = Path(reports_dir).resolve()
    if output == source or root not in output.parents or output.suffix != ".json" or output.exists():
        raise ValueError("Candidate must be a new .json file within reports, distinct from input")
    artifacts = [output.with_suffix(".diff"), output.with_suffix(".validation.json")]
    if any(p.exists() or p.is_symlink() or root not in p.resolve().parents for p in artifacts):
        raise ValueError("Candidate validation artifacts must be new files within reports")
    parser = CloudFormationParser()
    original = parser.parse_file(source)
    candidate = copy.deepcopy(original.raw)
    if Path(patch_path).stat().st_size > 100_000:
        raise ValueError("Patch too large")
    operations = json.loads(Path(patch_path).read_text(encoding="utf-8"))
    if not isinstance(operations, list) or not operations:
        raise ValueError("Patch must be a nonempty JSON operation list")
    touched = set()
    for operation in operations:
        if not isinstance(operation, dict) or set(operation) != {"op", "path", "value"} or operation["op"] not in {"add", "replace"}:
            raise ValueError("Only explicit add/replace property operations are supported")
        path = operation["path"]
        if path not in allowed_paths or path in touched:
            raise ValueError("Unrelated or duplicate property change rejected")
        parts = path.split("/")[1:]
        if len(parts) < 4 or not path.startswith("/Resources/") or parts[2] != "Properties":
            raise ValueError("Only resource Properties may change; resource deletion is forbidden")
        parts = [p.replace("~1", "/").replace("~0", "~") for p in parts]
        node = candidate
        for part in parts[:-1]:
            node = node[int(part)] if isinstance(node, list) else node[part]
        last = int(parts[-1]) if isinstance(node, list) else parts[-1]
        if operation["op"] == "replace" and isinstance(node, dict) and last not in node:
            raise ValueError("Replacement property does not exist")
        if operation["op"] == "add" and (not isinstance(node, dict) or last in node):
            raise ValueError("Add requires a new mapping property")
        node[last] = operation["value"]
        touched.add(path)
    serialized = json.dumps(candidate, indent=2, allow_nan=False) + "\n"
    parsed = parser.parse_text(serialized, suffix=".json")
    if set(original.raw.get("Resources", {})) != set(parsed.raw.get("Resources", {})):
        raise ValueError("Resource identity changed")
    document, version = load_policies(policy_path) if policy_path else ({"version": 1, "policies": []}, None)
    before_policy = evaluate_policies(original, document, environment, region)
    after_policy = evaluate_policies(parsed, document, environment, region)
    scanner, linter = scanner or Scanner(timeout=timeout), linter or Scanner("cfn-lint", timeout)
    with tempfile.TemporaryDirectory(prefix="secureiac-candidate-") as directory:
        staged = Path(directory) / "candidate.json"
        staged.write_text(serialized, encoding="utf-8")
        lint = linter.scan(staged)
        before_scan, after_scan = scanner.scan(source), scanner.scan(staged)
    failed = lambda scan: {(f["resource"], f["check_id"]) for f in scan.findings if f.get("outcome") == "failed"}
    policy_failed = lambda values: {(v["resource"], v["policy_id"]) for v in values if v["outcome"] == "failed"}
    complete = all(r.status == "completed" for r in (lint, before_scan, after_scan))
    new_scanner = failed(after_scan) - failed(before_scan)
    new_policy = policy_failed(after_policy) - policy_failed(before_policy)
    validation = {"status": "passed_checks" if complete and not lint.findings and not new_scanner and not new_policy else "unvalidated_or_failed",
        "linter": asdict(lint), "scanner_before": asdict(before_scan), "scanner_after": asdict(after_scan),
        "policies_before": before_policy, "policies_after": after_policy, "policy_version": version,
        "new_scanner_failures": sorted(new_scanner), "new_policy_failures": sorted(new_policy),
        "changed_paths": sorted(touched),
        "limitations": ["Functional equivalence is not established.", "Replacement, availability, cost and application behavior require human review.", "No deployment was performed."]}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        stream.write(serialized)
    baseline = json.dumps(original.raw, indent=2, default=str).splitlines(True)
    diff = "".join(difflib.unified_diff(baseline, serialized.splitlines(True), fromfile="original (normalized JSON)", tofile="candidate"))
    output.with_suffix(".diff").write_text(diff, encoding="utf-8")
    output.with_suffix(".validation.json").write_text(json.dumps(validation, indent=2, default=str), encoding="utf-8")
    return validation, diff
