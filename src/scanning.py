"""Bounded local scanner adapters. Missing tools never imply a clean scan."""
import json
import os
import shutil
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from importlib.metadata import version, PackageNotFoundError
from src.parser.cloudformation_parser import CloudFormationParser


@dataclass
class ScanResult:
    scanner: str
    version: str
    status: str
    findings: list = field(default_factory=list)
    error: str | None = None


def bounded_run(args, timeout=60, max_bytes=2_000_000, cwd=None):
    """Drain a single pipe into bounded memory; kill on timeout or overflow."""
    env = {k: v for k, v in os.environ.items() if k.upper() in {
        "PATH", "SYSTEMROOT", "SYSTEMDRIVE", "PROGRAMDATA", "WINDIR", "TEMP", "TMP", "PATHEXT", "VIRTUAL_ENV"}}
    if cwd:
        env.update({"USERPROFILE": str(cwd), "HOME": str(cwd), "APPDATA": str(cwd), "LOCALAPPDATA": str(cwd)})
    env.update({"CKV_SKIP_DOWNLOAD": "true", "AWS_EC2_METADATA_DISABLED": "true"})
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               stdin=subprocess.DEVNULL, shell=False, cwd=cwd, env=env)
    chunks = bytearray()
    overflow = threading.Event()

    def read():
        while True:
            block = process.stdout.read(8192)
            if not block:
                break
            if len(chunks) + len(block) > max_bytes:
                overflow.set()
                process.kill()
                break
            chunks.extend(block)

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise TimeoutError("scanner_timeout") from None
    finally:
        reader.join(timeout=2)
        process.stdout.close()
    if overflow.is_set():
        raise ValueError("scanner_output_limit")
    return process.returncode, chunks.decode("utf-8", errors="replace")


class Scanner:
    def __init__(self, name="checkov", timeout=60, runner=bounded_run):
        self.name, self.timeout, self.runner = name, timeout, runner

    def scan(self, path):
        executable = shutil.which(self.name)
        try:
            tool_version = version(self.name)
        except PackageNotFoundError:
            tool_version = "unknown"
        if not executable:
            return ScanResult(self.name, tool_version, "unavailable", error="not_installed")
        resource_types = {r.logical_id: r.resource_type for r in CloudFormationParser().parse_file(path).resources}
        # A separate working directory avoids repository-local scanner configuration.
        with tempfile.TemporaryDirectory(prefix="secureiac-scan-") as workspace:
            target = Path(workspace) / ("template" + Path(path).suffix)
            target.write_bytes(Path(path).read_bytes())
            config = Path(workspace) / "config.yaml"
            config.write_text("{}", encoding="utf-8")
            if self.name == "checkov":
                args = [executable, "--file", str(target), "--framework", "cloudformation",
                        "--output", "json", "--skip-download", "--download-external-modules", "false",
                        "--config-file", str(config)]
            else:
                args = [executable, "--template", str(target), "--format", "json", "--config-file", str(config)]
            try:
                code, output = self.runner(args, self.timeout, cwd=workspace)
                payload = json.loads(output)
                if self.name == "checkov":
                    if code not in {0, 1}:
                        raise ValueError("scanner_exit")
                    reports = payload if isinstance(payload, list) else [payload]
                    findings = []
                    for report in reports:
                        results = report["results"]
                        if not isinstance(results, dict) or not any(k in results for k in ("failed_checks", "passed_checks", "skipped_checks")):
                            raise ValueError("scanner_missing_results")
                        if results.get("parsing_errors"):
                            raise ValueError("scanner_parse")
                        for group in ("failed_checks", "passed_checks", "skipped_checks"):
                            for check in results.get(group, []):
                                scanner_resource = check["resource"]
                                logical_id = scanner_resource if scanner_resource in resource_types else scanner_resource.rsplit(".", 1)[-1]
                                findings.append({"check_id": check["check_id"], "resource": logical_id,
                                    "resource_type": resource_types.get(logical_id), "scanner_resource": scanner_resource,
                                    "source_location": check.get("file_line_range"), "outcome": group.removesuffix("_checks"),
                                    "description": check.get("check_name", ""), "provenance": "checkov"})
                    return ScanResult(self.name, tool_version, "completed", findings)
                if not isinstance(payload, list) or code not in range(0, 16) or (code != 0 and not payload):
                    raise ValueError("linter_output")
                return ScanResult(self.name, tool_version, "completed", payload)
            except TimeoutError:
                return ScanResult(self.name, tool_version, "failed", error="timeout")
            except (ValueError, KeyError, TypeError, OSError):
                return ScanResult(self.name, tool_version, "failed", error="invalid_output_or_execution")
