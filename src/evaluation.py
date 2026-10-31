"""Offline-first reproducibility harness; unreviewed labels cannot produce scores."""
import argparse
import json
import time
import hashlib
from dataclasses import asdict
from pathlib import Path
from src.config import Settings
from src.cli import _embedder
from src.llm.factory import create_provider
from src.agents import VulnerabilityDetectionAgent
from src.workflow import SecurityAnalysisWorkflow
from src.scanning import Scanner
from src.retrieval.retriever import RetrievalAgent
from src.retrieval.vector_store import LocalVectorStore

VARIANTS = {"scanner-only", "llm-only", "llm-rag", "scanner-llm-rag", "full"}


def metrics(expected, predicted):
    """Exact (resource, rule/category) set matching, one TP per unique identity."""
    expected, predicted = set(map(tuple, expected)), set(map(tuple, predicted))
    tp, fp, fn = len(expected & predicted), len(predicted - expected), len(expected - predicted)
    precision = tp / (tp+fp) if tp+fp else (1.0 if not expected else 0.0)
    recall = tp / (tp+fn) if tp+fn else 1.0
    return {"precision": precision, "recall": recall, "f1": 2*precision*recall/(precision+recall) if precision+recall else 0,
            "true_positives": tp, "false_positives": fp, "false_negatives": fn}


def review_metrics(annotations):
    """Aggregate independent post-run reviews, never infer correctness from confidence."""
    result = {}
    for field in ("evidence_correct", "remediation_valid"):
        values = [a[field] for a in annotations if a.get(field) is not None]
        if any(type(v) is not bool for v in values):
            raise ValueError("Review labels must be boolean or null")
        result[field + "_rate"] = sum(values) / len(values) if values else None
        result[field + "_reviewed"] = len(values)
    return result


def validate_dataset(dataset):
    if dataset.get("version") != 1:
        raise ValueError("Unsupported dataset version")
    groups = {}
    ids = set()
    for case in dataset["cases"]:
        if case["id"] in ids:
            raise ValueError("Duplicate case ID")
        ids.add(case["id"])
        if case["group"] in groups and groups[case["group"]] != case["split"]:
            raise ValueError("Related variants must remain in the same split")
        groups[case["group"]] = case["split"]


def run(dataset_path, output, variant, settings, no_relationships=False, no_policies=False, no_rag=False):
    if variant not in VARIANTS:
        raise ValueError("Unknown evaluation variant")
    root = Path.cwd().resolve()
    dataset_bytes = Path(dataset_path).read_bytes()
    dataset = json.loads(dataset_bytes)
    validate_dataset(dataset)
    destination = Path(output).resolve()
    if settings.reports_path.resolve() not in destination.parents:
        raise ValueError("Evaluation output must be inside reports directory")
    retrieval = None
    if not no_rag and variant in {"llm-rag", "scanner-llm-rag", "full"}:
        retrieval = RetrievalAgent(_embedder(settings), LocalVectorStore(settings.local_vector_store_path), settings.top_k_retrieval)
    detection = None if variant == "scanner-only" else VulnerabilityDetectionAgent(create_provider(settings), settings.max_attempts-1, settings.max_input_bytes, settings.max_output_bytes)
    rows = []
    for index, case in enumerate(dataset["cases"]):
        started = time.perf_counter()
        path = (root / case["template"]).resolve()
        if root not in path.parents:
            raise ValueError("Dataset template must be inside repository")
        workflow = SecurityAnalysisWorkflow(retrieval, detection, reports_dir=settings.reports_path / "evaluation",
            scanner=Scanner(timeout=settings.scanner_timeout) if variant in {"scanner-only", "scanner-llm-rag", "full"} else None,
            deterministic_only=variant == "scanner-only", policy_path=settings.policy_path if variant == "full" and not no_policies else None,
            environment=settings.environment, relationships=not no_relationships)
        row = {"case": case["id"], "split": case["split"], "label_status": case["label_status"], "metrics": None}
        try:
            result = workflow.analyze(path, f"case-{index}.md")
            metadata = result.analysis.analysis_metadata
            predicted = [(f.resource_logical_id, case.get("title_categories", {}).get(f.title, "unmapped:"+f.title)) for f in result.analysis.findings]
            predicted += [(f["resource"], f["check_id"]) for f in metadata["scanner"]["findings"] if f["outcome"] == "failed"]
            predicted += [(f["resource"], f["policy_id"]) for f in metadata["policies"] if f["outcome"] == "failed"]
            row.update(status=metadata["status"], metadata=metadata, predictions=predicted,
                       evidence_correctness=None, invalid_output=metadata.get("error") == "invalid_output", remediation_validity=None)
            if case["label_status"] == "human_reviewed" and metadata["status"] == "complete" and metadata["mode"] != "demo":
                row["metrics"] = metrics(case["expected"].get(variant, []), predicted)
        except Exception as exc:
            row.update(status="failed", error=type(exc).__name__)
        row["latency_ms"] = round((time.perf_counter()-started)*1000)
        rows.append(row)
    report = {"dataset_version": dataset["version"], "dataset_sha256": hashlib.sha256(dataset_bytes).hexdigest(),
        "variant": variant, "ablations": {"relationships": not no_relationships, "policies": not no_policies, "rag": not no_rag},
        "runs": rows, "failed_analyses": sum(r["status"] == "failed" for r in rows),
        "partial_analyses": sum(r["status"] == "partial" for r in rows),
        "invalid_output_rate": sum(bool(r.get("invalid_output")) for r in rows)/max(1,len(rows)),
        "notes": "Unreviewed labels and demo results are not scored. Evidence correctness and remediation validity need independent review."}
    destination = Path(output).resolve()
    if settings.reports_path.resolve() not in destination.parents:
        raise ValueError("Evaluation output must be inside reports directory")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default="evaluation/starter.json")
    parser.add_argument("--output", default="reports/evaluation.json")
    parser.add_argument("--variant", choices=sorted(VARIANTS), default="scanner-only")
    parser.add_argument("--no-relationships", action="store_true")
    parser.add_argument("--no-policies", action="store_true")
    parser.add_argument("--no-rag", action="store_true")
    parser.add_argument("--review", help="Aggregate a JSON list of independent post-run review annotations instead of running inference")
    args = parser.parse_args()
    if args.review:
        print(json.dumps(review_metrics(json.loads(Path(args.review).read_text(encoding="utf-8"))), indent=2))
        return
    report = run(args.dataset, args.output, args.variant, Settings.from_env(), args.no_relationships, args.no_policies, args.no_rag)
    print(json.dumps({"runs": len(report["runs"]), "failed": report["failed_analyses"], "partial": report["partial_analyses"]}))


if __name__ == "__main__":
    main()
