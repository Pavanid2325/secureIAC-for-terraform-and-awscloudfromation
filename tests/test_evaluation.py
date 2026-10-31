import pytest
from src.evaluation import metrics, review_metrics, validate_dataset, run
from src.config import Settings


def test_metrics_and_group_leakage():
    values = metrics([("A", "X"), ("B", "Y")], [("A", "X"), ("C", "Z")])
    assert values["precision"] == values["recall"] == values["f1"] == 0.5
    with pytest.raises(ValueError, match="same split"):
        validate_dataset({"version": 1, "cases": [{"id": "1", "group": "g", "split": "train"}, {"id": "2", "group": "g", "split": "test"}]})


def test_demo_evaluation_never_fabricates_scores(tmp_path):
    result = run("evaluation/starter.json", tmp_path / "evaluation.json", "llm-only", Settings(reports_path=tmp_path))
    assert len(result["runs"]) == 7
    assert all(r["metrics"] is None for r in result["runs"])
    assert result["failed_analyses"] == 0


def test_independent_evidence_and_remediation_review_metrics():
    result = review_metrics([{"evidence_correct": True, "remediation_valid": None},
                             {"evidence_correct": False, "remediation_valid": True}])
    assert result["evidence_correct_rate"] == 0.5
    assert result["remediation_valid_rate"] == 1
    with pytest.raises(ValueError):
        review_metrics([{"evidence_correct": "probably"}])
