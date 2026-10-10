"""Strict validation for untrusted model-generated analysis JSON."""

from __future__ import annotations

import json
from typing import Any

from src.models.schemas import (
    SEVERITIES,
    Remediation,
    TemplateAnalysisResult,
    VulnerabilityFinding,
)


class AnalysisValidationError(ValueError):
    """Raised when model output violates the analysis contract."""


def parse_analysis_response(
    response: str,
    template_name: str,
    resource_types: dict[str, str],
    allowed_sources: set[str],
) -> TemplateAnalysisResult:
    try:
        data = json.loads(response)
    except json.JSONDecodeError as exc:
        raise AnalysisValidationError("Model response must be a single JSON object") from exc
    return validate_analysis(data, template_name, resource_types, allowed_sources)


def validate_analysis(
    data: Any,
    template_name: str,
    resource_types: dict[str, str],
    allowed_sources: set[str],
) -> TemplateAnalysisResult:
    root = _mapping(data, "analysis")
    _exact_keys(root, {"template_name", "resources_analyzed", "findings", "summary"}, "analysis")
    if _text(root["template_name"], "template_name") != template_name:
        raise AnalysisValidationError("template_name does not match analyzed template")
    resources_analyzed = _integer(root["resources_analyzed"], "resources_analyzed")
    if resources_analyzed != len(resource_types):
        raise AnalysisValidationError("resources_analyzed does not match template")
    raw_findings = root["findings"]
    if not isinstance(raw_findings, list):
        raise AnalysisValidationError("findings must be a list")
    findings = [
        _finding(item, index, resource_types, allowed_sources)
        for index, item in enumerate(raw_findings)
    ]
    ids = [item.finding_id for item in findings]
    if len(ids) != len(set(ids)):
        raise AnalysisValidationError("finding_id values must be unique")
    return TemplateAnalysisResult(
        template_name=template_name,
        resources_analyzed=resources_analyzed,
        findings=findings,
        summary=_text(root["summary"], "summary", allow_empty=True),
    )


def _finding(
    value: Any, index: int, resource_types: dict[str, str], allowed_sources: set[str]
) -> VulnerabilityFinding:
    item = _mapping(value, f"findings[{index}]")
    expected = {
        "finding_id", "resource_logical_id", "resource_type", "title", "description",
        "severity", "evidence", "security_impact", "retrieved_guidance",
        "guidance_sources", "remediation", "confidence", "related_resources",
    }
    _exact_keys(item, expected, f"findings[{index}]")
    resource_id = _text(item["resource_logical_id"], "resource_logical_id")
    if resource_id not in resource_types:
        raise AnalysisValidationError(f"Finding references unknown resource: {resource_id}")
    resource_type = _text(item["resource_type"], "resource_type")
    if resource_type != resource_types[resource_id]:
        raise AnalysisValidationError(f"Incorrect resource type for {resource_id}")
    severity = _text(item["severity"], "severity").upper()
    if severity not in SEVERITIES:
        raise AnalysisValidationError(f"Invalid severity: {severity}")
    sources = _text_list(item["guidance_sources"], "guidance_sources")
    if any(source not in allowed_sources for source in sources):
        raise AnalysisValidationError("Finding cites guidance that was not retrieved")
    related = _text_list(item["related_resources"], "related_resources")
    if any(resource not in resource_types for resource in related):
        raise AnalysisValidationError("Finding references an unknown related resource")
    remediation_data = _mapping(item["remediation"], "remediation")
    _exact_keys(
        remediation_data,
        {"explanation", "recommended_change", "cloudformation_snippet", "assumptions"},
        "remediation",
    )
    snippet = remediation_data["cloudformation_snippet"]
    if snippet is not None and not isinstance(snippet, str):
        raise AnalysisValidationError("cloudformation_snippet must be a string or null")
    confidence = item["confidence"]
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise AnalysisValidationError("confidence must be numeric")
    if not 0 <= float(confidence) <= 1:
        raise AnalysisValidationError("confidence must be between 0 and 1")
    return VulnerabilityFinding(
        finding_id=_text(item["finding_id"], "finding_id"),
        resource_logical_id=resource_id,
        resource_type=resource_type,
        title=_text(item["title"], "title"),
        description=_text(item["description"], "description"),
        severity=severity,
        evidence=_text(item["evidence"], "evidence"),
        security_impact=_text(item["security_impact"], "security_impact"),
        retrieved_guidance=_text_list(item["retrieved_guidance"], "retrieved_guidance"),
        guidance_sources=sources,
        remediation=Remediation(
            explanation=_text(remediation_data["explanation"], "remediation.explanation"),
            recommended_change=_text(remediation_data["recommended_change"], "remediation.recommended_change"),
            cloudformation_snippet=snippet,
            assumptions=_text_list(remediation_data["assumptions"], "remediation.assumptions"),
        ),
        confidence=float(confidence),
        related_resources=related,
    )


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AnalysisValidationError(f"{name} must be an object")
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], name: str) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        extra = sorted(set(value) - expected)
        raise AnalysisValidationError(f"{name} has invalid fields; missing={missing}, extra={extra}")


def _text(value: Any, name: str, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise AnalysisValidationError(f"{name} must be a non-empty string")
    return value.strip()


def _text_list(value: Any, name: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise AnalysisValidationError(f"{name} must be a list of strings")
    return [item.strip() for item in value if item.strip()]


def _integer(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AnalysisValidationError(f"{name} must be a non-negative integer")
    return value
