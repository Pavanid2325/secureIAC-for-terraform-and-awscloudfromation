"""Strict validation for untrusted model-generated analysis JSON."""

from __future__ import annotations

import json
import math
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
    raw_template: dict | None = None,
) -> TemplateAnalysisResult:
    try:
        data = json.loads(response, parse_constant=lambda value: (_ for _ in ()).throw(ValueError("non-finite JSON")))
    except (ValueError, RecursionError) as exc:
        raise AnalysisValidationError("Model response must be a single JSON object") from exc
    return validate_analysis(data, template_name, resource_types, allowed_sources, raw_template)


def validate_analysis(
    data: Any,
    template_name: str,
    resource_types: dict[str, str],
    allowed_sources: set[str],
    raw_template: dict | None = None,
) -> TemplateAnalysisResult:
    root = _mapping(data, "analysis")
    versioned = raw_template is not None or "schema_version" in root
    _exact_keys(root, {"template_name", "resources_analyzed", "findings", "summary"} | ({"schema_version"} if versioned else set()), "analysis")
    if versioned and root["schema_version"] != "2":
        raise AnalysisValidationError("Unsupported schema_version")
    if _text(root["template_name"], "template_name") != template_name:
        raise AnalysisValidationError("template_name does not match analyzed template")
    resources_analyzed = _integer(root["resources_analyzed"], "resources_analyzed")
    if resources_analyzed != len(resource_types):
        raise AnalysisValidationError("resources_analyzed does not match template")
    raw_findings = root["findings"]
    if not isinstance(raw_findings, list):
        raise AnalysisValidationError("findings must be a list")
    findings = [
        _finding(item, index, resource_types, allowed_sources, raw_template, versioned)
        for index, item in enumerate(raw_findings)
    ]
    ids = [item.finding_id for item in findings]
    if len(ids) != len(set(ids)):
        raise AnalysisValidationError("finding_id values must be unique")
    # Collapse identical concerns while retaining every contributing finding ID.
    unique, provenance = {}, {}
    for finding in findings:
        key = (finding.resource_logical_id, finding.property_path, finding.observed_value_json, finding.title, finding.severity)
        provenance.setdefault(key, []).append(finding.finding_id)
        if key not in unique:
            unique[key] = finding
        else:
            from dataclasses import replace
            prior = unique[key]
            unique[key] = replace(prior,
                guidance_sources=sorted(set(prior.guidance_sources + finding.guidance_sources)),
                related_resources=sorted(set(prior.related_resources + finding.related_resources)),
                uncertainty=sorted(set(prior.uncertainty + finding.uncertainty)))
    findings = list(unique.values())
    return TemplateAnalysisResult(
        template_name=template_name,
        resources_analyzed=resources_analyzed,
        findings=findings,
        summary=_text(root["summary"], "summary", allow_empty=True),
        analysis_metadata={"deduplicated_finding_ids": list(provenance.values())},
    )


def _finding(
    value: Any, index: int, resource_types: dict[str, str], allowed_sources: set[str],
    raw_template=None, versioned=False,
) -> VulnerabilityFinding:
    item = _mapping(value, f"findings[{index}]")
    expected = {
        "finding_id", "resource_logical_id", "resource_type", "title", "description",
        "severity", "evidence", "security_impact", "retrieved_guidance",
        "guidance_sources", "remediation", "confidence", "related_resources",
    }
    if versioned:
        expected |= {"property_path", "observed_value_json", "missing", "status", "uncertainty"}
    _exact_keys(item, expected, f"findings[{index}]")
    resource_id = _text(item["resource_logical_id"], "resource_logical_id")
    if resource_id not in resource_types:
        raise AnalysisValidationError(f"Finding references unknown resource: {resource_id}")
    resource_type = _text(item["resource_type"], "resource_type")
    if resource_type != resource_types[resource_id]:
        raise AnalysisValidationError(f"Incorrect resource type for {resource_id}")
    severity = _text(item["severity"], "severity")
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
    if not math.isfinite(confidence) or not 0 <= float(confidence) <= 1:
        raise AnalysisValidationError("confidence must be between 0 and 1")
    evidence_fields = validate_evidence(item, raw_template) if versioned else {}
    return VulnerabilityFinding(
        **evidence_fields,
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


def property_value(resource, path):
    """JSON Pointer relative to the original resource; no expression evaluation."""
    if not isinstance(path, str) or not path.startswith("/Properties/"):
        raise AnalysisValidationError("property_path must start with /Properties/")
    parts = path.split("/")[1:]
    current = resource
    for index, raw_part in enumerate(parts):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if part not in current:
                if index == 0 and part == "Properties" and len(parts) == 2:
                    return False, None
                if index != len(parts)-1:
                    raise AnalysisValidationError("Evidence parent path is missing")
                return False, None
            current = current[part]
        elif isinstance(current, list) and part.isdecimal() and int(part) < len(current):
            current = current[int(part)]
        else:
            raise AnalysisValidationError("Evidence path does not resolve")
    return True, current


def unresolved(value):
    if isinstance(value, dict):
        return any(k == "Ref" or k.startswith("Fn::") or unresolved(v) for k, v in value.items())
    return isinstance(value, list) and any(unresolved(v) for v in value)


def validate_evidence(item, raw_template):
    fields = {key: item[key] for key in ("property_path", "observed_value_json", "missing", "status", "uncertainty")}
    if type(fields["missing"]) is not bool or fields["status"] not in {"verified_configuration_fact", "contextual_concern", "insufficient_information"}:
        raise AnalysisValidationError("Invalid evidence status or missing flag")
    fields["uncertainty"] = _text_list(fields["uncertainty"], "uncertainty")
    try:
        observed = json.loads(_text(fields["observed_value_json"], "observed_value_json"), parse_constant=lambda x: (_ for _ in ()).throw(ValueError()))
    except ValueError as exc:
        raise AnalysisValidationError("Invalid observed value JSON") from exc
    if raw_template is None:
        raise AnalysisValidationError("Original template required for evidence validation")
    resource = raw_template["Resources"][item["resource_logical_id"]]
    exists, actual = property_value(resource, fields["property_path"])
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), default=str, allow_nan=False)
    if fields["missing"] == exists or canonical(actual) != canonical(observed):
        raise AnalysisValidationError("Evidence contradicts template")
    if (resource.get("Condition") or unresolved(actual)) and fields["status"] != "insufficient_information":
        raise AnalysisValidationError("Unresolved evidence requires insufficient_information")
    return fields


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
