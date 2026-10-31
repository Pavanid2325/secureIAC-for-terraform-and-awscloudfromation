"""Deterministic report agent for validated security findings."""

from __future__ import annotations

from collections import Counter
from dataclasses import replace
import html
import re

from src.models import TemplateAnalysisResult, TemplateSummary


class ReportGenerationAgent:
    """Format validated findings without invoking an LLM or adding content."""

    def generate(self, analysis: TemplateAnalysisResult, summary: TemplateSummary) -> str:
        # Escape model/template text before adding trusted Markdown structure.
        analysis = _safe_dataclass(analysis)
        summary = _safe_dataclass(summary)
        counts = Counter(finding.severity for finding in analysis.findings)
        scanner = analysis.analysis_metadata.get("scanner", {"status": "not_requested", "findings": []})
        policies = analysis.analysis_metadata.get("policies", [])
        scanner_failed = sum(f.get("outcome") == "failed" for f in scanner.get("findings", []))
        policy_failed = sum(p.get("outcome") == "failed" for p in policies)
        lines = [
            "# Infrastructure-as-Code Security Analysis",
            "",
            "## Executive Summary",
            "",
            f"Template: `{analysis.template_name}`  ",
            f"Resources analyzed: {analysis.resources_analyzed}  ",
            f"Status: {analysis.analysis_metadata.get('status', 'validated')}  ",
            f"Mode: {analysis.analysis_metadata.get('mode', 'contextual')}  ",
            f"Total findings: {len(analysis.findings) + scanner_failed + policy_failed}  ",
            f"Contextual: {len(analysis.findings)}; scanner failures: {scanner_failed}; policy violations: {policy_failed}  ",
            "Contextual severity totals:  ",
            f"Critical: {counts['CRITICAL']}  ",
            f"High: {counts['HIGH']}  ",
            f"Medium: {counts['MEDIUM']}  ",
            f"Low: {counts['LOW']}  ",
            f"Info: {counts['INFO']}",
            "",
            analysis.summary if analysis.findings or analysis.analysis_metadata.get("mode") in {"demo", "deterministic-only"} or analysis.analysis_metadata.get("status") == "failed" else "No findings within the completed analysis scope.",
            "",
            "## Findings",
            "",
        ]
        if not analysis.findings:
            lines.extend(["No contextual findings within the completed analysis scope. See stage status and deterministic results below.", ""])
        for finding in analysis.findings:
            lines.extend(
                [
                    f"### [{finding.severity}] {finding.title}", "",
                    f"Finding ID: `{finding.finding_id}`  ",
                    f"Resource: `{finding.resource_logical_id}`  ",
                    f"Type: `{finding.resource_type}`", "",
                    "**Problem**", "", finding.description, "",
                    "**Evidence**", "", finding.evidence, "",
                    f"Property: {finding.property_path}; observed JSON: {finding.observed_value_json}; missing: {finding.missing}",
                    f"Status: {finding.status}; provenance: {finding.provenance}",
                    *_bullets(finding.uncertainty), "",
                    "**Security Impact**", "", finding.security_impact, "",
                    "**Relevant Security Guidance**", "",
                    *(_bullets(finding.retrieved_guidance) or ["No retrieved guidance quoted."]), "",
                    "**Source(s)**", "",
                    *(_bullets([f"`{source}`" for source in finding.guidance_sources]) or ["No source cited."]), "",
                    "**Recommended Remediation**", "", finding.remediation.explanation, "",
                    finding.remediation.recommended_change, "",
                ]
            )
            if finding.remediation.cloudformation_snippet:
                lines.extend(
                    ["**Suggested CloudFormation**", "", "```yaml",
                     finding.remediation.cloudformation_snippet.rstrip(), "```", ""]
                )
            if finding.remediation.assumptions:
                lines.extend(["**Assumptions**", "", *_bullets(finding.remediation.assumptions), ""])
            if finding.related_resources:
                lines.extend(
                    ["Related resources: " + ", ".join(f"`{item}`" for item in finding.related_resources), ""]
                )
            lines.extend([f"Self-reported confidence (not a calibrated probability): {finding.confidence:.2f}", "", "---", ""])
        lines.extend(["## Resource Summary", "", summary.summary, ""])
        for resource in summary.normalized_resources:
            lines.append(f"- `{resource.resource.logical_id}`: `{resource.resource.resource_type}`")
        lines.extend(["", "## Analysis Metadata", ""])
        lines.extend(["### Scanner (independent results)", "",
                      f"Status: {scanner['status']}; version: {scanner.get('version', 'not available')}", ""])
        for finding in scanner.get("findings", []):
            if finding.get("outcome") != "passed":
                lines.extend([f"- {finding.get('outcome')}: {finding.get('check_id')} on {finding.get('resource')} — {finding.get('description')}"])
        lines.extend(["", "### Organization policies (independent results)", ""])
        if policies:
            lines.extend(["| Policy | Resource | Outcome | Severity | Property | Observed |", "|---|---|---|---|---|---|"])
            for policy in policies:
                cells = [str(policy[key]).replace('|', '\\|').replace('\n', ' ') for key in ('policy_id', 'resource', 'outcome', 'severity', 'property_path', 'observed')]
                lines.append("| " + " | ".join(cells) + " |")
                if policy.get("exception"):
                    lines.extend(["", "Exception: " + str(policy["exception"]), ""])
        else:
            lines.append("No applicable organization policies were evaluated.")
        lines.extend(["", "### Run metadata", ""])
        for key, value in sorted(analysis.analysis_metadata.items()):
            if key in {"scanner", "policies"}:
                continue
            lines.append(f"- {key}: `{value}`")
        uncertain = [finding for finding in analysis.findings if finding.confidence < 0.7]
        lines.extend(["", "## Limitations / Uncertain Findings", ""])
        lines.append(
            "CloudFormation conditions and runtime state were not fully evaluated. "
            "Findings describe static template evidence and retrieved guidance."
        )
        for finding in uncertain:
            lines.append(f"- `{finding.finding_id}` has confidence {finding.confidence:.2f}.")
        return "\n".join(lines).rstrip() + "\n"


def _bullets(items: list[str]) -> list[str]:
    return [f"- {item}" for item in items]


def _safe_dataclass(value):
    from dataclasses import fields, is_dataclass
    if isinstance(value, str):
        text = html.escape(value, quote=True)
        return re.sub(r"([`\[\]\\])", r"\\\1", text)
    if is_dataclass(value):
        return replace(value, **{f.name: _safe_dataclass(getattr(value, f.name)) for f in fields(value)})
    if isinstance(value, list):
        return [_safe_dataclass(x) for x in value]
    if isinstance(value, dict):
        return {k: _safe_dataclass(v) for k, v in value.items()}
    return value
