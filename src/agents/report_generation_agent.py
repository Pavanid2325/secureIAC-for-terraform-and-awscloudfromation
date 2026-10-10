"""Deterministic report agent for validated security findings."""

from __future__ import annotations

from collections import Counter

from src.models import TemplateAnalysisResult, TemplateSummary


class ReportGenerationAgent:
    """Format validated findings without invoking an LLM or adding content."""

    def generate(self, analysis: TemplateAnalysisResult, summary: TemplateSummary) -> str:
        counts = Counter(finding.severity for finding in analysis.findings)
        lines = [
            "# Infrastructure-as-Code Security Analysis",
            "",
            "## Executive Summary",
            "",
            f"Template: `{analysis.template_name}`  ",
            f"Resources analyzed: {analysis.resources_analyzed}  ",
            f"Total findings: {len(analysis.findings)}  ",
            f"Critical: {counts['CRITICAL']}  ",
            f"High: {counts['HIGH']}  ",
            f"Medium: {counts['MEDIUM']}  ",
            f"Low: {counts['LOW']}  ",
            f"Info: {counts['INFO']}",
            "",
            analysis.summary or "No security findings were produced.",
            "",
            "## Findings",
            "",
        ]
        if not analysis.findings:
            lines.extend(["No validated findings.", ""])
        for finding in analysis.findings:
            lines.extend(
                [
                    f"### [{finding.severity}] {finding.title}", "",
                    f"Finding ID: `{finding.finding_id}`  ",
                    f"Resource: `{finding.resource_logical_id}`  ",
                    f"Type: `{finding.resource_type}`", "",
                    "**Problem**", "", finding.description, "",
                    "**Evidence**", "", finding.evidence, "",
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
            lines.extend([f"Confidence: {finding.confidence:.2f}", "", "---", ""])
        lines.extend(["## Resource Summary", "", summary.summary, ""])
        for resource in summary.normalized_resources:
            lines.append(f"- `{resource.resource.logical_id}`: `{resource.resource.resource_type}`")
        lines.extend(["", "## Analysis Metadata", ""])
        for key, value in sorted(analysis.analysis_metadata.items()):
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
