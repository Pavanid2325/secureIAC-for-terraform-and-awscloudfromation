"""Dataclass schemas used across the Phase 1 pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


JsonMap = dict[str, Any]


@dataclass(frozen=True)
class ResourceModel:
    logical_id: str
    resource_type: str
    properties: JsonMap = field(default_factory=dict)
    condition: str | None = None
    depends_on: str | list[str] | None = None
    metadata: JsonMap = field(default_factory=dict)
    creation_policy: JsonMap = field(default_factory=dict)
    update_policy: JsonMap = field(default_factory=dict)
    raw: JsonMap = field(default_factory=dict)
    security_properties: JsonMap = field(default_factory=dict)


@dataclass(frozen=True)
class ParsedTemplate:
    path: str
    raw: JsonMap
    resources: list[ResourceModel]
    parameters: JsonMap = field(default_factory=dict)
    mappings: JsonMap = field(default_factory=dict)
    conditions: JsonMap = field(default_factory=dict)
    outputs: JsonMap = field(default_factory=dict)
    metadata: JsonMap = field(default_factory=dict)
    description: str | None = None
    format_version: str | None = None


@dataclass(frozen=True)
class NormalizedResource:
    resource: ResourceModel
    machine: JsonMap
    summary: str
    relationships: JsonMap = field(default_factory=dict)


@dataclass(frozen=True)
class TemplateSummary:
    resource_count: int
    resource_types: dict[str, int]
    parameters: list[str]
    conditions: list[str]
    dependencies: dict[str, list[str]]
    security_sensitive_properties: dict[str, JsonMap]
    summary: str
    normalized_resources: list[NormalizedResource]
    raw_template: JsonMap


@dataclass(frozen=True)
class KnowledgeDocument:
    document_id: str
    text: str
    source: str
    title: str
    metadata: JsonMap = field(default_factory=dict)


@dataclass(frozen=True)
class DocumentChunk:
    chunk_id: str
    text: str
    source: str
    title: str
    service: str | None = None
    resource_type: str | None = None
    metadata: JsonMap = field(default_factory=dict)


@dataclass(frozen=True)
class ResourceDescriptor:
    resource: str
    resource_type: str
    query: str
    metadata: JsonMap = field(default_factory=dict)


@dataclass(frozen=True)
class RetrievalContext:
    chunk_id: str
    text: str
    source: str
    score: float
    metadata: JsonMap = field(default_factory=dict)


@dataclass(frozen=True)
class RetrievalResult:
    resource: str
    resource_type: str
    query: str
    retrieved_context: list[RetrievalContext]


SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


@dataclass(frozen=True)
class Remediation:
    explanation: str
    recommended_change: str
    cloudformation_snippet: str | None = None
    assumptions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class VulnerabilityFinding:
    finding_id: str
    resource_logical_id: str
    resource_type: str
    title: str
    description: str
    severity: str
    evidence: str
    security_impact: str
    retrieved_guidance: list[str]
    guidance_sources: list[str]
    remediation: Remediation
    confidence: float
    related_resources: list[str] = field(default_factory=list)
    property_path: str = ""
    observed_value_json: str = "null"
    missing: bool = False
    status: str = "contextual_concern"
    uncertainty: list[str] = field(default_factory=list)
    provenance: str = "llm"
    source_location: int | None = None


@dataclass(frozen=True)
class TemplateAnalysisResult:
    template_name: str
    resources_analyzed: int
    findings: list[VulnerabilityFinding]
    summary: str
    analysis_metadata: JsonMap = field(default_factory=dict)
