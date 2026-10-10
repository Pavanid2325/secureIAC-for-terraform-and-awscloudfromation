"""CloudFormation normalization for security-oriented retrieval."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from src.models import NormalizedResource, ParsedTemplate, ResourceModel, TemplateSummary


def normalize_template(parsed: ParsedTemplate) -> TemplateSummary:
    """Create machine-readable and human-readable normalized context."""

    normalized = [normalize_resource(resource) for resource in parsed.resources]
    resource_types = Counter(resource.resource_type for resource in parsed.resources)
    dependencies = {
        resource.logical_id: _as_dependency_list(resource.depends_on)
        for resource in parsed.resources
        if resource.depends_on
    }
    sensitive = {
        resource.logical_id: resource.security_properties
        for resource in parsed.resources
        if resource.security_properties
    }
    lines = [
        f"Template contains {len(parsed.resources)} resources.",
        "Resource types: "
        + (", ".join(f"{kind} ({count})" for kind, count in sorted(resource_types.items())) or "none"),
        "Parameters: " + (", ".join(sorted(parsed.parameters)) or "none"),
        "Conditions: " + (", ".join(sorted(parsed.conditions)) or "none"),
    ]
    return TemplateSummary(
        resource_count=len(parsed.resources),
        resource_types=dict(resource_types),
        parameters=sorted(parsed.parameters),
        conditions=sorted(parsed.conditions),
        dependencies=dependencies,
        security_sensitive_properties=sensitive,
        summary="\n".join(lines),
        normalized_resources=normalized,
        raw_template=parsed.raw,
    )


def normalize_resource(resource: ResourceModel) -> NormalizedResource:
    relationships = _find_relationships(resource.properties)
    machine = {
        "logical_id": resource.logical_id,
        "resource_type": resource.resource_type,
        "properties": resource.properties,
        "condition": resource.condition,
        "depends_on": resource.depends_on,
        "metadata": resource.metadata,
        "creation_policy": resource.creation_policy,
        "update_policy": resource.update_policy,
        "security_properties": resource.security_properties,
        "relationships": relationships,
    }
    return NormalizedResource(
        resource=resource,
        machine=machine,
        summary=_resource_summary(resource, relationships),
        relationships=relationships,
    )


def _resource_summary(resource: ResourceModel, relationships: dict[str, list[str]]) -> str:
    lines = [
        f"Resource: {resource.logical_id}",
        f"Type: {resource.resource_type}",
    ]
    if resource.condition:
        lines.append(f"Condition: {resource.condition}")
    depends = _as_dependency_list(resource.depends_on)
    if depends:
        lines.append("DependsOn: " + ", ".join(depends))
    if relationships:
        flattened = [f"{kind}: {', '.join(values)}" for kind, values in sorted(relationships.items())]
        lines.append("Relationships: " + "; ".join(flattened))
    if resource.security_properties:
        lines.append("Security-sensitive properties:")
        for key, value in sorted(resource.security_properties.items()):
            rendered = json.dumps(value, sort_keys=True, default=str)
            lines.append(f"- {key}: {rendered}")
    else:
        lines.append("Security-sensitive properties: none explicitly configured")
    if resource.properties:
        lines.append("Properties:")
        for key, value in sorted(resource.properties.items()):
            rendered = json.dumps(value, sort_keys=True, default=str)
            lines.append(f"- {key}: {rendered}")
    return "\n".join(lines)


def _as_dependency_list(depends_on: str | list[str] | None) -> list[str]:
    if depends_on is None:
        return []
    if isinstance(depends_on, str):
        return [depends_on]
    return [str(item) for item in depends_on]


def _find_relationships(value: Any) -> dict[str, list[str]]:
    relationships: dict[str, set[str]] = {"Ref": set(), "Fn::GetAtt": set(), "Fn::ImportValue": set()}

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                if key == "Ref" and isinstance(child, str):
                    relationships["Ref"].add(child)
                elif key == "Fn::GetAtt":
                    if isinstance(child, list) and child:
                        relationships["Fn::GetAtt"].add(str(child[0]))
                    elif isinstance(child, str):
                        relationships["Fn::GetAtt"].add(child.split(".", 1)[0])
                elif key == "Fn::ImportValue":
                    relationships["Fn::ImportValue"].add(str(child))
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(value)
    return {key: sorted(values) for key, values in relationships.items() if values}
