"""Resource descriptor and retrieval query generation."""

from __future__ import annotations

import re

from src.models import ResourceDescriptor, TemplateSummary


RESOURCE_KEYWORDS = {
    "AWS::S3::Bucket": ["s3", "bucket", "encryption", "public access", "logging"],
    "AWS::IAM::Role": ["iam", "role", "least privilege", "trust policy", "wildcard"],
    "AWS::IAM::Policy": ["iam", "policy", "least privilege", "wildcard"],
    "AWS::EC2::SecurityGroup": ["ec2", "security group", "ingress", "cidr", "port"],
    "AWS::RDS::DBInstance": ["rds", "database", "encryption", "public accessibility", "backup"],
}


def build_resource_descriptors(summary: TemplateSummary) -> list[ResourceDescriptor]:
    descriptors: list[ResourceDescriptor] = []
    template_context = " ".join(summary.resource_types.keys())
    for normalized in summary.normalized_resources:
        resource = normalized.resource
        tokens = [
            *split_resource_type(resource.resource_type),
            *RESOURCE_KEYWORDS.get(resource.resource_type, []),
            *_security_terms(resource.security_properties),
            *_property_terms(resource.properties),
            template_context,
            "security best practices recommendations",
        ]
        query = " ".join(dict.fromkeys(token for token in tokens if token))
        descriptors.append(
            ResourceDescriptor(
                resource=resource.logical_id,
                resource_type=resource.resource_type,
                query=query,
                metadata={
                    "condition": resource.condition,
                    "depends_on": resource.depends_on,
                    "relationships": normalized.relationships,
                },
            )
        )
    return descriptors


def split_resource_type(resource_type: str) -> list[str]:
    parts = resource_type.replace("::", " ").split()
    expanded: list[str] = []
    for part in parts:
        if re.fullmatch(r"[A-Z0-9]+", part):
            expanded.append(part)
        else:
            expanded.extend(re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)|\d+", part))
    return [part.lower() for part in expanded] or [resource_type.lower()]


def _security_terms(properties: dict[str, object]) -> list[str]:
    terms: list[str] = []
    for key, value in properties.items():
        lower = key.lower()
        terms.append(lower.replace(".", " "))
        rendered = str(value).lower()
        if "0.0.0.0/0" in rendered:
            terms.extend(["unrestricted", "public cidr"])
        if "*" in rendered:
            terms.extend(["wildcard", "least privilege"])
        if "false" in rendered:
            terms.append("disabled")
    return terms


def _property_terms(properties: dict[str, object]) -> list[str]:
    terms: list[str] = []
    for key, value in properties.items():
        lower = key.lower()
        if any(word in lower for word in ["encrypt", "public", "logging", "policy", "ingress", "egress"]):
            terms.append(lower)
        rendered = str(value).lower()
        if "publiclyaccessible" in lower or "0.0.0.0/0" in rendered:
            terms.append("public exposure")
    return terms
