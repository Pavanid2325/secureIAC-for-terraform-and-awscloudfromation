"""CloudFormation resource extraction."""

from __future__ import annotations

from typing import Any

from src.models import ResourceModel

SECURITY_PROPERTY_NAMES = {
    "Policies",
    "PolicyDocument",
    "AssumeRolePolicyDocument",
    "SecurityGroupIngress",
    "SecurityGroupEgress",
    "BucketEncryption",
    "PublicAccessBlockConfiguration",
    "StorageEncrypted",
    "KmsKeyId",
    "Encrypted",
    "VpcConfig",
    "NetworkInterfaces",
    "LoggingConfiguration",
    "DeletionProtection",
    "BackupRetentionPeriod",
    "MasterUsername",
    "ManageMasterUserPassword",
    "PubliclyAccessible",
    "AccessControl",
    "VersioningConfiguration",
}


def extract_resources(template: dict[str, Any]) -> list[ResourceModel]:
    """Extract all resources while preserving unknown CloudFormation properties."""

    resources = template.get("Resources", {}) or {}
    if not isinstance(resources, dict):
        raise ValueError("Resources must be a mapping/object")

    extracted: list[ResourceModel] = []
    for logical_id, raw_resource in resources.items():
        if not isinstance(raw_resource, dict):
            raise ValueError(f"Resource {logical_id} must be a mapping/object")
        properties = raw_resource.get("Properties", {}) or {}
        if not isinstance(properties, dict):
            raise ValueError(f"Resource {logical_id} Properties must be a mapping/object")
        extracted.append(
            ResourceModel(
                logical_id=logical_id,
                resource_type=raw_resource.get("Type", "Unknown"),
                properties=properties,
                condition=raw_resource.get("Condition"),
                depends_on=raw_resource.get("DependsOn"),
                metadata=raw_resource.get("Metadata", {}) or {},
                creation_policy=raw_resource.get("CreationPolicy", {}) or {},
                update_policy=raw_resource.get("UpdatePolicy", {}) or {},
                raw=raw_resource,
                security_properties=_security_properties(properties),
            )
        )
    return extracted


def _security_properties(value: Any) -> dict[str, Any]:
    found: dict[str, Any] = {}

    def walk(node: Any, path: list[str]) -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                next_path = [*path, str(key)]
                if key in SECURITY_PROPERTY_NAMES:
                    found[".".join(next_path)] = child
                walk(child, next_path)
        elif isinstance(node, list):
            for index, child in enumerate(node):
                walk(child, [*path, str(index)])

    walk(value, [])
    return found
