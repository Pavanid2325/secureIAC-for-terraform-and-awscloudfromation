"""Metadata helpers for local security guidance documents."""

from __future__ import annotations

from pathlib import Path


SERVICE_HINTS = {
    "s3": "Amazon S3",
    "iam": "AWS IAM",
    "ec2": "Amazon EC2",
    "securitygroup": "Amazon EC2",
    "rds": "Amazon RDS",
    "kms": "AWS KMS",
    "cloudformation": "AWS CloudFormation",
}


def infer_metadata(path: Path, text: str) -> dict[str, str]:
    """Infer lightweight searchable metadata from path and document text."""

    lower = f"{path.as_posix()} {text[:1000]}".lower()
    metadata: dict[str, str] = {"local_path": str(path)}
    for hint, service in SERVICE_HINTS.items():
        if hint in lower:
            metadata["service"] = service
            break
    if "cis" in lower:
        metadata["framework"] = "CIS"
    elif "well-architected" in lower or "well architected" in lower:
        metadata["framework"] = "AWS Well-Architected"
    return metadata
