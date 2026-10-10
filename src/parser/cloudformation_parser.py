"""Safe CloudFormation YAML/JSON parsing without deployment."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from src.models import ParsedTemplate
from src.parser.resource_extractor import extract_resources


class CloudFormationParseError(ValueError):
    """Raised when a CloudFormation template cannot be parsed safely."""


INTRINSIC_TAGS = {
    "!And": "Fn::And",
    "!Base64": "Fn::Base64",
    "!Cidr": "Fn::Cidr",
    "!Equals": "Fn::Equals",
    "!FindInMap": "Fn::FindInMap",
    "!GetAtt": "Fn::GetAtt",
    "!If": "Fn::If",
    "!ImportValue": "Fn::ImportValue",
    "!Join": "Fn::Join",
    "!Not": "Fn::Not",
    "!Or": "Fn::Or",
    "!Ref": "Ref",
    "!Select": "Fn::Select",
    "!Split": "Fn::Split",
    "!Sub": "Fn::Sub",
}


class CloudFormationLoader(yaml.SafeLoader):
    """YAML loader that preserves CloudFormation short-form intrinsics."""


def _intrinsic_constructor(loader: CloudFormationLoader, node: yaml.Node) -> dict[str, Any]:
    key = INTRINSIC_TAGS[node.tag]
    if isinstance(node, yaml.ScalarNode):
        value: Any = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    elif isinstance(node, yaml.MappingNode):
        value = loader.construct_mapping(node)
    else:
        value = loader.construct_object(node)
    if node.tag == "!GetAtt" and isinstance(value, str):
        value = value.split(".", 1)
    return {key: value}


for tag in INTRINSIC_TAGS:
    CloudFormationLoader.add_constructor(tag, _intrinsic_constructor)


class CloudFormationParser:
    """Parse CloudFormation templates into raw and structured forms."""

    SUPPORTED_SUFFIXES = {".yaml", ".yml", ".json"}

    def __init__(self, max_bytes: int = 1_048_576) -> None:
        self.max_bytes = max_bytes

    def parse_file(self, path: str | Path) -> ParsedTemplate:
        template_path = Path(path)
        if template_path.suffix.lower() not in self.SUPPORTED_SUFFIXES:
            raise CloudFormationParseError(
                f"Unsupported template extension '{template_path.suffix}'. "
                "Use .yaml, .yml, or .json."
            )
        try:
            if template_path.stat().st_size > self.max_bytes:
                raise CloudFormationParseError(
                    f"Template exceeds maximum size of {self.max_bytes} bytes"
                )
            text = template_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise CloudFormationParseError(f"Unable to read template {template_path}: {exc}") from exc
        return self.parse_text(text, source=str(template_path), suffix=template_path.suffix.lower())

    def parse_text(self, text: str, source: str = "<memory>", suffix: str = ".yaml") -> ParsedTemplate:
        if len(text.encode("utf-8")) > self.max_bytes:
            raise CloudFormationParseError(
                f"Template exceeds maximum size of {self.max_bytes} bytes"
            )
        if not text.strip():
            raw: dict[str, Any] = {}
        else:
            raw = self._load(text, suffix, source)
        if raw is None:
            raw = {}
        if not isinstance(raw, dict):
            raise CloudFormationParseError("CloudFormation template root must be a mapping/object")

        resources = extract_resources(raw)
        return ParsedTemplate(
            path=source,
            raw=raw,
            resources=resources,
            parameters=raw.get("Parameters", {}) or {},
            mappings=raw.get("Mappings", {}) or {},
            conditions=raw.get("Conditions", {}) or {},
            outputs=raw.get("Outputs", {}) or {},
            metadata=raw.get("Metadata", {}) or {},
            description=raw.get("Description"),
            format_version=str(raw.get("AWSTemplateFormatVersion"))
            if raw.get("AWSTemplateFormatVersion") is not None
            else None,
        )

    def _load(self, text: str, suffix: str, source: str) -> dict[str, Any]:
        try:
            if suffix == ".json":
                return json.loads(text)
            return yaml.load(text, Loader=CloudFormationLoader)
        except json.JSONDecodeError as exc:
            raise CloudFormationParseError(f"Malformed JSON in {source}: {exc}") from exc
        except yaml.YAMLError as exc:
            raise CloudFormationParseError(f"Malformed YAML in {source}: {exc}") from exc
