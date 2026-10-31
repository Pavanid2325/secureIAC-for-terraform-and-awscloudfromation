"""Single provider-independent wire contract, version 2."""
SCHEMA_VERSION = "2"


def obj(properties):
    return {"type": "object", "properties": properties,
            "required": list(properties), "additionalProperties": False}


TEXT = {"type": "string"}
TEXTS = {"type": "array", "items": TEXT}
FINDING_SCHEMA = obj({
    **{key: TEXT for key in ("finding_id", "resource_logical_id", "resource_type",
                            "title", "description", "evidence", "security_impact")},
    "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
    "retrieved_guidance": TEXTS, "guidance_sources": TEXTS,
    "remediation": obj({"explanation": TEXT, "recommended_change": TEXT,
                        "cloudformation_snippet": {"type": ["string", "null"]}, "assumptions": TEXTS}),
    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
    "related_resources": TEXTS,
    "property_path": TEXT,
    "observed_value_json": TEXT,
    "missing": {"type": "boolean"},
    "status": {"type": "string", "enum": ["verified_configuration_fact", "contextual_concern", "insufficient_information"]},
    "uncertainty": TEXTS,
})
ANALYSIS_SCHEMA = obj({"schema_version": {"type": "string", "enum": [SCHEMA_VERSION]},
                      "template_name": TEXT, "resources_analyzed": {"type": "integer"},
                      "findings": {"type": "array", "items": FINDING_SCHEMA}, "summary": TEXT})
