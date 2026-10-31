"""Versioned deterministic organization policy evaluation on original values."""
import hashlib
import ipaddress
import json
from datetime import date
from pathlib import Path
import yaml
from src.models.validation import property_value, unresolved, AnalysisValidationError
from src.parser.cloudformation_parser import CloudFormationLoader, _validate_tree

KINDS = {"required_tags", "approved_regions", "encryption", "admin_cidrs", "public_access", "logging"}


def load_policies(path):
    if Path(path).stat().st_size > 200_000:
        raise ValueError("Policy file too large")
    text = Path(path).read_text(encoding="utf-8")
    data = yaml.load(text, Loader=CloudFormationLoader)
    _validate_tree(data)
    if not isinstance(data, dict) or set(data) != {"version", "policies"} or data["version"] != 1:
        raise ValueError("Policy format must have version: 1 and policies")
    if not isinstance(data["policies"], list):
        raise ValueError("policies must be a list")
    ids = set()
    for p in data["policies"]:
        required = {"id", "description", "type", "resource_types", "environments", "severity", "parameters"}
        if not isinstance(p, dict) or not required <= p.keys() or set(p) - required - {"exceptions"}:
            raise ValueError("Invalid policy fields")
        if p["id"] in ids or p["type"] not in KINDS or p["severity"] not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            raise ValueError("Invalid policy identity/type/severity")
        ids.add(p["id"])
        for key in ("resource_types", "environments"):
            if not isinstance(p[key], list) or not p[key] or any(not isinstance(x, str) for x in p[key]):
                raise ValueError("Policy scope must be a nonempty string list")
        params = p["parameters"]
        kind = p["type"]
        keys = {"required_tags": {"tags"}, "approved_regions": {"allowed"}, "admin_cidrs": {"allowed", "ports"}}.get(kind, {"path", "equals"})
        if not isinstance(params, dict) or set(params) != keys:
            raise ValueError("Invalid policy parameters")
        if "path" in params and (not isinstance(params["path"], str) or not params["path"].startswith("/Properties/")):
            raise ValueError("Invalid policy property path")
        if kind in {"required_tags", "approved_regions", "admin_cidrs"}:
            values = params.get("tags", params.get("allowed"))
            if not isinstance(values, list) or not values or any(not isinstance(x, str) for x in values):
                raise ValueError("Invalid policy values")
        if kind == "admin_cidrs":
            for cidr in params["allowed"]:
                ipaddress.ip_network(cidr)
            if not isinstance(params["ports"], list) or any(type(p) is not int or not 0 <= p <= 65535 for p in params["ports"]):
                raise ValueError("Invalid administrative ports")
        for ex in p.get("exceptions", []):
            if set(ex) != {"resource", "reason", "expires"} or not isinstance(ex["reason"], str) or not ex["reason"].strip():
                raise ValueError("Exceptions require resource, reason and expiry")
            date.fromisoformat(str(ex["expires"]))
    return data, hashlib.sha256(text.encode()).hexdigest()


def evaluate_policies(parsed, document, environment, region=None, today=None):
    """Environment and region come from the operator, never template metadata."""
    today = today or date.today()
    results = []
    for policy in document["policies"]:
        if environment not in policy["environments"] and "*" not in policy["environments"]:
            continue
        for resource in parsed.resources:
            if resource.resource_type not in policy["resource_types"] and "*" not in policy["resource_types"]:
                continue
            status, path, observed = _evaluate(resource, policy, region)
            exception = next((ex for ex in policy.get("exceptions", []) if ex["resource"] == resource.logical_id and date.fromisoformat(str(ex["expires"])) >= today), None)
            results.append({"policy_id": policy["id"], "resource": resource.logical_id,
                "resource_type": resource.resource_type, "severity": policy["severity"],
                "description": policy["description"], "outcome": "excepted" if exception else status,
                "property_path": path, "observed": observed, "exception": exception,
                "provenance": "organization_policy", "source_location": None})
    return results


def _evaluate(resource, policy, region):
    params, kind = policy["parameters"], policy["type"]
    if kind == "approved_regions":
        return ("unknown" if not region else "passed" if region in params["allowed"] else "failed", "deployment.region", region)
    path = params.get("path", "/Properties/Tags" if kind == "required_tags" else "/Properties/SecurityGroupIngress")
    raw = {**resource.raw, "Properties": resource.properties}
    try:
        exists, value = property_value(raw, path)
    except AnalysisValidationError:
        return "unknown", path, None
    if resource.condition or unresolved(value):
        return "unknown", path, value
    if kind == "required_tags":
        if exists and (not isinstance(value, list) or any(not isinstance(t, dict) or "Key" not in t or "Value" not in t for t in value)):
            return "unknown", path, value
        tags = {t["Key"]: t["Value"] for t in value or []}
        passed = all(tag in tags and tags[tag] not in ("", None) for tag in params["tags"])
    elif kind == "admin_cidrs":
        if not exists:
            return "unknown", path, value
        rules = value if isinstance(value, list) else [value]
        passed = True
        for rule in rules:
            if not isinstance(rule, dict):
                return "unknown", path, value
            protocol = str(rule.get("IpProtocol", ""))
            if protocol not in {"tcp", "6", "-1"}:
                continue
            try:
                admin = protocol == "-1" or any(int(rule["FromPort"]) <= p <= int(rule["ToPort"]) for p in params["ports"])
                if not admin:
                    continue
                cidr = rule.get("CidrIp", rule.get("CidrIpv6"))
                if cidr is None:
                    return "unknown", path, value
                network = ipaddress.ip_network(cidr, strict=False)
                allowed = [ipaddress.ip_network(c) for c in params["allowed"]]
                passed &= any(network.version == a.version and network.subnet_of(a) for a in allowed)
            except (ValueError, KeyError, TypeError):
                return "unknown", path, value
    else:
        passed = exists and json.dumps(value, sort_keys=True) == json.dumps(params["equals"], sort_keys=True)
    return "passed" if passed else "failed", path, value
