"""Validate a SCIM 2.0 request or response body (RFC 7643 / RFC 7644)."""
from __future__ import annotations

import json
import re

from .common import FAIL, INFO, PASS, WARN, check, first_failure

URN_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
URN_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
URN_ENTERPRISE = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
URN_PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
URN_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"
URN_LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse"

SCIM_TYPES = {
    "uniqueness": "A unique attribute (usually userName or externalId) already exists on another resource.",
    "invalidFilter": "The filter syntax is wrong or uses an attribute or operator the server does not support.",
    "tooMany": "The filter matches more results than the server is willing to return.",
    "mutability": "The request tried to change an attribute that is read-only or immutable.",
    "invalidSyntax": "The request body is malformed or does not follow the schema.",
    "invalidPath": "The PATCH path is malformed or names an attribute that does not exist.",
    "noTarget": "The PATCH path filter matched nothing, for example an email of type 'work' that the user does not have.",
    "invalidValue": "A required value is missing or a value is not compatible with the attribute.",
    "invalidVers": "The SCIM protocol version is not supported.",
    "sensitive": "The request put sensitive data in the URI.",
}
STATUS_HINTS = {
    "400": "The server rejected the request as malformed.",
    "401": "The bearer token is missing, expired or wrong.",
    "403": "The token is valid but lacks permission for this operation.",
    "404": "The resource or endpoint does not exist; the stored ID may be stale or the base URL wrong.",
    "409": "Conflict: the resource already exists or a unique value is taken.",
    "412": "Version mismatch: the ETag sent in If-Match is out of date.",
    "429": "Rate limited; too many requests.",
    "500": "The SCIM server failed internally.",
    "501": "The server does not implement this operation.",
}
_OPERATORS = {"eq", "ne", "co", "sw", "ew", "pr", "gt", "ge", "lt", "le"}


class DecodeError(ValueError):
    pass


def parse(text: str) -> dict:
    try:
        body = json.loads(text)
    except (TypeError, ValueError) as exc:
        raise DecodeError(f"Body is not valid JSON: {exc}") from exc
    if not isinstance(body, dict):
        raise DecodeError("A SCIM body must be a JSON object.")
    return body


def doc_type(body: dict) -> str:
    schemas = body.get("schemas") or []
    if not isinstance(schemas, list):
        return "unknown"
    lowered = [str(s).lower() for s in schemas]
    for urn, name in ((URN_ERROR, "Error"), (URN_PATCH, "PatchOp"), (URN_LIST, "ListResponse"),
                      (URN_USER, "User"), (URN_GROUP, "Group")):
        if urn.lower() in lowered:
            return name
    if "userName" in body:
        return "User"
    if "Operations" in body or "operations" in body:
        return "PatchOp"
    return "unknown"


def check_filter(expression: str) -> dict:
    """A light grammar check: balanced quotes and brackets, and known operators."""
    title = "Filter syntax"
    if expression.count('"') % 2:
        return check("filter_invalid", title, FAIL, "Unbalanced double quotes in the filter.")
    stripped = re.sub(r'"(?:[^"\\]|\\.)*"', '""', expression)
    if stripped.count("(") != stripped.count(")") or stripped.count("[") != stripped.count("]"):
        return check("filter_invalid", title, FAIL, "Unbalanced parentheses or brackets in the filter.")
    if re.search(r"[=<>!]", stripped):
        return check("filter_invalid", title, FAIL,
                     "SCIM filters use word operators (eq, ne, co, sw, gt ...), not symbols such as = or ==.")
    if "'" in stripped:
        return check("filter_invalid", title, FAIL, "String values must use double quotes, not single quotes.")
    tokens = re.findall(r'""|[A-Za-z0-9_.:$\-]+', stripped)
    position = 0
    while position < len(tokens):
        token = tokens[position]
        if token.lower() in {"and", "or", "not"}:
            position += 1
            continue
        if position + 1 >= len(tokens):
            return check("filter_invalid", title, FAIL, f"'{token}' is not followed by an operator.")
        operator = tokens[position + 1].lower()
        if operator not in _OPERATORS:
            return check("filter_invalid", title, FAIL,
                         f"'{tokens[position + 1]}' is not a SCIM operator. Valid: {', '.join(sorted(_OPERATORS))}.")
        if operator == "pr":
            position += 2
            continue
        if position + 2 >= len(tokens):
            return check("filter_invalid", title, FAIL, f"Operator '{operator}' has no value.")
        position += 3
    return check("filter_invalid", title, PASS, expression)


def run_checks(body: dict, filter_expression: str = "") -> list[dict]:
    checks: list[dict] = []
    kind = doc_type(body)
    schemas = body.get("schemas")

    if kind == "Error":
        status = str(body.get("status", ""))
        scim_type = str(body.get("scimType", ""))
        detail = str(body.get("detail", ""))
        meaning = SCIM_TYPES.get(scim_type) or STATUS_HINTS.get(status, "The SCIM server returned an error.")
        check_id = f"scim_error_{scim_type}" if scim_type in SCIM_TYPES else f"scim_error_{status or 'unknown'}"
        text = f"HTTP {status or '?'}" + (f", scimType {scim_type}" if scim_type else "") + f". {meaning}"
        if detail:
            text += f" Server detail: {detail}"
        checks.append(check(check_id, "Error response", FAIL, text))
        return checks

    if not isinstance(schemas, list) or not schemas:
        checks.append(check("schemas_missing", "schemas attribute", FAIL,
                            "The body has no 'schemas' array; every SCIM message must declare its schema URNs."))
    else:
        checks.append(check("schemas_missing", "schemas attribute", PASS, ", ".join(map(str, schemas))))

    if kind == "User":
        if not str(body.get("userName", "")).strip():
            checks.append(check("username_missing", "userName", FAIL, "userName is required and is missing or empty."))
        else:
            checks.append(check("username_missing", "userName", PASS, "present"))
        if "active" in body and not isinstance(body["active"], bool):
            checks.append(check("active_not_boolean", "active", FAIL,
                                f"active must be a JSON boolean, but it is {json.dumps(body['active'])} "
                                f"({type(body['active']).__name__}). Strict servers reject this."))
        if "name" in body and not isinstance(body["name"], dict):
            checks.append(check("name_not_object", "name", FAIL,
                                "name must be an object with givenName and familyName, not a string."))
        for attr in ("emails", "phoneNumbers", "addresses", "groups", "roles"):
            if attr not in body:
                continue
            value = body[attr]
            if not isinstance(value, list) or any(not isinstance(v, dict) for v in value):
                checks.append(check("multivalue_shape", attr, FAIL,
                                    f"{attr} must be an array of objects such as "
                                    '[{"value": "...", "type": "work", "primary": true}].'))
            elif sum(1 for v in value if v.get("primary") is True) > 1:
                checks.append(check("multiple_primary", attr, FAIL,
                                    f"More than one {attr} entry has primary: true; only one may."))
            elif attr == "emails" and any(not str(v.get("value", "")).strip() for v in value):
                checks.append(check("multivalue_shape", attr, FAIL, "An emails entry has no value."))
        if URN_ENTERPRISE in body and isinstance(schemas, list) and URN_ENTERPRISE not in schemas:
            checks.append(check("extension_not_declared", "Enterprise extension", FAIL,
                                "The body carries the enterprise User extension but its URN is not listed in 'schemas'."))
        if "externalId" not in body:
            checks.append(check("external_id", "externalId", INFO,
                                "No externalId; the client cannot correlate this user by its own key."))
    elif kind == "Group":
        if not str(body.get("displayName", "")).strip():
            checks.append(check("displayname_missing", "displayName", FAIL, "displayName is required for a Group."))
        members = body.get("members", [])
        if not isinstance(members, list) or any(not isinstance(m, dict) or "value" not in m for m in members):
            checks.append(check("multivalue_shape", "members", FAIL,
                                'members must be an array of objects with a "value" holding the member ID.'))
    elif kind == "PatchOp":
        if "Operations" not in body:
            wrong = next((k for k in body if k.lower() == "operations"), "")
            checks.append(check("patch_operations_missing", "Operations", FAIL,
                                f"The key must be 'Operations' with a capital O; found '{wrong}'." if wrong
                                else "A PatchOp body needs an 'Operations' array."))
        elif not isinstance(body["Operations"], list) or not body["Operations"]:
            checks.append(check("patch_operations_missing", "Operations", FAIL, "Operations must be a non-empty array."))
        else:
            for number, op in enumerate(body["Operations"], start=1):
                if not isinstance(op, dict):
                    checks.append(check("patch_op_invalid", f"Operation {number}", FAIL, "Each operation must be an object."))
                    continue
                name = str(op.get("op", ""))
                if name.lower() not in {"add", "replace", "remove"}:
                    checks.append(check("patch_op_invalid", f"Operation {number}", FAIL,
                                        f"op is '{name or 'missing'}'; it must be add, replace or remove."))
                    continue
                if name != name.lower():
                    checks.append(check("patch_op_case", f"Operation {number}", WARN,
                                        f"op is '{name}'. The RFC uses lowercase; Entra ID sends capitalised "
                                        "op values, and strict servers reject them."))
                if name.lower() == "remove" and not op.get("path"):
                    checks.append(check("patch_remove_no_path", f"Operation {number}", FAIL,
                                        "A remove operation needs a path."))
                if name.lower() in {"add", "replace"} and "value" not in op:
                    checks.append(check("patch_no_value", f"Operation {number}", FAIL,
                                        f"An {name.lower()} operation needs a value."))
                path = str(op.get("path", ""))
                if "[" in path:
                    inner = path[path.find("[") + 1: path.rfind("]")] if "]" in path else path
                    result = check_filter(inner)
                    if result["status"] == FAIL:
                        checks.append(check("patch_path_invalid", f"Operation {number} path", FAIL,
                                            f"Path '{path}': {result['detail']}"))
            if not any(c["id"].startswith("patch_") for c in checks):
                checks.append(check("patch_op_invalid", "Operations", PASS,
                                    f"{len(body['Operations'])} operation(s) well formed."))
    elif kind == "ListResponse":
        if not isinstance(body.get("Resources", []), list):
            checks.append(check("list_shape", "Resources", FAIL, "Resources must be an array."))
        elif not isinstance(body.get("totalResults"), int):
            checks.append(check("list_shape", "totalResults", FAIL, "totalResults must be an integer."))
        else:
            checks.append(check("list_shape", "ListResponse", PASS,
                                f"totalResults {body['totalResults']}, {len(body.get('Resources', []))} returned."))
    else:
        checks.append(check("unknown_document", "Document type", WARN,
                            "Could not tell what kind of SCIM message this is from its schemas."))

    if filter_expression:
        checks.append(check_filter(filter_expression))
    return checks


def analyze(text: str, filter_expression: str = "") -> dict:
    body = parse(text)
    checks = run_checks(body, filter_expression)
    summary = {"document_type": doc_type(body), "schemas": body.get("schemas", []),
               "attributes": sorted(k for k in body if k != "schemas")}
    if doc_type(body) == "Error":
        summary.update({"status": body.get("status"), "scimType": body.get("scimType"),
                        "detail": body.get("detail")})
    return {"kind": "scim", "decoded": summary, "checks": checks, "first_failure": first_failure(checks)}
