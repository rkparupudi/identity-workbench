"""One entry point for the debugger: detect the artifact type, decode, check, explain."""
from __future__ import annotations

import json

from ..core.redaction import redact_obj
from . import har, jwt_tool, playbooks, saml, scim
from .common import parse_time

KINDS = ("saml", "jwt", "scim", "har")


def detect_kind(text: str) -> str:
    stripped = (text or "").strip()
    if not stripped:
        raise ValueError("Nothing was pasted.")
    token = stripped[7:].strip() if stripped.lower().startswith("bearer ") else stripped
    if token.startswith("eyJ") and token.count(".") in (2, 4) and " " not in token:
        return "jwt"
    if stripped.startswith("{"):
        try:
            body = json.loads(stripped)
        except ValueError:
            return "scim"
        if isinstance(body, dict) and isinstance(body.get("log"), dict) and "entries" in body["log"]:
            return "har"
        return "scim"
    return "saml"


def diagnose(text: str, kind: str = "", platform: str = "", llm=None, at=None, **expected) -> dict:
    """Returns decoded fields, every check, the first failure and what to do about it.

    expected: keyword arguments for the artifact's checks, for example
    expected_audience, expected_acs, expected_issuer, required_scopes, key.
    Unknown or empty ones are ignored. `at` is when the receiver saw the artifact.
    """
    kind = (kind or detect_kind(text)).lower()
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {', '.join(KINDS)}")
    when = parse_time(at) if at is not None and not hasattr(at, "tzinfo") else at
    expected = {k: v for k, v in expected.items() if v not in (None, "", [])}

    def pick(*names: str) -> dict:
        return {n: expected[n] for n in names if n in expected}

    if kind == "saml":
        result = saml.analyze(text, at=when, **pick("expected_audience", "expected_acs",
                                                   "expected_nameid_format", "required_attributes",
                                                   "skew_seconds"))
    elif kind == "jwt":
        result = jwt_tool.analyze(text, at=when, **pick("expected_issuer", "expected_audience",
                                                       "expected_nonce", "required_scopes", "key",
                                                       "skew_seconds"))
    elif kind == "scim":
        result = scim.analyze(text, **pick("filter_expression"))
    else:
        result = har.analyze(text, at=when, **pick("expected_audience", "expected_acs",
                                                  "expected_nameid_format", "required_attributes"))

    failure = result["first_failure"]
    if failure:
        book = playbooks.lookup(failure["id"], platform)
        result["diagnosis"] = {
            "failed_check": failure["id"], "what_failed": failure["detail"],
            "likely_cause": book["cause"], "how_to_confirm": book["confirm"],
            "fix": book["fix"], "platform_fix": book["platform_fix"],
        }
    else:
        warnings = [c for c in result["checks"] if c["status"] == "warn"]
        result["diagnosis"] = {
            "failed_check": None,
            "what_failed": "No check failed." + (
                " Warnings: " + "; ".join(c["detail"] for c in warnings) if warnings else ""),
            "likely_cause": "", "how_to_confirm": "",
            "fix": ["If sign-in still fails, supply the values the receiver expects (audience, "
                    "ACS URL, issuer, receipt time) so those checks can run."],
            "platform_fix": {},
        }

    # A copy with secrets and personal data masked: the only form a model may see.
    result["redacted"] = redact_obj({"kind": kind, "decoded": result["decoded"],
                                     "checks": result["checks"]})
    if llm is not None and failure:
        from ..llm.tasks import explain_diagnosis
        result["explanation"] = explain_diagnosis(llm, result["redacted"], result["diagnosis"], platform)
    return result
