"""Decode a SAML 2.0 Response or AuthnRequest and run checks on it.

Accepts raw XML, base64 (POST binding), or URL-encoded deflated base64 (Redirect
binding). Signatures are reported as present or absent; cryptographic
verification is not implemented in this version.
"""
from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
import zlib
from datetime import datetime, timedelta

from lxml import etree

from .common import FAIL, INFO, PASS, SKIPPED, WARN, check, first_failure, iso, parse_time, url_difference

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}
_STATUS_HINTS = {
    "Requester": "The IdP says the request from the service provider was at fault.",
    "Responder": "The IdP reports an error on its own side.",
    "VersionMismatch": "The IdP could not process this SAML version.",
    "AuthnFailed": "The user could not be authenticated.",
    "InvalidNameIDPolicy": "The IdP cannot supply the NameID format the SP asked for.",
    "NoPassive": "The SP asked for passive sign-in but the user had no session.",
    "RequestDenied": "The IdP refused the request, usually an assignment or policy block.",
    "UnknownPrincipal": "The IdP does not know this user.",
    "NoAuthnContext": "The IdP cannot meet the requested authentication context.",
    "RequestUnsupported": "The IdP does not support this request.",
    "UnsupportedBinding": "The IdP does not support the requested binding.",
}


class DecodeError(ValueError):
    pass


def to_xml(text: str) -> bytes:
    """Turn whatever was pasted into XML bytes."""
    text = (text or "").strip()
    if not text:
        raise DecodeError("Nothing to decode.")
    match = re.match(r"^(SAMLResponse|SAMLRequest)=(.*)$", text, re.S)
    if match:
        text = match.group(2).split("&", 1)[0]
    if text.startswith("<"):
        return text.encode("utf-8")
    if "%" in text:
        text = urllib.parse.unquote(text)
    compact = re.sub(r"\s+", "", text).replace("-", "+").replace("_", "/")
    compact += "=" * (-len(compact) % 4)
    try:
        raw = base64.b64decode(compact, validate=False)
    except (binascii.Error, ValueError) as exc:
        raise DecodeError("Input is neither XML nor valid base64.") from exc
    if raw.lstrip().startswith(b"<"):
        return raw
    try:
        inflated = zlib.decompress(raw, -15)       # Redirect binding: raw DEFLATE
    except zlib.error as exc:
        raise DecodeError("Base64 decoded, but the result is not XML or deflated XML.") from exc
    if not inflated.lstrip().startswith(b"<"):
        raise DecodeError("Decoded and inflated, but the result is not XML.")
    return inflated


def _parse(xml: bytes):
    if b"<!DOCTYPE" in xml[:2000].upper() or b"<!ENTITY" in xml.upper():
        raise DecodeError("XML with a DOCTYPE or entities is refused for safety.")
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False,
                             huge_tree=False, remove_comments=True)
    try:
        return etree.fromstring(xml, parser)
    except etree.XMLSyntaxError as exc:
        raise DecodeError(f"XML is malformed or truncated: {exc.msg}") from exc


def _text(node, path: str) -> str:
    found = node.find(path, NS) if node is not None else None
    return (found.text or "").strip() if found is not None else ""


def _local(tag) -> str:
    return etree.QName(tag).localname if isinstance(tag, str) else ""


def decode(text: str) -> dict:
    """Returns the fields a person needs to reason about the message."""
    root = _parse(to_xml(text))
    kind = _local(root.tag)
    out: dict = {
        "message_type": kind,
        "id": root.get("ID", ""),
        "issue_instant": root.get("IssueInstant", ""),
        "destination": root.get("Destination", ""),
        "issuer": _text(root, "saml:Issuer"),
    }
    if kind == "AuthnRequest":
        policy = root.find("samlp:NameIDPolicy", NS)
        out.update({
            "acs_url": root.get("AssertionConsumerServiceURL", ""),
            "protocol_binding": root.get("ProtocolBinding", ""),
            "force_authn": root.get("ForceAuthn", ""),
            "is_passive": root.get("IsPassive", ""),
            "name_id_policy_format": policy.get("Format", "") if policy is not None else "",
            "signed": root.find("ds:Signature", NS) is not None,
        })
        return out
    if kind == "Assertion":
        assertion, response = root, None
    elif kind == "Response":
        response = root
        assertion = root.find("saml:Assertion", NS)
    else:
        raise DecodeError(f"Root element is <{kind}>, not a SAML Response, Assertion or AuthnRequest.")

    if response is not None:
        codes = [c.get("Value", "").rsplit(":", 1)[-1]
                 for c in response.iterfind(".//samlp:StatusCode", NS)]
        out.update({
            "in_response_to": response.get("InResponseTo", ""),
            "status_codes": codes,
            "status_message": _text(response, "samlp:Status/samlp:StatusMessage"),
            "encrypted_assertion": response.find("saml:EncryptedAssertion", NS) is not None,
            "response_signed": response.find("ds:Signature", NS) is not None,
        })
    out["assertion_signed"] = assertion is not None and assertion.find("ds:Signature", NS) is not None
    method = root.find(".//ds:SignatureMethod", NS)
    out["signature_algorithm"] = method.get("Algorithm", "").rsplit("#", 1)[-1] if method is not None else ""

    if assertion is None:
        out["assertion"] = None
        return out
    name_id = assertion.find("saml:Subject/saml:NameID", NS)
    confirm = assertion.find("saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData", NS)
    conditions = assertion.find("saml:Conditions", NS)
    authn = assertion.find("saml:AuthnStatement", NS)
    attributes: dict[str, list[str]] = {}
    for attr in assertion.iterfind("saml:AttributeStatement/saml:Attribute", NS):
        values = [(v.text or "").strip() for v in attr.iterfind("saml:AttributeValue", NS)]
        attributes[attr.get("Name", "")] = values
    out["assertion"] = {
        "id": assertion.get("ID", ""),
        "issuer": _text(assertion, "saml:Issuer"),
        "name_id": (name_id.text or "").strip() if name_id is not None else "",
        "name_id_format": name_id.get("Format", "") if name_id is not None else "",
        "recipient": confirm.get("Recipient", "") if confirm is not None else "",
        "subject_not_on_or_after": confirm.get("NotOnOrAfter", "") if confirm is not None else "",
        "subject_in_response_to": confirm.get("InResponseTo", "") if confirm is not None else "",
        "not_before": conditions.get("NotBefore", "") if conditions is not None else "",
        "not_on_or_after": conditions.get("NotOnOrAfter", "") if conditions is not None else "",
        "audiences": [(a.text or "").strip()
                      for a in assertion.iterfind("saml:Conditions/saml:AudienceRestriction/saml:Audience", NS)],
        "authn_instant": authn.get("AuthnInstant", "") if authn is not None else "",
        "authn_context": _text(authn, "saml:AuthnContext/saml:AuthnContextClassRef") if authn is not None else "",
        "attributes": attributes,
    }
    return out


def run_checks(decoded: dict, expected_audience: str = "", expected_acs: str = "",
               expected_nameid_format: str = "", required_attributes: list[str] | None = None,
               at: datetime | None = None, skew_seconds: int = 120) -> list[dict]:
    """`at` is the time the service provider received the message, if known."""
    checks: list[dict] = []
    skew = timedelta(seconds=skew_seconds)

    if decoded["message_type"] == "AuthnRequest":
        acs = decoded.get("acs_url", "")
        if expected_acs:
            if acs and acs != expected_acs:
                hint = url_difference(expected_acs, acs)
                checks.append(check("request_acs_mismatch", "ACS URL in the request", FAIL,
                                    f"Request asks for '{acs}', expected '{expected_acs}'. {hint}".strip()))
            else:
                checks.append(check("request_acs_mismatch", "ACS URL in the request", PASS, acs))
        else:
            checks.append(check("request_acs_mismatch", "ACS URL in the request", INFO,
                                acs or "Not stated; the IdP will use its configured default."))
        checks.append(check("request_issuer", "Issuer (SP entity ID)",
                            PASS if decoded["issuer"] else FAIL,
                            decoded["issuer"] or "The request has no Issuer, so the IdP cannot tell which app is asking."))
        checks.append(check("request_nameid_policy", "Requested NameID format", INFO,
                            decoded.get("name_id_policy_format") or "none requested"))
        return checks

    # 1. Status
    codes = decoded.get("status_codes")
    if codes is not None:
        if codes and codes[0] == "Success":
            checks.append(check("status_not_success", "Status", PASS, "Success"))
        else:
            hints = " ".join(_STATUS_HINTS[c] for c in codes if c in _STATUS_HINTS)
            message = decoded.get("status_message") or ""
            detail = f"Status is {' / '.join(codes) or 'missing'}."
            if message:
                detail += f" Message from the IdP: {message}"
            checks.append(check("status_not_success", "Status", FAIL, f"{detail} {hints}".strip()))

    # 2. Assertion
    assertion = decoded.get("assertion")
    if assertion is None:
        if decoded.get("encrypted_assertion"):
            checks.append(check("assertion_missing", "Assertion", INFO,
                                "The assertion is encrypted, so its contents cannot be inspected here. "
                                "Decrypt it with the SP private key or capture it before encryption."))
        else:
            checks.append(check("assertion_missing", "Assertion", FAIL,
                                "The response contains no assertion."))
        return checks
    checks.append(check("assertion_missing", "Assertion", PASS, f"ID {assertion['id']}"))

    # 3. Signature
    signed = decoded.get("response_signed") or decoded.get("assertion_signed")
    where = [name for name, flag in (("response", decoded.get("response_signed")),
                                     ("assertion", decoded.get("assertion_signed"))) if flag]
    if signed:
        algorithm = decoded.get("signature_algorithm", "")
        status = WARN if "sha1" in algorithm.lower() else PASS
        note = " SHA-1 is deprecated and some service providers reject it." if status == WARN else ""
        checks.append(check("signature_missing", "Signature", status,
                            f"Signed: {' and '.join(where)} ({algorithm or 'algorithm not stated'}). "
                            f"Presence only; the signature was not verified.{note}"))
    else:
        checks.append(check("signature_missing", "Signature", FAIL,
                            "Neither the response nor the assertion is signed."))

    # 4. Validity window
    not_before, not_after = parse_time(assertion["not_before"]), parse_time(assertion["not_on_or_after"])
    window = f"{assertion['not_before'] or '?'} to {assertion['not_on_or_after'] or '?'}"
    if not_before and not_after and not_before >= not_after:
        checks.append(check("conditions_window_invalid", "Validity window", FAIL,
                            f"NotBefore is not earlier than NotOnOrAfter ({window})."))
    elif at and not_before and at < not_before - skew:
        early = int((not_before - at).total_seconds())
        checks.append(check("assertion_not_yet_valid", "Validity window", FAIL,
                            f"Received at {iso(at)}, {early}s before NotBefore ({window}). "
                            "The two clocks disagree: the SP is behind or the IdP is ahead."))
    elif at and not_after and at >= not_after + skew:
        late = int((at - not_after).total_seconds())
        checks.append(check("assertion_expired", "Validity window", FAIL,
                            f"Received at {iso(at)}, {late}s after NotOnOrAfter ({window})."))
    elif at:
        checks.append(check("assertion_expired", "Validity window", PASS, f"{window}; received {iso(at)}"))
    else:
        length = f" ({int((not_after - not_before).total_seconds())}s long)" if not_before and not_after else ""
        checks.append(check("assertion_expired", "Validity window", INFO,
                            f"{window}{length}. Pass the time the SP received it to test this."))

    # 5. Subject confirmation
    subject_after = parse_time(assertion["subject_not_on_or_after"])
    if at and subject_after and at >= subject_after + skew:
        checks.append(check("subject_confirmation_expired", "Subject confirmation", FAIL,
                            f"SubjectConfirmationData NotOnOrAfter {assertion['subject_not_on_or_after']} "
                            f"had passed when received at {iso(at)}."))
    recipient = assertion["recipient"]
    if expected_acs:
        if recipient and recipient != expected_acs:
            hint = url_difference(expected_acs, recipient)
            checks.append(check("recipient_mismatch", "Recipient", FAIL,
                                f"Recipient is '{recipient}', the SP expects '{expected_acs}'. {hint}".strip()))
        else:
            checks.append(check("recipient_mismatch", "Recipient", PASS, recipient))
        destination = decoded.get("destination", "")
        if destination and destination != expected_acs:
            hint = url_difference(expected_acs, destination)
            checks.append(check("destination_mismatch", "Destination", FAIL,
                                f"Destination is '{destination}', the SP expects '{expected_acs}'. {hint}".strip()))
    else:
        checks.append(check("recipient_mismatch", "Recipient", INFO, recipient or "not stated"))

    # 6. Audience
    audiences = assertion["audiences"]
    if expected_audience:
        if expected_audience in audiences:
            checks.append(check("audience_mismatch", "Audience", PASS, expected_audience))
        else:
            hint = next((h for h in (url_difference(expected_audience, a) for a in audiences) if h), "")
            checks.append(check("audience_mismatch", "Audience", FAIL,
                                f"Assertion audience is {audiences or 'missing'}, the SP entity ID is "
                                f"'{expected_audience}'. {hint}".strip()))
    else:
        checks.append(check("audience_mismatch", "Audience", INFO if audiences else WARN,
                            ", ".join(audiences) or "No AudienceRestriction in the assertion."))

    # 7. NameID
    if not assertion["name_id"]:
        checks.append(check("nameid_missing", "NameID", FAIL, "The subject has no NameID."))
    elif expected_nameid_format and assertion["name_id_format"] != expected_nameid_format:
        checks.append(check("nameid_format_mismatch", "NameID format", FAIL,
                            f"Format is '{assertion['name_id_format'].rsplit(':', 1)[-1] or 'not stated'}', "
                            f"the SP expects '{expected_nameid_format.rsplit(':', 1)[-1]}'."))
    else:
        checks.append(check("nameid_missing", "NameID", PASS,
                            f"format {assertion['name_id_format'].rsplit(':', 1)[-1] or 'not stated'}"))

    # 8. Attributes
    if required_attributes:
        present = set(assertion["attributes"])
        missing = [name for name in required_attributes if name not in present]
        empty = [name for name in required_attributes
                 if name in present and not any(assertion["attributes"][name])]
        if missing or empty:
            parts = []
            if missing:
                parts.append("missing: " + ", ".join(missing))
            if empty:
                parts.append("present but empty: " + ", ".join(empty))
            checks.append(check("attribute_missing", "Required attributes", FAIL,
                                "; ".join(parts) + f". Sent: {', '.join(sorted(present)) or 'none'}."))
        else:
            checks.append(check("attribute_missing", "Required attributes", PASS, ", ".join(required_attributes)))
    else:
        checks.append(check("attribute_missing", "Attributes", INFO,
                            ", ".join(sorted(assertion["attributes"])) or "none sent"))

    checks.append(check("in_response_to", "InResponseTo",
                        INFO, decoded.get("in_response_to") or "absent (IdP-initiated sign-in)"))
    return checks


def analyze(text: str, **expected) -> dict:
    decoded = decode(text)
    checks = run_checks(decoded, **expected)
    return {"kind": "saml", "decoded": decoded, "checks": checks, "first_failure": first_failure(checks)}
