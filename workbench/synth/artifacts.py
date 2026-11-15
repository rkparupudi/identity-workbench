"""Synthetic SAML, JWT, SCIM and HAR artifacts, each broken in one known way.

Used for tests, for scoring the debugger, and as samples to try it with.
Signatures in the SAML samples are placeholders, not real cryptography.
Every key generated here is throwaway.
"""
from __future__ import annotations

import base64
import json
import urllib.parse
import zlib
from datetime import datetime, timedelta, timezone

SP_ENTITY = "https://sp.example.com/saml/metadata"
SP_ACS = "https://sp.example.com/saml/acs"
IDP_ISSUER = "https://idp.example.com/app/exk1abcd"
OIDC_ISSUER = "https://idp.example.com/oauth2/default"
OIDC_AUDIENCE = "api://workbench-demo"
EMAIL_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
UNSPECIFIED_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"

BASE_TIME = datetime(2026, 11, 2, 9, 30, 0, tzinfo=timezone.utc)


def _z(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


_SIGNATURE = (
    '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>'
    '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
    '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
    '<ds:Reference URI="#{ref}"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
    "<ds:DigestValue>cGxhY2Vob2xkZXItZGlnZXN0LXZhbHVlLW5vdC1yZWFsMTIzNDU2Nzg5MA==</ds:DigestValue>"
    "</ds:Reference></ds:SignedInfo><ds:SignatureValue>"
    "cGxhY2Vob2xkZXItc2lnbmF0dXJlLXZhbHVlLW5vdC1yZWFsLWNyeXB0b2dyYXBoeS0wMTIzNDU2Nzg5YWJjZGVm"
    "</ds:SignatureValue></ds:Signature>"
)


def saml_response(issued: datetime = BASE_TIME, audience: str = SP_ENTITY, recipient: str = SP_ACS,
                  destination: str = SP_ACS, name_id: str = "asha.rao@corp.example",
                  name_id_format: str = EMAIL_FORMAT, attributes: dict | None = None,
                  signed: bool = True, status: str = "Success", sub_status: str = "",
                  status_message: str = "", lifetime_seconds: int = 300) -> str:
    if attributes is None:
        attributes = {"email": ["asha.rao@corp.example"], "firstName": ["Asha"],
                      "lastName": ["Rao"], "groups": ["Engineering", "VPN-Users"]}
    not_before = issued - timedelta(seconds=30)
    not_after = issued + timedelta(seconds=lifetime_seconds)
    status_xml = f'<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:{status}">'
    if sub_status:
        status_xml += f'<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:{sub_status}"/>'
    status_xml += "</samlp:StatusCode>"
    if status_message:
        status_xml += f"<samlp:StatusMessage>{status_message}</samlp:StatusMessage>"
    head = (
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp8f2a1c" Version="2.0" '
        f'IssueInstant="{_z(issued)}" Destination="{destination}" InResponseTo="_req51d0e7">'
        f"<saml:Issuer>{IDP_ISSUER}</saml:Issuer><samlp:Status>{status_xml}</samlp:Status>")
    if status != "Success":
        return head + "</samlp:Response>"
    subject = ""
    if name_id:
        subject = f'<saml:NameID Format="{name_id_format}">{name_id}</saml:NameID>'
    attr_xml = "".join(
        f'<saml:Attribute Name="{name}">'
        + "".join(f"<saml:AttributeValue>{v}</saml:AttributeValue>" for v in values)
        + "</saml:Attribute>" for name, values in attributes.items())
    assertion = (
        f'<saml:Assertion ID="_asrt3b7d90" Version="2.0" IssueInstant="{_z(issued)}">'
        f"<saml:Issuer>{IDP_ISSUER}</saml:Issuer>"
        + (_SIGNATURE.format(ref="_asrt3b7d90") if signed else "")
        + f"<saml:Subject>{subject}"
        '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
        f'<saml:SubjectConfirmationData NotOnOrAfter="{_z(not_after)}" Recipient="{recipient}" '
        'InResponseTo="_req51d0e7"/></saml:SubjectConfirmation></saml:Subject>'
        f'<saml:Conditions NotBefore="{_z(not_before)}" NotOnOrAfter="{_z(not_after)}">'
        f"<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience>"
        "</saml:AudienceRestriction></saml:Conditions>"
        f'<saml:AuthnStatement AuthnInstant="{_z(issued)}" SessionIndex="_sess1">'
        "<saml:AuthnContext><saml:AuthnContextClassRef>"
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
        "</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>"
        f"<saml:AttributeStatement>{attr_xml}</saml:AttributeStatement></saml:Assertion>")
    return head + assertion + "</samlp:Response>"


def saml_authn_request(acs: str = SP_ACS, issued: datetime = BASE_TIME) -> str:
    return (
        '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req51d0e7" Version="2.0" '
        f'IssueInstant="{_z(issued)}" Destination="https://idp.example.com/sso/saml" '
        f'AssertionConsumerServiceURL="{acs}" '
        'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">'
        f"<saml:Issuer>{SP_ENTITY}</saml:Issuer>"
        f'<samlp:NameIDPolicy Format="{EMAIL_FORMAT}" AllowCreate="true"/></samlp:AuthnRequest>')


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def redirect_encode(xml: str) -> str:
    """Deflate, base64 and URL-encode, as the HTTP-Redirect binding does."""
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    raw = compressor.compress(xml.encode()) + compressor.flush()
    return urllib.parse.quote(base64.b64encode(raw).decode(), safe="")


# ---- JWT ----------------------------------------------------------------------------

_KEYS: dict = {}


def _keys() -> dict:
    """Two throwaway RSA key pairs and the JWKS for the first."""
    if not _KEYS:
        import jwt as pyjwt
        from cryptography.hazmat.primitives.asymmetric import rsa

        good = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(pyjwt.algorithms.RSAAlgorithm.to_jwk(good.public_key()))
        jwk.update({"kid": "demo-key-1", "use": "sig", "alg": "RS256"})
        _KEYS.update({"good": good, "other": other, "jwks": json.dumps({"keys": [jwk]})})
    return _KEYS


def jwks() -> str:
    return _keys()["jwks"]


def make_jwt(issued: datetime = BASE_TIME, issuer: str = OIDC_ISSUER, audience=OIDC_AUDIENCE,
             scope: str = "openid profile users.read", nonce: str = "n-7f3a", lifetime: int = 3600,
             nbf_offset: int = 0, key: str = "good", kid: str = "demo-key-1",
             alg: str = "RS256") -> str:
    import jwt as pyjwt

    claims = {"iss": issuer, "aud": audience, "sub": "00u1abcd2efgh", "scope": scope,
              "nonce": nonce, "iat": int(issued.timestamp()),
              "nbf": int(issued.timestamp()) + nbf_offset,
              "exp": int(issued.timestamp()) + lifetime, "email": "asha.rao@corp.example"}
    if alg == "none":
        def enc(obj) -> str:
            return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
        return f"{enc({'alg': 'none', 'typ': 'JWT'})}.{enc(claims)}."
    return pyjwt.encode(claims, _keys()[key], algorithm=alg, headers={"kid": kid})


# ---- SCIM ---------------------------------------------------------------------------

def scim_user(**changes) -> dict:
    body = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "asha.rao@corp.example", "externalId": "E100123", "active": True,
        "name": {"givenName": "Asha", "familyName": "Rao"},
        "emails": [{"value": "asha.rao@corp.example", "type": "work", "primary": True}],
    }
    body.update(changes)
    return {k: v for k, v in body.items() if v is not None}


def scim_error(status: str, scim_type: str = "", detail: str = "") -> dict:
    body = {"schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "status": status,
            "detail": detail}
    if scim_type:
        body["scimType"] = scim_type
    return body


def scim_patch(operations, key: str = "Operations") -> dict:
    return {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], key: operations}


# ---- HAR ----------------------------------------------------------------------------

def _entry(method: str, url: str, status: int, location: str = "", post: dict | None = None) -> dict:
    entry = {"request": {"method": method, "url": url,
                         "headers": [{"name": "Cookie", "value": "sid=3f9c1e7a5b2d4c6e8f0a1b2c3d4e5f60"}]},
             "response": {"status": status, "redirectURL": location,
                          "headers": [{"name": "Set-Cookie", "value": "session=9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d"}]}}
    if post is not None:
        entry["request"]["postData"] = {
            "mimeType": "application/x-www-form-urlencoded",
            "params": [{"name": k, "value": v} for k, v in post.items()]}
    return entry


def har(entries: list[dict]) -> str:
    return json.dumps({"log": {"version": "1.2", "creator": {"name": "synthetic"}, "entries": entries}})


def _saml_har(response_xml: str | None, callback_status: int = 302) -> str:
    request = redirect_encode(saml_authn_request())
    entries = [
        _entry("GET", "https://sp.example.com/login", 302,
               f"https://idp.example.com/sso/saml?SAMLRequest={request}&RelayState=%2Fdashboard"),
        _entry("GET", f"https://idp.example.com/sso/saml?SAMLRequest={request}&RelayState=%2Fdashboard", 200),
        _entry("GET", "https://idp.example.com/assets/app.js", 200),
    ]
    if response_xml is not None:
        entries.append(_entry("POST", SP_ACS, callback_status, "https://sp.example.com/dashboard",
                              {"SAMLResponse": b64(response_xml), "RelayState": "/dashboard"}))
        if callback_status < 400:
            entries.append(_entry("GET", "https://sp.example.com/dashboard", 200))
    return har(entries)


def _oidc_har(callback_query: str | None, callback_status: int = 302) -> str:
    authorize = ("https://idp.example.com/oauth2/default/v1/authorize?client_id=0oa1demo&response_type=code"
                 "&scope=openid%20profile&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback"
                 "&state=st-41c9&nonce=n-7f3a&code_challenge=abc123xyz")
    entries = [_entry("GET", "https://app.example.com/login", 302, authorize),
               _entry("GET", authorize, 200)]
    if callback_query is not None:
        entries.append(_entry("GET", f"https://app.example.com/callback?{callback_query}",
                              callback_status, "https://app.example.com/home"))
        if callback_status < 400:
            entries.append(_entry("GET", "https://app.example.com/home", 200))
    return har(entries)


# ---- the case list ------------------------------------------------------------------

def cases() -> list[dict]:
    """Each case: name, kind, text, expected (arguments for the checks), fault (check id or None)."""
    t = BASE_TIME
    on_time = t + timedelta(seconds=20)
    saml_expect = {"expected_audience": SP_ENTITY, "expected_acs": SP_ACS, "at": on_time}
    jwt_expect = {"expected_issuer": OIDC_ISSUER, "expected_audience": OIDC_AUDIENCE,
                  "key": jwks(), "at": on_time}
    out: list[dict] = []

    def add(name, kind, text, expected, fault):
        out.append({"name": name, "kind": kind, "text": text, "expected": expected, "fault": fault})

    # SAML
    add("saml_healthy", "saml", saml_response(), saml_expect, None)
    add("saml_healthy_base64", "saml", b64(saml_response()), saml_expect, None)
    add("saml_audience_trailing_slash", "saml", saml_response(audience=SP_ENTITY + "/"), saml_expect, "audience_mismatch")
    add("saml_audience_wrong_app", "saml", saml_response(audience="https://other.example.com/metadata"), saml_expect, "audience_mismatch")
    add("saml_recipient_wrong", "saml", saml_response(recipient="https://sp.example.com/sso/acs"), saml_expect, "recipient_mismatch")
    add("saml_destination_http", "saml", saml_response(destination=SP_ACS.replace("https", "http")), saml_expect, "destination_mismatch")
    add("saml_unsigned", "saml", saml_response(signed=False), saml_expect, "signature_missing")
    add("saml_clock_skew", "saml", saml_response(), {**saml_expect, "at": t - timedelta(minutes=10)}, "assertion_not_yet_valid")
    add("saml_expired", "saml", saml_response(), {**saml_expect, "at": t + timedelta(minutes=30)}, "assertion_expired")
    add("saml_status_denied", "saml",
        saml_response(status="Responder", sub_status="RequestDenied", status_message="User is not assigned to this application"),
        saml_expect, "status_not_success")
    add("saml_nameid_missing", "saml", saml_response(name_id=""), saml_expect, "nameid_missing")
    add("saml_nameid_format", "saml", saml_response(name_id_format=UNSPECIFIED_FORMAT),
        {**saml_expect, "expected_nameid_format": EMAIL_FORMAT}, "nameid_format_mismatch")
    add("saml_attribute_missing", "saml", saml_response(attributes={"email": ["asha.rao@corp.example"]}),
        {**saml_expect, "required_attributes": ["email", "groups"]}, "attribute_missing")
    add("saml_request_acs_redirect_binding", "saml",
        redirect_encode(saml_authn_request(acs="https://sp.example.com/old/acs")),
        {"expected_acs": SP_ACS}, "request_acs_mismatch")

    # JWT
    add("jwt_healthy", "jwt", make_jwt(), jwt_expect, None)
    add("jwt_expired", "jwt", make_jwt(), {**jwt_expect, "at": t + timedelta(hours=3)}, "token_expired")
    add("jwt_not_yet_valid", "jwt", make_jwt(nbf_offset=900), jwt_expect, "token_not_yet_valid")
    add("jwt_issuer_trailing_slash", "jwt", make_jwt(issuer=OIDC_ISSUER + "/"), jwt_expect, "issuer_mismatch")
    add("jwt_audience_wrong", "jwt", make_jwt(audience="0oa9otherclient"), jwt_expect, "audience_mismatch")
    add("jwt_alg_none", "jwt", make_jwt(alg="none"), jwt_expect, "alg_none")
    add("jwt_wrong_key", "jwt", make_jwt(key="other"), jwt_expect, "signature_invalid")
    add("jwt_unknown_kid", "jwt", make_jwt(kid="rotated-key-9"),
        {**jwt_expect, "key": json.dumps({"keys": json.loads(jwks())["keys"] + [{"kty": "RSA", "kid": "x", "n": "AQAB", "e": "AQAB"}]})},
        "signature_invalid")
    add("jwt_scope_missing", "jwt", make_jwt(scope="openid profile"),
        {**jwt_expect, "required_scopes": ["users.read"]}, "scope_missing")
    add("jwt_nonce_mismatch", "jwt", make_jwt(nonce="n-0000"), {**jwt_expect, "expected_nonce": "n-7f3a"}, "nonce_mismatch")

    # SCIM
    def scim(name, body, fault, **expected):
        add(name, "scim", json.dumps(body), expected, fault)

    scim("scim_healthy_user", scim_user(), None)
    scim("scim_healthy_patch", scim_patch([{"op": "replace", "path": "active", "value": False}]), None)
    scim("scim_conflict", scim_error("409", "uniqueness", "User already exists in the database."), "scim_error_uniqueness")
    scim("scim_unauthorized", scim_error("401", "", "Invalid bearer token."), "scim_error_401")
    scim("scim_invalid_filter", scim_error("400", "invalidFilter", "Unsupported filter attribute: emails.value"), "scim_error_invalidFilter")
    scim("scim_no_target", scim_error("400", "noTarget", "No email of type work"), "scim_error_noTarget")
    scim("scim_active_string", scim_user(active="true"), "active_not_boolean")
    scim("scim_username_missing", scim_user(userName=""), "username_missing")
    scim("scim_emails_strings", scim_user(emails=["asha.rao@corp.example"]), "multivalue_shape")
    scim("scim_two_primaries", scim_user(emails=[
        {"value": "a@corp.example", "primary": True}, {"value": "b@corp.example", "primary": True}]), "multiple_primary")
    scim("scim_no_schemas", scim_user(schemas=None), "schemas_missing")
    scim("scim_extension_undeclared", scim_user(**{
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {"department": "Engineering"}}), "extension_not_declared")
    scim("scim_patch_lowercase_key", scim_patch([{"op": "replace", "path": "active", "value": False}], key="operations"), "patch_operations_missing")
    scim("scim_patch_remove_no_path", scim_patch([{"op": "remove"}]), "patch_remove_no_path")
    scim("scim_patch_no_value", scim_patch([{"op": "replace", "path": "displayName"}]), "patch_no_value")
    scim("scim_filter_symbol", scim_user(), "filter_invalid", filter_expression='userName = "asha.rao@corp.example"')

    # HAR
    add("har_saml_healthy", "har", _saml_har(saml_response()), saml_expect, None)
    add("har_oidc_healthy", "har", _oidc_har("code=SplxlOBeZQQYbYS6WxSbIA&state=st-41c9"), {}, None)
    add("har_saml_no_response", "har", _saml_har(None), {}, "saml_no_response")
    add("har_saml_audience", "har", _saml_har(saml_response(audience="https://sp.example.com/metadata")), saml_expect, "audience_mismatch")
    add("har_callback_403", "har", _saml_har(saml_response(), callback_status=403), saml_expect, "http_error")
    add("har_oidc_access_denied", "har",
        _oidc_har("error=access_denied&error_description=User%20is%20not%20assigned%20to%20the%20client%20application&state=st-41c9"),
        {}, "oauth_error")
    add("har_oidc_state_mismatch", "har", _oidc_har("code=SplxlOBeZQQYbYS6WxSbIA&state=st-ffff"), {}, "state_mismatch")
    add("har_oidc_no_callback", "har", _oidc_har(None), {}, "oidc_no_callback")
    return out


def malformed_inputs() -> list[tuple[str, str]]:
    """(kind, text) pairs that must produce a clear error, never a crash."""
    whole = saml_response()
    token = make_jwt()
    return [
        ("saml", whole[: len(whole) // 2]),
        ("saml", "this is not base64 or xml !!!"),
        ("saml", b64("just some text, not xml")),
        ("saml", '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'),
        ("saml", "<html><body>Sign-in error</body></html>"),
        ("jwt", ".".join(token.split(".")[:2])),
        ("jwt", "eyJhbGciOi.###.sig"),
        ("jwt", "a.b.c.d.e"),
        ("scim", '{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": '),
        ("scim", "[1, 2, 3]"),
        ("har", '{"log": {}}'),
        ("har", '{"log": {"entries": []}}'),
    ]
