"""Follow a sign-in through a HAR file and find where it breaks.

Only the request line, status, redirect target and the *names* of sign-in
parameters are kept. Cookies, headers and parameter values are never returned.
"""
from __future__ import annotations

import json
import urllib.parse

from . import saml as saml_tool
from .common import FAIL, INFO, PASS, WARN, check, first_failure

_PARAMS = ("SAMLRequest", "SAMLResponse", "RelayState", "state", "code", "error",
           "error_description", "id_token", "access_token", "nonce", "response_type",
           "client_id", "redirect_uri", "code_challenge")
_STATIC = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".map")


class DecodeError(ValueError):
    pass


def _params(entry: dict) -> dict[str, str]:
    request = entry.get("request", {})
    url = request.get("url", "")
    parsed = urllib.parse.urlsplit(url)
    found: dict[str, str] = {}
    for source in (parsed.query, parsed.fragment):
        for key, values in urllib.parse.parse_qs(source, keep_blank_values=True).items():
            found.setdefault(key, values[0])
    post = request.get("postData") or {}
    for item in post.get("params") or []:
        if isinstance(item, dict) and item.get("name"):
            found.setdefault(item["name"], item.get("value", "") or "")
    text = post.get("text") or ""
    if text and "=" in text and not text.lstrip().startswith(("{", "<")):
        for key, values in urllib.parse.parse_qs(text, keep_blank_values=True).items():
            found.setdefault(key, values[0])
    return {k: v for k, v in found.items() if k in _PARAMS}


def _location(entry: dict) -> str:
    response = entry.get("response", {})
    if response.get("redirectURL"):
        return response["redirectURL"]
    for header in response.get("headers") or []:
        if str(header.get("name", "")).lower() == "location":
            return header.get("value", "")
    return ""


def _short(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    return f"{parsed.netloc}{parsed.path}"


def analyze(text: str, **saml_expected) -> dict:
    try:
        data = json.loads(text)
        entries = data["log"]["entries"]
    except (TypeError, ValueError, KeyError) as exc:
        raise DecodeError("Not a HAR file: expected JSON with log.entries.") from exc
    if not isinstance(entries, list) or not entries:
        raise DecodeError("The HAR file has no entries.")

    steps, checks = [], []
    saml_request = saml_response = None
    authorize = callback = None
    error_step = http_error = None
    embedded_saml = ""

    for number, entry in enumerate(entries, start=1):
        request, response = entry.get("request", {}), entry.get("response", {})
        url = request.get("url", "")
        status = response.get("status", 0) or 0
        params = _params(entry)
        path = urllib.parse.urlsplit(url).path.lower()
        if path.endswith(_STATIC) and not params:
            continue
        kinds = []
        if "SAMLRequest" in params:
            kinds.append("saml_request")
            saml_request = saml_request or (number, params)
        if "SAMLResponse" in params:
            kinds.append("saml_response")
            saml_response = saml_response or (number, params)
            embedded_saml = embedded_saml or params["SAMLResponse"]
        if "response_type" in params and "client_id" in params:
            kinds.append("oidc_authorize")
            authorize = authorize or (number, params)
        elif ("code" in params or "id_token" in params) and "state" in params and "SAMLRequest" not in params:
            kinds.append("oidc_callback")
            callback = callback or (number, params)
        if "error" in params and error_step is None:
            error_step = (number, _short(url), params["error"], params.get("error_description", ""))
        if status >= 400 and http_error is None:
            http_error = (number, _short(url), status, request.get("method", ""))
        steps.append({"step": number, "method": request.get("method", ""), "url": _short(url),
                      "status": status, "redirects_to": _short(_location(entry)) if _location(entry) else "",
                      "kinds": kinds, "sign_in_parameters": sorted(params)})

    if error_step:
        number, where, error, description = error_step
        checks.append(check("oauth_error", "Error returned in the flow", FAIL,
                            f"Step {number} ({where}) carries error={error}"
                            + (f": {description}" if description else "") + "."))
    else:
        checks.append(check("oauth_error", "Error parameters", PASS, "No error parameter in any step."))

    if http_error:
        number, where, status, method = http_error
        checks.append(check("http_error", "HTTP errors", FAIL,
                            f"Step {number}: {method} {where} returned HTTP {status}."))
    else:
        checks.append(check("http_error", "HTTP errors", PASS, "No step returned 4xx or 5xx."))

    if saml_request and not saml_response:
        checks.append(check("saml_no_response", "SAML round trip", FAIL,
                            f"A SAMLRequest was sent at step {saml_request[0]} but no SAMLResponse came "
                            "back in this capture. The flow stopped at the identity provider: sign-in "
                            "failed, the user is not assigned, or the capture ended early."))
    elif saml_response:
        checks.append(check("saml_no_response", "SAML round trip", PASS,
                            f"SAMLResponse posted at step {saml_response[0]}."))
        if saml_request and "RelayState" in saml_request[1] and "RelayState" not in saml_response[1]:
            checks.append(check("relaystate_lost", "RelayState", WARN,
                                "RelayState was sent with the request but did not come back with the response."))

    if authorize:
        if not callback:
            checks.append(check("oidc_no_callback", "OIDC round trip", FAIL,
                                f"An authorization request was sent at step {authorize[0]} but no callback "
                                "with a code or token appears. The flow stopped at the provider."))
        else:
            sent, returned = authorize[1].get("state", ""), callback[1].get("state", "")
            if sent and returned != sent:
                checks.append(check("state_mismatch", "state parameter", FAIL,
                                    f"The state returned at step {callback[0]} differs from the one sent "
                                    f"at step {authorize[0]}. The app will reject the callback."))
            else:
                checks.append(check("state_mismatch", "state parameter", PASS, "state round-trips unchanged."))
        if "nonce" not in authorize[1] and "id_token" in authorize[1].get("response_type", ""):
            checks.append(check("nonce_not_sent", "nonce", WARN, "An ID token was requested without a nonce."))

    decoded: dict = {"steps": steps, "last_step": steps[-1] if steps else None}
    if embedded_saml:
        try:
            inner = saml_tool.analyze(embedded_saml, **saml_expected)
            decoded["saml_response"] = inner["decoded"]
            for item in inner["checks"]:
                checks.append({**item, "title": "SAML: " + item["title"]})
        except saml_tool.DecodeError as exc:
            checks.append(check("saml_undecodable", "Embedded SAMLResponse", WARN, str(exc)))
    if not (saml_request or saml_response or authorize or callback):
        checks.append(check("no_sign_in_flow", "Sign-in flow", INFO,
                            "No SAML or OIDC parameters were found in this capture."))
    return {"kind": "har", "decoded": decoded, "checks": checks, "first_failure": first_failure(checks)}
