"""Decode a JWT (OIDC ID token or OAuth access token) and run checks on it.

Decoding never needs a key. The signature is verified only when a key is
supplied: a JWKS document, a PEM public key, or a shared secret for HS* tokens.
"""
from __future__ import annotations

import base64
import binascii
import json
from datetime import datetime, timedelta

from .common import FAIL, INFO, PASS, SKIPPED, WARN, check, first_failure, iso, parse_time, url_difference


class DecodeError(ValueError):
    pass


def _b64url(part: str) -> bytes:
    part = part.strip()
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def clean_token(text: str) -> str:
    token = (text or "").strip().strip('"').strip("'")
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    return "".join(token.split())


def decode(text: str) -> dict:
    token = clean_token(text)
    parts = token.split(".")
    if len(parts) == 5:
        raise DecodeError("This is an encrypted token (JWE, five parts); its claims cannot be read without the key.")
    if len(parts) != 3:
        raise DecodeError(f"A JWT has three dot-separated parts; this has {len(parts)}. "
                          "It may be an opaque token or was truncated when copied.")
    try:
        header = json.loads(_b64url(parts[0]))
        claims = json.loads(_b64url(parts[1]))
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise DecodeError("Header or payload is not valid base64url JSON; the token is corrupt or truncated.") from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise DecodeError("Header and payload must be JSON objects.")
    if "nonce" in claims or "at_hash" in claims or "auth_time" in claims:
        token_use = "id_token"
    elif "scope" in claims or "scp" in claims or claims.get("token_use") == "access":
        token_use = "access_token"
    else:
        token_use = "unknown"
    return {"header": header, "claims": claims, "token_use": token_use,
            "has_signature": bool(parts[2])}


def _scopes(claims: dict) -> set[str]:
    out: set[str] = set()
    for key in ("scope", "scp"):
        value = claims.get(key)
        if isinstance(value, str):
            out.update(value.split())
        elif isinstance(value, list):
            out.update(str(v) for v in value)
    return out


def _verify(token: str, header: dict, key: str) -> tuple[str, str]:
    import jwt as pyjwt

    algorithm = header.get("alg", "")
    options = {"verify_exp": False, "verify_nbf": False, "verify_iat": False,
               "verify_aud": False, "verify_iss": False}
    try:
        material: object = key
        stripped = key.strip()
        if stripped.startswith("{"):
            jwks = json.loads(stripped)
            keys = jwks.get("keys", [jwks])
            kid = header.get("kid")
            chosen = next((k for k in keys if k.get("kid") == kid), None) if kid else None
            if chosen is None:
                if kid and len(keys) != 1:
                    return FAIL, (f"The token's key ID '{kid}' is not in the supplied JWKS "
                                  f"(which has {[k.get('kid') for k in keys]}). The issuer may have "
                                  "rotated its keys, or this is the wrong issuer's JWKS.")
                chosen = keys[0]
            material = pyjwt.PyJWK(chosen).key
        pyjwt.decode(token, material, algorithms=[algorithm], options=options)
        return PASS, f"Signature verified with the supplied key ({algorithm})."
    except pyjwt.InvalidSignatureError:
        return FAIL, ("The signature does not match the supplied key. The token was altered, or "
                      "the key belongs to another issuer or an older rotation.")
    except Exception as exc:  # malformed key, unsupported algorithm, ...
        return FAIL, f"Could not verify with the supplied key: {exc}"


def run_checks(decoded: dict, token: str = "", expected_issuer: str = "", expected_audience: str = "",
               expected_nonce: str = "", required_scopes: list[str] | None = None, key: str = "",
               at: datetime | None = None, skew_seconds: int = 120) -> list[dict]:
    header, claims = decoded["header"], decoded["claims"]
    skew = timedelta(seconds=skew_seconds)
    checks: list[dict] = []

    # 1. Algorithm
    algorithm = str(header.get("alg", ""))
    if algorithm.lower() == "none" or not algorithm:
        checks.append(check("alg_none", "Algorithm", FAIL,
                            "alg is 'none': the token is unsigned and must be rejected."))
    else:
        checks.append(check("alg_none", "Algorithm", PASS,
                            f"{algorithm}, key ID {header.get('kid', 'not stated')}"))

    # 2. Signature
    if not decoded["has_signature"] and algorithm.lower() != "none":
        checks.append(check("signature_invalid", "Signature", FAIL,
                            "The signature part is empty; the token was truncated when copied."))
    elif key and algorithm.lower() != "none":
        status, detail = _verify(clean_token(token), header, key)
        checks.append(check("signature_invalid", "Signature", status, detail))
    else:
        checks.append(check("signature_invalid", "Signature", SKIPPED,
                            "Not verified: supply the issuer's JWKS or public key to check it."))

    # 3. Time claims
    exp, nbf, iat = parse_time(claims.get("exp")), parse_time(claims.get("nbf")), parse_time(claims.get("iat"))
    if "exp" not in claims:
        checks.append(check("exp_missing", "Expiry", WARN, "No exp claim; the token never expires."))
    elif exp is None:
        checks.append(check("exp_missing", "Expiry", FAIL, f"exp is not a valid time: {claims.get('exp')!r}"))
    elif iat and exp <= iat:
        checks.append(check("token_expired", "Expiry", FAIL,
                            f"exp ({iso(exp)}) is not after iat ({iso(iat)})."))
    elif at and at >= exp + skew:
        checks.append(check("token_expired", "Expiry", FAIL,
                            f"Expired at {iso(exp)}; checked at {iso(at)}, "
                            f"{int((at - exp).total_seconds())}s later."))
    elif at:
        checks.append(check("token_expired", "Expiry", PASS,
                            f"Valid until {iso(exp)}; checked at {iso(at)}."))
    else:
        life = f", lifetime {int((exp - iat).total_seconds())}s" if iat else ""
        checks.append(check("token_expired", "Expiry", INFO,
                            f"Expires {iso(exp)}{life}. Pass a time to test this."))
    start = nbf or iat
    if at and start and at < start - skew:
        which = "nbf" if nbf else "iat"
        checks.append(check("token_not_yet_valid", "Not before", FAIL,
                            f"{which} is {iso(start)} but the token was checked at {iso(at)}, "
                            f"{int((start - at).total_seconds())}s earlier. The clocks disagree."))

    # 4. Issuer
    issuer = str(claims.get("iss", ""))
    if expected_issuer:
        if issuer == expected_issuer:
            checks.append(check("issuer_mismatch", "Issuer", PASS, issuer))
        else:
            hint = url_difference(expected_issuer, issuer)
            checks.append(check("issuer_mismatch", "Issuer", FAIL,
                                f"iss is '{issuer or 'missing'}', expected '{expected_issuer}'. {hint}".strip()))
    else:
        checks.append(check("issuer_mismatch", "Issuer", INFO if issuer else WARN, issuer or "No iss claim."))

    # 5. Audience
    aud = claims.get("aud")
    audiences = [str(a) for a in aud] if isinstance(aud, list) else ([str(aud)] if aud else [])
    if expected_audience:
        if expected_audience in audiences:
            checks.append(check("audience_mismatch", "Audience", PASS, expected_audience))
        else:
            hint = next((h for h in (url_difference(expected_audience, a) for a in audiences) if h), "")
            checks.append(check("audience_mismatch", "Audience", FAIL,
                                f"aud is {audiences or 'missing'}, expected '{expected_audience}'. "
                                f"The token was issued for a different client or API. {hint}".strip()))
    else:
        checks.append(check("audience_mismatch", "Audience", INFO if audiences else WARN,
                            ", ".join(audiences) or "No aud claim."))

    # 6. Nonce
    if expected_nonce:
        if claims.get("nonce") == expected_nonce:
            checks.append(check("nonce_mismatch", "Nonce", PASS, "matches"))
        else:
            checks.append(check("nonce_mismatch", "Nonce", FAIL,
                                "nonce is missing or differs from the one sent in the authorization "
                                "request; this can be a replayed response or a lost session."))

    # 7. Scopes
    if required_scopes:
        granted = _scopes(claims)
        missing = [s for s in required_scopes if s not in granted]
        if missing:
            checks.append(check("scope_missing", "Scopes", FAIL,
                                f"Missing: {', '.join(missing)}. Granted: {', '.join(sorted(granted)) or 'none'}."))
        else:
            checks.append(check("scope_missing", "Scopes", PASS, ", ".join(required_scopes)))
    elif _scopes(claims):
        checks.append(check("scope_missing", "Scopes", INFO, ", ".join(sorted(_scopes(claims)))))

    checks.append(check("token_use", "Token type", INFO,
                        {"id_token": "Looks like an OIDC ID token.",
                         "access_token": "Looks like an OAuth access token.",
                         "unknown": "Could not tell ID token from access token."}[decoded["token_use"]]))
    return checks


def analyze(text: str, **expected) -> dict:
    decoded = decode(text)
    checks = run_checks(decoded, token=text, **expected)
    return {"kind": "jwt", "decoded": decoded, "checks": checks, "first_failure": first_failure(checks)}
