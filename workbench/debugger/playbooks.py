"""Failed check -> likely cause, how to confirm, and the fix.

Hand-written. Console paths change between product versions: treat them as
pointers and confirm in the vendor's current documentation.
"""
from __future__ import annotations

_OKTA_SAML = "Okta: Applications > your app > General > SAML Settings > Edit"
_ENTRA_SAML = "Entra ID: Enterprise applications > your app > Single sign-on > Basic SAML Configuration"

PLAYBOOKS: dict[str, dict] = {
    # ---- SAML ----
    "status_not_success": {
        "cause": "The identity provider refused or failed the sign-in before issuing an assertion.",
        "confirm": "Read the status code and message, then find the same sign-in in the IdP's logs.",
        "fix": {"generic": ["Fix what the IdP log names: user not assigned to the app, a policy denial, "
                            "or a NameID format it cannot supply."],
                "okta": ["Reports > System Log: filter on the user and app for the failure reason.",
                         "Check the user is assigned under Applications > your app > Assignments."],
                "entra": ["Sign-in logs for the user show the failure reason and error code.",
                          "Check Users and groups on the enterprise app if assignment is required."]},
    },
    "assertion_missing": {
        "cause": "The response carries no assertion, which normally accompanies a non-success status.",
        "confirm": "Check the status code in the same response.",
        "fix": {"generic": ["Resolve the status error; a successful response always includes an assertion."]},
    },
    "signature_missing": {
        "cause": "The IdP is not signing the response or the assertion, and the SP requires a signature.",
        "confirm": "Look for a ds:Signature element under the Response or the Assertion.",
        "fix": {"generic": ["Turn on signing at the IdP for whichever element the SP validates."],
                "okta": [f"{_OKTA_SAML} > Show Advanced Settings: set Response and Assertion Signature to Signed."],
                "entra": ["Single sign-on > SAML Signing Certificate > Edit: choose the Signing Option "
                          "(response, assertion, or both)."]},
    },
    "conditions_window_invalid": {
        "cause": "The assertion's validity window is malformed.",
        "confirm": "Compare NotBefore and NotOnOrAfter in the Conditions element.",
        "fix": {"generic": ["This is an IdP defect or a tampered message; capture a fresh response."]},
    },
    "assertion_not_yet_valid": {
        "cause": "Clock skew: the service provider's clock is behind the identity provider's.",
        "confirm": "Compare the SP server's UTC time with NotBefore in the assertion.",
        "fix": {"generic": ["Sync the SP server clock with NTP.",
                            "If the SP has a clock-skew tolerance setting, allow a minute or two."]},
    },
    "assertion_expired": {
        "cause": "The assertion reached the SP after its validity window: a slow or replayed post, "
                 "or the SP clock is ahead.",
        "confirm": "Compare the SP server's UTC time with NotOnOrAfter; check how long the user took.",
        "fix": {"generic": ["Sync the SP server clock with NTP.",
                            "Start a fresh sign-in; do not replay a captured response."]},
    },
    "subject_confirmation_expired": {
        "cause": "The bearer confirmation window had passed when the SP received the assertion.",
        "confirm": "Compare SubjectConfirmationData NotOnOrAfter with the SP's receipt time.",
        "fix": {"generic": ["Sync clocks on both sides and retry with a fresh sign-in."]},
    },
    "recipient_mismatch": {
        "cause": "The IdP is posting to a different ACS URL than the one the SP validates.",
        "confirm": "Compare the Recipient value with the SP's ACS URL character by character.",
        "fix": {"generic": ["Set the IdP's ACS / reply URL to exactly the SP's value."],
                "okta": [f"{_OKTA_SAML}: correct Single sign-on URL (and Recipient URL if set separately)."],
                "entra": [f"{_ENTRA_SAML}: correct Reply URL (Assertion Consumer Service URL)."]},
    },
    "destination_mismatch": {
        "cause": "The Destination attribute does not equal the URL the SP received the response on.",
        "confirm": "Compare Destination with the SP's ACS URL; proxies and http/https rewrites cause this.",
        "fix": {"generic": ["Align the IdP's destination URL with the SP's public ACS URL."],
                "okta": [f"{_OKTA_SAML}: check Single sign-on URL and Destination URL."],
                "entra": [f"{_ENTRA_SAML}: check Reply URL."]},
    },
    "audience_mismatch": {
        "cause": "The audience the IdP issued the assertion or token for is not the identifier "
                 "the receiving application expects.",
        "confirm": "Compare the audience value with the SP entity ID (or API identifier) exactly, "
                   "including trailing slash, case and scheme.",
        "fix": {"generic": ["Make the IdP's audience equal the application's identifier."],
                "okta": [f"SAML: {_OKTA_SAML}: correct Audience URI (SP Entity ID).",
                         "OIDC: use the client ID of the right app, or the audience of the right "
                         "authorization server under Security > API."],
                "entra": [f"SAML: {_ENTRA_SAML}: correct Identifier (Entity ID).",
                          "OIDC: request the token for the right resource; the aud is the client ID "
                          "or the Application ID URI of the API."]},
    },
    "nameid_missing": {
        "cause": "The IdP sent no NameID, usually because the mapped source attribute is empty for this user.",
        "confirm": "Check the user's profile for the attribute mapped to NameID.",
        "fix": {"generic": ["Map NameID to an attribute every user has, or populate it for this user."],
                "okta": [f"{_OKTA_SAML}: check Application username and Name ID format."],
                "entra": ["Single sign-on > Attributes & Claims: check Unique User Identifier (Name ID)."]},
    },
    "nameid_format_mismatch": {
        "cause": "The IdP sends a NameID format the SP does not accept.",
        "confirm": "Compare the Format attribute on NameID with the format in the SP's metadata.",
        "fix": {"generic": ["Set the IdP's NameID format to the one the SP requires."],
                "okta": [f"{_OKTA_SAML}: set Name ID format."],
                "entra": ["Single sign-on > Attributes & Claims > Unique User Identifier: set Name identifier format."]},
    },
    "attribute_missing": {
        "cause": "The assertion lacks an attribute the SP needs, or sends it under a different name.",
        "confirm": "Compare attribute names in the assertion with the names the SP expects; they are case-sensitive.",
        "fix": {"generic": ["Add the attribute at the IdP with the exact name the SP expects, "
                            "and make sure the user has a value for it."],
                "okta": [f"{_OKTA_SAML}: add it under Attribute Statements (or Group Attribute Statements)."],
                "entra": ["Single sign-on > Attributes & Claims: add a claim with the expected name."]},
    },
    "request_acs_mismatch": {
        "cause": "The SP asks the IdP to reply to a URL the IdP does not have registered.",
        "confirm": "Compare AssertionConsumerServiceURL in the request with the IdP's configured reply URLs.",
        "fix": {"generic": ["Register the URL at the IdP, or fix the SP's configured ACS URL."],
                "entra": [f"{_ENTRA_SAML}: add the URL under Reply URL."]},
    },
    "request_issuer": {
        "cause": "The request does not identify the application.",
        "confirm": "Look for the Issuer element in the AuthnRequest.",
        "fix": {"generic": ["Set the SP's entity ID in its SAML configuration."]},
    },
    # ---- JWT ----
    "alg_none": {
        "cause": "The token is unsigned.",
        "confirm": "Read the alg value in the header.",
        "fix": {"generic": ["Reject it. Find where it came from; a legitimate issuer does not send alg none."]},
    },
    "signature_invalid": {
        "cause": "The token does not verify with the key supplied: wrong issuer's keys, rotated keys, "
                 "or a modified or truncated token.",
        "confirm": "Match the kid in the header against the issuer's current JWKS.",
        "fix": {"generic": ["Fetch the issuer's JWKS again; cache keys by kid and refresh on an unknown kid.",
                            "Check the token was copied whole."],
                "okta": ["Use the keys URL of the same authorization server that issued the token "
                         "(the org server and custom servers have different keys)."],
                "entra": ["Use the jwks_uri from the tenant's OpenID configuration; v1.0 and v2.0 "
                          "endpoints issue different issuers."]},
    },
    "token_expired": {
        "cause": "The token is past its exp time.",
        "confirm": "Compare exp with the current UTC time on the server that validates it.",
        "fix": {"generic": ["Get a new token (use the refresh token or sign in again).",
                            "If it expires immediately, check the validating server's clock."]},
    },
    "token_not_yet_valid": {
        "cause": "Clock skew: the validating server's clock is behind the issuer's.",
        "confirm": "Compare nbf or iat with the validating server's UTC time.",
        "fix": {"generic": ["Sync the server clock with NTP and allow a small leeway in validation."]},
    },
    "exp_missing": {
        "cause": "The exp claim is absent or not a number.",
        "confirm": "Read the claims.",
        "fix": {"generic": ["Treat the token as invalid; a standards-following issuer always sets exp."]},
    },
    "issuer_mismatch": {
        "cause": "The token came from a different issuer than the application is configured to trust.",
        "confirm": "Compare iss with the issuer in the application's configuration exactly.",
        "fix": {"generic": ["Point the application at the issuer that actually signs its tokens."],
                "okta": ["Org server issuer is https://{domain}; a custom server is "
                         "https://{domain}/oauth2/{serverId}. Use the matching one end to end."],
                "entra": ["v2.0 tokens use https://login.microsoftonline.com/{tenant}/v2.0; v1.0 tokens "
                          "use https://sts.windows.net/{tenant}/. Match the version the API accepts."]},
    },
    "nonce_mismatch": {
        "cause": "The ID token's nonce does not match the one the app sent: a replayed response, "
                 "or the app lost its session between request and callback.",
        "confirm": "Compare the nonce in the authorization request with the one in the ID token.",
        "fix": {"generic": ["Check session or cookie storage survives the redirect (SameSite, load balancer stickiness).",
                            "Start a fresh sign-in rather than reusing a callback URL."]},
    },
    "scope_missing": {
        "cause": "The token was not granted a scope the API requires.",
        "confirm": "Compare the scope or scp claim with what the API checks.",
        "fix": {"generic": ["Request the scope in the authorization request and make sure it is granted or consented."],
                "okta": ["Security > API > your authorization server: check Scopes and the Access Policy rule."],
                "entra": ["App registration > API permissions: add the permission and grant admin consent if needed."]},
    },
    # ---- SCIM ----
    "scim_error_uniqueness": {
        "cause": "The user already exists on the target: the same userName or externalId is taken.",
        "confirm": "GET /Users?filter=userName eq \"<value>\" on the SCIM server.",
        "fix": {"generic": ["Link the existing account instead of creating a new one, or fix the duplicate value.",
                            "Check the client's matching attribute so it finds existing users before creating."],
                "okta": ["Check the app's Provisioning > To App settings and the username format; "
                         "import and confirm the existing user to link it."],
                "entra": ["Check the matching attribute precedence under Provisioning > Mappings."]},
    },
    "scim_error_409": {
        "cause": "Conflict: the resource already exists or a unique value is taken.",
        "confirm": "Search the SCIM server for the userName or externalId being created.",
        "fix": {"generic": ["Link to the existing resource or resolve the duplicate."]},
    },
    "scim_error_invalidFilter": {
        "cause": "The server cannot process the filter the client sent.",
        "confirm": "Replay the GET with the same filter and read the detail message.",
        "fix": {"generic": ["Use an attribute and operator the server supports; most support only "
                            "userName eq and externalId eq."]},
    },
    "scim_error_noTarget": {
        "cause": "A PATCH targeted a value that does not exist on the resource.",
        "confirm": "GET the resource and compare with the path filter in the PATCH.",
        "fix": {"generic": ["Send an add instead of a replace for a value that is not there yet."]},
    },
    "scim_error_mutability": {
        "cause": "The client tried to change a read-only or immutable attribute.",
        "confirm": "Find the attribute named in the detail message.",
        "fix": {"generic": ["Remove that attribute from the client's update mappings."]},
    },
    "scim_error_invalidSyntax": {
        "cause": "The server could not parse the request body or it breaks the schema.",
        "confirm": "Validate the request body itself with this tool.",
        "fix": {"generic": ["Fix the body shape; check booleans, multi-valued attributes and the schemas array."]},
    },
    "scim_error_invalidValue": {
        "cause": "A required attribute is missing or has an incompatible value.",
        "confirm": "Read the detail message for the attribute name.",
        "fix": {"generic": ["Supply the attribute, in the type the server expects."]},
    },
    "scim_error_invalidPath": {
        "cause": "The PATCH path is malformed or names an unknown attribute.",
        "confirm": "Compare the path with the server's schema (GET /Schemas).",
        "fix": {"generic": ["Correct the path, including the full URN for extension attributes."]},
    },
    "scim_error_401": {
        "cause": "The SCIM bearer token is missing, expired or wrong.",
        "confirm": "Call GET /ServiceProviderConfig with the same token.",
        "fix": {"generic": ["Generate a new token on the SCIM server and update it in the provisioning client."]},
    },
    "scim_error_403": {
        "cause": "The token is valid but not allowed to do this.",
        "confirm": "Check the role or scopes behind the token.",
        "fix": {"generic": ["Grant the integration account the provisioning permission it needs."]},
    },
    "scim_error_404": {
        "cause": "The resource ID or endpoint does not exist on the server.",
        "confirm": "GET the same URL; check the SCIM base URL and whether the user was deleted on the target.",
        "fix": {"generic": ["Correct the base URL, or let the client re-match the user so it stores the current ID."]},
    },
    "scim_error_429": {
        "cause": "The SCIM server is rate limiting the client.",
        "confirm": "Look for a Retry-After header.",
        "fix": {"generic": ["Retry later; reduce the provisioning batch size or frequency."]},
    },
    "scim_error_500": {
        "cause": "The SCIM server failed internally.",
        "confirm": "Check the server's own logs for the same timestamp.",
        "fix": {"generic": ["Raise it with the application owner, with the request body attached."]},
    },
    "schemas_missing": {
        "cause": "The body does not declare its SCIM schemas.",
        "confirm": "Look for a top-level schemas array.",
        "fix": {"generic": ["Add the schemas array with the right URN for the message type."]},
    },
    "username_missing": {
        "cause": "userName is required and the client sent none, usually an empty source attribute.",
        "confirm": "Check the user's value for the attribute mapped to userName.",
        "fix": {"generic": ["Populate the source attribute or change the userName mapping."]},
    },
    "active_not_boolean": {
        "cause": "active was sent as a string, not a boolean.",
        "confirm": "Look at the raw JSON: \"active\": \"true\" versus \"active\": true.",
        "fix": {"generic": ["Send a real boolean."],
                "entra": ["A known Entra ID provisioning behaviour: the SCIM endpoint must accept it, "
                          "or use the documented feature flag on the tenant URL to get RFC-compliant output."]},
    },
    "name_not_object": {
        "cause": "name was sent as a string.",
        "confirm": "Look at the raw JSON.",
        "fix": {"generic": ["Send name as an object with givenName and familyName."]},
    },
    "multivalue_shape": {
        "cause": "A multi-valued attribute has the wrong shape.",
        "confirm": "Compare with the RFC 7643 example: an array of objects with value, type and primary.",
        "fix": {"generic": ["Send an array of objects, each with a value."]},
    },
    "multiple_primary": {
        "cause": "More than one entry is marked primary.",
        "confirm": "Count primary: true in the array.",
        "fix": {"generic": ["Mark exactly one entry primary."]},
    },
    "extension_not_declared": {
        "cause": "Extension attributes are present but the extension URN is missing from schemas.",
        "confirm": "Compare the top-level keys with the schemas array.",
        "fix": {"generic": ["Add the extension URN to schemas."]},
    },
    "displayname_missing": {
        "cause": "A Group needs a displayName.",
        "confirm": "Look at the body.",
        "fix": {"generic": ["Send displayName."]},
    },
    "patch_operations_missing": {
        "cause": "The PATCH body has no valid Operations array.",
        "confirm": "Check the key is spelled 'Operations' with a capital O.",
        "fix": {"generic": ["Send {\"schemas\": [PatchOp URN], \"Operations\": [...]}."]},
    },
    "patch_op_invalid": {
        "cause": "An operation has an op value that is not add, replace or remove.",
        "confirm": "Read each op value.",
        "fix": {"generic": ["Use add, replace or remove."]},
    },
    "patch_remove_no_path": {
        "cause": "A remove operation has no path, so the server does not know what to remove.",
        "confirm": "Look at the remove operation.",
        "fix": {"generic": ["Add a path, for example members[value eq \"<id>\"]."]},
    },
    "patch_no_value": {
        "cause": "An add or replace operation has no value.",
        "confirm": "Look at the operation.",
        "fix": {"generic": ["Add the value."]},
    },
    "patch_path_invalid": {
        "cause": "The filter inside the PATCH path is malformed.",
        "confirm": "Check quotes, brackets and the operator in the path.",
        "fix": {"generic": ["Write it as attribute[subAttribute eq \"value\"]."]},
    },
    "filter_invalid": {
        "cause": "The filter does not follow SCIM filter grammar.",
        "confirm": "Check operators are words (eq, co, sw), strings use double quotes, and brackets balance.",
        "fix": {"generic": ["Rewrite it, for example: userName eq \"asha.rao@example.com\"."]},
    },
    "list_shape": {
        "cause": "The ListResponse is malformed.",
        "confirm": "Check totalResults is a number and Resources is an array.",
        "fix": {"generic": ["Fix the server's list response."]},
    },
    # ---- HAR ----
    "oauth_error": {
        "cause": "The provider returned an OAuth or OIDC error instead of a code or token.",
        "confirm": "Read error and error_description on the callback URL.",
        "fix": {"generic": ["access_denied: the user or a policy refused; check assignment and consent.",
                            "invalid_request or redirect_uri mismatch: register the exact redirect URI.",
                            "invalid_scope: request only scopes the client is allowed."]},
    },
    "http_error": {
        "cause": "A step in the sign-in returned an HTTP error.",
        "confirm": "Open that request in the capture and read the response body.",
        "fix": {"generic": ["400 at the IdP: bad request parameters (client ID, redirect URI).",
                            "401 or 403 at the app's callback: the app rejected the assertion or token; "
                            "decode it with this tool.",
                            "404 at the callback: the ACS or redirect URL is wrong."]},
    },
    "saml_no_response": {
        "cause": "The identity provider never sent a SAML response back.",
        "confirm": "Look at the last page the browser showed and at the IdP's sign-in log.",
        "fix": {"generic": ["Fix the IdP-side failure: authentication, MFA, assignment or policy."]},
    },
    "oidc_no_callback": {
        "cause": "The provider never redirected back to the app with a code.",
        "confirm": "Look at the last page shown and the provider's sign-in log.",
        "fix": {"generic": ["Fix the provider-side failure: authentication, consent, or a redirect URI it rejects."]},
    },
    "state_mismatch": {
        "cause": "The state returned to the app is not the one it sent, so it cannot tie the callback to its session.",
        "confirm": "Compare state on the authorization request and on the callback.",
        "fix": {"generic": ["Check the app's session cookie survives the round trip (SameSite, domain, HTTPS).",
                            "Make sure the user is not completing a sign-in started in another tab."]},
    },
}


def lookup(check_id: str, platform: str = "") -> dict:
    """Returns cause, confirm and a merged list of fix steps for the platform."""
    if check_id.startswith("scim_error_") and check_id not in PLAYBOOKS:
        check_id = "scim_error_500" if check_id.endswith(("unknown",)) else check_id
    entry = PLAYBOOKS.get(check_id)
    if not entry:
        return {"cause": "", "confirm": "", "fix": [], "platform_fix": {}}
    fix = entry.get("fix", {})
    platforms = {name: steps for name, steps in fix.items() if name != "generic"}
    if platform:
        platforms = {platform: platforms[platform]} if platform in platforms else {}
    return {"cause": entry["cause"], "confirm": entry["confirm"],
            "fix": list(fix.get("generic", [])), "platform_fix": platforms}
