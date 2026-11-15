"""Hand-written risk notes and remediation steps per finding type and platform.

These are the offline answers. When a model is configured it may add a short
tailored explanation, but these steps are always shown.
Console paths change between product versions: treat them as pointers and
confirm in the vendor's current documentation.
"""
from __future__ import annotations

RISK = {
    "leaver_active_account":
        "A person who has left can still sign in. This is the most common audit failure "
        "in joiner-mover-leaver controls and a direct route for data theft or misuse.",
    "privileged_without_mfa":
        "An administrator account protected only by a password. One phished or reused "
        "password gives an attacker administrative control.",
    "orphaned_account":
        "Nobody in HR owns this account, so nothing triggers its removal when the person "
        "stops needing it. Orphans are often contractors, test users or missed leavers.",
    "unowned_service_account":
        "A non-human account with no named owner. Nobody rotates its credentials, reviews "
        "its access, or knows whether it is still needed.",
    "dormant_account":
        "An enabled account nobody uses. It widens the attack surface and usually still "
        "consumes a licence.",
    "duplicate_accounts":
        "One person holds several enabled accounts in the same system. Access reviews and "
        "offboarding tend to cover only one of them.",
    "missing_account":
        "An active employee has no account in a system everyone is expected to have. It "
        "points to a provisioning failure, or to an account that exists but could not be "
        "matched to this person.",
    "attribute_drift":
        "The account's profile no longer agrees with HR. Rules driven by department, "
        "manager or email (group membership, approvals, access reviews) act on stale data.",
}

_GENERIC = {
    "leaver_active_account": [
        "Confirm the termination with HR; rule out a rehire or a contractor conversion.",
        "Disable the account and end its active sessions.",
        "Remove group memberships and application assignments, then follow your retention "
        "policy for deletion.",
        "Find out why offboarding missed this account and fix the trigger.",
    ],
    "privileged_without_mfa": [
        "Enrol a phishing-resistant factor for the account today.",
        "Enforce MFA for all administrator roles by policy, not per user.",
        "Check recent sign-ins for the account for anything unexpected.",
    ],
    "orphaned_account": [
        "Identify the user: contractor, vendor, test account, or a leaver missing from the HR export.",
        "If legitimate, record an owner and an end date, or add the person to the source of truth.",
        "If nobody claims it, disable it, wait an agreed period, then delete it.",
    ],
    "unowned_service_account": [
        "Find the application or team that uses the account (sign-in logs, credential usage).",
        "Record an owner and purpose on the account itself.",
        "Rotate its credentials and remove any access it does not need.",
    ],
    "dormant_account": [
        "Check that the user is not on long leave before acting.",
        "Disable the account; delete after your retention period if nobody asks for it back.",
        "Add an automatic inactivity policy so this does not rely on audits.",
    ],
    "duplicate_accounts": [
        "Decide which account is primary and what the others are for.",
        "If a second account is a deliberate admin account, label it and give it an owner.",
        "Otherwise merge access into the primary account and disable the rest.",
    ],
    "missing_account": [
        "Check whether the account exists under a different name or email and was not matched.",
        "If it does not exist, re-run provisioning and check the assignment rule that should have fired.",
    ],
    "attribute_drift": [
        "Treat HR as the source of truth unless you know it is the stale side.",
        "Re-sync the profile from HR and check that attribute mappings still flow.",
        "Review rules that depend on the changed attribute, such as department-based groups.",
    ],
}

_PLATFORM = {
    "okta": {
        "leaver_active_account": [
            "Admin Console: Directory > People > open the user > More Actions > Deactivate.",
            "Use Clear User Sessions first if they may be signed in.",
            "If HR drives lifecycle, check the HR integration's import and deprovisioning settings.",
        ],
        "privileged_without_mfa": [
            "Security > Authenticators: make sure a strong authenticator is available to admins.",
            "Add or tighten the authentication policy for the Okta Admin Console app to require MFA.",
        ],
        "orphaned_account": [
            "Directory > People > open the user; review Applications and Groups, then Suspend or Deactivate.",
        ],
        "dormant_account": [
            "Reports > Okta usage reports help confirm inactivity before you Suspend the user.",
        ],
        "attribute_drift": [
            "Directory > Profile Editor: check the mappings from the profile source to the Okta user.",
        ],
    },
    "entra": {
        "leaver_active_account": [
            "Entra admin center: Users > open the user > Edit properties > clear Account enabled.",
            "Select Revoke sessions on the user.",
            "If HR-driven provisioning is in place, check the provisioning logs for the leaver event.",
        ],
        "privileged_without_mfa": [
            "Protection > Conditional Access: require MFA (or phishing-resistant strength) for directory roles.",
            "Protection > Authentication methods > User registration details shows who has not registered.",
            "Prefer Privileged Identity Management so admin roles are activated just in time.",
        ],
        "orphaned_account": [
            "Users > open the user; review Assigned roles, Groups and Applications, then disable the account.",
        ],
        "unowned_service_account": [
            "For service principals and app registrations, set Owners on the object.",
            "Where possible, replace user-style service accounts with managed identities.",
        ],
        "dormant_account": [
            "Use the user's sign-in activity (lastSignInDateTime) to confirm, then disable the account.",
        ],
        "attribute_drift": [
            "Check the attribute mappings in the provisioning configuration, or Entra Connect sync rules for hybrid users.",
        ],
    },
    "ad": {
        "leaver_active_account": [
            "Active Directory Users and Computers: right-click the user > Disable Account, "
            "or PowerShell: Disable-ADAccount -Identity <user>.",
            "Move the object to a disabled-users OU and remove group memberships.",
        ],
        "dormant_account": [
            "PowerShell: Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 -UsersOnly lists candidates.",
        ],
        "unowned_service_account": [
            "Record the owner in the managedBy or description attribute.",
            "Consider a group Managed Service Account so the password rotates automatically.",
        ],
    },
    "sailpoint": {
        "leaver_active_account": [
            "Check the identity's lifecycle state and that the leaver event triggered the "
            "expected provisioning to this source.",
        ],
        "orphaned_account": [
            "Uncorrelated accounts on a source are the same problem: review the source's "
            "correlation configuration, then correlate manually or disable.",
        ],
        "attribute_drift": [
            "Check the identity profile's attribute mappings and run an attribute sync.",
        ],
    },
}

_ALIASES = {
    "okta": "okta",
    "entra": "entra", "entra id": "entra", "entraid": "entra", "azure": "entra",
    "azure ad": "entra", "azuread": "entra", "aad": "entra", "microsoft": "entra",
    "ad": "ad", "active directory": "ad", "activedirectory": "ad", "ldap": "ad",
    "sailpoint": "sailpoint", "identitynow": "sailpoint", "isc": "sailpoint", "iiq": "sailpoint",
}


def platform_of(system: str) -> str:
    """Map a system name the user typed ('Azure AD', 'okta-prod') to a known platform."""
    name = (system or "").lower().strip()
    if name in _ALIASES:
        return _ALIASES[name]
    for alias, platform in sorted(_ALIASES.items(), key=lambda kv: -len(kv[0])):
        if len(alias) > 2 and alias in name:
            return platform
    return ""


def remediation(finding_type: str, system: str = "") -> dict:
    platform = platform_of(system)
    return {
        "risk": RISK.get(finding_type, ""),
        "steps": list(_GENERIC.get(finding_type, [])),
        "platform": platform,
        "platform_steps": list(_PLATFORM.get(platform, {}).get(finding_type, [])),
        "note": "Verify against the source system before acting; exports can be hours or days old.",
    }
