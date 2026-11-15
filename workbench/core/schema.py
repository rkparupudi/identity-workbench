"""The common schema every input file is reduced to, plus header synonyms.

Two record types exist: a *person* (from HR) and an *account* (from a directory
or application). The matcher and the rules only ever see these field names.
"""
from __future__ import annotations

import re

PERSON_FIELDS = [
    "employee_id", "first_name", "last_name", "display_name", "email", "status",
    "start_date", "end_date", "department", "manager", "worker_type",
]

ACCOUNT_FIELDS = [
    "account_id", "username", "email", "display_name", "first_name", "last_name",
    "employee_id", "status", "created", "last_login", "mfa_enrolled",
    "privileged", "account_type", "department", "owner",
]

# A file is usable if it has at least one of these after mapping.
PERSON_KEY_FIELDS = ("employee_id", "email")
ACCOUNT_KEY_FIELDS = ("account_id", "username", "email")


def norm_header(header: str) -> str:
    """'Work Email ' -> 'workemail', 'lastSignInDateTime' -> 'lastsignindatetime'."""
    return re.sub(r"[^a-z0-9]", "", header.lower())


# canonical field -> header spellings seen in HRIS exports (Workday, BambooHR,
# SuccessFactors and similar). Spellings are compared after norm_header().
_PERSON_SYNONYMS = {
    "employee_id": ["employee id", "employeeid", "employee number", "employeenumber",
                    "emp id", "worker id", "personnel number", "person id", "staff id",
                    "user id", "employee #", "emp no"],
    "first_name": ["first name", "firstname", "given name", "givenname", "legal first name",
                   "preferred first name"],
    "last_name": ["last name", "lastname", "surname", "family name", "sn",
                  "legal last name"],
    "display_name": ["name", "full name", "display name", "worker", "employee name",
                     "preferred name"],
    "email": ["email", "work email", "email address", "primary work email", "mail",
              "business email", "work e-mail", "e-mail"],
    "status": ["status", "employment status", "employee status", "worker status",
               "active status", "active"],
    "start_date": ["start date", "hire date", "original hire date", "date of joining",
                   "joining date", "doj"],
    "end_date": ["end date", "termination date", "last day of work", "last working day",
                 "last working date", "separation date", "exit date", "leaving date"],
    "department": ["department", "dept", "cost center", "organization", "org unit",
                   "business unit", "division", "team"],
    "manager": ["manager", "manager name", "supervisor", "reports to", "line manager",
                "manager email"],
    "worker_type": ["worker type", "employee type", "employment type", "type",
                    "worker sub type", "contract type"],
}

# canonical field -> header spellings seen in Okta, Entra ID, Active Directory
# and SailPoint exports.
_ACCOUNT_SYNONYMS = {
    "account_id": ["id", "account id", "object id", "objectid", "user id", "userid",
                   "okta id", "objectguid", "native identity", "account name",
                   "nativeidentity"],
    "username": ["username", "user name", "login", "userprincipalname", "upn",
                 "samaccountname", "logon name", "account", "user login", "uid",
                 "user logon name"],
    "email": ["email", "mail", "email address", "primary email", "e-mail",
              "emailaddress", "work email"],
    "display_name": ["display name", "displayname", "name", "full name", "cn"],
    "first_name": ["first name", "firstname", "given name", "givenname"],
    "last_name": ["last name", "lastname", "surname", "sn", "family name"],
    "employee_id": ["employee id", "employeeid", "employee number", "employeenumber",
                    "emp id", "worker id"],
    "status": ["status", "account status", "account enabled", "accountenabled",
               "enabled", "active", "state", "user status", "disabled", "iiq disabled"],
    "created": ["created", "created date", "createddatetime", "whencreated",
                "creation date", "date created", "created at"],
    "last_login": ["last login", "lastlogin", "last sign in", "lastsignindatetime",
                   "last sign-in date", "lastlogontimestamp", "lastlogondate",
                   "last logon", "last login date", "last sign-in", "lastsignin",
                   "last interactive sign-in"],
    "mfa_enrolled": ["mfa enrolled", "mfaenrolled", "mfa registered", "mfaregistered",
                     "mfa", "mfa enabled", "is mfa registered", "ismfaregistered",
                     "mfa capable", "ismfacapable", "strong auth", "mfa status"],
    "privileged": ["privileged", "is privileged", "isprivileged", "is admin", "isadmin",
                   "admin", "administrator", "admin role", "has admin role",
                   "privileged account"],
    "account_type": ["account type", "accounttype", "user type", "usertype", "type",
                     "identity type"],
    "department": ["department", "dept", "organization", "division"],
    "owner": ["owner", "managed by", "managedby", "account owner", "manager",
              "responsible", "service owner"],
}


def _index(synonyms: dict[str, list[str]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for field, names in synonyms.items():
        out.setdefault(norm_header(field), field)
        for name in names:
            out.setdefault(norm_header(name), field)
    return out


PERSON_HEADER_INDEX = _index(_PERSON_SYNONYMS)
ACCOUNT_HEADER_INDEX = _index(_ACCOUNT_SYNONYMS)


def fields_for(kind: str) -> list[str]:
    if kind == "person":
        return PERSON_FIELDS
    if kind == "account":
        return ACCOUNT_FIELDS
    raise ValueError(f"kind must be 'person' or 'account', not {kind!r}")


def header_index_for(kind: str) -> dict[str, str]:
    return PERSON_HEADER_INDEX if kind == "person" else ACCOUNT_HEADER_INDEX
