"""Value cleaning shared by the auditor: text, dates, booleans, statuses."""
from __future__ import annotations

import re
import unicodedata
from datetime import date, datetime, timedelta, timezone

_DATE_FORMATS = (
    "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%d %H:%M:%S", "%Y/%m/%d", "%d-%b-%Y", "%d %b %Y", "%b %d, %Y",
    "%m/%d/%Y", "%m/%d/%Y %H:%M", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p",
    "%d.%m.%Y", "%Y%m%d",
)
_DAYFIRST_FORMATS = ("%d/%m/%Y", "%d/%m/%Y %H:%M", "%d/%m/%Y %H:%M:%S", "%d-%m-%Y")

_TRUE = {"true", "t", "yes", "y", "1", "enabled", "enrolled", "registered", "active", "on"}
_FALSE = {"false", "f", "no", "n", "0", "disabled", "not enrolled", "not registered",
          "none", "off", "inactive"}

_PERSON_ACTIVE = {"active", "a", "employed", "current", "on leave", "leave", "true", "1",
                  "yes", "working"}
_PERSON_TERMINATED = {"terminated", "t", "inactive", "leaver", "separated", "resigned",
                      "former", "exited", "false", "0", "no", "retired", "offboarded"}

_ACCOUNT_ENABLED = {"active", "enabled", "true", "1", "yes", "provisioned", "recovery",
                    "password_expired", "locked_out", "password expired", "locked out"}
_ACCOUNT_DISABLED = {"disabled", "false", "0", "no", "suspended", "deprovisioned",
                     "inactive", "deactivated", "deleted", "staged", "blocked"}


def clean(value: object) -> str:
    """Trim, collapse whitespace, and turn the usual 'empty' markers into ''."""
    if value is None:
        return ""
    text = re.sub(r"\s+", " ", str(value)).strip()
    if text.lower() in {"null", "none", "n/a", "na", "-", "nan", "#n/a"}:
        return ""
    return text


def fold(value: str) -> str:
    """Lowercase, strip accents and punctuation: 'José  O'Neil-Smith' -> 'jose oneil smith'."""
    text = unicodedata.normalize("NFKD", value or "")
    text = "".join(ch for ch in text if not unicodedata.combining(ch)).lower()
    text = text.replace("'", "").replace("’", "")
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return text.strip()


def norm_email(value: str) -> str:
    text = clean(value).lower()
    return text if "@" in text else ""


def local_part(value: str) -> str:
    """'DOMAIN\\jsmith' -> 'jsmith', 'j.smith@corp.com' -> 'j.smith'."""
    text = clean(value).lower()
    if "\\" in text:
        text = text.split("\\", 1)[1]
    return text.split("@", 1)[0]


def parse_date(value: object, dayfirst: bool = False) -> date | None:
    text = clean(value)
    if not text:
        return None
    # Windows FILETIME (AD lastLogonTimestamp): 100-ns ticks since 1601-01-01.
    if text.isdigit() and len(text) >= 17:
        ticks = int(text)
        if ticks <= 0:
            return None
        try:
            return (datetime(1601, 1, 1, tzinfo=timezone.utc)
                    + timedelta(microseconds=ticks // 10)).date()
        except OverflowError:
            return None
    if text in {"0", "never", "Never"}:
        return None
    iso = text.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(iso).date()
    except ValueError:
        pass
    formats = (_DAYFIRST_FORMATS + _DATE_FORMATS) if dayfirst else (_DATE_FORMATS + _DAYFIRST_FORMATS)
    for fmt in formats:
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    return None


def parse_bool(value: object) -> bool | None:
    text = clean(value).lower()
    if not text:
        return None
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    return None


def person_status(value: object) -> str:
    """Returns 'active', 'terminated' or '' when the value is unknown."""
    text = clean(value).lower()
    if text in _PERSON_ACTIVE:
        return "active"
    if text in _PERSON_TERMINATED:
        return "terminated"
    if text.startswith("term"):
        return "terminated"
    return ""


def account_enabled(value: object, source_header: str = "") -> bool | None:
    """True if the account can sign in. Handles 'Disabled' columns, where True means off."""
    text = clean(value).lower()
    if not text:
        return None
    inverted = "disabled" in source_header.lower()
    if text in _ACCOUNT_ENABLED:
        return not inverted
    if text in _ACCOUNT_DISABLED:
        return inverted
    # AD userAccountControl: bit 2 set means disabled.
    if text.isdigit() and len(text) <= 8:
        return not (int(text) & 2)
    return None


_SERVICE_PATTERN = re.compile(
    r"(^|[._\-])(svc|service|srv|app|bot|system|sys|api|noreply|no-reply|batch|job|"
    r"integration|automation|scanner|printer|kiosk|shared|mailbox|test)([._\-0-9]|$)"
)


def infer_account_type(explicit: str, username: str) -> str:
    """'human', 'service' or 'shared'. Uses the file's own type column when it has one."""
    text = clean(explicit).lower()
    if text:
        if any(word in text for word in ("service", "system", "application", "app", "bot",
                                         "machine", "non-human", "nonhuman", "workload")):
            return "service"
        if "shared" in text or "generic" in text or "mailbox" in text:
            return "shared"
        if text in {"member", "guest", "user", "human", "person", "employee", "contractor",
                    "regular"}:
            return "human"
    name = local_part(username)
    if name and _SERVICE_PATTERN.search(name):
        return "shared" if ("shared" in name or "mailbox" in name) else "service"
    return "human"
