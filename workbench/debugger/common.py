"""Shared pieces for the decoders: the check record and time parsing."""
from __future__ import annotations

from datetime import datetime, timezone

PASS, FAIL, WARN, INFO, SKIPPED = "pass", "fail", "warn", "info", "skipped"


def check(check_id: str, title: str, status: str, detail: str = "") -> dict:
    return {"id": check_id, "title": title, "status": status, "detail": detail}


def first_failure(checks: list[dict]) -> dict | None:
    """Checks are listed in the order a receiving system would trip over them."""
    for item in checks:
        if item["status"] == FAIL:
            return item
    return None


def parse_time(value) -> datetime | None:
    """ISO 8601 string or epoch seconds -> aware UTC datetime."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if text.lower() == "now":
        return datetime.now(timezone.utc)
    if text.isdigit():
        return parse_time(int(text))
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def iso(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ") if value else ""


def url_difference(expected: str, actual: str) -> str:
    """Explain the usual near-miss between two URLs or URIs."""
    if expected == actual:
        return ""
    if expected.rstrip("/") == actual.rstrip("/"):
        return "They differ only by a trailing slash."
    if expected.lower() == actual.lower():
        return "They differ only in letter case."
    if expected.replace("https://", "http://") == actual.replace("https://", "http://"):
        return "They differ only in http versus https."
    return ""
