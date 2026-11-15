"""The findings catalogue: eight deterministic rules.

Each rule is a function over the matched data. A rule that needs a field no file
provided is skipped, and the skip is reported rather than hidden.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass
from datetime import date

from ..core.normalize import fold
from .matching import Match

SEVERITY = {
    "leaver_active_account": "critical",
    "privileged_without_mfa": "critical",
    "orphaned_account": "high",
    "unowned_service_account": "medium",
    "dormant_account": "medium",
    "duplicate_accounts": "medium",
    "missing_account": "low",
    "attribute_drift": "low",
}

TITLES = {
    "leaver_active_account": "Leaver with active account",
    "privileged_without_mfa": "Privileged account without MFA",
    "orphaned_account": "Orphaned account",
    "unowned_service_account": "Unowned service or shared account",
    "dormant_account": "Dormant account",
    "duplicate_accounts": "Duplicate accounts",
    "missing_account": "Missing account",
    "attribute_drift": "Attribute drift",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


@dataclass
class Context:
    people: list[dict]
    accounts: list[dict]
    matches: dict[str, Match]
    as_of: date
    person_fields: set[str]
    account_fields: dict[str, set[str]]     # system -> canonical fields present
    dormant_days: int = 90
    expected_systems: list[str] | None = None   # None = infer from coverage

    def __post_init__(self) -> None:
        self.people_by_key = {p["key"]: p for p in self.people}
        self.systems = sorted({a["system"] for a in self.accounts})
        self.accounts_by_person: dict[str, list[dict]] = defaultdict(list)
        for a in self.accounts:
            m = self.matches.get(a["key"])
            if m and m.band == "matched" and m.person_key:
                self.accounts_by_person[m.person_key].append(a)

    def person_for(self, account: dict) -> dict | None:
        m = self.matches.get(account["key"])
        if m and m.band == "matched" and m.person_key:
            return self.people_by_key.get(m.person_key)
        return None

    def systems_with(self, *fields: str) -> list[str]:
        return [s for s in self.systems if all(f in self.account_fields.get(s, set()) for f in fields)]


def is_leaver(person: dict, as_of: date) -> bool:
    if person["status"] == "terminated":
        return True
    return bool(person["end_date"] and person["end_date"] < as_of)


def _iso(value) -> str:
    return value.isoformat() if value else ""


def _account_evidence(a: dict) -> dict:
    return {"system": a["system"], "account_id": a["account_id"], "username": a["username"],
            "email": a["email"], "enabled": a["enabled"], "account_type": a["account_type"],
            "created": _iso(a["created"]), "last_login": _iso(a["last_login"]),
            "mfa_enrolled": a["mfa_enrolled"], "privileged": a["privileged"],
            "source_row": a["row"]}


def _person_evidence(p: dict) -> dict:
    return {"employee_id": p["employee_id"], "name": p["display_name"], "email": p["email"],
            "status": p["status"], "end_date": _iso(p["end_date"]),
            "department": p["department"], "source_row": p["row"]}


def _finding(type_: str, summary: str, account: dict | None = None, person: dict | None = None,
             system: str = "", extra: dict | None = None, match: Match | None = None) -> dict:
    evidence: dict = {}
    if account:
        evidence["account"] = _account_evidence(account)
    if person:
        evidence["person"] = _person_evidence(person)
    if match and match.person_key:
        evidence["match"] = {"method": match.method, "score": match.score}
    if extra:
        evidence.update(extra)
    system = system or (account["system"] if account else "")
    account_id = account["account_id"] if account else ""
    employee_id = (person["employee_id"] or person["key"]) if person else ""
    raw = f"{type_}|{system}|{account_id}|{employee_id}"
    return {
        "type": type_, "severity": SEVERITY[type_], "system": system,
        "account_id": account_id, "username": account["username"] if account else "",
        "employee_id": employee_id, "person_name": person["display_name"] if person else "",
        "summary": summary, "evidence": evidence,
        "fingerprint": hashlib.sha256(raw.encode()).hexdigest()[:20],
    }


# ---- rules ------------------------------------------------------------------

def leaver_active_account(ctx: Context):
    if not ({"status", "end_date"} & ctx.person_fields):
        return None, "HR file has no employment status or end date column"
    systems = ctx.systems_with("status")
    if not systems:
        return None, "no account file has a status column"
    out = []
    for a in ctx.accounts:
        if a["system"] not in systems or a["enabled"] is not True:
            continue
        p = ctx.person_for(a)
        if p and is_leaver(p, ctx.as_of):
            when = f" (ended {_iso(p['end_date'])})" if p["end_date"] else ""
            out.append(_finding(
                "leaver_active_account",
                f"{p['display_name']} has left{when} but {a['system']} account "
                f"{a['username']} is still enabled.", a, p, match=ctx.matches[a["key"]]))
    return out, None


def privileged_without_mfa(ctx: Context):
    systems = ctx.systems_with("privileged", "mfa_enrolled")
    if not systems:
        return None, "no account file has both a privileged flag and an MFA column"
    out = []
    for a in ctx.accounts:
        if a["system"] in systems and a["privileged"] is True and a["mfa_enrolled"] is False \
                and a["enabled"] is not False:
            out.append(_finding(
                "privileged_without_mfa",
                f"Privileged {a['system']} account {a['username']} has no MFA enrolled.",
                a, ctx.person_for(a)))
    return out, None


def orphaned_account(ctx: Context):
    out = []
    for a in ctx.accounts:
        m = ctx.matches[a["key"]]
        if a["account_type"] == "human" and a["enabled"] is not False and m.band == "unmatched":
            out.append(_finding(
                "orphaned_account",
                f"Enabled {a['system']} account {a['username']} matches no person in HR.",
                a, extra={"best_score": m.score}))
    return out, None


def unowned_service_account(ctx: Context):
    out = []
    for a in ctx.accounts:
        if a["account_type"] != "human" and a["enabled"] is not False and not a["owner"]:
            note = "" if "owner" in ctx.account_fields.get(a["system"], set()) \
                else " (the file has no owner column)"
            out.append(_finding(
                "unowned_service_account",
                f"{a['account_type'].capitalize()} account {a['username']} in {a['system']} "
                f"has no recorded owner{note}.", a))
    return out, None


def dormant_account(ctx: Context):
    systems = ctx.systems_with("last_login")
    if not systems:
        return None, "no account file has a last sign-in column"
    out = []
    for a in ctx.accounts:
        if a["system"] not in systems or a["enabled"] is False:
            continue
        if a["last_login"]:
            idle = (ctx.as_of - a["last_login"]).days
            if idle > ctx.dormant_days:
                out.append(_finding(
                    "dormant_account",
                    f"{a['system']} account {a['username']} last signed in {idle} days ago.",
                    a, ctx.person_for(a), extra={"days_idle": idle}))
        elif a["created"] and (ctx.as_of - a["created"]).days > ctx.dormant_days:
            age = (ctx.as_of - a["created"]).days
            out.append(_finding(
                "dormant_account",
                f"{a['system']} account {a['username']} was created {age} days ago and "
                "has never signed in.", a, ctx.person_for(a), extra={"never_signed_in": True}))
    return out, None


def duplicate_accounts(ctx: Context):
    out = []
    for person_key, accounts in ctx.accounts_by_person.items():
        per_system: dict[str, list[dict]] = defaultdict(list)
        for a in accounts:
            if a["enabled"] is not False:
                per_system[a["system"]].append(a)
        for system, group in per_system.items():
            if len(group) >= 2:
                p = ctx.people_by_key[person_key]
                names = ", ".join(sorted(a["username"] for a in group))
                out.append(_finding(
                    "duplicate_accounts",
                    f"{p['display_name']} has {len(group)} enabled accounts in {system}: {names}.",
                    person=p, system=system,
                    extra={"accounts": [_account_evidence(a) for a in group]}))
    return out, None


def missing_account(ctx: Context):
    active = [p for p in ctx.people if not is_leaver(p, ctx.as_of)]
    if not active:
        return [], None
    covered: dict[str, set[str]] = defaultdict(set)
    for person_key, accounts in ctx.accounts_by_person.items():
        for a in accounts:
            covered[a["system"]].add(person_key)
    # People with an account pair awaiting review are not reported as missing.
    pending: dict[str, set[str]] = defaultdict(set)
    for a in ctx.accounts:
        m = ctx.matches[a["key"]]
        if m.band == "review" and m.person_key:
            pending[a["system"]].add(m.person_key)

    if ctx.expected_systems is None:
        expected = [s for s in ctx.systems
                    if sum(1 for p in active if p["key"] in covered[s]) / len(active) >= 0.9]
    else:
        expected = [s for s in ctx.systems if s in ctx.expected_systems]
    if not expected:
        return None, "no system is expected for everyone (under 90% coverage and none specified)"
    out = []
    for system in expected:
        for p in active:
            if p["key"] not in covered[system] and p["key"] not in pending[system]:
                out.append(_finding(
                    "missing_account",
                    f"{p['display_name']} is active in HR but has no account in {system}.",
                    person=p, system=system))
    return out, None


def attribute_drift(ctx: Context):
    out = []
    for a in ctx.accounts:
        p = ctx.person_for(a)
        if not p or a["enabled"] is False:
            continue
        diffs = {}
        if a["email"] and p["email"] and a["email"] != p["email"]:
            diffs["email"] = {"hr": p["email"], "account": a["email"]}
        if a["department"] and p["department"] and fold(a["department"]) != fold(p["department"]):
            diffs["department"] = {"hr": p["department"], "account": a["department"]}
        a_name = fold(a["display_name"])
        p_name = fold(f"{p['first_name']} {p['last_name']}")
        if a_name and p_name and sorted(a_name.split()) != sorted(p_name.split()):
            diffs["name"] = {"hr": p["display_name"], "account": a["display_name"]}
        if diffs:
            fields = ", ".join(sorted(diffs))
            out.append(_finding(
                "attribute_drift",
                f"{a['system']} account {a['username']} differs from HR on: {fields}.",
                a, p, extra={"differences": diffs}))
    return out, None


RULES = [leaver_active_account, privileged_without_mfa, orphaned_account,
         unowned_service_account, dormant_account, duplicate_accounts, missing_account,
         attribute_drift]


def run_rules(ctx: Context) -> tuple[list[dict], dict[str, str]]:
    """Returns (findings sorted by severity, {skipped_rule: reason})."""
    findings: list[dict] = []
    skipped: dict[str, str] = {}
    for rule in RULES:
        result, reason = rule(ctx)
        if result is None:
            skipped[rule.__name__] = reason or "required data not present"
        else:
            findings.extend(result)
    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["type"], f["system"],
                                 f["username"], f["employee_id"]))
    for number, f in enumerate(findings, start=1):
        f["finding_id"] = f"F{number:05d}"
    return findings, skipped
