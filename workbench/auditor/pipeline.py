"""Run an audit end to end: load files, match, run rules, save the run."""
from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from ..config import get_settings
from ..core.store import Store
from . import ingest
from .matching import Match, match_accounts, match_stats
from .rules import Context, run_rules


@dataclass
class AuditResult:
    run_id: str
    as_of: date
    findings: list[dict]
    skipped_rules: dict[str, str]
    stats: dict
    review_pairs: list[dict]
    matches: dict[str, Match] = field(repr=False, default_factory=dict)

    @property
    def counts_by_type(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f["type"]] = out.get(f["type"], 0) + 1
        return out

    @property
    def counts_by_severity(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f["severity"]] = out.get(f["severity"], 0) + 1
        return out


def parse_account_spec(spec: str) -> tuple[str, str]:
    """'okta=exports/okta.csv' -> ('okta', 'exports/okta.csv'); bare path -> name from file."""
    if "=" in spec and not Path(spec).exists():
        system, _, path = spec.partition("=")
        return system.strip(), path.strip()
    return Path(spec).stem.lower(), spec


def run_audit(hr_source, account_sources: list[tuple[str, object]], as_of: date | None = None,
              store: Store | None = None, llm=None, upper: float | None = None,
              lower: float | None = None, dormant_days: int | None = None,
              expected_systems: list[str] | None = None, extra_keys: list[str] | None = None,
              dayfirst: bool = False, save: bool = True) -> AuditResult:
    """account_sources is a list of (system_name, path_or_bytes)."""
    settings = get_settings()
    if store is None and save:
        store = Store(settings.db_path)
    as_of = as_of or date.today()
    started = time.perf_counter()

    people = ingest.load_people(hr_source, store=store, llm=llm, dayfirst=dayfirst)
    tables = [ingest.load_accounts(src, system, store=store, llm=llm, dayfirst=dayfirst)
              for system, src in account_sources]
    accounts = [record for table in tables for record in table.records]

    matches = match_accounts(
        people.records, accounts,
        upper=settings.match_upper if upper is None else upper,
        lower=settings.match_lower if lower is None else lower,
        decisions=store.decisions() if store else None,
        extra_keys=extra_keys)

    ctx = Context(
        people=people.records, accounts=accounts, matches=matches, as_of=as_of,
        person_fields=people.fields_present,
        account_fields={t.system: t.fields_present for t in tables},
        dormant_days=settings.dormant_days if dormant_days is None else dormant_days,
        expected_systems=expected_systems)
    findings, skipped = run_rules(ctx)

    by_account = {a["key"]: a for a in accounts}
    review_pairs = []
    for m in matches.values():
        if m.band != "review" or not m.person_key:
            continue
        a, p = by_account[m.account_key], ctx.people_by_key[m.person_key]
        pair_id = hashlib.sha256(f"{m.account_key}|{m.person_key}".encode()).hexdigest()[:10]
        review_pairs.append({
            "pair_id": pair_id, "account_key": m.account_key, "person_key": m.person_key,
            "score": m.score,
            "detail": {
                "account": {"system": a["system"], "username": a["username"],
                            "display_name": a["display_name"], "email": a["email"],
                            "department": a["department"]},
                "person": {"employee_id": p["employee_id"], "name": p["display_name"],
                           "email": p["email"], "department": p["department"],
                           "status": p["status"]},
                "parts": m.detail,
            }})
    review_pairs.sort(key=lambda r: -r["score"])

    stats = {
        "people": len(people.records),
        "accounts": len(accounts),
        "accounts_by_system": {t.system: len(t.records) for t in tables},
        "matching": match_stats(matches),
        "skipped_rows": {"hr": people.skipped_rows, **{t.system: t.skipped_rows for t in tables}},
        "mappings": {"hr": people.mapping, **{t.system: t.mapping for t in tables}},
        "unmapped_columns": {"hr": people.unmapped, **{t.system: t.unmapped for t in tables}},
        "seconds": round(time.perf_counter() - started, 2),
    }
    run_id = uuid.uuid4().hex[:10]
    result = AuditResult(run_id, as_of, findings, skipped, stats, review_pairs, matches)
    if save and store:
        meta = {"stats": stats, "skipped_rules": skipped,
                "counts_by_type": result.counts_by_type,
                "counts_by_severity": result.counts_by_severity}
        store.save_run(run_id, as_of.isoformat(), meta, findings, review_pairs)
    return result
