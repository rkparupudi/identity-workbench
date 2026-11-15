"""Score the auditor against synthetic data with known seeded problems."""
from __future__ import annotations

import json
import tempfile
from datetime import date
from pathlib import Path

from ..auditor.pipeline import run_audit
from ..auditor.rules import SEVERITY
from ..synth.generate import generate

PERSON_LEVEL = {"duplicate_accounts", "missing_account"}


def _key(item: dict) -> tuple:
    if item["type"] in PERSON_LEVEL:
        return (item["type"], item["system"], item.get("employee_id", ""))
    return (item["type"], item["system"], item.get("account_id", ""))


def evaluate(employees: int = 2000, seed: int = 7, data_dir: str | Path | None = None,
             verbose: bool = False) -> dict:
    tmp = None
    if data_dir is None:
        tmp = tempfile.TemporaryDirectory()
        data_dir = tmp.name
    data = Path(data_dir)
    if not (data / "truth.json").exists():
        generate(data, employees=employees, seed=seed)
    truth = json.loads((data / "truth.json").read_text(encoding="utf-8"))
    result = run_audit(data / "hr.csv",
                       [("okta", data / "okta_users.csv"), ("entra", data / "entra_users.csv")],
                       as_of=date.fromisoformat(truth["as_of"]), save=False)

    reported = {_key(f) for f in result.findings}
    # 'conditional' items are only expected when the tool linked that account at all
    # (name variants that it may legitimately leave in the review queue instead).
    expected = {_key(item) for item in truth["findings"]
                if not item.get("conditional") or _key(item) in reported}
    per_rule = {}
    for rule in SEVERITY:
        exp = {k for k in expected if k[0] == rule}
        rep = {k for k in reported if k[0] == rule}
        hit = len(exp & rep)
        per_rule[rule] = {
            "seeded": len(exp), "reported": len(rep), "correct": hit,
            "precision": round(hit / len(rep), 4) if rep else None,
            "recall": round(hit / len(exp), 4) if exp else None,
        }
        if verbose:
            for k in sorted(rep - exp)[:5]:
                print("  false positive:", k)
            for k in sorted(exp - rep)[:5]:
                print("  missed:", k)

    links = truth["links"]
    auto = [m for m in result.matches.values() if m.band == "matched"]
    auto_correct = sum(1 for m in auto if links.get(m.account_key) == m.person_key)
    true_pairs = {k: v for k, v in links.items() if v}
    found = sum(1 for k, v in true_pairs.items()
                if result.matches[k].band in ("matched", "review")
                and result.matches[k].person_key == v)
    hard = truth["hard_links"]
    hard_bands = {band: sum(1 for k in hard if result.matches[k].band == band)
                  for band in ("matched", "review", "unmatched")}
    out = {
        "employees": truth["employees"], "accounts": result.stats["accounts"],
        "seconds": result.stats["seconds"],
        "match_precision": round(auto_correct / len(auto), 4) if auto else None,
        "match_recall": round(found / len(true_pairs), 4) if true_pairs else None,
        "auto_matched": len(auto), "auto_matched_wrong": len(auto) - auto_correct,
        "fuzzy_only_links": len(hard), "fuzzy_only_bands": hard_bands,
        "rules": per_rule,
    }
    if tmp:
        tmp.cleanup()
    return out


def format_report(result: dict) -> str:
    lines = [
        f"Auditor eval: {result['employees']:,} employees, {result['accounts']:,} accounts, "
        f"{result['seconds']}s",
        f"  match precision (auto-matched pairs correct): {result['match_precision']:.2%} "
        f"({result['auto_matched_wrong']} wrong of {result['auto_matched']:,})",
        f"  match recall (true pairs matched or sent to review): {result['match_recall']:.2%}",
        f"  links needing fuzzy matching: {result['fuzzy_only_links']} -> {result['fuzzy_only_bands']}",
        "",
        f"  {'rule':<26}{'seeded':>8}{'reported':>10}{'precision':>11}{'recall':>9}",
    ]
    for rule, r in result["rules"].items():
        p = "-" if r["precision"] is None else f"{r['precision']:.1%}"
        c = "-" if r["recall"] is None else f"{r['recall']:.1%}"
        lines.append(f"  {rule:<26}{r['seeded']:>8}{r['reported']:>10}{p:>11}{c:>9}")
    return "\n".join(lines)
