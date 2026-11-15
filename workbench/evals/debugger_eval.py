"""Score the debugger against artifacts that are each broken in one known way."""
from __future__ import annotations

import json

from ..debugger import diagnose
from ..synth import artifacts

# Values planted in the synthetic artifacts that must never survive redaction.
SEEDED_SECRETS = [
    "cGxhY2Vob2xkZXItc2lnbmF0dXJlLXZhbHVlLW5vdC1yZWFsLWNyeXB0b2dyYXBoeS0wMTIzNDU2Nzg5YWJjZGVm",
    "sid=3f9c1e7a5b2d4c6e8f0a1b2c3d4e5f60",
    "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d",
    "SplxlOBeZQQYbYS6WxSbIA",
    "asha.rao@corp.example",
]


def evaluate() -> dict:
    cases = artifacts.cases()
    rows, correct, leaks = [], 0, 0
    for case in cases:
        result = diagnose(case["text"], kind=case["kind"], **case["expected"])
        got = result["first_failure"]["id"] if result["first_failure"] else None
        ok = got == case["fault"]
        correct += ok
        blob = json.dumps(result["redacted"], default=str)
        leaked = [s for s in SEEDED_SECRETS + [case["text"][:60]] if s and s in blob and len(s) > 20
                  or s == "asha.rao@corp.example" and s in blob]
        if case["kind"] == "jwt" and case["text"] in blob:
            leaked.append("token")
        leaks += len(leaked)
        rows.append({"name": case["name"], "kind": case["kind"], "expected": case["fault"],
                     "got": got, "ok": ok, "leaked": leaked})

    clean_errors = 0
    malformed = artifacts.malformed_inputs()
    crashes = []
    for kind, text in malformed:
        try:
            diagnose(text, kind=kind)
            crashes.append((kind, "accepted without error"))
        except ValueError:
            clean_errors += 1
        except Exception as exc:  # anything else is a crash
            crashes.append((kind, f"{type(exc).__name__}: {exc}"))

    faulty = [r for r in rows if r["expected"]]
    healthy = [r for r in rows if not r["expected"]]
    return {
        "cases": len(rows),
        "root_cause_accuracy": round(sum(r["ok"] for r in faulty) / len(faulty), 4),
        "faulty_cases": len(faulty), "faulty_correct": sum(r["ok"] for r in faulty),
        "healthy_cases": len(healthy), "healthy_clean": sum(r["ok"] for r in healthy),
        "malformed_inputs": len(malformed), "malformed_clean_errors": clean_errors,
        "crashes": crashes, "redaction_leaks": leaks, "rows": rows,
    }


def format_report(result: dict) -> str:
    lines = [
        f"Debugger eval: {result['cases']} artifacts",
        f"  root cause named first: {result['faulty_correct']}/{result['faulty_cases']} "
        f"({result['root_cause_accuracy']:.1%})",
        f"  healthy artifacts with no failure reported: {result['healthy_clean']}/{result['healthy_cases']}",
        f"  malformed inputs handled with a clear error: "
        f"{result['malformed_clean_errors']}/{result['malformed_inputs']}",
        f"  seeded secrets found after redaction: {result['redaction_leaks']}",
    ]
    for row in result["rows"]:
        if not row["ok"] or row["leaked"]:
            lines.append(f"  MISS {row['name']}: expected {row['expected']}, got {row['got']}, "
                         f"leaked {row['leaked']}")
    for kind, message in result["crashes"]:
        lines.append(f"  CRASH {kind}: {message}")
    return "\n".join(lines)
