"""Command line interface: `idw <command>`. Run `idw --help` for the list."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

from . import __version__, service
from .auditor.pipeline import parse_account_spec, run_audit
from .auditor.rules import SEVERITY, SEVERITY_ORDER, TITLES
from .llm import get_llm


def _llm(args):
    return None if getattr(args, "no_llm", False) else get_llm()


def _print_table(rows: list[list[str]], header: list[str]) -> None:
    widths = [max(len(str(r[i])) for r in [header] + rows) for i in range(len(header))]
    line = "  ".join(str(h).ljust(w) for h, w in zip(header, widths))
    print(line)
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print("  ".join(str(c).ljust(w) for c, w in zip(row, widths)))


def cmd_synth(args) -> int:
    from .synth.generate import generate

    info = generate(args.out, employees=args.employees, seed=args.seed)
    print(f"Wrote {', '.join(info['files'])} to {info['out_dir']}")
    print(f"{info['employees']:,} employees, {info['okta_accounts']:,} Okta accounts, "
          f"{info['entra_accounts']:,} Entra accounts")
    print("Seeded problems:", json.dumps(info["seeded_counts"]))
    out = Path(args.out)
    print(f"\nTry:  idw audit --hr {out / 'hr.csv'} --accounts okta={out / 'okta_users.csv'} "
          f"entra={out / 'entra_users.csv'}")
    return 0


def cmd_audit(args) -> int:
    store = service.get_store()
    llm = _llm(args)
    sources = [parse_account_spec(spec) for spec in args.accounts]
    result = run_audit(
        args.hr, sources, as_of=date.fromisoformat(args.as_of) if args.as_of else None,
        store=store, llm=llm, upper=args.upper, lower=args.lower, dormant_days=args.dormant_days,
        expected_systems=args.expected_system, extra_keys=args.match_key, dayfirst=args.dayfirst)
    summary = service.run_summary(store, result.run_id, llm)
    print(f"Run {result.run_id}  (data as of {result.as_of}, {result.stats['seconds']}s)\n")
    print(summary["summary"], "\n")
    rows = [[TITLES[t], SEVERITY[t], f"{count:,}"]
            for t, count in sorted(summary["findings_by_type"].items(),
                                   key=lambda kv: (SEVERITY_ORDER.index(SEVERITY[kv[0]]), kv[0]))]
    if rows:
        _print_table(rows, ["Finding", "Severity", "Count"])
    for rule, reason in result.skipped_rules.items():
        print(f"Skipped {TITLES.get(rule, rule)}: {reason}")
    for name, columns in result.stats["unmapped_columns"].items():
        if columns:
            print(f"Columns not used in {name}: {', '.join(columns)}")
    if result.review_pairs:
        print(f"\n{len(result.review_pairs)} account(s) need a match decision: "
              f"idw review --run {result.run_id}")
    if args.csv:
        Path(args.csv).write_text(service.export_csv(store, result.run_id), encoding="utf-8")
        print(f"Findings CSV: {args.csv}")
    if args.report:
        Path(args.report).write_text(service.export_html(store, result.run_id, llm), encoding="utf-8")
        print(f"HTML report: {args.report}")
    print(f"\nNext: idw findings --run {result.run_id} --severity critical")
    return 0


def cmd_findings(args) -> int:
    store = service.get_store()
    run_id = service.resolve_run(store, args.run)
    rows = store.findings(run_id, type=args.type, severity=args.severity, system=args.system,
                          text=args.text, include_suppressed=args.all, limit=args.limit)
    if args.json:
        print(json.dumps(rows, indent=1))
        return 0
    if not rows:
        print("No findings match.")
        return 0
    _print_table([[r["finding_id"], r["severity"], r["system"], r["summary"]] for r in rows],
                 ["ID", "Severity", "System", "Finding"])
    return 0


def cmd_explain(args) -> int:
    store = service.get_store()
    run_id = service.resolve_run(store, args.run)
    info = service.explain_finding(store, run_id, args.finding_id)
    finding, guide = info["finding"], info["guidance"]
    print(f"{finding['finding_id']}  {info['title']}  [{finding['severity']}]")
    print(finding["summary"], "\n")
    print("Why it matters:", guide["risk"], "\n")
    print("What to do:")
    for step in guide["steps"]:
        print("  -", step)
    if guide["platform_steps"]:
        print(f"In {finding['system']}:")
        for step in guide["platform_steps"]:
            print("  -", step)
    print("\nEvidence:")
    print(json.dumps(finding["evidence"], indent=2))
    print("\n" + guide["note"])
    return 0


def cmd_review(args) -> int:
    store = service.get_store()
    run_id = service.resolve_run(store, args.run)
    pairs = store.review_pairs(run_id)
    for pair_id in args.confirm or []:
        print(f"confirm {pair_id}:", "saved" if store.decide(run_id, pair_id, "confirm") else "not found")
    for pair_id in args.reject or []:
        print(f"reject {pair_id}:", "saved" if store.decide(run_id, pair_id, "reject") else "not found")
    if args.confirm or args.reject:
        print("Decisions are saved. Re-run the audit to apply them.")
        return 0
    if not pairs:
        print("Nothing to review.")
        return 0
    rows = []
    for p in pairs:
        a, person = p["detail"]["account"], p["detail"]["person"]
        rows.append([p["pair_id"], f"{p['score']:.0f}", a["system"], a["username"],
                     a["display_name"], f"{person['name']} ({person['employee_id']})",
                     p.get("decision") or ""])
    _print_table(rows, ["Pair", "Score", "System", "Account", "Account name", "Suggested person", "Decision"])
    print(f"\nConfirm or reject:  idw review --run {run_id} --confirm PAIR [PAIR ...] --reject PAIR [PAIR ...]")
    return 0


def cmd_suppress(args) -> int:
    store = service.get_store()
    run_id = service.resolve_run(store, args.run)
    ok = store.suppress(run_id, args.finding_id, args.reason)
    print("Suppressed; it will stay hidden in later runs." if ok else "No such finding.")
    return 0 if ok else 1


def cmd_ask(args) -> int:
    store = service.get_store()
    run_id = service.resolve_run(store, args.run)
    answer = service.ask(store, run_id, args.question, _llm(args), limit=args.limit)
    print(f"Filter ({answer['filter_source']}): {json.dumps(answer['filter'])}  ->  {answer['total']:,} finding(s)\n")
    if answer["findings"]:
        _print_table([[r["finding_id"], r["severity"], r["system"], r["summary"]] for r in answer["findings"]],
                     ["ID", "Severity", "System", "Finding"])
    return 0


def cmd_report(args) -> int:
    store = service.get_store()
    run_id = service.resolve_run(store, args.run)
    if args.csv:
        Path(args.csv).write_text(service.export_csv(store, run_id), encoding="utf-8")
        print(f"Findings CSV: {args.csv}")
    out = args.out or f"audit-{run_id}.html"
    Path(out).write_text(service.export_html(store, run_id, _llm(args)), encoding="utf-8")
    print(f"HTML report: {out}")
    return 0


def cmd_runs(args) -> int:
    runs = service.get_store().list_runs()
    if not runs:
        print("No runs yet.")
        return 0
    _print_table([[r["run_id"], r["created_at"], r["as_of"]] for r in runs], ["Run", "Created (UTC)", "Data as of"])
    return 0


def cmd_debug(args) -> int:
    from .debugger import diagnose

    text = sys.stdin.read() if args.file == "-" else Path(args.file).read_text(encoding="utf-8-sig")
    key = Path(args.key).read_text(encoding="utf-8") if args.key and Path(args.key).is_file() else (args.key or "")
    try:
        result = diagnose(
            text, kind=args.kind or "", platform=args.platform or "", llm=_llm(args), at=args.at,
            expected_audience=args.audience, expected_acs=args.acs, expected_issuer=args.issuer,
            expected_nameid_format=args.nameid_format, expected_nonce=args.nonce,
            required_attributes=args.require_attribute, required_scopes=args.require_scope,
            key=key, filter_expression=args.filter)
    except ValueError as exc:
        print(f"Could not decode: {exc}")
        return 2
    if args.json:
        result.pop("redacted", None)
        print(json.dumps(result, indent=1, default=str))
        return 0
    marks = {"pass": "ok  ", "fail": "FAIL", "warn": "warn", "info": "info", "skipped": "skip"}
    print(f"Artifact type: {result['kind']}\n")
    for item in result["checks"]:
        print(f"[{marks[item['status']]}] {item['title']}: {item['detail']}")
    d = result["diagnosis"]
    print()
    if d["failed_check"]:
        print(f"First failure: {d['failed_check']}")
        print(f"Likely cause:  {d['likely_cause']}")
        print(f"Confirm:       {d['how_to_confirm']}")
        print("Fix:")
        for step in d["fix"]:
            print("  -", step)
        for platform, steps in d["platform_fix"].items():
            for step in steps:
                print(f"  - [{platform}] {step}")
        if result.get("explanation"):
            print("\n" + result["explanation"])
    else:
        print(d["what_failed"])
        print(d["fix"][0])
    return 1 if d["failed_check"] else 0


def cmd_samples(args) -> int:
    from .synth import artifacts

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    extensions = {"saml": "xml", "jwt": "jwt", "scim": "json", "har": "har"}
    for case in artifacts.cases():
        (out / f"{case['name']}.{extensions[case['kind']]}").write_text(case["text"], encoding="utf-8")
    (out / "jwks.json").write_text(artifacts.jwks(), encoding="utf-8")
    print(f"Wrote {len(artifacts.cases())} sample artifacts and jwks.json to {out}")
    print(f"Try:  idw debug {out / 'saml_audience_trailing_slash.xml'} "
          f"--audience {artifacts.SP_ENTITY} --acs {artifacts.SP_ACS}")
    return 0


def cmd_evals(args) -> int:
    from .evals import auditor_eval, debugger_eval

    print(auditor_eval.format_report(auditor_eval.evaluate(args.employees, args.seed)))
    print()
    print(debugger_eval.format_report(debugger_eval.evaluate()))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="idw", description="Identity Workbench: hygiene auditor and identity debugger.")
    parser.add_argument("--version", action="version", version=f"idw {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def no_llm(p):
        p.add_argument("--no-llm", action="store_true", help="do not call the model even if a key is set")

    p = sub.add_parser("synth", help="generate synthetic HR and account exports with seeded problems")
    p.add_argument("--out", default="sample_data")
    p.add_argument("--employees", type=int, default=2000)
    p.add_argument("--seed", type=int, default=7)
    p.set_defaults(func=cmd_synth)

    p = sub.add_parser("audit", help="compare an HR export with account exports and report findings")
    p.add_argument("--hr", required=True, help="HR export (CSV)")
    p.add_argument("--accounts", required=True, nargs="+", metavar="SYSTEM=FILE",
                   help="one or more account exports, e.g. okta=okta.csv entra=entra.csv")
    p.add_argument("--as-of", help="date the exports were taken, YYYY-MM-DD (default: today)")
    p.add_argument("--report", help="write an HTML report to this path")
    p.add_argument("--csv", help="write findings CSV to this path")
    p.add_argument("--upper", type=float, help="fuzzy score needed to auto-match (default 90)")
    p.add_argument("--lower", type=float, help="fuzzy score needed to enter review (default 70)")
    p.add_argument("--dormant-days", type=int, help="days without sign-in before an account is dormant (default 90)")
    p.add_argument("--expected-system", action="append",
                   help="system every active person should have an account in (repeatable; default: inferred)")
    p.add_argument("--match-key", action="append", metavar="ACCOUNT_FIELD:PERSON_FIELD",
                   help="extra exact match rule, e.g. username_local:email_local (repeatable)")
    p.add_argument("--dayfirst", action="store_true", help="read ambiguous dates as DD/MM/YYYY")
    no_llm(p)
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("findings", help="list findings from a run")
    p.add_argument("--run", help="run ID (default: latest)")
    p.add_argument("--type", choices=list(TITLES))
    p.add_argument("--severity", choices=SEVERITY_ORDER)
    p.add_argument("--system")
    p.add_argument("--text", help="search usernames, names and employee IDs")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--all", action="store_true", help="include suppressed findings")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_findings)

    p = sub.add_parser("explain", help="show one finding with evidence and remediation steps")
    p.add_argument("finding_id")
    p.add_argument("--run")
    p.set_defaults(func=cmd_explain)

    p = sub.add_parser("review", help="list or decide account-to-person pairs that need a human")
    p.add_argument("--run")
    p.add_argument("--confirm", nargs="+", metavar="PAIR")
    p.add_argument("--reject", nargs="+", metavar="PAIR")
    p.set_defaults(func=cmd_review)

    p = sub.add_parser("suppress", help="hide a finding, with a reason, in this and later runs")
    p.add_argument("finding_id")
    p.add_argument("--reason", required=True)
    p.add_argument("--run")
    p.set_defaults(func=cmd_suppress)

    p = sub.add_parser("ask", help="ask a question about a run's findings")
    p.add_argument("question")
    p.add_argument("--run")
    p.add_argument("--limit", type=int, default=25)
    no_llm(p)
    p.set_defaults(func=cmd_ask)

    p = sub.add_parser("report", help="write the HTML report (and CSV) for a run")
    p.add_argument("--run")
    p.add_argument("--out")
    p.add_argument("--csv")
    no_llm(p)
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("runs", help="list recent audit runs")
    p.set_defaults(func=cmd_runs)

    p = sub.add_parser("debug", help="decode a SAML, JWT, SCIM or HAR artifact and find what fails")
    p.add_argument("file", help="file holding the artifact, or - to read standard input")
    p.add_argument("--kind", choices=["saml", "jwt", "scim", "har"], help="default: detected")
    p.add_argument("--platform", choices=["okta", "entra"], help="show fixes for this platform only")
    p.add_argument("--audience", help="SP entity ID (SAML) or expected aud (JWT)")
    p.add_argument("--acs", help="the service provider's ACS URL (SAML)")
    p.add_argument("--issuer", help="expected iss (JWT)")
    p.add_argument("--nameid-format", help="NameID format URN the SP expects (SAML)")
    p.add_argument("--nonce", help="nonce sent in the authorization request (JWT)")
    p.add_argument("--require-attribute", action="append", help="attribute the SP needs (repeatable)")
    p.add_argument("--require-scope", action="append", help="scope the API needs (repeatable)")
    p.add_argument("--key", help="JWKS file, PEM public key file, or shared secret, to verify a JWT")
    p.add_argument("--filter", help="a SCIM filter expression to validate")
    p.add_argument("--at", help="when the receiver saw the artifact: ISO time, epoch seconds, or 'now'")
    p.add_argument("--json", action="store_true")
    no_llm(p)
    p.set_defaults(func=cmd_debug)

    p = sub.add_parser("samples", help="write sample broken artifacts to try the debugger with")
    p.add_argument("--out", default="sample_artifacts")
    p.set_defaults(func=cmd_samples)

    p = sub.add_parser("evals", help="score the auditor and debugger against seeded ground truth")
    p.add_argument("--employees", type=int, default=2000)
    p.add_argument("--seed", type=int, default=7)
    p.set_defaults(func=cmd_evals)
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):      # Windows consoles default to cp1252
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (LookupError, ValueError, FileNotFoundError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
