"""Web app. Start with:  streamlit run web/app.py"""
from __future__ import annotations

import json
from datetime import date

import streamlit as st

from workbench import __version__, service
from workbench.auditor.pipeline import run_audit
from workbench.auditor.rules import SEVERITY, SEVERITY_ORDER, TITLES
from workbench.debugger import diagnose
from workbench.llm import get_llm
from workbench.synth import artifacts

st.set_page_config(page_title="Identity Workbench", layout="wide")
store = service.get_store()
llm = get_llm()

st.title("Identity Workbench")
st.caption(f"v{__version__} · model layer {'on' if llm else 'off (set ANTHROPIC_API_KEY to enable)'} · "
           "files are processed on this machine")

tab_audit, tab_findings, tab_review, tab_debug = st.tabs(
    ["Run an audit", "Findings", "Review matches", "Debugger"])

# ---- Run an audit ---------------------------------------------------------------
with tab_audit:
    st.subheader("Compare an HR export with account exports")
    left, right = st.columns(2)
    with left:
        hr_file = st.file_uploader("HR export (CSV)", type=["csv", "txt"], key="hr")
        as_of = st.date_input("Date the exports were taken", value=date.today())
    with right:
        account_files = st.file_uploader("Account exports (CSV), one per system", type=["csv", "txt"],
                                         accept_multiple_files=True, key="accounts")
        names = {}
        for upload in account_files or []:
            default = upload.name.rsplit(".", 1)[0].lower().replace("_users", "")
            names[upload.name] = st.text_input(f"System name for {upload.name}", value=default,
                                               key=f"name-{upload.name}")
    if st.button("Run audit", type="primary", disabled=not (hr_file and account_files)):
        try:
            with st.spinner("Matching and running rules..."):
                result = run_audit(hr_file.getvalue(),
                                   [(names[u.name], u.getvalue()) for u in account_files],
                                   as_of=as_of, store=store, llm=llm)
            st.session_state["run_id"] = result.run_id
            st.success(f"Run {result.run_id} finished in {result.stats['seconds']}s. "
                       "Open the Findings tab.")
        except ValueError as exc:
            st.error(str(exc))
    st.divider()
    st.write("No data to hand? Generate a synthetic dataset with seeded problems.")
    size = st.number_input("Employees", min_value=50, max_value=50000, value=1000, step=50)
    if st.button("Generate and audit sample data"):
        import tempfile
        from pathlib import Path

        from workbench.synth.generate import generate

        with tempfile.TemporaryDirectory() as tmp, st.spinner("Generating and auditing..."):
            generate(tmp, employees=int(size))
            folder = Path(tmp)
            result = run_audit(folder / "hr.csv", [("okta", folder / "okta_users.csv"),
                                                   ("entra", folder / "entra_users.csv")],
                               store=store, llm=llm)
        st.session_state["run_id"] = result.run_id
        st.success(f"Run {result.run_id} finished. Open the Findings tab.")

# ---- shared run picker ----------------------------------------------------------
runs = store.list_runs()
run_ids = [r["run_id"] for r in runs]


def pick_run(key: str) -> str | None:
    if not run_ids:
        st.info("No audit runs yet. Run one in the first tab.")
        return None
    current = st.session_state.get("run_id")
    index = run_ids.index(current) if current in run_ids else 0
    labels = {r["run_id"]: f"{r['run_id']} · data as of {r['as_of']}" for r in runs}
    return st.selectbox("Run", run_ids, index=index, format_func=lambda r: labels[r], key=key)


# ---- Findings -------------------------------------------------------------------
with tab_findings:
    run_id = pick_run("run-findings")
    if run_id:
        summary = service.run_summary(store, run_id, llm)
        st.write(summary["summary"])
        cols = st.columns(5)
        for col, sev in zip(cols, SEVERITY_ORDER):
            col.metric(sev.capitalize(), summary["findings_by_severity"].get(sev, 0))
        cols[4].metric("Matches to review", summary["matching"]["review"])

        question = st.text_input("Ask about these findings",
                                 placeholder="leavers who still have access in okta")
        f1, f2, f3 = st.columns(3)
        types = sorted(summary["findings_by_type"], key=lambda t: (SEVERITY_ORDER.index(SEVERITY[t]), t))
        filters = {}
        if question:
            answer = service.ask(store, run_id, question, llm, limit=10_000)
            filters = answer["filter"]
            st.caption(f"Filter from your question ({answer['filter_source']}): {json.dumps(filters)}")
            rows = answer["findings"]
        else:
            chosen_type = f1.selectbox("Type", ["all"] + types,
                                       format_func=lambda t: "All types" if t == "all" else TITLES[t])
            chosen_sev = f2.selectbox("Severity", ["all"] + SEVERITY_ORDER)
            systems = ["all"] + list(summary["accounts_by_system"])
            chosen_sys = f3.selectbox("System", systems)
            rows = store.findings(run_id,
                                  type=None if chosen_type == "all" else chosen_type,
                                  severity=None if chosen_sev == "all" else chosen_sev,
                                  system=None if chosen_sys == "all" else chosen_sys)
        st.write(f"{len(rows):,} finding(s)")
        st.dataframe([{"ID": r["finding_id"], "Severity": r["severity"], "Type": TITLES[r["type"]],
                       "System": r["system"], "Account": r["username"], "Person": r["person_name"],
                       "Finding": r["summary"]} for r in rows[:2000]],
                     use_container_width=True, hide_index=True)

        if rows:
            chosen = st.selectbox("Open a finding", [r["finding_id"] for r in rows[:2000]])
            info = service.explain_finding(store, run_id, chosen)
            guide = info["guidance"]
            st.markdown(f"**{info['title']}** · {info['finding']['summary']}")
            st.write(guide["risk"])
            st.markdown("**What to do**\n" + "\n".join(f"- {s}" for s in guide["steps"]))
            if guide["platform_steps"]:
                st.markdown(f"**In {info['finding']['system']}**\n"
                            + "\n".join(f"- {s}" for s in guide["platform_steps"]))
            st.caption(guide["note"])
            with st.expander("Evidence"):
                st.json(info["finding"]["evidence"])
            reason = st.text_input("Suppress this finding, with a reason", key=f"reason-{chosen}")
            if st.button("Suppress", disabled=not reason):
                store.suppress(run_id, chosen, reason)
                st.rerun()

        d1, d2 = st.columns(2)
        d1.download_button("Download findings CSV", service.export_csv(store, run_id),
                           file_name=f"findings-{run_id}.csv", mime="text/csv")
        d2.download_button("Download HTML report", service.export_html(store, run_id, llm),
                           file_name=f"audit-{run_id}.html", mime="text/html")
        if summary["skipped_rules"]:
            with st.expander("Rules that were skipped"):
                for rule, reason in summary["skipped_rules"].items():
                    st.write(f"**{TITLES.get(rule, rule)}:** {reason}")

# ---- Review matches -------------------------------------------------------------
with tab_review:
    run_id = pick_run("run-review")
    if run_id:
        pairs = store.review_pairs(run_id)
        if not pairs:
            st.info("Nothing to review in this run.")
        else:
            st.write(f"{len(pairs)} account(s) have a plausible person but need your decision. "
                     "Decisions are saved and applied the next time you run an audit.")
            for pair in pairs[:200]:
                account, person = pair["detail"]["account"], pair["detail"]["person"]
                c1, c2, c3, c4 = st.columns([4, 4, 1, 2])
                c1.markdown(f"**{account['display_name'] or account['username']}**  \n"
                            f"{account['system']} · {account['username']}")
                c2.markdown(f"**{person['name']}** ({person['employee_id']})  \n"
                            f"{person['email']} · {person['department']}")
                c3.metric("Score", f"{pair['score']:.0f}")
                decision = pair.get("decision")
                if decision:
                    c4.write(f"Saved: {decision}")
                else:
                    if c4.button("Same person", key=f"c-{pair['pair_id']}"):
                        store.decide(run_id, pair["pair_id"], "confirm")
                        st.rerun()
                    if c4.button("Different", key=f"r-{pair['pair_id']}"):
                        store.decide(run_id, pair["pair_id"], "reject")
                        st.rerun()

# ---- Debugger -------------------------------------------------------------------
with tab_debug:
    st.subheader("Paste a SAML response, a JWT, a SCIM body or a HAR file")
    samples = {c["name"]: c for c in artifacts.cases()}
    sample = st.selectbox("Or load a sample", ["(none)"] + list(samples))
    default_text = samples[sample]["text"] if sample != "(none)" else ""
    expected_default = samples[sample]["expected"] if sample != "(none)" else {}
    text = st.text_area("Artifact", value=default_text, height=220)
    with st.expander("What the receiver expects (optional, enables more checks)",
                     expanded=bool(expected_default)):
        e1, e2 = st.columns(2)
        audience = e1.text_input("Audience / SP entity ID", value=expected_default.get("expected_audience", ""))
        acs = e2.text_input("ACS URL (SAML)", value=expected_default.get("expected_acs", ""))
        issuer = e1.text_input("Issuer (JWT)", value=expected_default.get("expected_issuer", ""))
        at_default = expected_default.get("at")
        at = e2.text_input("Time the receiver saw it (ISO, or 'now')",
                           value=at_default.strftime("%Y-%m-%dT%H:%M:%SZ") if at_default else "")
        scopes = e1.text_input("Required scopes (space separated)",
                               value=" ".join(expected_default.get("required_scopes", [])))
        attrs = e2.text_input("Required attributes (comma separated)",
                              value=", ".join(expected_default.get("required_attributes", [])))
        key = st.text_area("JWKS or public key, to verify a JWT signature",
                           value=expected_default.get("key", ""), height=80)
        scim_filter = st.text_input("SCIM filter to validate",
                                    value=expected_default.get("filter_expression", ""))
        platform = st.selectbox("Show fixes for", ["both", "okta", "entra"])
    if st.button("Diagnose", type="primary", disabled=not text.strip()):
        try:
            result = diagnose(
                text, platform="" if platform == "both" else platform, llm=llm, at=at or None,
                expected_audience=audience, expected_acs=acs, expected_issuer=issuer,
                expected_nameid_format=expected_default.get("expected_nameid_format", ""),
                expected_nonce=expected_default.get("expected_nonce", ""),
                required_scopes=scopes.split(), key=key, filter_expression=scim_filter,
                required_attributes=[a.strip() for a in attrs.split(",") if a.strip()])
        except ValueError as exc:
            st.error(f"Could not decode: {exc}")
        else:
            d = result["diagnosis"]
            if d["failed_check"]:
                st.error(f"**{d['failed_check']}** · {d['what_failed']}")
                st.markdown(f"**Likely cause:** {d['likely_cause']}")
                st.markdown(f"**How to confirm:** {d['how_to_confirm']}")
                st.markdown("**Fix**\n" + "\n".join(f"- {s}" for s in d["fix"]))
                for name, steps in d["platform_fix"].items():
                    st.markdown(f"**{name.capitalize()}**\n" + "\n".join(f"- {s}" for s in steps))
                if result.get("explanation"):
                    st.info(result["explanation"])
            else:
                st.success(d["what_failed"])
            icons = {"pass": "✅", "fail": "❌", "warn": "⚠️", "info": "ℹ️", "skipped": "⏭️"}
            st.dataframe([{"": icons[c["status"]], "Check": c["title"], "Detail": c["detail"]}
                          for c in result["checks"]], use_container_width=True, hide_index=True)
            with st.expander("Decoded fields"):
                st.json(json.loads(json.dumps(result["decoded"], default=str)))
