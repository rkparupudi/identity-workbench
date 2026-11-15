"""Operations shared by the CLI, the API, the MCP server and the web app."""
from __future__ import annotations

from .auditor.guidance import remediation
from .auditor.report import findings_csv, html_report, template_summary
from .auditor.rules import TITLES
from .config import get_settings
from .core.store import Store
from .llm.tasks import question_to_filter, write_summary


def get_store() -> Store:
    return Store(get_settings().db_path)


def resolve_run(store: Store, run_id: str | None) -> str:
    run_id = run_id or store.latest_run_id()
    if not run_id or not store.get_run(run_id):
        raise LookupError("No such audit run. Run an audit first, or check the run ID.")
    return run_id


def run_summary(store: Store, run_id: str, llm=None) -> dict:
    run = store.get_run(run_id)
    counts = store.counts(run_id)
    fallback = template_summary(run["stats"], counts["by_type"], counts["by_severity"],
                                run["skipped_rules"])
    text, source = write_summary(llm, run["stats"], counts["by_type"], counts["by_severity"],
                                 run["skipped_rules"], fallback)
    return {"run_id": run_id, "as_of": run["as_of"], "summary": text, "summary_source": source,
            "findings_by_type": counts["by_type"], "findings_by_severity": counts["by_severity"],
            "matching": run["stats"]["matching"], "people": run["stats"]["people"],
            "accounts_by_system": run["stats"]["accounts_by_system"],
            "skipped_rules": run["skipped_rules"], "seconds": run["stats"]["seconds"]}


def explain_finding(store: Store, run_id: str, finding_id: str) -> dict:
    finding = store.finding(run_id, finding_id)
    if not finding:
        raise LookupError(f"No finding {finding_id} in run {run_id}.")
    return {"finding": finding, "title": TITLES[finding["type"]],
            "guidance": remediation(finding["type"], finding.get("system", ""))}


def ask(store: Store, run_id: str, question: str, llm=None, limit: int = 50) -> dict:
    """Answer a question about a run by building a filter and running it locally."""
    run = store.get_run(run_id)
    systems = list(run["stats"]["accounts_by_system"])
    filters = question_to_filter(llm, question, systems)
    rows = store.findings(run_id, limit=None, **filters)
    return {"question": question, "filter": filters,
            "filter_source": "model" if llm is not None else "keywords",
            "total": len(rows), "findings": rows[:limit]}


def export_csv(store: Store, run_id: str) -> str:
    return findings_csv(store.findings(run_id))


def export_html(store: Store, run_id: str, llm=None) -> str:
    run = store.get_run(run_id)
    summary = run_summary(store, run_id, llm)["summary"]
    return html_report(run_id, run["as_of"], run["stats"], store.findings(run_id),
                       run["skipped_rules"], summary_text=summary)
