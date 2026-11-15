"""HTTP API. Start with:  uvicorn workbench.api.main:app --port 8000

Interactive documentation is served at /docs.
"""
from __future__ import annotations

from datetime import date

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from .. import __version__, service
from ..auditor.pipeline import run_audit
from ..debugger import diagnose
from ..llm import get_llm

app = FastAPI(title="Identity Workbench", version=__version__,
              description="Identity hygiene auditor and identity debugger.")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__, "model_enabled": get_llm() is not None}


@app.post("/audits")
async def create_audit(
    hr: UploadFile = File(..., description="HR export (CSV)"),
    accounts: list[UploadFile] = File(..., description="One or more account exports (CSV)"),
    systems: str = Form("", description="Comma-separated system names, one per account file, in order"),
    as_of: str = Form("", description="Date the exports were taken, YYYY-MM-DD"),
) -> dict:
    names = [s.strip() for s in systems.split(",") if s.strip()]
    sources = []
    for index, upload in enumerate(accounts):
        name = names[index] if index < len(names) else (upload.filename or f"system{index + 1}").rsplit(".", 1)[0]
        sources.append((name, await upload.read()))
    store = service.get_store()
    try:
        result = run_audit(await hr.read(), sources,
                           as_of=date.fromisoformat(as_of) if as_of else None,
                           store=store, llm=get_llm())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return service.run_summary(store, result.run_id, get_llm())


def _run(run_id: str):
    store = service.get_store()
    try:
        return store, service.resolve_run(store, None if run_id == "latest" else run_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/audits")
def list_audits() -> list[dict]:
    return service.get_store().list_runs()


@app.get("/audits/{run_id}")
def get_audit(run_id: str) -> dict:
    store, run_id = _run(run_id)
    return service.run_summary(store, run_id, get_llm())


@app.get("/audits/{run_id}/findings")
def get_findings(run_id: str, type: str | None = None, severity: str | None = None,
                 system: str | None = None, text: str | None = None, limit: int = 200) -> list[dict]:
    store, run_id = _run(run_id)
    return store.findings(run_id, type=type, severity=severity, system=system, text=text, limit=limit)


@app.get("/audits/{run_id}/findings/{finding_id}")
def get_finding(run_id: str, finding_id: str) -> dict:
    store, run_id = _run(run_id)
    try:
        return service.explain_finding(store, run_id, finding_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/audits/{run_id}/review")
def get_review(run_id: str) -> list[dict]:
    store, run_id = _run(run_id)
    return store.review_pairs(run_id)


class Decision(BaseModel):
    decision: str


@app.post("/audits/{run_id}/review/{pair_id}")
def decide(run_id: str, pair_id: str, body: Decision) -> dict:
    store, run_id = _run(run_id)
    try:
        saved = store.decide(run_id, pair_id, body.decision)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not saved:
        raise HTTPException(status_code=404, detail="No such pair.")
    return {"saved": True, "note": "Re-run the audit to apply saved decisions."}


class Question(BaseModel):
    question: str


@app.post("/audits/{run_id}/ask")
def ask(run_id: str, body: Question) -> dict:
    store, run_id = _run(run_id)
    return service.ask(store, run_id, body.question, get_llm())


@app.get("/audits/{run_id}/report", response_class=HTMLResponse)
def report(run_id: str) -> str:
    store, run_id = _run(run_id)
    return service.export_html(store, run_id, get_llm())


@app.get("/audits/{run_id}/findings.csv", response_class=PlainTextResponse)
def findings_csv(run_id: str) -> str:
    store, run_id = _run(run_id)
    return service.export_csv(store, run_id)


class DebugRequest(BaseModel):
    text: str
    kind: str = ""
    platform: str = ""
    at: str = ""
    expected_audience: str = ""
    expected_acs: str = ""
    expected_issuer: str = ""
    expected_nameid_format: str = ""
    expected_nonce: str = ""
    required_attributes: list[str] = []
    required_scopes: list[str] = []
    key: str = ""
    filter_expression: str = ""


@app.post("/debug")
def debug(body: DebugRequest) -> dict:
    args = body.model_dump()
    text, at = args.pop("text"), args.pop("at") or None
    try:
        result = diagnose(text, llm=get_llm(), at=at, **args)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result.pop("redacted", None)
    return result
