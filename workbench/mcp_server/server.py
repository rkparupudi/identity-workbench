"""MCP server: the auditor and the debugger as tools for Claude and other MCP clients.

Runs over stdio. Start it with `idw-mcp` (or `python -m workbench.mcp_server.server`).

File access is limited to one folder, IDW_DATA_DIR (default: the folder the
server was started in). No tool changes anything outside the workbench's own store.
"""
from __future__ import annotations

from datetime import date
from pathlib import Path

try:                                   # MCP Python SDK 2.x
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:                    # MCP Python SDK 1.x
    from mcp.server.fastmcp import FastMCP as _Server

from .. import service
from ..auditor import ingest
from ..auditor.pipeline import parse_account_spec, run_audit as _run_audit
from ..config import get_settings
from ..debugger import diagnose
from ..llm import get_llm

mcp = _Server("identity-workbench")


def _safe_path(path: str) -> Path:
    """Resolve `path` inside the allowed data folder, or refuse."""
    root = get_settings().data_dir
    candidate = Path(path)
    resolved = (candidate if candidate.is_absolute() else root / candidate).resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError(f"'{path}' is outside the allowed data folder ({root}). "
                         "Set IDW_DATA_DIR to change the folder.")
    return resolved


def _slim(finding: dict) -> dict:
    return {k: finding[k] for k in ("finding_id", "type", "severity", "system", "username",
                                    "employee_id", "person_name", "summary")}


@mcp.tool()
def generate_sample_data(folder: str = "sample_data", employees: int = 2000) -> dict:
    """Create synthetic HR, Okta and Entra ID exports with seeded identity problems.

    Use this to try the auditor without real data. Files are written inside the
    allowed data folder. Returns the file names and how many problems were seeded.
    """
    from ..synth.generate import generate

    return generate(_safe_path(folder), employees=max(10, min(employees, 200_000)))


@mcp.tool()
def map_columns(file: str, kind: str = "account") -> dict:
    """Show how a CSV file's columns map to the common schema, before running an audit.

    kind is 'person' for an HR export or 'account' for a directory or application export.
    Returns the mapping (schema field -> column header) and the columns left unused.
    """
    headers, rows = ingest.read_csv(_safe_path(file))
    mapping, unmapped, source = ingest.suggest_mapping(
        headers, "person" if kind.lower().startswith("p") else "account", rows,
        store=service.get_store(), llm=get_llm())
    return {"file": file, "rows": len(rows), "mapping": mapping, "mapped_by": source,
            "unused_columns": unmapped}


@mcp.tool()
def run_audit(hr_file: str, account_files: list[str], as_of: str = "") -> dict:
    """Run a hygiene audit: match HR records to accounts and apply the rules.

    account_files: one entry per export, written 'system=path' (for example
    'okta=okta_users.csv', 'entra=entra_users.csv'). as_of: date the exports were
    taken, YYYY-MM-DD; defaults to today. Returns the run ID, a summary, and
    finding counts by type and severity.
    """
    sources = []
    for spec in account_files:
        system, path = parse_account_spec(spec) if "=" in spec else (Path(spec).stem.lower(), spec)
        sources.append((system, _safe_path(path)))
    store = service.get_store()
    llm = get_llm()
    result = _run_audit(_safe_path(hr_file), sources,
                        as_of=date.fromisoformat(as_of) if as_of else None, store=store, llm=llm)
    return service.run_summary(store, result.run_id, llm)


@mcp.tool()
def list_findings(run_id: str = "", type: str = "", severity: str = "", system: str = "",
                  text: str = "", limit: int = 50) -> dict:
    """List findings from an audit run, most severe first.

    run_id defaults to the latest run. Optional filters: type (leaver_active_account,
    privileged_without_mfa, orphaned_account, unowned_service_account, dormant_account,
    duplicate_accounts, missing_account, attribute_drift), severity (critical, high,
    medium, low), system, and text (a name, username or employee ID).
    """
    store = service.get_store()
    run = service.resolve_run(store, run_id or None)
    rows = store.findings(run, type=type or None, severity=severity or None,
                          system=system or None, text=text or None)
    return {"run_id": run, "total": len(rows),
            "findings": [_slim(f) for f in rows[: max(1, min(limit, 500))]]}


@mcp.tool()
def explain_finding(finding_id: str, run_id: str = "") -> dict:
    """Return one finding with its evidence rows, why it matters, and remediation steps."""
    store = service.get_store()
    return service.explain_finding(store, service.resolve_run(store, run_id or None), finding_id)


@mcp.tool()
def ask_findings(question: str, run_id: str = "") -> dict:
    """Answer a plain-language question about a run, e.g. 'leavers who still have Okta access'.

    The question becomes a structured filter that is run locally.
    """
    store = service.get_store()
    answer = service.ask(store, service.resolve_run(store, run_id or None), question, get_llm())
    answer["findings"] = [_slim(f) for f in answer["findings"]]
    return answer


@mcp.tool()
def review_matches(run_id: str = "", confirm: list[str] | None = None,
                   reject: list[str] | None = None) -> dict:
    """List account-to-person pairs that need a human decision, or record decisions.

    With no confirm/reject lists, returns the pairs. Pass pair IDs in confirm or
    reject to save decisions; they apply the next time an audit runs.
    Only record a decision the user has explicitly made.
    """
    store = service.get_store()
    run = service.resolve_run(store, run_id or None)
    saved = {"confirmed": [p for p in confirm or [] if store.decide(run, p, "confirm")],
             "rejected": [p for p in reject or [] if store.decide(run, p, "reject")]}
    if confirm or reject:
        return {"run_id": run, **saved, "note": "Re-run the audit to apply these decisions."}
    return {"run_id": run, "pairs": [
        {"pair_id": p["pair_id"], "score": p["score"], "account": p["detail"]["account"],
         "suggested_person": p["detail"]["person"], "decision": p.get("decision")}
        for p in store.review_pairs(run)]}


def _diagnose(text: str, kind: str, **expected) -> dict:
    result = diagnose(text, kind=kind, llm=None, **expected)
    # Return the redacted form: tool output goes to a model.
    return {"kind": result["kind"], "decoded": result["redacted"]["decoded"],
            "checks": result["redacted"]["checks"], "diagnosis": result["diagnosis"]}


@mcp.tool()
def decode_saml(text: str, expected_audience: str = "", expected_acs: str = "",
                expected_nameid_format: str = "", required_attributes: list[str] | None = None,
                received_at: str = "") -> dict:
    """Decode a SAML Response or AuthnRequest and find the failing check.

    text: raw XML, base64 (POST binding) or URL-encoded deflated base64 (Redirect binding).
    Supply what the service provider expects (entity ID as expected_audience, ACS URL as
    expected_acs) and when it received the message (received_at, ISO time) to enable those
    checks. Signatures are checked for presence only. Emails and secrets are masked.
    """
    return _diagnose(text, "saml", expected_audience=expected_audience, expected_acs=expected_acs,
                     expected_nameid_format=expected_nameid_format,
                     required_attributes=required_attributes or [], at=received_at or None)


@mcp.tool()
def decode_jwt(token: str, expected_issuer: str = "", expected_audience: str = "",
               required_scopes: list[str] | None = None, jwks: str = "", checked_at: str = "") -> dict:
    """Decode a JWT (ID token or access token) and find the failing check.

    Optional: expected_issuer, expected_audience, required_scopes, a JWKS JSON document to
    verify the signature, and checked_at (ISO time or 'now') to test expiry.
    """
    return _diagnose(token, "jwt", expected_issuer=expected_issuer,
                     expected_audience=expected_audience, required_scopes=required_scopes or [],
                     key=jwks, at=checked_at or None)


@mcp.tool()
def validate_scim(body: str, filter_expression: str = "") -> dict:
    """Validate a SCIM 2.0 request or response body (User, Group, PatchOp, Error, ListResponse).

    For an error response, explains the status and scimType. Optionally validates a
    filter expression such as: userName eq "asha.rao@example.com".
    """
    return _diagnose(body, "scim", filter_expression=filter_expression)


@mcp.tool()
def analyze_har(file: str, expected_audience: str = "", expected_acs: str = "") -> dict:
    """Follow a SAML or OIDC sign-in through a HAR file and find where it breaks.

    file: path to the .har file inside the allowed data folder. Cookies, headers and
    parameter values are not returned.
    """
    text = _safe_path(file).read_text(encoding="utf-8-sig")
    return _diagnose(text, "har", expected_audience=expected_audience, expected_acs=expected_acs)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
