"""Local store: one SQLite file holding runs, findings, review pairs and saved decisions.

SQLite is used because the CLI, the web app and the MCP server may all open the
store at the same time, and it needs no server.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    as_of TEXT NOT NULL,
    meta TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    run_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    system TEXT,
    account_id TEXT,
    username TEXT,
    employee_id TEXT,
    person_name TEXT,
    summary TEXT NOT NULL,
    evidence TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    suppressed INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (run_id, finding_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_type ON findings (run_id, type);
CREATE TABLE IF NOT EXISTS review_pairs (
    run_id TEXT NOT NULL,
    pair_id TEXT NOT NULL,
    account_key TEXT NOT NULL,
    person_key TEXT NOT NULL,
    score REAL NOT NULL,
    detail TEXT NOT NULL,
    PRIMARY KEY (run_id, pair_id)
);
CREATE TABLE IF NOT EXISTS decisions (
    account_key TEXT NOT NULL,
    person_key TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('confirm', 'reject')),
    decided_at TEXT NOT NULL,
    PRIMARY KEY (account_key, person_key)
);
CREATE TABLE IF NOT EXISTS suppressions (
    fingerprint TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS mappings (
    header_key TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    mapping TEXT NOT NULL,
    saved_at TEXT NOT NULL
);
"""

_SEVERITY_ORDER = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as con:
            con.executescript(_SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        con = sqlite3.connect(self.path, timeout=30)
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
        finally:
            con.close()

    # ---- runs -----------------------------------------------------------
    def save_run(self, run_id: str, as_of: str, meta: dict, findings: list[dict],
                 review_pairs: list[dict]) -> None:
        suppressed = self.suppressions()
        with self._conn() as con:
            con.execute("INSERT OR REPLACE INTO runs VALUES (?, ?, ?, ?)",
                        (run_id, _now(), as_of, json.dumps(meta)))
            con.execute("DELETE FROM findings WHERE run_id = ?", (run_id,))
            con.execute("DELETE FROM review_pairs WHERE run_id = ?", (run_id,))
            con.executemany(
                "INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [(run_id, f["finding_id"], f["type"], f["severity"], f.get("system", ""),
                  f.get("account_id", ""), f.get("username", ""), f.get("employee_id", ""),
                  f.get("person_name", ""), f["summary"], json.dumps(f.get("evidence", {})),
                  f["fingerprint"], 1 if f["fingerprint"] in suppressed else 0)
                 for f in findings])
            con.executemany(
                "INSERT INTO review_pairs VALUES (?, ?, ?, ?, ?, ?)",
                [(run_id, p["pair_id"], p["account_key"], p["person_key"], p["score"],
                  json.dumps(p["detail"])) for p in review_pairs])

    def get_run(self, run_id: str) -> dict | None:
        with self._conn() as con:
            row = con.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if not row:
            return None
        return {"run_id": row["run_id"], "created_at": row["created_at"],
                "as_of": row["as_of"], **json.loads(row["meta"])}

    def list_runs(self, limit: int = 20) -> list[dict]:
        with self._conn() as con:
            rows = con.execute(
                "SELECT run_id, created_at, as_of FROM runs ORDER BY created_at DESC LIMIT ?",
                (limit,)).fetchall()
        return [dict(r) for r in rows]

    def latest_run_id(self) -> str | None:
        runs = self.list_runs(1)
        return runs[0]["run_id"] if runs else None

    # ---- findings -------------------------------------------------------
    def findings(self, run_id: str, type: str | None = None, severity: str | None = None,
                 system: str | None = None, text: str | None = None,
                 include_suppressed: bool = False, limit: int | None = None) -> list[dict]:
        sql = "SELECT * FROM findings WHERE run_id = ?"
        args: list[Any] = [run_id]
        if type:
            sql += " AND type = ?"
            args.append(type)
        if severity:
            sql += " AND severity = ?"
            args.append(severity.lower())
        if system:
            sql += " AND lower(system) = ?"
            args.append(system.lower())
        if text:
            sql += (" AND (lower(summary) LIKE ? OR lower(username) LIKE ? "
                    "OR lower(person_name) LIKE ? OR lower(employee_id) LIKE ?)")
            args += [f"%{text.lower()}%"] * 4
        if not include_suppressed:
            sql += " AND suppressed = 0"
        sql += f" ORDER BY {_SEVERITY_ORDER}, type, system, username"
        if limit:
            sql += " LIMIT ?"
            args.append(limit)
        with self._conn() as con:
            rows = con.execute(sql, args).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["evidence"] = json.loads(item["evidence"])
            item["suppressed"] = bool(item["suppressed"])
            out.append(item)
        return out

    def finding(self, run_id: str, finding_id: str) -> dict | None:
        with self._conn() as con:
            row = con.execute("SELECT * FROM findings WHERE run_id = ? AND finding_id = ?",
                              (run_id, finding_id)).fetchone()
        if not row:
            return None
        item = dict(row)
        item["evidence"] = json.loads(item["evidence"])
        item["suppressed"] = bool(item["suppressed"])
        return item

    def counts(self, run_id: str) -> dict[str, dict[str, int]]:
        with self._conn() as con:
            by_type = con.execute(
                "SELECT type, COUNT(*) n FROM findings WHERE run_id = ? AND suppressed = 0 "
                "GROUP BY type", (run_id,)).fetchall()
            by_sev = con.execute(
                "SELECT severity, COUNT(*) n FROM findings WHERE run_id = ? AND suppressed = 0 "
                "GROUP BY severity", (run_id,)).fetchall()
        return {"by_type": {r["type"]: r["n"] for r in by_type},
                "by_severity": {r["severity"]: r["n"] for r in by_sev}}

    # ---- suppressions ---------------------------------------------------
    def suppress(self, run_id: str, finding_id: str, reason: str) -> bool:
        item = self.finding(run_id, finding_id)
        if not item:
            return False
        with self._conn() as con:
            con.execute("INSERT OR REPLACE INTO suppressions VALUES (?, ?, ?)",
                        (item["fingerprint"], reason, _now()))
            con.execute("UPDATE findings SET suppressed = 1 WHERE fingerprint = ?",
                        (item["fingerprint"],))
        return True

    def suppressions(self) -> dict[str, str]:
        with self._conn() as con:
            rows = con.execute("SELECT fingerprint, reason FROM suppressions").fetchall()
        return {r["fingerprint"]: r["reason"] for r in rows}

    # ---- match review ---------------------------------------------------
    def review_pairs(self, run_id: str) -> list[dict]:
        with self._conn() as con:
            rows = con.execute(
                "SELECT p.*, d.decision FROM review_pairs p LEFT JOIN decisions d "
                "ON d.account_key = p.account_key AND d.person_key = p.person_key "
                "WHERE p.run_id = ? ORDER BY p.score DESC", (run_id,)).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["detail"] = json.loads(item["detail"])
            out.append(item)
        return out

    def decide(self, run_id: str, pair_id: str, decision: str) -> bool:
        if decision not in ("confirm", "reject"):
            raise ValueError("decision must be 'confirm' or 'reject'")
        with self._conn() as con:
            row = con.execute("SELECT account_key, person_key FROM review_pairs "
                              "WHERE run_id = ? AND pair_id = ?", (run_id, pair_id)).fetchone()
            if not row:
                return False
            con.execute("INSERT OR REPLACE INTO decisions VALUES (?, ?, ?, ?)",
                        (row["account_key"], row["person_key"], decision, _now()))
        return True

    def decisions(self) -> dict[tuple[str, str], str]:
        with self._conn() as con:
            rows = con.execute("SELECT account_key, person_key, decision FROM decisions").fetchall()
        return {(r["account_key"], r["person_key"]): r["decision"] for r in rows}

    # ---- saved column mappings -------------------------------------------
    def save_mapping(self, header_key: str, kind: str, mapping: dict[str, str]) -> None:
        with self._conn() as con:
            con.execute("INSERT OR REPLACE INTO mappings VALUES (?, ?, ?, ?)",
                        (header_key, kind, json.dumps(mapping), _now()))

    def get_mapping(self, header_key: str) -> dict[str, str] | None:
        with self._conn() as con:
            row = con.execute("SELECT mapping FROM mappings WHERE header_key = ?",
                              (header_key,)).fetchone()
        return json.loads(row["mapping"]) if row else None
