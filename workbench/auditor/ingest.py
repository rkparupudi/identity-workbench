"""Read CSV exports and reduce them to the common schema.

Column mapping happens in three steps:
1. a mapping the user confirmed earlier for the same set of headers (from the store),
2. built-in header synonyms for HRIS, Okta, Entra ID, Active Directory and SailPoint,
3. for columns still unmapped, an optional model suggestion (headers and masked
   sample shapes only; no real values are sent).
"""
from __future__ import annotations

import csv
import hashlib
import io
from dataclasses import dataclass, field
from pathlib import Path

from ..core import normalize as nz
from ..core.redaction import mask_shape
from ..core.schema import (ACCOUNT_KEY_FIELDS, PERSON_KEY_FIELDS, fields_for,
                           header_index_for, norm_header)


@dataclass
class Table:
    """A loaded file: normalised records plus what was known about its columns."""
    kind: str                      # 'person' or 'account'
    system: str                    # 'hr' or the account system name
    records: list[dict]
    mapping: dict[str, str]        # canonical field -> source header
    unmapped: list[str]            # source headers that were not used
    mapping_source: dict[str, str] = field(default_factory=dict)  # field -> saved|builtin|model
    skipped_rows: int = 0

    @property
    def fields_present(self) -> set[str]:
        return set(self.mapping)


def read_csv(source: str | Path | bytes) -> tuple[list[str], list[dict[str, str]]]:
    """Returns (headers, rows). Accepts a path or raw bytes; sniffs the delimiter."""
    if isinstance(source, bytes):
        raw = source
    else:
        raw = Path(source).read_bytes()
    for encoding in ("utf-8-sig", "utf-16", "cp1252"):
        try:
            text = raw.decode(encoding)
            break
        except UnicodeError:
            continue
    else:
        text = raw.decode("utf-8", "replace")
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    headers = [h for h in (reader.fieldnames or []) if h is not None]
    rows = [{k: (v or "") for k, v in row.items() if k is not None} for row in reader]
    return headers, rows


def header_key(headers: list[str], kind: str) -> str:
    joined = kind + "|" + "|".join(sorted(norm_header(h) for h in headers))
    return hashlib.sha256(joined.encode()).hexdigest()[:16]


def suggest_mapping(headers: list[str], kind: str, rows: list[dict] | None = None,
                    store=None, llm=None) -> tuple[dict[str, str], list[str], dict[str, str]]:
    """Returns (mapping, unmapped_headers, source_per_field)."""
    mapping: dict[str, str] = {}
    source: dict[str, str] = {}

    saved = store.get_mapping(header_key(headers, kind)) if store else None
    if saved:
        for canonical, header in saved.items():
            if header in headers:
                mapping[canonical] = header
                source[canonical] = "saved"

    index = header_index_for(kind)
    for header in headers:
        canonical = index.get(norm_header(header))
        if canonical and canonical not in mapping and header not in mapping.values():
            mapping[canonical] = header
            source[canonical] = "builtin"

    unmapped = [h for h in headers if h not in mapping.values()]
    missing = [f for f in fields_for(kind) if f not in mapping]
    if llm is not None and unmapped and missing:
        from ..llm.tasks import suggest_mapping_llm
        samples = {}
        for header in unmapped:
            values = [r.get(header, "") for r in (rows or [])[:50]]
            values = [v for v in values if v][:3]
            samples[header] = [mask_shape(v) for v in values]
        for canonical, header in suggest_mapping_llm(llm, kind, missing, samples).items():
            if canonical in missing and header in unmapped and canonical not in mapping:
                mapping[canonical] = header
                source[canonical] = "model"
        unmapped = [h for h in headers if h not in mapping.values()]
    return mapping, unmapped, source


def _get(row: dict, mapping: dict[str, str], name: str) -> str:
    header = mapping.get(name)
    return nz.clean(row.get(header, "")) if header else ""


def _split_display(display: str) -> tuple[str, str]:
    """'Rao, Asha' -> ('Asha', 'Rao'); 'Asha K Rao' -> ('Asha', 'Rao')."""
    if "," in display:
        last, _, first = display.partition(",")
        return first.strip().split(" ")[0] if first.strip() else "", last.strip()
    parts = display.split()
    if len(parts) >= 2:
        return parts[0], parts[-1]
    return (parts[0], "") if parts else ("", "")


def load_people(source, mapping: dict[str, str] | None = None, store=None, llm=None,
                dayfirst: bool = False) -> Table:
    headers, rows = read_csv(source)
    unmapped: list[str] = []
    src: dict[str, str] = {}
    if mapping is None:
        mapping, unmapped, src = suggest_mapping(headers, "person", rows, store, llm)
    if not any(k in mapping for k in PERSON_KEY_FIELDS):
        raise ValueError(
            "HR file needs an employee ID or email column. Headers found: " + ", ".join(headers))

    records, skipped = [], 0
    for line, row in enumerate(rows, start=2):
        emp = _get(row, mapping, "employee_id")
        email = nz.norm_email(_get(row, mapping, "email"))
        if not emp and not email:
            skipped += 1
            continue
        first, last = _get(row, mapping, "first_name"), _get(row, mapping, "last_name")
        display = _get(row, mapping, "display_name")
        if display and not (first and last):
            d_first, d_last = _split_display(display)
            first, last = first or d_first, last or d_last
        if not display:
            display = f"{first} {last}".strip()
        end_date = nz.parse_date(_get(row, mapping, "end_date"), dayfirst)
        records.append({
            "key": emp or email,
            "employee_id": emp,
            "first_name": first,
            "last_name": last,
            "display_name": display,
            "email": email,
            "status": nz.person_status(_get(row, mapping, "status")),
            "start_date": nz.parse_date(_get(row, mapping, "start_date"), dayfirst),
            "end_date": end_date,
            "department": _get(row, mapping, "department"),
            "manager": _get(row, mapping, "manager"),
            "worker_type": _get(row, mapping, "worker_type"),
            "row": line,
        })
    return Table("person", "hr", records, mapping, unmapped, src, skipped)


def load_accounts(source, system: str, mapping: dict[str, str] | None = None, store=None,
                  llm=None, dayfirst: bool = False) -> Table:
    headers, rows = read_csv(source)
    unmapped: list[str] = []
    src: dict[str, str] = {}
    if mapping is None:
        mapping, unmapped, src = suggest_mapping(headers, "account", rows, store, llm)
    if not any(k in mapping for k in ACCOUNT_KEY_FIELDS):
        raise ValueError(
            f"Account file for '{system}' needs an account ID, username or email column. "
            "Headers found: " + ", ".join(headers))

    status_header = mapping.get("status", "")
    records, skipped = [], 0
    for line, row in enumerate(rows, start=2):
        username = _get(row, mapping, "username")
        email = nz.norm_email(_get(row, mapping, "email"))
        account_id = _get(row, mapping, "account_id") or username or email
        if not account_id:
            skipped += 1
            continue
        if not email and "@" in username:
            # A UPN is usually, but not always, a mailbox; keep it as a match hint only.
            upn_email = nz.norm_email(username)
        else:
            upn_email = ""
        first, last = _get(row, mapping, "first_name"), _get(row, mapping, "last_name")
        display = _get(row, mapping, "display_name")
        if display and not (first and last):
            d_first, d_last = _split_display(display)
            first, last = first or d_first, last or d_last
        if not display:
            display = f"{first} {last}".strip()
        records.append({
            "key": f"{system}|{account_id}",
            "system": system,
            "account_id": account_id,
            "username": username or email or account_id,
            "email": email,
            "upn_email": upn_email,
            "display_name": display,
            "first_name": first,
            "last_name": last,
            "employee_id": _get(row, mapping, "employee_id"),
            "enabled": nz.account_enabled(_get(row, mapping, "status"), status_header),
            "created": nz.parse_date(_get(row, mapping, "created"), dayfirst),
            "last_login": nz.parse_date(_get(row, mapping, "last_login"), dayfirst),
            "mfa_enrolled": nz.parse_bool(_get(row, mapping, "mfa_enrolled")),
            "privileged": nz.parse_bool(_get(row, mapping, "privileged")),
            "account_type": nz.infer_account_type(_get(row, mapping, "account_type"),
                                                  username or email or account_id),
            "department": _get(row, mapping, "department"),
            "owner": _get(row, mapping, "owner"),
            "row": line,
        })
    return Table("account", system, records, mapping, unmapped, src, skipped)
