import csv
import io
from datetime import date

import pytest

from workbench.auditor import ingest
from workbench.auditor.matching import match_accounts
from workbench.auditor.pipeline import run_audit
from workbench.auditor.report import findings_csv, html_report
from workbench.core import normalize as nz
from workbench.evals.auditor_eval import evaluate

AS_OF = date(2026, 11, 1)


def _csv(rows):
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue().encode()


HR = _csv([
    {"Employee ID": "E1", "First Name": "Asha", "Last Name": "Rao", "Work Email": "asha.rao@corp.example",
     "Status": "Active", "Termination Date": "", "Department": "Finance"},
    {"Employee ID": "E2", "First Name": "Vikram", "Last Name": "Nair", "Work Email": "vikram.nair@corp.example",
     "Status": "Terminated", "Termination Date": "2026-09-30", "Department": "Sales"},
    {"Employee ID": "E3", "First Name": "Katherine", "Last Name": "Johnson", "Work Email": "katherine.johnson@corp.example",
     "Status": "Active", "Termination Date": "", "Department": "Legal"},
])
ACCOUNTS = _csv([
    {"login": "asha.rao@corp.example", "status": "ACTIVE", "employeeNumber": "E1", "lastLogin": "2026-10-30",
     "mfaEnrolled": "false", "isAdmin": "true", "department": "Marketing", "created": "2024-01-01"},
    {"login": "vikram.nair@corp.example", "status": "ACTIVE", "employeeNumber": "E2", "lastLogin": "2026-10-29",
     "mfaEnrolled": "true", "isAdmin": "false", "department": "Sales", "created": "2024-01-01"},
    {"login": "kate.johnson@corp.example", "status": "ACTIVE", "employeeNumber": "", "lastLogin": "2026-03-01",
     "mfaEnrolled": "true", "isAdmin": "false", "department": "Legal", "created": "2024-01-01"},
    {"login": "pat.contractor@partner.example", "status": "ACTIVE", "employeeNumber": "", "lastLogin": "2026-10-28",
     "mfaEnrolled": "true", "isAdmin": "false", "department": "", "created": "2025-01-01"},
    {"login": "svc-backup-01@corp.example", "status": "ACTIVE", "employeeNumber": "", "lastLogin": "2026-10-31",
     "mfaEnrolled": "", "isAdmin": "false", "department": "", "created": "2023-01-01"},
])


def _types(result):
    return {(f["type"], f["username"] or f["employee_id"]) for f in result.findings}


def test_each_rule_fires_on_a_small_dataset(store):
    result = run_audit(HR, [("okta", ACCOUNTS)], as_of=AS_OF, store=store)
    found = _types(result)
    assert ("leaver_active_account", "vikram.nair@corp.example") in found
    assert ("privileged_without_mfa", "asha.rao@corp.example") in found
    assert ("attribute_drift", "asha.rao@corp.example") in found          # department differs
    assert ("orphaned_account", "pat.contractor@partner.example") in found
    assert ("unowned_service_account", "svc-backup-01@corp.example") in found
    # the nickname account is sent to review, not reported as an orphan or auto-matched
    assert result.matches["okta|kate.johnson@corp.example"].band == "review"
    assert ("orphaned_account", "kate.johnson@corp.example") not in found
    assert result.findings[0]["severity"] == "critical"


def test_review_decision_is_applied_on_the_next_run(store):
    first = run_audit(HR, [("okta", ACCOUNTS)], as_of=AS_OF, store=store)
    pair = store.review_pairs(first.run_id)[0]
    assert store.decide(first.run_id, pair["pair_id"], "confirm")
    second = run_audit(HR, [("okta", ACCOUNTS)], as_of=AS_OF, store=store)
    match = second.matches["okta|kate.johnson@corp.example"]
    assert (match.band, match.method, match.person_key) == ("matched", "saved_decision", "E3")
    assert ("dormant_account", "kate.johnson@corp.example") in _types(second)


def test_suppression_carries_over(store):
    first = run_audit(HR, [("okta", ACCOUNTS)], as_of=AS_OF, store=store)
    target = next(f for f in first.findings if f["type"] == "unowned_service_account")
    assert store.suppress(first.run_id, target["finding_id"], "known backup account")
    second = run_audit(HR, [("okta", ACCOUNTS)], as_of=AS_OF, store=store)
    visible = store.findings(second.run_id)
    assert all(f["type"] != "unowned_service_account" for f in visible)
    assert any(f["suppressed"] for f in store.findings(second.run_id, include_suppressed=True))


def test_rules_are_skipped_when_columns_are_missing(store):
    bare = _csv([{"login": "asha.rao@corp.example", "status": "ACTIVE"}])
    result = run_audit(HR, [("app", bare)], as_of=AS_OF, store=store)
    assert "privileged_without_mfa" in result.skipped_rules
    assert "dormant_account" in result.skipped_rules


def test_file_without_key_columns_is_rejected(store):
    with pytest.raises(ValueError, match="employee ID or email"):
        run_audit(_csv([{"Colour": "red"}]), [("okta", ACCOUNTS)], store=store)


def test_header_mapping_for_entra_and_ad_exports():
    entra, _, _ = ingest.suggest_mapping(
        ["userPrincipalName", "displayName", "mail", "accountEnabled", "lastSignInDateTime",
         "employeeId", "isMfaRegistered", "userType", "Favourite colour"], "account")
    assert entra["username"] == "userPrincipalName" and entra["last_login"] == "lastSignInDateTime"
    assert entra["mfa_enrolled"] == "isMfaRegistered" and entra["status"] == "accountEnabled"
    ad, unmapped, _ = ingest.suggest_mapping(
        ["sAMAccountName", "mail", "Enabled", "whenCreated", "LastLogonDate", "employeeID", "extra"], "account")
    assert ad["username"] == "sAMAccountName" and ad["created"] == "whenCreated"
    assert unmapped == ["extra"]


def test_value_parsing():
    assert nz.parse_date("2026-10-30T08:15:00Z") == date(2026, 10, 30)
    assert nz.parse_date("10/30/2026") == date(2026, 10, 30)
    assert nz.parse_date("30/10/2026") == date(2026, 10, 30)
    assert nz.parse_date("05/04/2026", dayfirst=True) == date(2026, 4, 5)
    assert nz.parse_date("133747200000000000") == date(2024, 10, 30)   # AD FILETIME
    assert nz.parse_date("never") is None
    assert nz.account_enabled("DEPROVISIONED") is False
    assert nz.account_enabled("TRUE", "Disabled") is False
    assert nz.account_enabled("514") is False and nz.account_enabled("512") is True
    assert nz.infer_account_type("", "svc-jenkins@corp.example") == "service"
    assert nz.infer_account_type("Guest", "pat@partner.example") == "human"
    assert nz.fold("José O'Neil-Smith") == "jose oneil smith"


def test_custom_match_key():
    people = ingest.load_people(HR).records
    accounts = ingest.load_accounts(_csv([{"sAMAccountName": "E3", "Enabled": "True"}]), "ad").records
    assert match_accounts(people, accounts)["ad|E3"].band != "matched"
    matched = match_accounts(people, accounts, extra_keys=["username:employee_id"])["ad|E3"]
    assert (matched.band, matched.person_key) == ("matched", "E3")


def test_reports(store):
    result = run_audit(HR, [("okta", ACCOUNTS)], as_of=AS_OF, store=store)
    rows = list(csv.DictReader(io.StringIO(findings_csv(result.findings))))
    assert len(rows) == len(result.findings)
    page = html_report(result.run_id, "2026-11-01", result.stats, result.findings, result.skipped_rules)
    assert "Leaver with active account" in page and "<script" not in page


def test_synthetic_eval_meets_targets():
    result = evaluate(employees=1200, seed=3)
    assert result["match_precision"] >= 0.99
    assert result["match_recall"] >= 0.95
    for rule in ("leaver_active_account", "privileged_without_mfa", "dormant_account",
                 "unowned_service_account", "duplicate_accounts", "orphaned_account"):
        assert result["rules"][rule]["precision"] >= 0.95, rule
        assert result["rules"][rule]["recall"] >= 0.90, rule
