import json

import pytest

from workbench.core.redaction import mask_shape, redact_obj, redact_text
from workbench.debugger import detect_kind, diagnose
from workbench.evals.debugger_eval import evaluate
from workbench.synth import artifacts

CASES = artifacts.cases()


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_seeded_fault_is_the_first_failure(case):
    result = diagnose(case["text"], kind=case["kind"], **case["expected"])
    got = result["first_failure"]["id"] if result["first_failure"] else None
    assert got == case["fault"]
    if case["fault"]:
        assert result["diagnosis"]["likely_cause"], "every fault needs a playbook entry"
        assert result["diagnosis"]["fix"]


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_kind_is_detected(case):
    assert detect_kind(case["text"]) == case["kind"]


@pytest.mark.parametrize("kind,text", artifacts.malformed_inputs())
def test_malformed_input_gives_a_clear_error(kind, text):
    with pytest.raises(ValueError):
        diagnose(text, kind=kind)


def test_eval_summary():
    result = evaluate()
    assert result["root_cause_accuracy"] == 1.0
    assert result["redaction_leaks"] == 0 and not result["crashes"]


def test_time_checks_need_a_time():
    result = diagnose(artifacts.saml_response(), kind="saml")
    window = next(c for c in result["checks"] if c["title"] == "Validity window")
    assert window["status"] == "info"          # an old paste is not called 'expired'


def test_redaction_of_text():
    token = artifacts.make_jwt()
    text = (f"Authorization: Bearer {token}\nclient_secret=s3cr3tValue123 password: hunter2 "
            "user asha.rao@corp.example api_key=AKIA1234567890ABCDEFGH")
    out = redact_text(text)
    for secret in (token, "s3cr3tValue123", "hunter2", "asha.rao@corp.example", "AKIA1234567890ABCDEFGH"):
        assert secret not in out
    assert redact_text("asha.rao@corp.example") == redact_text("ASHA.RAO@corp.example")


def test_redaction_of_objects_and_shapes():
    obj = {"issuer": "https://idp.example.com", "client_secret": "abc", "nested": [{"Cookie": "sid=1"}],
           "email": "asha.rao@corp.example"}
    out = redact_obj(obj)
    assert out["issuer"] == "https://idp.example.com"
    assert out["client_secret"] == "<removed>" and out["nested"][0]["Cookie"] == "<removed>"
    assert "asha" not in json.dumps(out)
    assert mask_shape("Asha.Rao42@corp.com") == "Xxxx.Xxx99@xxxx.xxx"
