import asyncio
import json

import pytest

from workbench import cli
from workbench.llm.tasks import keyword_filter, question_to_filter, suggest_mapping_llm, write_summary
from workbench.synth import artifacts


def test_cli_end_to_end(dataset, capsys, tmp_path):
    folder, _ = dataset
    code = cli.main(["audit", "--hr", str(folder / "hr.csv"), "--accounts",
                     f"okta={folder / 'okta_users.csv'}", f"entra={folder / 'entra_users.csv'}",
                     "--as-of", "2026-11-01", "--report", "r.html", "--csv", "f.csv"])
    out = capsys.readouterr().out
    assert code == 0 and "Leaver with active account" in out
    assert (tmp_path / "r.html").stat().st_size > 2000 and (tmp_path / "f.csv").exists()
    assert cli.main(["findings", "--severity", "critical", "--json"]) == 0
    findings = json.loads(capsys.readouterr().out)
    assert findings and all(f["severity"] == "critical" for f in findings)
    assert cli.main(["explain", findings[0]["finding_id"]]) == 0
    assert "What to do" in capsys.readouterr().out
    assert cli.main(["ask", "dormant accounts in okta"]) == 0
    assert '"type": "dormant_account"' in capsys.readouterr().out
    assert cli.main(["review"]) == 0 and cli.main(["runs"]) == 0


def test_cli_debug(tmp_path, capsys):
    sample = tmp_path / "resp.xml"
    sample.write_text(artifacts.saml_response(audience=artifacts.SP_ENTITY + "/"))
    code = cli.main(["debug", str(sample), "--audience", artifacts.SP_ENTITY, "--acs", artifacts.SP_ACS])
    out = capsys.readouterr().out
    assert code == 1 and "audience_mismatch" in out and "trailing slash" in out
    assert cli.main(["debug", str(sample)]) == 0          # nothing expected, nothing fails
    assert cli.main(["explain", "F00001"]) == 2           # no runs yet: clean error


def test_api(dataset):
    from fastapi.testclient import TestClient

    from workbench.api.main import app

    folder, _ = dataset
    client = TestClient(app)
    assert client.get("/health").json()["status"] == "ok"
    files = [("hr", ("hr.csv", (folder / "hr.csv").read_bytes(), "text/csv")),
             ("accounts", ("okta.csv", (folder / "okta_users.csv").read_bytes(), "text/csv")),
             ("accounts", ("entra.csv", (folder / "entra_users.csv").read_bytes(), "text/csv"))]
    response = client.post("/audits", files=files, data={"systems": "okta,entra", "as_of": "2026-11-01"})
    assert response.status_code == 200, response.text
    run_id = response.json()["run_id"]
    critical = client.get(f"/audits/{run_id}/findings", params={"severity": "critical"}).json()
    assert critical and critical[0]["severity"] == "critical"
    assert client.get(f"/audits/{run_id}/findings/{critical[0]['finding_id']}").json()["guidance"]["steps"]
    assert "<h1>" in client.get("/audits/latest/report").text
    assert client.get("/audits/nope/findings").status_code == 404
    answer = client.post(f"/audits/{run_id}/ask", json={"question": "orphaned accounts"}).json()
    assert answer["filter"] == {"type": "orphaned_account"}

    debug = client.post("/debug", json={"text": artifacts.make_jwt(audience="other"),
                                        "expected_audience": artifacts.OIDC_AUDIENCE}).json()
    assert debug["diagnosis"]["failed_check"] == "audience_mismatch" and "redacted" not in debug
    assert client.post("/debug", json={"text": "a.b", "kind": "jwt"}).status_code == 400
    assert client.post("/audits", files=[("hr", ("x.csv", b"Colour\nred\n", "text/csv")), files[1]]).status_code == 400


def _call(server, name, args):
    result = asyncio.run(server.mcp.call_tool(name, args))
    if hasattr(result, "content"):                    # SDK 2.x: CallToolResult
        assert not getattr(result, "is_error", False), result.content
        blocks = result.content
    else:                                             # SDK 1.x: list, or (list, structured)
        blocks = result[0] if isinstance(result, tuple) else result
    return json.loads(blocks[0].text)


def test_mcp_tools(tmp_path):
    from workbench.mcp_server import server

    names = {tool.name for tool in asyncio.run(server.mcp.list_tools())}
    assert {"run_audit", "list_findings", "explain_finding", "review_matches", "map_columns",
            "decode_saml", "decode_jwt", "validate_scim", "analyze_har", "generate_sample_data",
            "ask_findings"} <= names

    info = _call(server, "generate_sample_data", {"folder": "demo", "employees": 200})
    assert "hr.csv" in info["files"]
    mapping = _call(server, "map_columns", {"file": "demo/okta_users.csv"})
    assert mapping["mapping"]["username"] == "login"
    run = _call(server, "run_audit", {"hr_file": "demo/hr.csv",
                                      "account_files": ["okta=demo/okta_users.csv", "entra=demo/entra_users.csv"]})
    assert run["findings_by_severity"]
    listed = _call(server, "list_findings", {"severity": "critical", "limit": 5})
    assert listed["total"] >= 1 and len(listed["findings"]) <= 5
    detail = _call(server, "explain_finding", {"finding_id": listed["findings"][0]["finding_id"]})
    assert detail["guidance"]["risk"]

    decoded = _call(server, "decode_saml", {"text": artifacts.saml_response(signed=False),
                                            "expected_audience": artifacts.SP_ENTITY})
    assert decoded["diagnosis"]["failed_check"] == "signature_missing"
    assert "asha.rao@corp.example" not in json.dumps(decoded)       # tool output is redacted
    scim = _call(server, "validate_scim", {"body": json.dumps(artifacts.scim_error("409", "uniqueness", "exists"))})
    assert scim["diagnosis"]["failed_check"] == "scim_error_uniqueness"


def test_mcp_refuses_paths_outside_the_data_folder(tmp_path):
    from workbench.mcp_server import server

    with pytest.raises(ValueError, match="outside the allowed data folder"):
        server._safe_path("../secrets.csv")
    with pytest.raises(ValueError):
        server._safe_path("/etc/passwd")
    assert server._safe_path("demo/hr.csv") == tmp_path.resolve() / "demo" / "hr.csv"


class FakeLLM:
    def __init__(self, reply):
        self.reply, self.calls = reply, []

    def complete(self, system, user, max_tokens=700):
        self.calls.append(user)
        return self.reply


STATS = {"people": 100, "accounts": 210, "accounts_by_system": {"okta": 110, "entra": 100},
         "matching": {"matched": 200, "review": 4, "unmatched": 6}}


def test_summary_with_wrong_numbers_is_discarded():
    good = FakeLLM("Of 210 accounts, 6 matched nobody and 4 need review. 7 leavers still have access.")
    bad = FakeLLM("About 95% of 210 accounts are fine; 9 leavers still have access.")
    counts = {"leaver_active_account": 7}
    assert write_summary(good, STATS, counts, {"critical": 7}, {}, "fallback") == (good.reply, "model")
    assert write_summary(bad, STATS, counts, {"critical": 7}, {}, "fallback") == ("fallback", "template")
    assert write_summary(None, STATS, counts, {"critical": 7}, {}, "fallback")[1] == "template"


def test_model_suggestions_are_validated():
    llm = FakeLLM('{"last_login": "Zuletzt angemeldet", "privileged": "No such column", "bogus": "X"}')
    samples = {"Zuletzt angemeldet": ["9999-99-99"], "X": ["xx"]}
    assert suggest_mapping_llm(llm, "account", ["last_login", "privileged"], samples) == {
        "last_login": "Zuletzt angemeldet"}
    assert "9999-99-99" in llm.calls[0]                      # only masked shapes are sent
    assert question_to_filter(FakeLLM('{"type": "hack", "system": "okta"}'), "x", ["okta"]) == {"system": "okta"}
    assert question_to_filter(FakeLLM("not json"), "dormant users", ["okta"]) == {"type": "dormant_account"}
    assert keyword_filter("critical findings in Entra", ["okta", "entra"]) == {"severity": "critical", "system": "entra"}


def test_web_app_loads():
    from pathlib import Path

    from streamlit.testing.v1 import AppTest

    app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "web" / "app.py"), default_timeout=60)
    app.run()
    assert not app.exception
    assert app.title[0].value == "Identity Workbench"

    # Generate sample data, audit it, and check the findings tab fills in.
    next(b for b in app.button if b.label == "Generate and audit sample data").click().run()
    assert not app.exception
    assert any("finished" in s.value for s in app.success)
    assert any(m.label == "Critical" and int(m.value) > 0 for m in app.metric)

    # Load a broken sample into the debugger and diagnose it.
    next(s for s in app.selectbox if s.label == "Or load a sample").select("saml_audience_trailing_slash").run()
    next(b for b in app.button if b.label == "Diagnose").click().run()
    assert not app.exception
    assert any("audience_mismatch" in e.value for e in app.error)
