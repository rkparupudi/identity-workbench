# Identity Workbench

Identity Workbench is a toolkit for Identity and Access Management (IAM) practitioners. It works on **your own data and artifacts** and tells you what is wrong, instead of explaining IAM in general.

It has two modules and four ways to use them:

| Module | You give it | You get back |
| --- | --- | --- |
| **Hygiene auditor** | An HR export and one or more account exports (Okta, Entra ID, Active Directory, SailPoint or any CSV) | A prioritised list of identity problems, each with the evidence rows and the fix |
| **Identity debugger** | A SAML response, a JWT, a SCIM body or a HAR file | The check that fails, the likely cause, how to confirm it, and the fix for Okta or Entra ID |

Both modules are reachable from a **command line** (`idw`), a **web app** (Streamlit), a **REST API** (FastAPI) and an **MCP server** (`idw-mcp`) for Claude and other AI clients.

Two design rules hold everywhere:

1. **Detection and decoding are deterministic Python.** The same input always gives the same output, and every result traces to a named rule or check. The AI model never decides whether something is a finding.
2. **It runs locally and works without an AI model.** A model (Claude) is optional. When enabled it only suggests column mappings, writes the summary and explains results, and it never receives row-level personal data.

---

## Contents

- [What the hygiene auditor does](#what-the-hygiene-auditor-does)
- [What the identity debugger does](#what-the-identity-debugger-does)
- [Install and run](#install-and-run)
- [Ten-minute tour](#ten-minute-tour)
- [Command reference](#command-reference)
- [Using your own files](#using-your-own-files)
- [Web app](#web-app)
- [REST API](#rest-api)
- [MCP server](#mcp-server)
- [The optional AI model](#the-optional-ai-model)
- [Privacy and data handling](#privacy-and-data-handling)
- [Configuration](#configuration)
- [Evaluation](#evaluation)
- [Project layout](#project-layout)
- [Design doc](#design-doc)
- [Known limits](#known-limits)
- [Roadmap](#roadmap)

---

## What the hygiene auditor does

The auditor answers one question: *does every account belong to someone who should have it?* It runs four stages.

**1. Schema mapping.** Each file's columns are mapped to a common schema: a *person* (from HR) or an *account* (from a system). Built-in header lists recognise common Workday, BambooHR, Okta, Entra ID, Active Directory and SailPoint column names. Unrecognised columns are left out, or suggested by the model if one is enabled.

**2. Matching.** Every account is linked to at most one person and placed in one of three bands:

| Band | Meaning | How it gets there |
| --- | --- | --- |
| Matched | The account belongs to this person | Same employee ID, same email, a custom key, or a fuzzy score at or above the upper threshold (default 90) |
| Needs review | Probably this person, but a human should decide | Fuzzy score between the thresholds (default 70 to 89), or two candidates too close to call |
| Unmatched | Nobody in HR fits | Everything else |

Fuzzy scoring compares names, usernames and email local parts, with a small bonus when the department agrees. Decisions you make in review are saved and reused on later runs.

**3. Detection.** Eight rules run over the matched data:

| Finding | Rule | Severity |
| --- | --- | --- |
| Leaver with active account | The person is terminated or past their end date, and a matched account is still enabled | Critical |
| Privileged account without MFA | The account is privileged, enabled, and not enrolled in MFA | Critical |
| Orphaned account | An enabled human account that matched nobody in HR | High |
| Unowned service or shared account | A non-human account with no owner recorded | Medium |
| Dormant account | Enabled, with no sign-in for 90 days (configurable) | Medium |
| Duplicate accounts | One person has two or more enabled accounts in the same system | Medium |
| Missing account | An active person has no account in a system nearly everyone else is in | Low |
| Attribute drift | Email, department or name differs between HR and the account | Low |

A rule that needs a column your file does not have is skipped, and the report says so.

**4. Reporting.** Findings are saved to a local store and can be listed, filtered, explained, suppressed with a reason, exported to CSV, and written to a standalone HTML report.

## What the identity debugger does

The debugger takes one artifact, decodes it, runs a fixed list of checks, and names the first one that fails.

| Artifact | Decoded | Checks |
| --- | --- | --- |
| **SAML** response or request (raw XML, base64, or URL-encoded) | Status, issuer, destination, assertion, NameID, conditions, audience, recipient, attributes, signature block | Status, assertion present, signature present, validity window and clock skew, recipient and destination against your ACS URL, audience against your entity ID, NameID and its format, required attributes |
| **JWT** (OIDC ID token or OAuth access token) | Header and claims | Structure, algorithm (`none` is rejected), expiry and not-before, issuer, audience, nonce, required scopes, signature when you supply a key or JWKS |
| **SCIM** request, response or error body | Schemas, resource, PATCH operations, error type | Schema URNs, required attributes, email structure, PATCH operation shape, error types such as `uniqueness`, filter syntax |
| **HAR** file from a browser sign-in | The redirect chain (cookies, headers and parameter values are never shown) | Error parameters, 4xx and 5xx steps, whether the OIDC or SAML round trip completed, state mismatch, plus the SAML checks on any SAMLResponse found in the flow |

Checks that need a value only you know (your entity ID, ACS URL, expected issuer, the time the receiver saw the artifact) run when you pass that value, and report "info" otherwise. For each failure the debugger gives the likely cause, how to confirm it, and vendor steps for Okta and Entra ID from a hand-written playbook.

---

## Install and run

You need **one** of the following. Nothing else has to be installed.

| Option | Install | Best for |
| --- | --- | --- |
| **A. Docker** | Docker Desktop | Trying the web app and API with nothing else on your machine |
| **B. Python** | Python 3.10 or newer | Day-to-day development, running tests, and the MCP server with Claude Desktop |

No database, Node.js or other service is required. The store is a single SQLite file, and SQLite ships with Python.

### Option A: Docker

Install [Docker Desktop](https://www.docker.com/products/docker-desktop/) (on Windows it uses WSL 2, which the installer sets up). Then, from the project folder:

```powershell
docker compose up --build
```

- Web app: http://localhost:8501
- API docs: http://localhost:8000/docs

The `data` folder next to `docker-compose.yml` is mounted into the container as its working folder, so files you put there are visible inside, and files the tool writes appear there.

Run the command line inside the container:

```powershell
docker compose run --rm web idw synth --out sample_data --employees 2000
docker compose run --rm web idw audit --hr sample_data/hr.csv --accounts okta=sample_data/okta_users.csv entra=sample_data/entra_users.csv --report report.html
docker compose run --rm web idw evals
docker compose run --rm -w /app web pytest -q
```

Stop everything with `Ctrl+C`, then `docker compose down`.

### Option B: Python

Install Python 3.10+ from [python.org](https://www.python.org/downloads/) (tick "Add python.exe to PATH" on Windows). Then, from the project folder:

**Windows (PowerShell)**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[all]"
idw --version
```

If PowerShell refuses to run the activate script, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or use `.venv\Scripts\activate.bat` from `cmd`.

**macOS or Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[all]"
idw --version
```

`[all]` installs every surface. To install less: the base package has only the command line; add `[api]`, `[web]`, `[mcp]`, `[llm]` or `[dev]` as needed, for example `pip install -e ".[web,dev]"`.

Run the tests:

```powershell
pytest -q
```

---

## Ten-minute tour

These commands use synthetic data, so you can try everything without real identity data.

**1. Generate sample exports with known problems**

```powershell
idw synth --out sample_data --employees 2000
```

This writes `hr.csv`, `okta_users.csv`, `entra_users.csv` and `truth.json` (the list of seeded problems, used by the evals).

**2. Run an audit**

```powershell
idw audit --hr sample_data/hr.csv --accounts okta=sample_data/okta_users.csv entra=sample_data/entra_users.csv --report report.html --csv findings.csv
```

Example output:

```
Run 27dd5756db  (data as of 2026-11-14, 0.19s)

Finding                            Severity  Count
---------------------------------  --------  -----
Leaver with active account         critical  58
Privileged account without MFA     critical  32
Orphaned account                   high      39
Dormant account                    medium    130
Duplicate accounts                 medium    13
Unowned service or shared account  medium    10
Attribute drift                    low       102
Missing account                    low       56

15 account(s) need a match decision: idw review --run 27dd5756db
```

Open `report.html` in a browser for the full report.

**3. Look at findings**

```powershell
idw findings --severity critical --limit 10
idw explain F00001
idw ask "leavers who still have admin access"
```

`idw explain` shows the rule, the HR and account rows behind the finding, and remediation steps for the platform.

**4. Decide the uncertain matches**

```powershell
idw review
idw review --confirm d5c5b77ed5 --reject 98f8934fba
```

Decisions are saved. Re-run the audit and confirmed pairs are matched, rejected pairs are never suggested again.

**5. Suppress a known exception**

```powershell
idw suppress F00012 --reason "Break-glass account, approved by security"
```

**6. Try the debugger**

```powershell
idw samples --out sample_artifacts
idw debug sample_artifacts/saml_audience_trailing_slash.xml --audience https://sp.example.com/saml/metadata --acs https://sp.example.com/saml/acs
```

Example output:

```
[ok  ] Status: Success
[ok  ] Signature: Signed: assertion (rsa-sha256). Presence only; the signature was not verified.
[ok  ] Recipient: https://sp.example.com/saml/acs
[FAIL] Audience: Assertion audience is ['https://sp.example.com/saml/metadata/'], the SP
       entity ID is 'https://sp.example.com/saml/metadata'. They differ only by a trailing slash.

First failure: audience_mismatch
Likely cause:  The audience the IdP issued the assertion or token for is not the identifier
               the receiving application expects.
Fix:
  - [okta] SAML: Okta: Applications > your app > General > SAML Settings > Edit: correct
    Audience URI (SP Entity ID).
  - [entra] SAML: Entra ID: Enterprise applications > your app > Single sign-on > Basic SAML
    Configuration: correct Identifier (Entity ID).
```

`idw samples` writes 48 artifacts, each healthy or broken in one known way, so you can see every check fire.

**7. Score the tool against ground truth**

```powershell
idw evals
```

---

## Command reference

Run `idw <command> --help` for every option.

| Command | What it does |
| --- | --- |
| `idw synth` | Generate synthetic HR and account exports with seeded problems. `--out`, `--employees`, `--seed` |
| `idw audit` | Compare an HR export with account exports. `--hr FILE --accounts SYSTEM=FILE ...` |
| `idw findings` | List findings from a run. `--type`, `--severity`, `--system`, `--text`, `--limit`, `--all`, `--json` |
| `idw explain` | Show one finding with evidence and remediation steps |
| `idw review` | List pairs that need a decision; `--confirm PAIR ...` and `--reject PAIR ...` record decisions |
| `idw suppress` | Hide a finding in this and later runs. `--reason` is required |
| `idw ask` | Ask a plain-language question about a run's findings |
| `idw report` | Write the HTML report and CSV for a run. `--out`, `--csv` |
| `idw runs` | List recent audit runs |
| `idw debug` | Decode a SAML, JWT, SCIM or HAR artifact from a file, or `-` for standard input |
| `idw samples` | Write sample healthy and broken artifacts |
| `idw evals` | Score the auditor and the debugger against seeded ground truth |

Commands that take `--run` use the latest run when it is omitted.

### Useful `idw audit` options

| Option | Purpose |
| --- | --- |
| `--as-of YYYY-MM-DD` | The date the exports were taken. Dormancy and end dates are measured from it. Default: today |
| `--upper`, `--lower` | Fuzzy thresholds for auto-match and review (defaults 90 and 70) |
| `--dormant-days N` | Days without sign-in before an account is dormant (default 90) |
| `--expected-system NAME` | A system every active person should have an account in. Repeatable. Without it, a system counts as expected when nearly all active people already have an account there |
| `--match-key ACCOUNT_FIELD:PERSON_FIELD` | An extra exact-match key, for example `username:email` |
| `--dayfirst` | Read ambiguous dates such as `03/04/2026` as day first |
| `--no-llm` | Do not call the model even if a key is set |

### Useful `idw debug` options

| Option | Applies to | Purpose |
| --- | --- | --- |
| `--audience` | SAML, JWT | Your SP entity ID, or the expected `aud` |
| `--acs` | SAML | Your Assertion Consumer Service URL |
| `--issuer` | JWT | The expected `iss` |
| `--nonce` | JWT | The nonce sent in the authorization request |
| `--nameid-format` | SAML | The NameID format your application requires |
| `--require-attribute`, `--require-scope` | SAML, JWT | An attribute or scope that must be present. Repeatable |
| `--key` | JWT | A JWKS file, PEM public key file or shared secret, to verify the signature |
| `--filter` | SCIM | A filter expression to validate |
| `--at` | SAML, JWT | When the receiver saw the artifact (ISO time or epoch). Needed to test expiry and clock skew on an old capture |
| `--platform okta\|entra` | all | Show fixes for one platform only |
| `--json` | all | Machine-readable output |

---

## Using your own files

Export users as CSV from each system and pass each file with a name you choose:

```powershell
idw audit --hr workday.csv --accounts okta=okta.csv entra=entra.csv ad=ad_users.csv
```

**Minimum columns**

| File | Required | Each extra column enables |
| --- | --- | --- |
| HR | Employee ID or work email | Status or end date: leaver detection. Department, name: drift checks and fuzzy matching |
| Accounts | Username, email or account ID | Status: every rule that needs "enabled". Last sign-in: dormancy. MFA and privileged flags: the MFA rule. Account type or owner: service account rules |

**How columns are recognised.** Header names are compared case-insensitively and ignoring spaces and punctuation, so `Work Email`, `work_email` and `WorkEmail` are the same. The full lists are in `workbench/core/schema.py`; add a spelling there if your export uses one that is missing. The audit output lists which columns were mapped and which were ignored, and which rules were skipped for lack of data.

**Getting the exports**

- **Okta:** Reports, or the Users API, with `login`, `email`, `status`, `created`, `lastLogin` and profile attributes.
- **Entra ID:** Users > Download users, or Microsoft Graph, with `userPrincipalName`, `mail`, `accountEnabled`, `createdDateTime`, `employeeId` and sign-in activity.
- **Active Directory:** for example `Get-ADUser -Filter * -Properties mail,employeeID,Enabled,whenCreated,LastLogonDate,Department | Export-Csv ad_users.csv -NoTypeInformation`.
- **SailPoint:** an accounts or identities report exported as CSV.

MFA and privileged-role flags are not in the default user exports of most platforms. Add them as columns (for example `mfaEnrolled`, `isAdmin`) from the platform's MFA and role reports, or the MFA rule is skipped.

---

## Web app

```powershell
streamlit run web/app.py
```

Open http://localhost:8501. Four tabs:

- **Audit:** upload the HR file and account files, name each system, run.
- **Findings:** filter, search, ask questions, read evidence and remediation, download the CSV and HTML report.
- **Review:** confirm or reject the pairs that need a decision.
- **Debugger:** paste an artifact, fill in the values your application expects, diagnose.

## REST API

```powershell
uvicorn workbench.api.main:app --reload
```

Interactive docs at http://localhost:8000/docs.

| Method and path | Purpose |
| --- | --- |
| `GET /health` | Liveness check |
| `POST /audits` | Upload an HR file and account files, run an audit |
| `GET /audits` | List runs |
| `GET /audits/{run_id}` | Run summary and counts |
| `GET /audits/{run_id}/findings` | Findings, with filters |
| `GET /audits/{run_id}/findings/{finding_id}` | One finding with evidence and remediation |
| `GET /audits/{run_id}/review` | Pairs needing a decision |
| `POST /audits/{run_id}/review/{pair_id}` | Confirm or reject a pair |
| `POST /audits/{run_id}/ask` | Ask a question about the findings |
| `GET /audits/{run_id}/report` | HTML report |
| `GET /audits/{run_id}/findings.csv` | Findings as CSV |
| `POST /debug` | Diagnose a pasted artifact |

The API has no authentication. Run it on your own machine only.

## MCP server

The MCP server exposes the same functions as tools, so an AI client can run audits and decode artifacts.

| Tool | What it does |
| --- | --- |
| `generate_sample_data` | Create synthetic HR and account files |
| `map_columns` | Show how a file's columns map to the common schema |
| `run_audit` | Run matching and rules, return a run ID and counts |
| `list_findings` | Findings for a run, filtered by type, severity or system |
| `explain_finding` | Rule, evidence and remediation for one finding |
| `ask_findings` | Answer a question about a run's findings |
| `review_matches` | List pairs needing a decision, and record decisions |
| `decode_saml`, `decode_jwt`, `validate_scim`, `analyze_har` | Decode one artifact and return the check results |

It runs over stdio. File access is limited to one folder, `IDW_DATA_DIR`.

**Claude Desktop with a Python install.** Add this to `claude_desktop_config.json` (Settings > Developer > Edit Config), using your own paths:

```json
{
  "mcpServers": {
    "identity-workbench": {
      "command": "C:\\path\\to\\identity-workbench\\.venv\\Scripts\\idw-mcp.exe",
      "env": { "IDW_DATA_DIR": "C:\\path\\to\\identity-workbench\\data" }
    }
  }
}
```

**Claude Desktop with Docker.** Build the image once with `docker build -t identity-workbench .`, then:

```json
{
  "mcpServers": {
    "identity-workbench": {
      "command": "docker",
      "args": ["run", "-i", "--rm",
               "-v", "C:\\path\\to\\identity-workbench\\data:/data/files",
               "-v", "idw-store:/data/store",
               "identity-workbench", "idw-mcp"]
    }
  }
}
```

Restart Claude Desktop, then ask, for example, "generate sample data and run an identity audit on it".

---

## The optional AI model

Everything works with no model and no network. To enable Claude, set `ANTHROPIC_API_KEY` (in your shell or in a `.env` file copied from `.env.example`). The model is then used for four things:

| Job | What is sent | Without a model |
| --- | --- | --- |
| Column mapping for unrecognised headers | Header names and masked value shapes (`Xxxx.Xxxxx@xxxx.xxx`, `99999`) | Unrecognised columns are ignored |
| Questions over findings | Your question and the list of valid filter values | A keyword parser builds the filter |
| Report summary | Counts only | A template summary |
| Debugger explanation | Redacted decoded fields and check results | The playbook text |

Two safeguards apply. The filter a question turns into is run locally, so the model never sees the rows. Every number in a model-written summary is checked against the computed counts, and the template is used if any number does not match.

To use a different or local model, implement one method, `complete(system, user, max_tokens)`, as described in `workbench/llm/provider.py`.

## Privacy and data handling

- **Local by default.** Files are read from your disk. Findings, saved match decisions and suppressions go into one SQLite file (`~/.identity-workbench/workbench.db`, or `IDW_HOME`).
- **No row-level data to the model.** Names, emails and employee IDs are never sent, with or without a key.
- **Secrets are masked.** The debugger masks tokens, signatures, certificates, cookies, authorization headers and client secrets before output or any model call. HAR parameter values are never shown.
- **Uploaded cell values are data.** Text inside files is never treated as instructions.
- **Advisory only.** Nothing is changed in any system. Verify critical findings against the source system before acting.
- **Do not commit real exports.** `.gitignore` excludes `data/`, `sample_data/`, `*.db`, reports and findings CSVs. Check `git status` before your first push.

## Configuration

Environment variables, all optional (see `.env.example`):

| Variable | Default | Purpose |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | unset | Enables the model layer |
| `IDW_MODEL` | `claude-sonnet-5-5` | Model used when a key is set |
| `IDW_HOME` | `~/.identity-workbench` | Folder holding the SQLite store |
| `IDW_DATA_DIR` | current folder | The only folder the MCP server may read or write |
| `IDW_MATCH_UPPER` | `90` | Fuzzy score needed to auto-match |
| `IDW_MATCH_LOWER` | `70` | Fuzzy score needed to enter review |
| `IDW_DORMANT_DAYS` | `90` | Days without sign-in before an account is dormant |

## Evaluation

`idw evals` generates synthetic data with seeded problems, runs the auditor, and scores it against the ground truth. It then runs the debugger over 48 artifacts, each healthy or broken in one known way.

Results on the default seed with 2,000 employees and 4,025 accounts:

| Measure | Result |
| --- | --- |
| Auto-matched pairs that are correct | 100% (0 wrong of 3,951) |
| True pairs matched or sent to review | 99.8% |
| Precision and recall, seven of eight rules | 97.5% to 100% |
| Missing account rule | 83.9% precision, 97.9% recall |
| Debugger: seeded fault named first | 41 of 41 |
| Debugger: healthy artifacts with no failure reported | 7 of 7 |
| Malformed inputs handled with a clear error | 12 of 12 |
| Seeded secrets found after redaction | 0 |

Read these with care. The data is synthetic and was written alongside the rules, so the scores show the pipeline is internally correct, not how it performs on real exports. Real data is messier, and the missing-account rule already shows false positives here: when someone's surname changed, their account lands in review (sometimes suggested for a different person with a similar name), and until that pair is decided the person is reported as having no account. Expect to tune thresholds and header lists on your first real files.

## Project layout

```
identity-workbench/
  workbench/
    core/         common schema, value cleaning, redaction, SQLite store
    auditor/      ingest, matching, rules, pipeline, guidance, report
    debugger/     saml, jwt, scim, har decoders, playbooks, diagnose
    llm/          optional model provider and the four model tasks
    synth/        synthetic data and sample artifact generators
    evals/        scoring against seeded ground truth
    api/          FastAPI app
    mcp_server/   MCP tools
    service.py    functions shared by the CLI, API, web app and MCP server
    cli.py        the idw command
  web/app.py      Streamlit app
  tests/          pytest suite
  Dockerfile, docker-compose.yml, pyproject.toml
```

## Design doc

The original design is in [`docs/design-doc.pdf`](docs/design-doc.pdf). The code follows it, with four differences made during the build:

| Design doc | Code | Why |
| --- | --- | --- |
| DuckDB store | SQLite | DuckDB allows one writing process at a time, and the web app, API and MCP server share the store |
| Polars for data frames | Plain Python | Fast enough at this scale, and one less dependency |
| PDF report through WeasyPrint | HTML report | WeasyPrint needs system libraries that are awkward on Windows; print the HTML to PDF |
| SAML signature verified when a certificate is supplied | Signature presence only | Not implemented yet; see Known limits |

## Known limits

- **SAML signatures are not verified.** The debugger reports whether a signature is present and which algorithm it uses. JWT signatures are verified when you supply a key.
- **Encrypted SAML assertions cannot be inspected.**
- **Files only.** There is no live connection to Okta, Entra ID or any tenant.
- **No entitlement analysis.** Groups and roles per account are not read, so excess access and movers with stale access are not detected.
- **The report is HTML, not PDF.** Print it to PDF from a browser.
- **Remediation steps are general guidance.** Vendor consoles change; confirm the steps in the current documentation.
- **No authentication** on the API or web app. They are meant for one user on one machine.
- **Synthetic-only validation.** It has not been run on real exports yet.

## Roadmap

1. Read-only connectors for Okta and Microsoft Graph, so no export step is needed.
2. Entitlement analysis: groups and roles, excess access against peers, movers with stale access.
3. Scheduled runs and trends.
4. SAML signature verification and more playbooks.
5. Guided remediation with human approval and an audit trail.

## License

MIT. See [`LICENSE`](LICENSE).
