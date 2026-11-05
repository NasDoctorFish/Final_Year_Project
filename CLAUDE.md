# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

BioAudit: a security testing tool for Android biometric authentication. It inspects an
Android app (installed device, or an APK on disk) and reports whether biometric auth is
*secure*, not just whether it works — static APK analysis + runtime testing over ADB, with
an AI layer (server-side only) that explains rule-based findings. **Detection is
deterministic**: the AI never decides whether a vulnerability exists, only explains and
remediates findings the rule engine already confirmed.

Two independent codebases in one repo:

- **`bioaudit/`** — Python: CLI, PySide6 desktop GUI, Streamlit dashboard, the scanning
  engine. Root-level `requirements.txt`.
- **`backend/`** — Node/Express REST API (accounts, scan history, teams, AI explanation),
  Firebase Auth + Firestore, deployed on Cloud Run (`deploy-render/render.yaml` also present
  as a Render.com deploy target). Independent `package.json`/npm install.

**An account is required.** BioAudit keeps no local copy of a scan — every finished run is
uploaded to the backend, which is what lets history follow a user between machines and
gives a team's admin oversight. There is no guest mode and no local database.

Scope: Mode B (black-box) only — no root, no rebuild, no source needed. Every runtime test
is gated behind an explicit `--i-am-authorized` flag / GUI checkbox.

## Commands

### Python side

```bash
pip install -r requirements.txt
python -m bioaudit login                                          # or: register --email ... --organisation "Team"
python -m bioaudit scan-apk path/to/app.apk                        # static analysis, no device
python -m bioaudit assess --package com.example.app --i-am-authorized  # full runtime assessment
python -m bioaudit explain <scan-id>                                # AI explanation from the server
python -m bioaudit whoami                                           # show signed-in account
python -m bioaudit logout                                           # clear saved session
python -m bioaudit gui                                              # desktop app
python -m bioaudit dashboard                                        # Streamlit dashboard

pytest tests/                          # offline unit tests
pytest tests/test_models.py::test_name # single test
pytest tests/test_api_client.py -v     # needs a reachable server (see backend); self-skips otherwise
```

Sample APK / device target for manual testing:

```bash
python tests/fixtures/make_sample_apk.py           # writes sample-vuln-app.apk, no Android SDK needed
python -m bioaudit scan-apk sample-vuln-app.apk

python sample-app/build.py --install                # builds + installs VulnDemo (Gradle-free: aapt2/d8/apksigner)
python -m bioaudit assess --package com.bioaudit.vulndemo --apk sample-app/dist/vulndemo.apk --i-am-authorized
```

Heavy deps (androguard, PySide6, weasyprint, streamlit) import lazily, so the rule-based
core runs with none of them installed; `scan-apk` needs androguard, the GUI needs PySide6.

Build standalone Windows exe: `pyinstaller BioAudit.spec` (needs `pip install pyinstaller`).

### Backend (`backend/`)

```bash
cd backend
npm install
npm run dev              # against real Firebase (cp .env.example .env first)
npm run dev:emulated     # against local Firebase emulators — no credentials, no cost, data vanishes on stop; needs Java 11+
npm run emulators        # emulators only

npm test                 # smoke.mjs — 13 offline checks, no emulator
npm run test:integration # integration.mjs — 42 checks against Firebase emulators
npm run lint              # eslint src

node tests/aiGraph.test.mjs        # AI graph service checks (no npm script yet, run directly)
node scripts/create-indexes.mjs    # create Firestore composite indexes
node scripts/poll-indexes.mjs      # poll index build status
```

Point the desktop app at a local backend via `config/config.yaml` at repo root:
```yaml
api:
  base_url: http://127.0.0.1:4000/api
```
(No server field in the sign-in UI on purpose — override paths are `config.yaml` or the
CLI's `--server` flag only.)

## Architecture

### Python (`bioaudit/`)

```
cli.py              every terminal command (cmd_login, cmd_scan_apk, cmd_assess, ...)
core.py             orchestration: builds and ranks a TestRun. No UI, no network — this is
                     what lets the CLI and GUI share logic.
models.py           Finding / Severity / TestRun — shared vocabulary
config.py           defaults + config.yaml loading
session.py          saved-session file, shared by CLI, GUI, dashboard
adb.py              adb CLI wrapper, no root
api/client.py       HTTP client for the backend, standard library only

static_analysis/    APK + manifest inspection (androguard)
runtime/            ipc_oracle (exported-component authorization), response_oracle
                     (auth-state/enumeration side channel — the Mode-B side channel that
                     matters, since timing is impractical over ADB), scenarios, observers
                     (logcat leakage, FLAG_SECURE/recents, allowBackup)
analysis/           error_oracle, lockout, statistics (robust-z outlier detection, no ML)
engine/             severity.py (ranking), recommendations.py (fallback fixes)
report/generator.py HTML/PDF export

gui/
  app.py            MainWindow — defined INSIDE run(), not module level, so importing
                     bioaudit.gui.app does not pull in PySide6 (CLI stays fast, works with
                     no Qt installed). Cannot `from bioaudit.gui.app import MainWindow`;
                     tests reach it through run(). Sections: Account, Server sync
                     (_upload/_retry_upload), Scan tab, Assess tab, History tab, shared job
                     machinery (_start_job).
  theme.py          colours + stylesheet
  signin.py         welcome gate + switch-account dialogs
  team.py           Team tab (admin tools)
  account_dialogs.py profile / password / delete-account / join-org dialogs

dashboard/app.py    Streamlit view of account history
```

Two rules that matter across this tree:

- **`core.py` never touches UI or network.** If you want to `print()` or call the API from
  in there, that logic belongs in the caller instead.
- **`_refresh_account_ui` in `gui/app.py` is the single place UI state is decided** — menu
  items, Compare availability, Team tab contents, history reload, anything dependent on who
  is signed in. Call it after anything that changes the account rather than scattering
  `setEnabled()` calls across individual event handlers.
- **Long-running work (scanning) goes through `_start_job`**, which runs the job on a worker
  thread — never touch a Qt widget from inside a job closure.

### Backend (`backend/src/`)

```
server.js            HTTP listener entry point
app.js                Express setup: helmet, cors, rate limit, routes, error handler
config/
  env.js              reads + validates all configuration, fails fast at startup
  firebase.js         Admin SDK init + credential resolution
constants/index.js    collection names, tiers, roles, statuses, severities
middleware/
  auth.js              requireAuth, loadProfile, requirePremium, requireAdmin, requireOwnOrganisation
  validate.js          zod request validation
  errorHandler.js      one response shape for every failure
routes/                HTTP layer: paths, validation, permissions
services/               business logic + all Firestore access
utils/
  ApiError.js           typed errors with status codes
  asyncHandler.js       forwards async errors to the error handler
  redact.js             strips secrets before anything reaches the AI

firestore.rules         second line of defence — Admin SDK bypasses these, so every real
                         access check must live in middleware/auth.js and the services
firestore.indexes.json  composite index definitions
```

**The one architectural rule: routes handle HTTP, services handle data, nothing else
touches Firestore.** A route validates input, checks permissions, calls a service, shapes
the response. A service does the work and owns every `db.collection(...)` call — this is
what keeps retention limits, audit logging, and access rules enforceable in one place.

Auth flow: desktop/CLI sign in once, then send the Firebase ID token as `Authorization:
Bearer <token>` on every request. `requireAuth` verifies it with `checkRevoked=true` (so a
forced sign-out takes effect immediately, not just at token expiry) and attaches
`req.user` from token custom claims (tier/role/organisationId) — no DB read on the common
path. `loadProfile` loads the Firestore doc when claims might be stale and overrides with
stored values.

Credential resolution order in `config/env.js` / `config/firebase.js`: Firebase emulators →
`GOOGLE_APPLICATION_CREDENTIALS` file → inline `FIREBASE_PROJECT_ID`/`CLIENT_EMAIL`/
`PRIVATE_KEY` env vars → Application Default Credentials (Cloud Run/Cloud Functions/GCE
metadata server, detected via `K_SERVICE`/`GOOGLE_CLOUD_PROJECT`/`GAE_SERVICE`). Startup
throws immediately if none of these are present, deliberately, so a missing credential
fails at boot instead of on the first request.

## Docs map

- [docs/USER-GUIDE.md](docs/USER-GUIDE.md) — using the app: sign-in, scanning, results, teams
- [docs/FRONTEND-GUIDE.md](docs/FRONTEND-GUIDE.md) — changing the Python side
- [docs/BACKEND-GUIDE.md](docs/BACKEND-GUIDE.md) — changing the Node/Express API
- [backend/README.md](backend/README.md) — API reference: every endpoint, data model, auth flow
- [backend/docs/TDM-technical-design-manual.md](backend/docs/TDM-technical-design-manual.md) — technical design manual
- [backend/docs/TDM-sequence-diagrams-plantuml.md](backend/docs/TDM-sequence-diagrams-plantuml.md) — sequence diagrams (PlantUML)
