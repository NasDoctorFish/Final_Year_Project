# BioAudit

**A security testing tool for Android biometric authentication.** BioAudit is a
pure-Python tool that inspects an Android app (installed on a real device, or an
APK on disk) and reports whether its biometric authentication is *secure* — not
just whether it *works*. It combines static APK analysis with runtime testing over
ADB, then uses an AI layer to turn each confirmed finding into a plain-language
explanation, a severity rank, and a concrete fix.

Use it three ways: a **command-line tool**, a **native desktop app** (PySide6), or
a **standalone Windows `.exe`** — all driving the same detection engine.

> **Scope:** Mode B (black-box) only. Point it at an app you **own or are
> authorized to test**. No root required, no app rebuild, no source needed.
>
> **An account is required.** BioAudit keeps no local copy of a scan — every result is
> uploaded to your account on the backend in `backend/`, which is what lets your history
> follow you between machines and gives a team's admin oversight. See
> [Accounts and shared history](#accounts-and-shared-history) below.

### Guides

| Guide | For |
|---|---|
| [docs/USER-GUIDE.md](docs/USER-GUIDE.md) | Using the app: signing in, scanning, reading results, teams |
| [docs/FRONTEND-GUIDE.md](docs/FRONTEND-GUIDE.md) | Changing the Python side (GUI, CLI, detectors, building the exe) |
| [docs/BACKEND-GUIDE.md](docs/BACKEND-GUIDE.md) | Changing the Node/Express API (endpoints, Firestore, deployment) |
| [backend/README.md](backend/README.md) | API reference: every endpoint, the data model, the auth flow |

---

## What it does

| Capability | Module | OWASP |
|---|---|---|
| APK static analysis (insecure biometric patterns) | `static_analysis/` | M3, M10, M1 |
| **IPC / exported-component authorization oracle** (headline) | `runtime/ipc_oracle.py` | M3 |
| **Auth-state / response oracle** (Mode-B side channel) | `runtime/response_oracle.py` | M3, M1 |
| Scenario testing (success / failure / lockout / fallback) | `runtime/scenarios.py` | M3 |
| Logcat leakage observer | `runtime/observers.py` | M9, M6 |
| Screen-capture / FLAG_SECURE / recents check | `runtime/observers.py` | M8 |
| `allowBackup` data-extraction check | `runtime/observers.py` | M9 |
| Behavioural error-oracle | `analysis/error_oracle.py` | M3 |
| Lockout / attempt-counter oracle | `analysis/lockout.py` | M3 |
| Statistical baseline + outlier detection (no ML) | `analysis/statistics.py` | — |
| AI explanation + mitigation (grounded, redacted) — server-side only | `backend/src/services/gemini.service.js` | — |
| Severity ranking + recommendation engine | `engine/` | — |
| Desktop GUI (scan / assess / history / accounts) | `gui/` | — |
| Backend: accounts, history, team oversight (required — see below) | `backend/`, `api/` | — |
| Dashboard: browse an account's history | `dashboard/` | — |
| HTML/PDF report export | `report/` | — |

**Detection is deterministic.** The AI layer never decides whether a vulnerability
exists — it only explains and remediates findings the rule-based engine already
confirmed.

---

## Requirements

- Python 3.10+
- `adb` on your PATH ([platform-tools](https://developer.android.com/tools/releases/platform-tools)) — only for the runtime `assess` command
- A **real physical device** (a Google Pixel on Android 12+ is the reference) with USB debugging on — only for `assess`

```bash
pip install -r requirements.txt
```

The deterministic core degrades gracefully: heavy dependencies (androguard, PySide6,
weasyprint, …) import lazily, so the rule-based engine runs even with none of them
installed. `scan-apk` needs androguard; the desktop app needs `PySide6`. Nothing here
needs a Gemini key — AI explanation runs entirely on the backend (see
[Accounts and shared history](#accounts-and-shared-history)), not on your machine.

---

## Usage

Sign in once before scanning — see [Accounts and shared history](#accounts-and-shared-history)
for how to get the backend running and create an account. The CLI remembers the session
on disk, same as the GUI's "keep me signed in":

```bash
python -m bioaudit login          # or: register --email ... --organisation "Team Name"

# Static analysis of an APK (no device needed)
python -m bioaudit scan-apk path/to/app.apk

# Full assessment against an installed app on a connected device
python -m bioaudit assess --package com.example.app --i-am-authorized

# Ask the server for a plain-language explanation and fix (prints the scan id above)
python -m bioaudit explain <scan-id>

# Launch the desktop app (scan / assess / browse history in one window)
python -m bioaudit gui

# Launch the Streamlit dashboard (reads whichever account you last logged in as)
python -m bioaudit dashboard
```

The `--i-am-authorized` flag is a required authorization gate for any runtime
testing — the tool refuses to probe an app without it. The GUI enforces the same
gate with a mandatory authorization checkbox before it will assess a device.

### Try it with a sample APK

No app handy? Generate a deliberately insecure sample APK (no Android SDK needed)
and scan it — a quick way to see every static detector fire end to end:

```bash
python tests/fixtures/make_sample_apk.py         # writes sample-vuln-app.apk
python -m bioaudit scan-apk sample-vuln-app.apk
```

Expect four findings: a debuggable app (High), `allowBackup` enabled (Medium), a
boolean-only biometric check with no crypto binding (Medium), and an unguarded
exported activity (Low).

### Try it against a real device (VulnDemo)

`scan-apk` above needs no device, but `assess` needs a real, *installed* app.
`sample-app/` builds **VulnDemo**, a small deliberately-insecure app (Gradle-free —
uses the Android SDK's own `aapt2`/`d8`/`apksigner` directly) covering every runtime
detector, including the auth-state / response oracle side channel:

```bash
python sample-app/build.py --install    # builds + installs VulnDemo on a connected device
python -m bioaudit assess --package com.bioaudit.vulndemo --apk sample-app/dist/vulndemo.apk --i-am-authorized
```

Against VulnDemo, `assess` fires several findings including the **auth-state /
response oracle**: VulnDemo ships an exported, unguarded `ContentProvider` that
answers a valid identifier differently from an invalid one, and BioAudit
detects that distinguishable response over adb — see the next section.

### Auth-state / response oracle (the Mode-B side channel)

A timing side channel is impractical black-box: a Python host measuring over ADB
buries a microsecond signal in millisecond USB/OS noise, and Mode B has no
on-device stopwatch. The *practical* Mode-B side
channel is an **oracle attack** — and an oracle attack **is** a side channel: the
app's observable *response* leaks secret auth state.

`runtime/response_oracle.py` reuses the exported-component surface the IPC oracle
enumerates and asks the sharper question: does an exported, unguarded component
answer a **valid** identifier differently from an **invalid** one? A
`ContentProvider` that returns data for `content://…/admin` but nothing for
`content://…/zzzzzzzz9999` is an enumeration / auth-state oracle an unauthenticated
caller can query to brute-force a token — the classic error/enumeration oracle
class, applied to Android's IPC surface. Unlike timing, this is **deterministic**
(a differing response is a hard fact, fires every run), needs **no rebuild, no
root, no fingerprint**, and never emits a "no leak" verdict — it stays silent when
responses are indistinguishable.

### Accounts and shared history

BioAudit keeps no local copy of a scan. Every finished run is uploaded to an account on
the REST backend in `backend/` (Express, Firestore, Firebase Authentication) — that is
what lets your history follow you between machines and gives a team's admin oversight, and
it is why an account is required rather than optional.

```bash
cd backend
npm install
cp .env.example .env      # fill in your Firebase keys
npm run dev
```

Then sign in:

- **Desktop app**: a welcome screen appears on launch — create an account, join one from a
  team invite, or sign in. There is no guest mode; closing the screen without signing in
  closes the app, since there would be nowhere to put a result.
- **CLI**: `python -m bioaudit login` (or `register`). `scan-apk` and `assess` refuse to
  run without a session. `python -m bioaudit whoami` shows who is currently signed in;
  `logout` ends the session.
- **Dashboard**: reads whichever account the CLI last signed in as; run `bioaudit login`
  first if it says nobody is signed in.

Two things to know. **A failed upload does not throw the scan away**: the findings still
render (the GUI keeps a "Retry saving" button for the run in memory; the CLI prints them to
the terminal and exits non-zero, so rerun the command once you are back online) and the
report is still written to disk — but until an upload succeeds the run exists nowhere else,
since there is no local fallback. And **"keep me signed in" is off by default in the GUI**
(the CLI's `login`/`register` persist by default, since that is the point of running them),
because signing in returns a long-lived refresh token and writing that to disk is a
trade-off worth making visible rather than quietly convenient.

See [backend/README.md](backend/README.md) for the API reference, the data model, and how
to run its two test suites against the Firebase emulators.

### Build a standalone `.exe`

Package the GUI + scanner + reporting into a single Windows executable with
PyInstaller. Double-clicking it opens the GUI; from a terminal it behaves as the
CLI. See [docs/FRONTEND-GUIDE.md](docs/FRONTEND-GUIDE.md) for prerequisites and caveats.

```bash
pip install pyinstaller
pyinstaller BioAudit.spec        # -> dist/BioAudit.exe
```

---

## Project layout

```
bioaudit/
  cli.py            entry point / command dispatch
  core.py           shared assessment orchestration (used by the CLI and GUI)
  config.py         config loading
  models.py         Finding / Severity / TestRun data models
  adb.py            ADB wrapper (no root)
  api/              client for the backend (standard library only)
  session.py        saved-session file, shared by the CLI, GUI, and dashboard
  static_analysis/  APK + manifest inspection (androguard)
  runtime/          IPC oracle, response oracle (side channel), scenarios, observers
  analysis/         error-oracle, lockout, statistics (robust-z outliers)
  engine/           severity model + recommendation orchestration
  report/           HTML/PDF export
  gui/              PySide6 desktop app (app.py, signin.py — sign-in and welcome gate)
  dashboard/        Streamlit UI
launcher.py         frozen-exe entry point (GUI by default, CLI with args)
BioAudit.spec   PyInstaller build spec
backend/            Express + Firestore API (accounts, history, teams, AI explanation) — required
config/             example config
docs/               user guide + front-end and back-end editing guides
sample-app/         VulnDemo — deliberately-insecure demo app + Gradle-free builder
tests/
  fixtures/         sample-APK generator (make_sample_apk.py)
```

---

## Ethics

BioAudit performs no exploitation beyond what is needed to *demonstrate* a
finding, and every runtime flow is gated behind an explicit authorization
confirmation. Only test applications you own or are explicitly authorized to test.
