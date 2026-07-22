# BioAuthGuard

**A security testing tool for Android biometric authentication.** BioAuthGuard is a
pure-Python tool that inspects an Android app (installed on a real device, or an
APK on disk) and reports whether its biometric authentication is *secure* — not
just whether it *works*. It combines static APK analysis with runtime testing over
ADB, then uses an AI layer to turn each confirmed finding into a plain-language
explanation, a severity rank, and a concrete fix.

Use it three ways: a **command-line tool**, a **native desktop app** (PySide6), or
a **standalone Windows `.exe`** — all driving the same detection engine.

> **Scope:** Mode B (black-box) only. Point it at an app you **own or are
> authorized to test**. No root required, no app rebuild, no source needed. See
> `docs/design-report.md` for the full design rationale.

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
| AI explanation + mitigation (grounded, redacted) | `ai/` | — |
| Severity ranking + recommendation engine | `engine/` | — |
| Desktop GUI (scan / assess / history) | `gui/` | — |
| Dashboard + test history | `dashboard/`, `storage/` | — |
| HTML/PDF report export | `report/` | — |

**Detection is deterministic.** The AI layer never decides whether a vulnerability
exists — it only explains and remediates findings the rule-based engine already
confirmed.

---

## Requirements

- Python 3.10+
- `adb` on your PATH ([platform-tools](https://developer.android.com/tools/releases/platform-tools)) — only for the runtime `assess` command
- A **real physical device** (a Google Pixel on Android 12+ is the reference) with USB debugging on — only for `assess`
- A `GEMINI_API_KEY` (or `GOOGLE_API_KEY`) for the AI layer — optional; findings still work without it

```bash
pip install -r requirements.txt
```

The deterministic core degrades gracefully: heavy dependencies (androguard,
google-genai, PySide6, weasyprint, …) import lazily, so the rule-based engine runs
even with none of them installed. `scan-apk` needs androguard; the desktop app
needs `PySide6`.

---

## Usage

```bash
# Static analysis of an APK (no device needed)
python -m bioauthguard scan-apk path/to/app.apk

# Full assessment against an installed app on a connected device
python -m bioauthguard assess --package com.example.app --i-am-authorized

# Launch the desktop app (scan / assess / browse history in one window)
python -m bioauthguard gui

# Launch the Streamlit dashboard
python -m bioauthguard dashboard
```

The `--i-am-authorized` flag is a required authorization gate for any runtime
testing — the tool refuses to probe an app without it. The GUI enforces the same
gate with a mandatory authorization checkbox before it will assess a device.

### Try it with a sample APK

No app handy? Generate a deliberately insecure sample APK (no Android SDK needed)
and scan it — a quick way to see every static detector fire end to end:

```bash
python tests/fixtures/make_sample_apk.py         # writes sample-vuln-app.apk
python -m bioauthguard scan-apk sample-vuln-app.apk
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
python -m bioauthguard assess --package com.bioauthguard.vulndemo --apk sample-app/dist/vulndemo.apk --i-am-authorized
```

Against VulnDemo, `assess` fires several findings including the **auth-state /
response oracle**: VulnDemo ships an exported, unguarded `ContentProvider` that
answers a valid identifier differently from an invalid one, and BioAuthGuard
detects that distinguishable response over adb — see the next section.

### Auth-state / response oracle (the Mode-B side channel)

A timing side channel is impractical black-box: a Python host measuring over ADB
buries a microsecond signal in millisecond USB/OS noise, and Mode B has no
on-device stopwatch (see `docs/DESIGN-DECISIONS.md`). The *practical* Mode-B side
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

### Build a standalone `.exe`

Package the GUI + scanner + reporting into a single Windows executable with
PyInstaller. Double-clicking it opens the GUI; from a terminal it behaves as the
CLI. See [docs/BUILD-EXE.md](docs/BUILD-EXE.md) for prerequisites and caveats.

```bash
pip install pyinstaller
pyinstaller BioAuthGuard.spec        # -> dist/BioAuthGuard.exe
```

---

## Project layout

```
bioauthguard/
  cli.py            entry point / command dispatch
  core.py           shared assessment orchestration (used by the CLI and GUI)
  config.py         config loading
  models.py         Finding / Severity / TestRun data models
  adb.py            ADB wrapper (no root)
  static_analysis/  APK + manifest inspection (androguard)
  runtime/          IPC oracle, response oracle (side channel), scenarios, observers
  analysis/         error-oracle, lockout, statistics (robust-z outliers)
  ai/               grounded LLM explanation + secret redaction
  engine/           severity model + recommendation orchestration
  report/           HTML/PDF export
  storage/          SQLite test history
  gui/              PySide6 desktop app
  dashboard/        Streamlit UI
launcher.py         frozen-exe entry point (GUI by default, CLI with args)
BioAuthGuard.spec   PyInstaller build spec
config/             example config + AI knowledge base
docs/               full design report + BUILD-EXE.md
sample-app/         VulnDemo — deliberately-insecure demo app + Gradle-free builder
tests/
  fixtures/         sample-APK generator (make_sample_apk.py)
```

---

## Ethics

BioAuthGuard performs no exploitation beyond what is needed to *demonstrate* a
finding, and every runtime flow is gated behind an explicit authorization
confirmation. Only test applications you own or are explicitly authorized to test.
