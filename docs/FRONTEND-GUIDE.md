# BioAudit — Editing the Front End

The front end is Python: a PySide6 (Qt 6) desktop app, a CLI, and a small Streamlit
dashboard, all driving the same scanning engine. This guide covers where things live, the
patterns you have to follow, and how to test a change without shipping a broken exe.

For the server, see [BACKEND-GUIDE.md](BACKEND-GUIDE.md). For using the app, see
[USER-GUIDE.md](USER-GUIDE.md).

---

## 1. Getting set up

```bash
pip install -r requirements.txt
python -m bioaudit gui          # the desktop app
python -m bioaudit --help       # the CLI
```

You do not need to run the backend locally. The app defaults to the hosted one, so you can
sign in and work against real data straight away. If you *do* want a local server (to
change API behaviour at the same time), start it per BACKEND-GUIDE.md and point the app at
it by creating `config/config.yaml`:

```yaml
api:
  base_url: http://127.0.0.1:4000/api
```

There is no server field in the sign-in window on purpose — an ordinary user never needs
it. `config.yaml` and the CLI's `--server` flag are the override paths.

---

## 2. The map

```
bioaudit/
  cli.py              every terminal command
  core.py             orchestration: build a TestRun, rank it. No UI, no network.
  models.py           Finding / Severity / TestRun — the shared vocabulary
  config.py           defaults + config.yaml loading
  session.py          the saved-session file (shared by GUI, CLI, dashboard)
  adb.py              wrapper around the adb CLI

  gui/
    app.py            the window. 1600 lines, the file you will spend most time in.
    theme.py          all colours and the stylesheet
    signin.py         welcome gate + switch-account dialogs
    team.py           the Team tab (admin tools)
    account_dialogs.py  profile / password / delete-account / join-org dialogs

  api/client.py       HTTP client for the backend. Standard library only.

  static_analysis/    reading APKs (androguard): manifest.py, apk_analyzer.py
  runtime/            probing a live device: ipc_oracle, response_oracle, observers
  analysis/           error_oracle, lockout, statistics
  engine/             severity.py, recommendations.py — ranking and fallback fixes
  report/generator.py HTML + PDF output
  dashboard/app.py    Streamlit view of account history
```

### Two rules worth knowing before you touch anything

**`core.py` never touches the UI or the network.** It builds findings and ranks them. That
is what lets the CLI and the GUI share it. If you find yourself wanting to `print()` or
call the API from `core.py`, the logic belongs in the caller instead.

**There is no local storage.** A finished run is uploaded to the user's account, and that
is the only copy. Nothing is written to a local database. If a scan needs to be
"remembered", it needs to go through `api/client.py`.

---

## 3. The window: `gui/app.py`

`MainWindow` is defined **inside** the `run()` function, not at module level. That is
deliberate — it means `import bioaudit.gui.app` does not pull in PySide6, so the CLI stays
fast and works on a machine with no Qt installed. The side effect is that you cannot
`from bioaudit.gui.app import MainWindow`; tests reach it through `run()` instead
(see §7).

The file is organised in labelled sections, in this order:

| Section | What is in it |
|---|---|
| Account | menu, sign-in/out, the welcome gate, `_refresh_account_ui` |
| Server sync | `_upload`, `_retry_upload` |
| Scan APK tab | `_build_scan_tab`, `_run_scan` |
| Assess device tab | `_build_assess_tab`, `_run_assess` |
| History tab | `_build_history_tab`, `_reload_history`, `_compare_runs` |
| Shared job machinery | `_start_job` and the signal handlers |

Module-level helpers at the bottom render HTML: `_comparison_html`, `_sync_banner_html`,
`_payload_to_html`, `_escape`.

### `_refresh_account_ui` is the single place UI state is decided

Anything that depends on who is signed in — which menu items are enabled, whether Compare
is available, whether the Team tab shows tables or a placeholder, reloading history — is
set here, and only here. Call it after anything that changes the account.

Do not scatter `setEnabled()` calls around the file in response to individual events. One
function that reads the current state and sets everything is far easier to keep correct
than a dozen handlers that each remember to update three widgets.

---

## 4. Long-running work: the worker pattern

Scanning takes seconds to minutes. Doing it on the UI thread freezes the window, so every
scan goes through `_start_job`.

```python
def _run_something(self) -> None:
    sync_result: dict = {}

    def job(report) -> TestRun:
        # This runs on a WORKER THREAD. Do not touch a widget in here.
        stop = self._cancel_event
        run_ = core.build_scan_apk(apk, self.cfg, on_progress=report,
                                   should_cancel=(stop.is_set if stop else None))
        core.process_findings(run_, on_progress=report)
        report("Saving to your account")
        self._upload(run_, authorised=True, apk_file_name=name, into=sync_result)
        return run_

    self._start_job(job, self.scan_btn, self.scan_progress, self.scan_results,
                    self.scan_open_report, "Starting",
                    sync_result=sync_result, summary_label=self.scan_summary,
                    stage_label=self.scan_stage, cancel_btn=self.scan_cancel_btn,
                    retry_btn=self.scan_retry_btn, apk_file_name=name)
```

### The rules, and why they exist

**Never touch a widget from inside `job`.** Qt widgets are not thread-safe; doing this
segfaults the frozen exe, often not immediately, which makes it painful to diagnose. The
worker communicates by Qt signals (`progress`, `finished`, `failed`, `cancelled`), which
Qt delivers on the main thread automatically because the receiving slots belong to
`MainWindow`.

**Pass results back through a dict, not a return value.** `job` returns the `TestRun`, but
the upload outcome goes into the `sync_result` dict the caller created. The `finished`
signal is the handover point, so no extra locking is needed — by the time
`_on_job_finished` reads that dict, the worker is done writing to it.

**Report progress by calling `report(...)`.** `job` receives an emitter as its only
argument. It knows nothing about Qt. Same for `core.py`, which takes an `on_progress`
callable — that is how the same code serves both the GUI's stage label and the CLI's
silence.

**Cancellation is cooperative.** `core.py` checks `should_cancel()` at step boundaries and
raises `ScanCancelled`. It cannot interrupt a step that is mid-`adb` call, because there is
no safe way to kill a blocking subprocess read from outside and leaving a device
half-probed would be worse than waiting. `_on_job_cancelled` handles it as its own outcome
— not an error, since the user asked for it.

**Report rendering stays on the main thread.** `_on_job_finished` calls
`core.write_report`, not `job`. weasyprint/GTK misbehaves when driven from a secondary
thread in a frozen build.

---

## 5. Styling: `gui/theme.py`

Never hard-code a colour in `app.py`. Read it from the palette:

```python
self.palette_colours["muted"]     # available on MainWindow
theme.SEVERITY_COLOURS["high"]
```

`theme.py` has two palettes (`LIGHT`, `DARK`) and builds the stylesheet from whichever
matches the system theme, because Qt on Windows follows it. A hard-coded light colour
looks fine on your machine and unreadable on a colleague's dark-mode one.

Severity colours are deliberately identical in both themes: they carry meaning, and a
reader should not have to relearn red.

Useful helpers:

| Function | For |
|---|---|
| `apply_theme(app)` | called once at startup, returns the palette |
| `severity_chips_html(counts, palette)` | the coloured count badges |
| `empty_state_html(title, lines, palette)` | "nothing here yet" panels |

For layout, use the local helpers in `run()`: `_section("Title")` for a titled card,
`_hint("...")` for small muted text, `_field_label("...")` for form labels. Grouping
controls into titled cards is what makes the difference between a readable form and a flat
stack of widgets.

---

## 6. Common tasks

### Add a widget to an existing tab

Find the relevant `_build_*_tab`, add the widget, and if its enabled state depends on the
account, handle that in `_refresh_account_ui` — not inline.

### Add a whole tab

1. Write `_build_mytab(self) -> QWidget`, following an existing one for structure.
2. Register it in `__init__`: `tabs.addTab(self._build_mytab(), "My Tab")`.
3. If it is big, put it in its own module like `team.py` does, and add that module to
   `hiddenimports` in `BioAudit.spec` (see §8).

### Call a new backend endpoint

Add a method to `api/client.py` beside the related ones. It is standard-library only
(`urllib`) on purpose, so the exe does not need `requests`. Token refresh and one retry on
a 401 are already handled centrally in `_request` — do not reimplement them.

```python
def my_thing(self, thing_id: str) -> dict:
    return self._request("GET", f"/things/{thing_id}")["thing"]
```

### Add a CLI command

In `cli.py`: write `cmd_mything(args, cfg)`, then register it in `build_parser()`. Use
`_require_session(cfg)` if it needs the user signed in. Return an exit code — `0` success,
`1` failure, `2` bad usage.

### Add a detector

Put it in `static_analysis/` (reading a file) or `runtime/` (probing a device), following
the shape of a neighbour — `probe(adb, package, manifest) -> list[Finding]` for runtime
ones. Yield `Finding` objects; the engine ranks them. Then:

1. Call it from `core.build_scan_apk` or `core.build_assess`, with a `report(...)` line and
   a `guard()` before it so it is cancellable.
2. Add a fallback fix to `_FALLBACK_MITIGATIONS` in `engine/recommendations.py`, keyed on
   your finding's `category`. This is what a user sees when the AI layer is unavailable, so
   every category needs one.
3. Use `confidence="likely"` for anything inferred from compiled code — the engine dials
   those back one severity level automatically. `"confirmed"` is for things the tool
   watched happen.

**Never emit a "no problem found" finding.** Silence means "not detected", not "safe". A
clean bill of health the tool cannot actually vouch for is worse than saying nothing.

---

## 7. Testing a change

```bash
pytest tests/ -q --ignore=tests/test_api_client.py     # offline, fast
```

`test_api_client.py` is written for the **local Firebase emulator**, not the live server.
Running it against production burns through the sign-in rate limit (20 attempts per 15
minutes) and will lock you out for a while. Start the emulator first (BACKEND-GUIDE.md §7)
or leave that file alone.

### Driving the real window headlessly

Qt runs without a display if you set the offscreen platform, which is how the GUI gets
tested without a human clicking. Since `MainWindow` lives inside `run()`, you create the
`QApplication` first, schedule your checks on a timer, then let `run()` reuse your
instance:

```python
import os, sys
os.environ["QT_QPA_PLATFORM"] = "offscreen"
os.environ["BIOAUDIT_SKIP_WELCOME"] = "1"   # or the modal gate blocks forever

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication
from bioaudit.config import Config
from bioaudit.gui import app as gui_app

qapp = QApplication.instance() or QApplication(sys.argv)

def inspect():
    try:
        win = next(w for w in qapp.topLevelWidgets()
                   if w.__class__.__name__ == "MainWindow")
        assert win.scan_btn.objectName() == "primary"
        # ... poke widgets, call handlers, assert
    except Exception:
        import traceback; traceback.print_exc()   # see the gotcha below
    qapp.quit()

QTimer.singleShot(0, inspect)
gui_app.run(Config())
```

Three things that will cost you an afternoon otherwise:

- **`BIOAUDIT_SKIP_WELCOME=1`** — without it, the mandatory sign-in dialog opens a modal
  loop and the process hangs until it times out. The same flag also stops sign-out from
  re-opening the gate.
- **Always wrap the body in try/except.** PySide6 *swallows* exceptions raised inside a
  slot rather than propagating them, so an `AttributeError` in your check silently skips
  the `qapp.quit()` and the process hangs forever with no error. Catch and print it
  yourself.
- **`isVisible()` is `False` for anything on a non-active tab.** Use `isHidden()`, which is
  only true when something was explicitly hidden.

To drive a nested modal dialog (like the welcome gate), you cannot pump events manually —
your loop would sit *inside* the modal loop and never reach the form. Use a small state
machine on `QTimer.singleShot` instead, advancing one step per tick.

---

## 8. Building the exe

```bash
pip install pyinstaller
pyinstaller BioAudit.spec        # -> dist/BioAudit.exe (~104 MB)
```

PDF export needs the native GTK/Pango/Cairo libraries on the **build** machine. The spec
looks for them at `C:\msys64\mingw64\bin`, overridable with
`WEASYPRINT_DLL_DIRECTORIES`. Without them the build still succeeds, but the exe falls
back to HTML reports. `adb` is never bundled — it is an external CLI, so the user needs it
on PATH.

### If your new module works from source but not in the exe

Add it to `hiddenimports` in `BioAudit.spec`. PyInstaller analyses imports **statically**
and does not follow a `from .signin import ...` sitting inside a method body — and this
codebase imports lazily on purpose, to keep the CLI from loading Qt. Anything reached only
from inside a function is invisible to the analyser and gets silently left out, then fails
at runtime on someone else's machine.

### Keeping it small

`excludes` in the spec drops `pandas`, `pyarrow`, `scipy`, and unused Qt modules
(`QtQml`, `QtQuick`, `QtPdf`) — together about 68 MB. None are imported by this codebase;
they arrived as transitive dependencies of `streamlit`, which the `dashboard` command runs
as a **separate process** rather than importing, so it never needed bundling.

If you add a real dependency on any of those, remove it from `excludes` or the exe will
break in a way source runs will not. Check what you actually shipped:

```bash
python - <<'PY'
from PyInstaller.archive.readers import CArchiveReader
r = CArchiveReader(r"dist\BioAudit.exe")
top = sorted(((l, n) for n, (p, l, u, c, t) in r.toc.items()), reverse=True)[:25]
for length, name in top:
    print(f"{length/1e6:6.1f} MB  {name}")
PY
```

A frozen windowed build has no console, so `sys.stdout` is `None` and any library that
writes to stderr at import time crashes before your error handling runs. `launcher.py`
attaches null streams first to prevent that; `_install_crash_logging()` in `app.py` then
catches native crashes and uncaught exceptions to `~/bioaudit-crash.log`. Check that file
first when the exe misbehaves but source runs fine.
