"""Reusable assessment orchestration, shared by the CLI and the GUI.

The CLI (`cli.py`) and the desktop GUI (`gui/app.py`) are both thin shells over
these functions. Detectors emit Findings and the engine ranks them — exactly as
documented in models.py. Nothing here prints, touches a UI, or talks to the network,
so either front end can drive it.

AI explanation is not done here. It runs entirely on the backend, once a run is
uploaded — see `ApiClient.explain_finding`. There used to be a second, local AI path
here too, reading a `GEMINI_API_KEY` from the calling machine's own environment; it was
removed because that meant a checkbox that only worked on whichever computer happened
to have that variable set.

Persistence is deliberately not here either. BioAudit keeps no local copy of a scan; the
only place a run is stored is the account it is uploaded to, and uploading needs a
signed-in API client, which this module has no concept of. That upload is the caller's
job — see `gui/app.py`'s `_upload` and `cli.py`'s `_finish` — done straight after
`process_findings` so a run is never shown as "done" before it is actually saved
somewhere.

Each `build_*` function returns an unfinished `TestRun` (findings collected but not yet
ranked). Call `process_findings()` to run the engine, then have the caller upload the
result and, if wanted, `write_report()` it to disk.
"""

from __future__ import annotations

import time

from .adb import Adb, AdbError
from .config import Config
from .engine import recommendations
from .models import TestRun
from .report import generator


class ScanCancelled(RuntimeError):
    """Raised when the caller asked to stop between steps.

    Cancellation is cooperative: it is checked at step boundaries, so a step already
    waiting on the device finishes before the run stops. Killing a thread mid-ADB-call
    would risk leaving the device in a half-probed state, and there is no safe way to
    interrupt a blocking subprocess read from outside it.
    """


def _progress(callback):
    """Normalise an optional progress callback into something always callable."""
    return callback or (lambda stage: None)


def _cancel_guard(should_cancel):
    """Return a function that raises ScanCancelled once the caller asks to stop."""
    check = should_cancel or (lambda: False)

    def guard():
        if check():
            raise ScanCancelled("Stopped at your request.")

    return guard


def build_scan_apk(apk: str, cfg: Config, on_progress=None, should_cancel=None) -> TestRun:
    """Static-only assessment of an APK on disk (no device).

    `on_progress` receives a short plain-language description of each step, so a caller
    with a UI can say what is happening instead of showing an unexplained wait.
    `should_cancel` is polled between steps; see ScanCancelled.
    """
    from .static_analysis import apk_analyzer, manifest

    report = _progress(on_progress)
    guard = _cancel_guard(should_cancel)

    report("Reading the app's settings")
    info = manifest.parse_apk(apk)
    run = TestRun(package=info.package, app_version=info.version_name)
    run.tests_performed.append("Reading the app's settings")
    for f in manifest.manifest_findings(info):
        run.add(f)

    guard()
    report("Scanning the app's code")
    run.tests_performed.append("Scanning the app's code")
    for f in apk_analyzer.analyze_apk(apk):
        run.add(f)

    # A stop asked for during the last step is honoured here, before the run is kept.
    guard()
    return run


def build_assess(package: str, apk: str | None, cfg: Config, adb: Adb | None = None,
                 on_progress=None, should_cancel=None) -> TestRun:
    """Full black-box assessment on a connected device.

    Raises AdbError if no device is available or the package is not installed, and
    ScanCancelled if the caller asked to stop.
    """
    from .runtime import ipc_oracle, observers, response_oracle
    from .static_analysis.manifest import ManifestInfo

    report = _progress(on_progress)
    guard = _cancel_guard(should_cancel)

    report("Connecting to the device")
    adb = adb or Adb(cfg.device["adb_path"], cfg.device["serial"])
    serial = adb.require_device()
    if not adb.is_installed(package):
        raise AdbError(f"Package {package} is not installed on {serial}.")

    run = TestRun(
        package=package,
        device_serial=serial,
        device_model=adb.device_model(),
        android_version=adb.android_version(),
        app_version=adb.app_version_name(package),
    )

    def _static_from_apk(apk_path: str) -> ManifestInfo:
        """Manifest + code findings from an APK on disk. Shared by the supplied-APK
        path and the pulled-from-device path, so both get identical fidelity."""
        from .static_analysis import apk_analyzer, manifest as mparse
        guard()
        report("Reading the app's settings")
        run.tests_performed.append("Reading the app's settings")
        parsed = mparse.parse_apk(apk_path)
        for f in mparse.manifest_findings(parsed):
            run.add(f)

        guard()
        report("Scanning the app's code")
        run.tests_performed.append("Scanning the app's code")
        for f in apk_analyzer.analyze_apk(apk_path):
            run.add(f)
        return parsed

    # The IPC and response oracles need the exported-component list, which lives in
    # the manifest. A supplied APK is highest fidelity, but when none is given we
    # pull the installed app's base APK off the device so these checks still run --
    # only falling back to a bare manifest (component-blind) if that pull fails.
    if apk:
        info = _static_from_apk(apk)
    else:
        import shutil
        import tempfile

        guard()
        report("Fetching the installed app from the device")
        tmpdir = tempfile.mkdtemp(prefix="bioaudit-pull-")
        try:
            pulled = adb.pull_base_apk(package, tmpdir)
            if pulled:
                info = _static_from_apk(pulled)
            else:
                report("Could not read the installed app; probing with no manifest")
                info = ManifestInfo(package=package)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    guard()
    report("Trying to open the app's screens without logging in")
    run.tests_performed.append("Trying to open the app's screens without logging in")
    for f in ipc_oracle.probe(adb, package, info):
        run.add(f)

    guard()
    report("Checking whether the app gives away answers to guesses")
    run.tests_performed.append("Checking whether the app gives away answers to guesses")
    for f in response_oracle.probe(adb, package, info):
        run.add(f)

    guard()
    report("Reading the phone's log for leaked secrets")
    run.tests_performed.append("Reading the phone's log for leaked secrets")
    for f in observers.scan_logcat(adb, package):
        run.add(f)

    guard()
    report("Checking the backup setting")
    run.tests_performed.append("Checking the backup setting")
    for f in observers.check_allow_backup(adb, package, info):
        run.add(f)

    guard()
    return run


def process_findings(run: TestRun, on_progress=None) -> None:
    """Rank findings and mark the run finished. Does not persist it, and does not
    explain findings with AI -- that happens later, server-side, once the run has
    somewhere to be explained *about* (see the module docstring).

    Split out from report writing so a GUI can run this heavy step on a worker
    thread while keeping report rendering (weasyprint/GTK, which dislikes being
    driven from a secondary thread in a frozen build) on the main thread.

    Not cancellable: by this point the findings already exist, and stopping here would
    throw away work that has been done rather than saving the caller any time.
    """
    report = _progress(on_progress)
    report("Ranking the findings")
    run.findings = recommendations.process(run.findings)
    run.finished_at = time.time()


def write_report(run: TestRun, cfg: Config) -> str:
    """Render the report; returns its path (PDF if weasyprint works, else HTML).

    This writes a file the user explicitly asked to keep (a deliverable export), which
    is a different thing from the run's history record — that record lives only in the
    account it was uploaded to.
    """
    return generator.export(run, cfg.report["output_dir"], to_pdf=True)
