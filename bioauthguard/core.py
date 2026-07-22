"""Reusable assessment orchestration, shared by the CLI and the GUI.

The CLI (`cli.py`) and the desktop GUI (`gui/app.py`) are both thin shells over
these functions. Detectors emit Findings, the engine ranks + the AI explains, and
the report/history persist — exactly as documented in models.py. Nothing here
prints or touches a UI, so either front end can drive it.

Each `build_*` function returns an unfinished `TestRun` (findings collected but not
yet ranked/explained/persisted). Call `finalize()` to run the engine + AI layer,
save to history, and write the report.
"""

from __future__ import annotations

import time

from .adb import Adb, AdbError
from .ai.explainer import Explainer
from .config import Config
from .engine import recommendations
from .models import TestRun
from .report import generator
from .storage.history import History


def build_explainer(cfg: Config) -> Explainer | None:
    """Construct the AI explainer, or None when the AI layer is disabled."""
    if not cfg.ai.get("enabled", True):
        return None
    return Explainer(
        model=cfg.ai.get("model"),
        effort=cfg.ai.get("effort", "medium"),
        redact_before_send=cfg.ai.get("redact_before_send", True),
        knowledge_base_path=cfg.ai.get("knowledge_base"),
    )


def build_scan_apk(apk: str, cfg: Config) -> TestRun:
    """Static-only assessment of an APK on disk (no device)."""
    from .static_analysis import apk_analyzer, manifest

    info = manifest.parse_apk(apk)
    run = TestRun(package=info.package)
    for f in manifest.manifest_findings(info):
        run.add(f)
    for f in apk_analyzer.analyze_apk(apk):
        run.add(f)
    return run


def build_assess(package: str, apk: str | None, cfg: Config, adb: Adb | None = None) -> TestRun:
    """Full black-box assessment on a connected device.

    Raises AdbError if no device is available or the package is not installed.
    """
    from .runtime import ipc_oracle, observers, response_oracle
    from .static_analysis.manifest import ManifestInfo

    adb = adb or Adb(cfg.device["adb_path"], cfg.device["serial"])
    serial = adb.require_device()
    if not adb.is_installed(package):
        raise AdbError(f"Package {package} is not installed on {serial}.")

    run = TestRun(package=package, device_serial=serial)

    # With the APK on disk we get higher-fidelity exported-component data;
    # without it the IPC oracle can only work from the installed manifest.
    if apk:
        from .static_analysis import apk_analyzer, manifest as mparse
        info = mparse.parse_apk(apk)
        for f in mparse.manifest_findings(info):
            run.add(f)
        for f in apk_analyzer.analyze_apk(apk):
            run.add(f)
    else:
        info = ManifestInfo(package=package)

    for f in ipc_oracle.probe(adb, package, info):
        run.add(f)
    for f in response_oracle.probe(adb, package, info):
        run.add(f)
    for f in observers.scan_logcat(adb, package):
        run.add(f)
    for f in observers.check_allow_backup(adb, package, info):
        run.add(f)
    return run


def process_findings(run: TestRun, cfg: Config, explain: bool) -> None:
    """Rank + explain findings and persist the run (no report file).

    Split out from report writing so a GUI can run this heavy step on a worker
    thread while keeping report rendering (weasyprint/GTK, which dislikes being
    driven from a secondary thread in a frozen build) on the main thread.
    """
    explainer = build_explainer(cfg) if explain else None
    run.findings = recommendations.process(run.findings, explainer)
    run.finished_at = time.time()
    History(cfg.storage["database"]).save(run)


def write_report(run: TestRun, cfg: Config) -> str:
    """Render the report; returns its path (PDF if weasyprint works, else HTML)."""
    return generator.export(run, cfg.report["output_dir"], to_pdf=True)


def finalize(run: TestRun, cfg: Config, explain: bool) -> str:
    """Process findings then write the report. Returns the report path."""
    process_findings(run, cfg, explain)
    return write_report(run, cfg)
