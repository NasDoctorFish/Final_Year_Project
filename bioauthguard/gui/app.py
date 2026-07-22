"""BioAuthGuard desktop GUI (PySide6).

A thin shell over `bioauthguard.core` — the same orchestration the CLI drives.
Long-running work (APK decompilation, ADB probing, the AI layer) runs on a
QThread so the window never freezes. Findings are shown by reusing the report
renderer (`report.generator.render_html`) inside a QTextBrowser, so the on-screen
view matches the exported report exactly.

Launch with:  python -m bioauthguard gui
"""

from __future__ import annotations

import os
import sys
import traceback
from typing import Callable

from .. import core
from ..adb import Adb
from ..config import Config
from ..models import TestRun
from ..report import generator


def _require_pyside():
    try:
        import PySide6  # noqa: F401
    except ImportError:
        sys.stderr.write(
            "The desktop GUI needs PySide6.\n"
            "Install it with:  pip install PySide6\n"
            "(Or use the CLI: python -m bioauthguard scan-apk <apk>)\n"
        )
        raise SystemExit(1)


# --------------------------------------------------------------------------- #
# Background worker: runs a callable off the UI thread and reports the result.
# --------------------------------------------------------------------------- #

def _make_worker_classes():
    """Defined inside a function so PySide6 is only imported when the GUI runs."""
    from PySide6.QtCore import QObject, QThread, Signal

    class Worker(QObject):
        finished = Signal(object)   # emits the return value of `fn`
        failed = Signal(str)        # emits a formatted traceback / message

        def __init__(self, fn: Callable[[], object]):
            super().__init__()
            self._fn = fn

        def run(self) -> None:
            try:
                result = self._fn()
            except Exception as exc:  # noqa: BLE001 - surfaced to the user
                tb = traceback.format_exc()
                _log_diag(f"Worker job raised:\n{tb}")
                self.failed.emit(f"{type(exc).__name__}: {exc}\n\n{tb}")
                return
            self.finished.emit(result)

    return Worker, QThread


_crash_log_handles: list = []   # keep the file object alive for the process lifetime


def _log_diag(text: str) -> None:
    """Append a line to the crash log (best effort), for post-mortem diagnosis."""
    for fh in _crash_log_handles:
        try:
            fh.write(text + "\n")
        except Exception:
            pass


def _install_crash_logging() -> str | None:
    """Log native crashes (segfaults) and uncaught exceptions to a file.

    A frozen windowed app has no console, so a native crash on a worker thread
    would otherwise just vanish. faulthandler catches those with a traceback.
    Returns the log path, or None if it could not be set up.
    """
    import datetime
    import faulthandler
    import threading
    from pathlib import Path

    try:
        path = Path(os.path.expanduser("~")) / "bioauthguard-crash.log"
        fh = open(path, "a", buffering=1, encoding="utf-8")
        _crash_log_handles.append(fh)
        fh.write(f"\n=== BioAuthGuard GUI started {datetime.datetime.now():%Y-%m-%d %H:%M:%S} ===\n")
        faulthandler.enable(fh)

        def _hook(exc_type, exc, tb):
            import traceback
            fh.write("Uncaught exception:\n")
            traceback.print_exception(exc_type, exc, tb, file=fh)

        sys.excepthook = _hook
        if hasattr(threading, "excepthook"):
            threading.excepthook = lambda a: _hook(a.exc_type, a.exc_value, a.exc_traceback)
        return str(path)
    except Exception:
        return None


def run(cfg: Config | None = None) -> int:
    """Entry point used by `cli.cmd_gui`. Returns a process exit code."""
    _require_pyside()
    _install_crash_logging()

    from PySide6.QtCore import Qt
    from PySide6.QtGui import QDesktopServices
    from PySide6.QtCore import QUrl
    from PySide6.QtWidgets import (
        QApplication, QCheckBox, QComboBox, QCompleter, QFileDialog, QHBoxLayout,
        QLabel, QLineEdit, QMainWindow, QMessageBox, QProgressBar, QPushButton,
        QTabWidget, QTextBrowser, QVBoxLayout, QWidget,
    )

    Worker, QThread = _make_worker_classes()
    cfg = cfg or Config.load()

    # A double-clicked exe can start in a directory it cannot write to (Program
    # Files, a read-only mount, etc.), which would make the SQLite history and the
    # report export raise. Anchor both under the user's home so writes always work.
    from pathlib import Path
    _base = Path(os.path.expanduser("~")) / "BioAuthGuard"
    try:
        _base.mkdir(parents=True, exist_ok=True)
        if not os.path.isabs(cfg.storage["database"]):
            cfg.storage["database"] = str(_base / cfg.storage["database"])
        if not os.path.isabs(cfg.report["output_dir"]):
            cfg.report["output_dir"] = str(_base / cfg.report["output_dir"])
    except Exception as exc:  # noqa: BLE001
        _log_diag(f"could not set up writable output dir: {exc}")

    class MainWindow(QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.cfg = cfg
            self._thread: QThread | None = None
            self._worker: Worker | None = None
            self._last_report_path: str | None = None
            self._job_ctx: dict | None = None

            self.setWindowTitle("BioAuthGuard — Android biometric auth security")
            self.resize(1000, 720)

            tabs = QTabWidget()
            tabs.addTab(self._build_scan_tab(), "Scan APK")
            tabs.addTab(self._build_assess_tab(), "Assess Device")
            tabs.addTab(self._build_history_tab(), "History")
            self.setCentralWidget(tabs)

            self.statusBar().showMessage("Ready")

        # ---- Scan APK tab ------------------------------------------------- #

        def _build_scan_tab(self) -> QWidget:
            w = QWidget()
            layout = QVBoxLayout(w)

            row = QHBoxLayout()
            self.scan_apk_edit = QLineEdit()
            self.scan_apk_edit.setPlaceholderText("Path to an .apk file you own or are authorized to test")
            browse = QPushButton("Browse…")
            browse.clicked.connect(self._pick_scan_apk)
            row.addWidget(QLabel("APK:"))
            row.addWidget(self.scan_apk_edit, 1)
            row.addWidget(browse)
            layout.addLayout(row)

            self.scan_explain = QCheckBox("Run the AI explanation layer (needs an API key)")
            layout.addWidget(self.scan_explain)

            self.scan_btn = QPushButton("Run static scan")
            self.scan_btn.clicked.connect(self._run_scan)
            layout.addWidget(self.scan_btn)

            self.scan_progress = QProgressBar()
            self.scan_progress.setRange(0, 0)  # indeterminate
            self.scan_progress.hide()
            layout.addWidget(self.scan_progress)

            self.scan_results = QTextBrowser()
            self.scan_results.setOpenExternalLinks(True)
            layout.addWidget(self.scan_results, 1)

            self.scan_open_report = QPushButton("Open full report")
            self.scan_open_report.setEnabled(False)
            self.scan_open_report.clicked.connect(self._open_last_report)
            layout.addWidget(self.scan_open_report)

            return w

        def _pick_scan_apk(self) -> None:
            path, _ = QFileDialog.getOpenFileName(self, "Select APK", "", "Android package (*.apk);;All files (*)")
            if path:
                self.scan_apk_edit.setText(path)

        def _run_scan(self) -> None:
            apk = self.scan_apk_edit.text().strip()
            if not apk:
                QMessageBox.warning(self, "No APK", "Choose an APK file first.")
                return
            if not os.path.exists(apk):
                QMessageBox.warning(self, "Not found", f"File does not exist:\n{apk}")
                return

            explain = self.scan_explain.isChecked()

            def job() -> TestRun:
                # Heavy work on the worker thread; the report (weasyprint/GTK) is
                # written later on the main thread in _start_job's finished handler.
                run_ = core.build_scan_apk(apk, self.cfg)
                core.process_findings(run_, self.cfg, explain)
                return run_

            self._start_job(job, self.scan_btn, self.scan_progress, self.scan_results,
                            self.scan_open_report, "Scanning APK…")

        # ---- Assess device tab -------------------------------------------- #

        def _build_assess_tab(self) -> QWidget:
            w = QWidget()
            layout = QVBoxLayout(w)

            dev_row = QHBoxLayout()
            self.device_combo = QComboBox()
            refresh = QPushButton("Refresh devices")
            refresh.clicked.connect(self._refresh_devices)
            dev_row.addWidget(QLabel("Device:"))
            dev_row.addWidget(self.device_combo, 1)
            dev_row.addWidget(refresh)
            layout.addLayout(dev_row)

            pkg_row = QHBoxLayout()
            self.package_combo = QComboBox()
            self.package_combo.setEditable(True)          # type to filter, or pick
            self.package_combo.setInsertPolicy(QComboBox.NoInsert)
            self.package_combo.lineEdit().setPlaceholderText("com.example.app — or click Load apps")
            comp = self.package_combo.completer()
            if comp:
                comp.setFilterMode(Qt.MatchContains)      # match anywhere in the name
                comp.setCompletionMode(QCompleter.PopupCompletion)
            self.include_system = QCheckBox("incl. system")
            load_apps = QPushButton("Load apps")
            load_apps.clicked.connect(self._load_packages)
            pkg_row.addWidget(QLabel("Package:"))
            pkg_row.addWidget(self.package_combo, 1)
            pkg_row.addWidget(self.include_system)
            pkg_row.addWidget(load_apps)
            layout.addLayout(pkg_row)

            apk_row = QHBoxLayout()
            self.assess_apk_edit = QLineEdit()
            self.assess_apk_edit.setPlaceholderText("Optional — enables the IPC oracle + static analysis")
            browse = QPushButton("Browse…")
            browse.clicked.connect(self._pick_assess_apk)
            apk_row.addWidget(QLabel("APK:"))
            apk_row.addWidget(self.assess_apk_edit, 1)
            apk_row.addWidget(browse)
            layout.addLayout(apk_row)

            self.assess_authorized = QCheckBox(
                "I own or am authorized to test this app (required)")
            layout.addWidget(self.assess_authorized)

            self.assess_ai = QCheckBox("Run the AI explanation layer (needs an API key)")
            self.assess_ai.setChecked(True)
            layout.addWidget(self.assess_ai)

            self.assess_btn = QPushButton("Run full assessment")
            self.assess_btn.clicked.connect(self._run_assess)
            layout.addWidget(self.assess_btn)

            self.assess_progress = QProgressBar()
            self.assess_progress.setRange(0, 0)
            self.assess_progress.hide()
            layout.addWidget(self.assess_progress)

            self.assess_results = QTextBrowser()
            self.assess_results.setOpenExternalLinks(True)
            layout.addWidget(self.assess_results, 1)

            self.assess_open_report = QPushButton("Open full report")
            self.assess_open_report.setEnabled(False)
            self.assess_open_report.clicked.connect(self._open_last_report)
            layout.addWidget(self.assess_open_report)

            self._refresh_devices()
            return w

        def _pick_assess_apk(self) -> None:
            path, _ = QFileDialog.getOpenFileName(self, "Select APK", "", "Android package (*.apk);;All files (*)")
            if path:
                self.assess_apk_edit.setText(path)

        def _load_packages(self) -> None:
            serial = (self.device_combo.currentText().strip()
                      if self.device_combo.isEnabled() else None)
            try:
                adb = Adb(self.cfg.device["adb_path"], serial or self.cfg.device["serial"])
                pkgs = adb.list_packages(third_party_only=not self.include_system.isChecked())
            except Exception as exc:  # noqa: BLE001
                QMessageBox.warning(
                    self, "Could not list apps",
                    f"Failed to list installed packages:\n{exc}\n\n"
                    "Make sure a device is connected and authorized.")
                return
            typed = self.package_combo.currentText()
            self.package_combo.clear()
            self.package_combo.addItems(pkgs)
            self.package_combo.setEditText(typed)   # keep whatever was already typed
            self.statusBar().showMessage(
                f"Loaded {len(pkgs)} package(s) — type to filter, or pick from the list")

        def _refresh_devices(self) -> None:
            self.device_combo.clear()
            try:
                serials = Adb(self.cfg.device["adb_path"], self.cfg.device["serial"]).devices()
            except Exception as exc:  # noqa: BLE001
                self.statusBar().showMessage(f"adb error: {exc}")
                serials = []
            if serials:
                self.device_combo.addItems(serials)
            else:
                self.device_combo.addItem("(no device — check USB debugging)")
                self.device_combo.setEnabled(False)
            if serials:
                self.device_combo.setEnabled(True)

        def _run_assess(self) -> None:
            if not self.assess_authorized.isChecked():
                QMessageBox.warning(
                    self, "Authorization required",
                    "Runtime probing requires confirming you own or are authorized "
                    "to test this app. Tick the authorization box first.")
                return
            package = self.package_combo.currentText().strip()
            if not package:
                QMessageBox.warning(self, "No package", "Enter the target package name.")
                return

            apk = self.assess_apk_edit.text().strip() or None
            if apk and not os.path.exists(apk):
                QMessageBox.warning(self, "Not found", f"APK does not exist:\n{apk}")
                return

            serial = self.device_combo.currentText().strip()
            explain = self.assess_ai.isChecked()

            # Honour the device selected in the combo box for this run.
            cfg = self.cfg
            selected_serial = serial if self.device_combo.isEnabled() else None

            def job() -> TestRun:
                adb = Adb(cfg.device["adb_path"], selected_serial or cfg.device["serial"])
                run_ = core.build_assess(package, apk, cfg, adb=adb)
                core.process_findings(run_, cfg, explain)   # report written on main thread
                return run_

            self._start_job(job, self.assess_btn, self.assess_progress, self.assess_results,
                            self.assess_open_report, "Assessing device…")

        # ---- History tab -------------------------------------------------- #

        def _build_history_tab(self) -> QWidget:
            w = QWidget()
            layout = QVBoxLayout(w)

            top = QHBoxLayout()
            self.history_combo = QComboBox()
            reload_btn = QPushButton("Reload")
            reload_btn.clicked.connect(self._reload_history)
            top.addWidget(QLabel("Past runs:"))
            top.addWidget(self.history_combo, 1)
            top.addWidget(reload_btn)
            layout.addLayout(top)

            self.history_combo.currentIndexChanged.connect(self._show_history_run)

            self.history_results = QTextBrowser()
            self.history_results.setOpenExternalLinks(True)
            layout.addWidget(self.history_results, 1)

            self._reload_history()
            return w

        def _reload_history(self) -> None:
            from ..storage.history import History
            self.history_combo.blockSignals(True)
            self.history_combo.clear()
            self._history_ids: list[str] = []
            try:
                runs = History(self.cfg.storage["database"]).list_runs()
            except Exception as exc:  # noqa: BLE001
                self.statusBar().showMessage(f"history error: {exc}")
                runs = []
            for r in runs:
                sev = f"C{r['critical']} H{r['high']} M{r['medium']} L{r['low']} I{r['info']}"
                self.history_combo.addItem(f"{r['package']} — {sev}  [{r['id']}]")
                self._history_ids.append(r["id"])
            self.history_combo.blockSignals(False)
            if self._history_ids:
                self._show_history_run(0)
            else:
                self.history_results.setHtml("<p>No runs yet. Run a scan or assessment first.</p>")

        def _show_history_run(self, index: int) -> None:
            from ..storage.history import History
            if index < 0 or index >= len(self._history_ids):
                return
            payload = History(self.cfg.storage["database"]).get(self._history_ids[index])
            if payload:
                self.history_results.setHtml(_payload_to_html(payload))

        # ---- Shared job machinery ----------------------------------------- #

        def _start_job(self, job, button, progress, results_view, open_btn, status_msg) -> None:
            if self._thread is not None:
                QMessageBox.information(self, "Busy", "A task is already running.")
                return

            button.setEnabled(False)
            open_btn.setEnabled(False)
            progress.show()
            results_view.setHtml(f"<p>{status_msg}</p>")
            self.statusBar().showMessage(status_msg)

            # Remember which widgets this job drives; the finished/failed handlers
            # (which run on the MAIN thread) read this.
            self._job_ctx = {
                "button": button, "progress": progress,
                "results_view": results_view, "open_btn": open_btn,
            }

            self._thread = QThread()
            self._worker = Worker(job)
            self._worker.moveToThread(self._thread)
            self._thread.started.connect(self._worker.run)
            # Connect to bound methods of `self` — a QObject living on the main
            # thread. Because the worker emits from the worker thread, Qt uses a
            # queued connection and runs these slots on the MAIN thread, which is
            # mandatory: they touch Qt widgets and weasyprint/GTK, neither of which
            # is safe off the main thread (doing so segfaults the frozen build).
            self._worker.finished.connect(self._on_job_finished)
            self._worker.failed.connect(self._on_job_failed)
            self._thread.start()

        def _on_job_finished(self, run_: object) -> None:
            ctx = self._job_ctx
            try:
                self._last_report_path = core.write_report(run_, self.cfg)
            except Exception as exc:  # noqa: BLE001 - findings still shown
                self._last_report_path = None
                _log_diag(f"write_report failed: {exc}")
                self.statusBar().showMessage(f"Report export failed: {exc}")
            ctx["results_view"].setHtml(generator.render_html(run_))
            ctx["open_btn"].setEnabled(self._last_report_path is not None)
            counts = run_.counts()
            summary = ", ".join(f"{k} {v}" for k, v in counts.items() if v) or "no findings"
            self.statusBar().showMessage(f"Done: {run_.package} — {summary}")
            self._cleanup_thread(ctx["button"], ctx["progress"])

        def _on_job_failed(self, msg: str) -> None:
            ctx = self._job_ctx
            ctx["results_view"].setHtml(
                f"<pre style='color:#b00020; white-space:pre-wrap'>{msg}</pre>")
            self.statusBar().showMessage("Failed")
            self._cleanup_thread(ctx["button"], ctx["progress"])

        def _cleanup_thread(self, button, progress) -> None:
            progress.hide()
            button.setEnabled(True)
            if self._thread is not None:
                self._thread.quit()
                self._thread.wait()
            self._thread = None
            self._worker = None
            self._reload_history()

        def _open_last_report(self) -> None:
            if self._last_report_path and os.path.exists(self._last_report_path):
                QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.abspath(self._last_report_path)))
            else:
                QMessageBox.information(self, "No report", "No report file is available yet.")

    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("BioAuthGuard")
    window = MainWindow()
    window.show()
    return app.exec()


def _payload_to_html(payload: dict) -> str:
    """Reconstruct a TestRun from a stored payload and render it via the report
    generator, so history entries look identical to fresh results."""
    from ..models import Finding, Severity

    _sev = {s.label: s for s in Severity}
    run = TestRun(package=payload.get("package", "?"))
    run.id = payload.get("id", run.id)
    for fd in payload.get("findings", []):
        run.add(Finding(
            category=fd.get("category", ""),
            title=fd.get("title", ""),
            severity=_sev.get(fd.get("severity", "Info"), Severity.INFO),
            owasp=fd.get("owasp", []),
            evidence=fd.get("evidence", ""),
            source=fd.get("source", ""),
            confidence=fd.get("confidence", "confirmed"),
            component=fd.get("component"),
            explanation=fd.get("explanation"),
            mitigation=fd.get("mitigation"),
            references=fd.get("references", []),
        ))
    return generator.render_html(run)


if __name__ == "__main__":
    raise SystemExit(run())
