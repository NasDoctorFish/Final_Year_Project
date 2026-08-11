"""BioAudit desktop GUI (PySide6).

A thin shell over `bioaudit.core` — the same orchestration the CLI drives.
Long-running work (APK decompilation, ADB probing, the AI layer) runs on a
QThread so the window never freezes. Findings are shown by reusing the report
renderer (`report.generator.render_html`) inside a QTextBrowser, so the on-screen
view matches the exported report exactly.

Launch with:  python -m bioaudit gui
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
            "(Or use the CLI: python -m bioaudit scan-apk <apk>)\n"
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
        progress = Signal(str)      # emits a plain-language step description
        cancelled = Signal()        # emits when the job stopped at the user's request

        def __init__(self, fn: Callable[[Callable[[str], None]], object]):
            super().__init__()
            self._fn = fn

        def run(self) -> None:
            from .. import core

            try:
                # The job is handed the emitter rather than the signal itself, so job
                # closures stay plain callables and know nothing about Qt.
                result = self._fn(self.progress.emit)
            except core.ScanCancelled:
                # Not a failure. The user asked for this, so it gets its own path and
                # does not show them a traceback for something they chose.
                self.cancelled.emit()
                return
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
        path = Path(os.path.expanduser("~")) / "bioaudit-crash.log"
        fh = open(path, "a", buffering=1, encoding="utf-8")
        _crash_log_handles.append(fh)
        fh.write(f"\n=== BioAudit GUI started {datetime.datetime.now():%Y-%m-%d %H:%M:%S} ===\n")
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
    from PySide6.QtGui import QAction, QDesktopServices
    from PySide6.QtCore import QUrl
    from PySide6.QtWidgets import (
        QApplication, QCheckBox, QComboBox, QCompleter, QFileDialog, QFormLayout,
        QGroupBox, QHBoxLayout, QLabel, QLineEdit, QMainWindow,
        QMessageBox, QProgressBar, QPushButton, QTabWidget,
        QTextBrowser, QVBoxLayout, QWidget,
    )

    from . import team, theme

    # --- small layout helpers, shared by every tab --------------------------
    # Grouping controls into titled cards is what turns a flat stack of widgets into
    # something readable: it tells the user which inputs belong together and where one
    # decision ends and the next begins.

    def _section(title: str):
        """A titled card. Returns (box, inner_layout) so callers can fill it."""
        box = QGroupBox(title)
        inner = QVBoxLayout(box)
        inner.setContentsMargins(2, 6, 2, 2)
        inner.setSpacing(8)
        return box, inner

    def _hint(text: str) -> QLabel:
        """Small muted explanatory text under a control."""
        label = QLabel(text)
        label.setObjectName("hint")
        label.setWordWrap(True)
        return label

    def _field_label(text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("fieldLabel")
        return label

    Worker, QThread = _make_worker_classes()
    cfg = cfg or Config.load()

    # A double-clicked exe can start in a directory it cannot write to (Program
    # Files, a read-only mount, etc.), which would make the report export raise.
    # Anchor it, and the saved session file, under the user's home so writes always work.
    from .. import session as _session_module
    try:
        _base = _session_module.default_base_dir()
        if not os.path.isabs(cfg.report["output_dir"]):
            cfg.report["output_dir"] = str(_base / cfg.report["output_dir"])
    except Exception as exc:  # noqa: BLE001
        from pathlib import Path
        _base = Path(os.path.expanduser("~")) / "BioAudit"
        _log_diag(f"could not set up writable output dir: {exc}")

    class MainWindow(QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.cfg = cfg
            self._thread: QThread | None = None
            self._worker: Worker | None = None
            self._last_report_path: str | None = None
            self._job_ctx: dict | None = None
            # Set while a job runs so the worker thread can see a cancel request. An Event
            # is used rather than a plain bool because it is written on the UI thread and
            # read on the worker thread.
            self._cancel_event = None
            # Set when a run has been saved to the account, which is what the server-backed
            # explain and export buttons need.
            self._last_scan_id: str | None = None

            # Optional server connection. Stays None unless the user signs in, and
            # nothing in the scanning path depends on it.
            self.api = None
            self._session_dir = str(_base)

            # The colours the stylesheet was built from, so the HTML rendered into the
            # results panes matches the surrounding chrome in either theme.
            self.palette_colours = palette_colours

            self.setWindowTitle("BioAudit — Android biometric authentication security")
            self.resize(1060, 780)
            self.setMinimumSize(820, 600)

            self._build_account_menu()

            tabs = QTabWidget()
            tabs.setDocumentMode(True)   # flat tabs, no heavy frame around the pane
            tabs.addTab(self._build_scan_tab(), "Scan an APK")
            tabs.addTab(self._build_assess_tab(), "Assess a device")
            tabs.addTab(self._build_history_tab(), "History")
            # Always present, but it explains itself instead of showing empty tables when
            # the signed-in account is not an organisation admin.
            self.team_tab = team.make_team_tab(self, self.palette_colours)
            tabs.addTab(self.team_tab, "Team")
            self.setCentralWidget(tabs)

            # Shown on the right of the status bar so the signed-in state is always
            # visible, rather than hidden behind a menu.
            self.account_label = QLabel("")
            self.account_label.setObjectName("accountBadge")
            self.statusBar().addPermanentWidget(self.account_label)

            self.statusBar().showMessage("Ready")
            self._restore_saved_session()
            self._refresh_account_ui()

            # The welcome gate is a startup step, not a constructor step: show it once the
            # window itself is on screen (via a zero-delay timer) so it appears over a
            # painted app rather than a blank one. Skipped when a saved session already
            # signed the user in, and suppressible for automated tests.
            if self.api is None and not os.environ.get("BIOAUDIT_SKIP_WELCOME"):
                from PySide6.QtCore import QTimer
                QTimer.singleShot(0, self._require_signed_in_or_quit)

        # ---- Account ------------------------------------------------------ #

        def _build_account_menu(self) -> None:
            menu = self.menuBar().addMenu("&Account")

            self.action_sign_in = QAction("Sign in…", self)
            self.action_sign_in.triggered.connect(self._sign_in)
            menu.addAction(self.action_sign_in)

            self.action_sign_out = QAction("Sign out", self)
            self.action_sign_out.triggered.connect(self._sign_out)
            menu.addAction(self.action_sign_out)

            menu.addSeparator()

            self.action_account_info = QAction("Account details…", self)
            self.action_account_info.triggered.connect(self._show_account_details)
            menu.addAction(self.action_account_info)

            self.action_settings = QAction("Account settings…", self)
            self.action_settings.setToolTip(
                "Change your display name, email address, or password, or delete your account.")
            self.action_settings.triggered.connect(self._open_account_settings)
            menu.addAction(self.action_settings)

            self.action_join_org = QAction("Join an organisation…", self)
            self.action_join_org.triggered.connect(self._join_organisation)
            menu.addAction(self.action_join_org)

            menu.addSeparator()

            self.action_upgrade = QAction("Upgrade to premium…", self)
            self.action_upgrade.triggered.connect(self._upgrade)
            menu.addAction(self.action_upgrade)

            self.action_cancel_sub = QAction("Cancel subscription…", self)
            self.action_cancel_sub.triggered.connect(self._cancel_subscription)
            menu.addAction(self.action_cancel_sub)

        def _restore_saved_session(self) -> None:
            """Reuse a stored session if the user asked to stay signed in.

            Runs on startup, so it must never block for long or raise. A dead session or
            an unreachable server simply leaves the app signed out.
            """
            # A saved session means the user ticked "keep me signed in", so honour it even
            # when the API section is off by default: choosing to stay signed in is itself
            # the opt-in. Skip the work only when neither the flag nor a saved file exists.
            from ..session import restore_session, session_path
            if not self.cfg.api.get("enabled", False) and not session_path(self._session_dir).exists():
                return
            try:
                client = restore_session(self._session_dir, self.cfg.api["base_url"])
            except Exception as exc:  # noqa: BLE001
                _log_diag(f"session restore failed: {exc}")
                return
            if client is not None:
                self.api = client
                self.cfg.api["enabled"] = True
                self.statusBar().showMessage("Signed in from a saved session.")

        def _show_welcome_gate(self) -> bool:
            """Front door: the user must register, join a team, or sign in to continue.

            Follows the functional hierarchy's unregistered-user paths (register / join via
            invite), with a sign-in tab for returning users. There is no guest mode: BioAudit
            keeps no local copy of a scan, so with nobody signed in there is nowhere for a
            result to go. Returns whether the user ended up signed in.
            """
            from .signin import show_welcome_dialog

            try:
                client, _remember = show_welcome_dialog(
                    self, base_url=self.cfg.api["base_url"], base_dir=self._session_dir)
            except Exception as exc:  # noqa: BLE001 - a broken gate must not trap the user
                _log_diag(f"welcome gate failed: {exc}")
                client = None

            if client is None:
                return False

            self.api = client
            self.cfg.api["enabled"] = True
            self.statusBar().showMessage(f"Signed in as {client.account.email}.")
            self._refresh_account_ui()
            return True

        def _require_signed_in_or_quit(self) -> None:
            """Show the welcome gate; close the app if it is dismissed without signing in.

            There is nothing a signed-out session can do here: no local storage to fall
            back to, no guest mode. Closing rather than limping on with a dead window is
            the honest response, and mirrors what clicking the window's own close button
            does, so it needs no special-casing at the call sites.

            Skipped under the same flag the startup gate honours: an automated test that
            drives sign-out directly wants to inspect the resulting signed-out state, not
            hit a blocking modal dialog or have the process quit out from under it.
            """
            if os.environ.get("BIOAUDIT_SKIP_WELCOME"):
                return
            if not self._show_welcome_gate():
                self.close()

        def _refresh_account_ui(self) -> None:
            from .signin import account_summary

            account = self.api.account if self.api else None
            signed_in = account is not None

            self.account_label.setText(account_summary(account))
            self.action_sign_in.setText("Switch account…" if signed_in else "Sign in…")
            self.action_sign_out.setEnabled(signed_in)
            self.action_account_info.setEnabled(signed_in)
            self.action_settings.setEnabled(signed_in)
            # Joining is only offered when you are not already in a team; the server refuses
            # a second organisation, so offering it would only produce an error.
            self.action_join_org.setEnabled(signed_in and not account.organisation_id)
            self.action_upgrade.setEnabled(signed_in and not account.is_premium)
            self.action_cancel_sub.setEnabled(signed_in and account.is_premium)

            # Premium-only actions on the History tab.
            self.compare_btn.setEnabled(signed_in and account.is_premium)
            self.compare_btn.setToolTip(
                "Compare two saved runs to see what was fixed and what is new."
                if signed_in and account.is_premium
                else "Comparing runs is part of the premium plan.")

            self.team_tab.refresh_visibility()
            # The History tab has nothing of its own to poll on a timer, so any moment
            # the signed-in account might have changed is also a moment to refresh it.
            self._reload_history()

        def _sign_in(self) -> None:
            from .signin import show_signin_dialog

            client, _remember = show_signin_dialog(
                self, base_url=self.cfg.api["base_url"], base_dir=self._session_dir
            )
            if client is None:
                return

            self.api = client
            # Signing in is also how the server gets enabled for this session, so a user
            # who never signs in is never asked about a server they do not have.
            self.cfg.api["enabled"] = True
            self._refresh_account_ui()
            self.statusBar().showMessage(f"Signed in as {client.account.email}")

        def _sign_out(self) -> None:
            from .signin import clear_session

            if self.api is not None:
                self.api.logout()
            clear_session(self._session_dir)
            self.api = None
            self._refresh_account_ui()
            self.statusBar().showMessage("Signed out.")
            # No account, no local storage, nowhere for the next scan to go: ask for a
            # sign-in immediately rather than leaving buttons on screen that would fail.
            self._require_signed_in_or_quit()

        def _upgrade(self) -> None:
            if self.api is None:
                return
            confirm = QMessageBox.question(
                self, "Upgrade to premium",
                "Premium keeps your full scan history, and adds run comparison and "
                "report export.\n\nThis demo build does not take payment, so the upgrade "
                "is applied immediately.\n\nContinue?",
            )
            if confirm != QMessageBox.Yes:
                return
            try:
                account = self.api.upgrade()
            except Exception as exc:  # noqa: BLE001
                QMessageBox.warning(self, "Upgrade failed", str(exc))
                return
            self._refresh_account_ui()
            QMessageBox.information(
                self, "Upgraded", f"Your account is now {account.tier}."
            )

        def _open_account_settings(self) -> None:
            """Display name, email, password, and account deletion."""
            if self.api is None:
                return
            from .account_dialogs import show_profile_dialog

            result = show_profile_dialog(self, self.api)
            if result.account_deleted or result.signed_out:
                # The session is gone either way, so clear it here rather than leaving the
                # window believing it is still signed in.
                self._force_sign_out(result.message)
            elif result.changed:
                try:
                    self.api.get_profile()
                except Exception:  # noqa: BLE001 - display only
                    pass
                self._refresh_account_ui()

        def _join_organisation(self) -> None:
            if self.api is None:
                return
            from .account_dialogs import show_join_organisation_dialog

            result = show_join_organisation_dialog(self, self.api)
            if result.signed_out:
                self._force_sign_out(result.message)

        def _cancel_subscription(self) -> None:
            if self.api is None:
                return
            from .account_dialogs import confirm_cancel_subscription

            result = confirm_cancel_subscription(self, self.api)
            if result.signed_out:
                self._force_sign_out(result.message)

        def _force_sign_out(self, message: str = "") -> None:
            """Drop the session locally after the server has already ended it.

            Used when an action revokes the session as a side effect, such as changing a
            password or a tier. Calling logout() would only fail against a token the server
            has already rejected.
            """
            from .signin import clear_session

            clear_session(self._session_dir)
            self.api = None
            self._refresh_account_ui()
            self.statusBar().showMessage(message or "Signed out.")
            self._require_signed_in_or_quit()

        def _show_account_details(self) -> None:
            if self.api is None:
                return
            try:
                account = self.api.get_profile()
                subscription = self.api.get_subscription()
            except Exception as exc:  # noqa: BLE001
                QMessageBox.warning(self, "Could not load account", str(exc))
                return

            limit = subscription["limits"]["historyLimit"]
            lines = [
                f"<b>Email:</b> {account.email}",
                f"<b>Name:</b> {account.display_name or 'not set'}",
                f"<b>Plan:</b> {account.tier}",
                f"<b>Role:</b> {account.role}",
                f"<b>Scans saved:</b> {account.scan_count}",
                f"<b>History kept:</b> {'unlimited' if limit is None else f'newest {limit}'}",
            ]
            if account.organisation_id:
                try:
                    org = self.api.my_organisation()
                    if org:
                        lines.append(f"<b>Organisation:</b> {org['name']} ({org['memberCount']} members)")
                except Exception:  # noqa: BLE001 - detail is optional
                    pass

            QMessageBox.information(self, "Account details", "<br>".join(lines))

        # ---- Server sync -------------------------------------------------- #

        def _upload(self, run_, *, authorised: bool, apk_file_name: str | None,
                    into: dict) -> None:
            """Upload a finished run, recording the outcome in `into`.

            Called from the worker thread, so it must not touch a widget. The result is
            left in the dict the caller passed, which the main thread reads once the
            finished signal arrives. Emitting that signal is the handover point, so no
            further synchronisation is needed.

            Every error is captured rather than raised, so a failed upload cannot crash
            the job — but note that BioAudit keeps no local copy, so a failure here really
            does mean the run is not saved anywhere until a retry succeeds.
            """
            from ..api import ApiClientError

            try:
                result = self.api.upload_run(
                    run_, authorised=authorised, apk_file_name=apk_file_name
                )
                into["scan_id"] = result["scan"]["id"]
                retention = result.get("retention")
                into["message"] = "Saved to your account."
                if retention:
                    into["message"] += " " + retention["message"]
            except ApiClientError as exc:
                into["error"] = exc.message
            except Exception as exc:  # noqa: BLE001
                into["error"] = f"{type(exc).__name__}: {exc}"

        def _retry_upload(self) -> None:
            """Try again to save the last run whose upload failed.

            Runs on the main thread with a short blocking call rather than spinning up a
            whole worker thread: the run's findings already exist, this is just one HTTP
            request, and the wait cursor is enough feedback for something this quick.
            """
            ctx = self._job_ctx
            if not ctx or ctx.get("run") is None:
                return
            if self.api is None:
                QMessageBox.information(
                    self, "Not signed in",
                    "Sign in from the Account menu, then retry saving this run.")
                return

            retry_btn = ctx.get("retry_btn")
            if retry_btn is not None:
                retry_btn.setEnabled(False)
            self.setCursor(Qt.WaitCursor)
            try:
                sync_result: dict = {}
                self._upload(ctx["run"], authorised=True,
                            apk_file_name=ctx.get("apk_file_name"), into=sync_result)
            finally:
                self.setCursor(Qt.ArrowCursor)

            ctx["sync"] = sync_result
            self._last_scan_id = sync_result.get("scan_id")
            premium = bool(self.api and self.api.account and self.api.account.is_premium)
            for explain_btn, save_btn in (
                (self.scan_explain_btn, self.scan_save_report_btn),
                (self.assess_explain_btn, self.assess_save_report_btn),
            ):
                explain_btn.setEnabled(bool(self._last_scan_id))
                save_btn.setEnabled(bool(self._last_scan_id) and premium)

            html = _sync_banner_html(sync_result) + generator.render_html(ctx["run"])
            ctx["results_view"].setHtml(html)
            if retry_btn is not None:
                retry_btn.setEnabled(True)
                retry_btn.setVisible(bool(sync_result.get("error")))

            self.statusBar().showMessage(
                "Saved to your account." if sync_result.get("scan_id")
                else f"Still not saved: {sync_result.get('error', 'unknown error')}")
            self._reload_history()

        # ---- Scan APK tab ------------------------------------------------- #

        def _build_scan_tab(self) -> QWidget:
            w = QWidget()
            layout = QVBoxLayout(w)
            layout.setContentsMargins(16, 12, 16, 12)
            layout.setSpacing(10)

            # --- target -----------------------------------------------
            target, tl = _section("Target")
            row = QHBoxLayout()
            row.setSpacing(8)
            self.scan_apk_edit = QLineEdit()
            self.scan_apk_edit.setPlaceholderText(
                "Path to an .apk file you own or are authorised to test")
            browse = QPushButton("Browse…")
            browse.clicked.connect(self._pick_scan_apk)
            row.addWidget(self.scan_apk_edit, 1)
            row.addWidget(browse)
            tl.addLayout(row)
            tl.addWidget(_hint(
                "Reads the app's settings and compiled code without running it. No phone needed."))
            layout.addWidget(target)

            # --- action -----------------------------------------------
            action = QHBoxLayout()
            action.setSpacing(10)
            self.scan_btn = QPushButton("Run static scan")
            self.scan_btn.setObjectName("primary")
            self.scan_btn.setCursor(Qt.PointingHandCursor)
            self.scan_btn.clicked.connect(self._run_scan)
            self.scan_open_report = QPushButton("Open full report")
            self.scan_open_report.setEnabled(False)
            self.scan_open_report.clicked.connect(self._open_last_report)
            # These two need the run to exist on the server, so they stay disabled until a
            # run has been saved to the account.
            self.scan_explain_btn = QPushButton("Explain findings")
            self.scan_explain_btn.setEnabled(False)
            self.scan_explain_btn.setToolTip(
                "Ask the server to write a plain-language explanation and fix for every "
                "finding. Needs the run to be saved to your account.")
            self.scan_explain_btn.clicked.connect(self._explain_last_run)
            self.scan_save_report_btn = QPushButton("Save report from account")
            self.scan_save_report_btn.setEnabled(False)
            self.scan_save_report_btn.setToolTip(
                "Download this run's report from your account. Part of the premium plan.")
            self.scan_save_report_btn.clicked.connect(self._save_server_report)
            # Only shown while a run is going, so the row is not cluttered when idle.
            self.scan_cancel_btn = QPushButton("Cancel")
            self.scan_cancel_btn.setToolTip(
                "Stop after the current step finishes. A step already reading the file "
                "cannot be interrupted part way.")
            self.scan_cancel_btn.clicked.connect(self._cancel_job)
            self.scan_cancel_btn.hide()
            # Only shown when the automatic upload failed, since BioAudit keeps no local
            # copy and this is the only way to get the run saved after that.
            self.scan_retry_btn = QPushButton("Retry saving to your account")
            self.scan_retry_btn.clicked.connect(self._retry_upload)
            self.scan_retry_btn.hide()

            action.addWidget(self.scan_btn)
            action.addWidget(self.scan_cancel_btn)
            action.addWidget(self.scan_retry_btn)
            action.addWidget(self.scan_open_report)
            action.addWidget(self.scan_explain_btn)
            action.addWidget(self.scan_save_report_btn)
            action.addStretch(1)
            layout.addLayout(action)

            # Naming the current step is what stops a long run looking like a freeze.
            self.scan_stage = QLabel("")
            self.scan_stage.setObjectName("hint")
            self.scan_stage.hide()
            layout.addWidget(self.scan_stage)

            self.scan_progress = QProgressBar()
            self.scan_progress.setRange(0, 0)  # indeterminate
            self.scan_progress.setTextVisible(False)
            self.scan_progress.hide()
            layout.addWidget(self.scan_progress)

            # --- results ----------------------------------------------
            self.scan_summary = QLabel("")
            self.scan_summary.setTextFormat(Qt.RichText)
            self.scan_summary.hide()
            layout.addWidget(self.scan_summary)

            self.scan_results = QTextBrowser()
            self.scan_results.setOpenExternalLinks(True)
            self.scan_results.setHtml(theme.empty_state_html(
                "Check an app's file",
                ["Choose an .apk file above, then run the scan.",
                 "It flags a debuggable build, backup exposure, screens left open to other "
                 "apps, and a fingerprint check that is not tied to a key.",
                 "The result is saved to your account automatically when it finishes."],
                self.palette_colours))
            layout.addWidget(self.scan_results, 1)

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

            sync_result: dict = {}
            apk_name = os.path.basename(apk)

            def job(report) -> TestRun:
                # Heavy work on the worker thread; the report (weasyprint/GTK) is
                # written later on the main thread in _start_job's finished handler.
                stop = self._cancel_event
                run_ = core.build_scan_apk(
                    apk, self.cfg, on_progress=report,
                    should_cancel=(stop.is_set if stop else None))
                core.process_findings(run_, on_progress=report)
                report("Saving to your account")
                # A static scan reads a file the user chose, so there is no live app
                # to authorise probing against. Uploading is not optional: BioAudit keeps
                # no local copy, so this is the only place the run ends up.
                self._upload(run_, authorised=True, apk_file_name=apk_name,
                             into=sync_result)
                return run_

            self._start_job(job, self.scan_btn, self.scan_progress, self.scan_results,
                            self.scan_open_report, "Starting",
                            sync_result=sync_result, summary_label=self.scan_summary,
                            stage_label=self.scan_stage, cancel_btn=self.scan_cancel_btn,
                            retry_btn=self.scan_retry_btn, apk_file_name=apk_name)

        # ---- Assess device tab -------------------------------------------- #

        def _build_assess_tab(self) -> QWidget:
            w = QWidget()
            layout = QVBoxLayout(w)
            layout.setContentsMargins(16, 12, 16, 12)
            layout.setSpacing(10)

            # --- device and app ---------------------------------------
            target, tl = _section("Device and app")
            form = QFormLayout()
            form.setSpacing(8)
            form.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)
            form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)

            dev_row = QHBoxLayout()
            dev_row.setSpacing(8)
            self.device_combo = QComboBox()
            refresh = QPushButton("Refresh")
            refresh.clicked.connect(self._refresh_devices)
            dev_row.addWidget(self.device_combo, 1)
            dev_row.addWidget(refresh)
            form.addRow(_field_label("Device"), dev_row)

            pkg_row = QHBoxLayout()
            pkg_row.setSpacing(8)
            self.package_combo = QComboBox()
            self.package_combo.setEditable(True)          # type to filter, or pick
            self.package_combo.setInsertPolicy(QComboBox.NoInsert)
            self.package_combo.lineEdit().setPlaceholderText("com.example.app, or click Load apps")
            comp = self.package_combo.completer()
            if comp:
                comp.setFilterMode(Qt.MatchContains)      # match anywhere in the name
                comp.setCompletionMode(QCompleter.PopupCompletion)
            self.include_system = QCheckBox("incl. system")
            load_apps = QPushButton("Load apps")
            load_apps.clicked.connect(self._load_packages)
            pkg_row.addWidget(self.package_combo, 1)
            pkg_row.addWidget(self.include_system)
            pkg_row.addWidget(load_apps)
            form.addRow(_field_label("App"), pkg_row)

            apk_row = QHBoxLayout()
            apk_row.setSpacing(8)
            self.assess_apk_edit = QLineEdit()
            self.assess_apk_edit.setPlaceholderText(
                "Optional, but adds the file checks and finds more open screens")
            browse = QPushButton("Browse…")
            browse.clicked.connect(self._pick_assess_apk)
            apk_row.addWidget(self.assess_apk_edit, 1)
            apk_row.addWidget(browse)
            form.addRow(_field_label("APK file"), apk_row)

            tl.addLayout(form)
            layout.addWidget(target)

            # --- authorisation ----------------------------------------
            # Its own section rather than another tick box in a list, because it is a
            # legal confirmation and not a preference.
            auth, al = _section("Authorisation")
            self.assess_authorized = QCheckBox(
                "I own this app, or I have permission to test it")
            self.assess_authorized.setStyleSheet("font-weight: 600;")
            al.addWidget(self.assess_authorized)
            al.addWidget(_hint(
                "Required. This test opens the app's screens on a real device, and testing "
                "an app without permission can be an offence."))
            layout.addWidget(auth)

            # --- action -----------------------------------------------
            action = QHBoxLayout()
            action.setSpacing(10)
            self.assess_btn = QPushButton("Run full assessment")
            self.assess_btn.setObjectName("primary")
            self.assess_btn.setCursor(Qt.PointingHandCursor)
            self.assess_btn.clicked.connect(self._run_assess)
            self.assess_open_report = QPushButton("Open full report")
            self.assess_open_report.setEnabled(False)
            self.assess_open_report.clicked.connect(self._open_last_report)
            # These two need the run to exist on the server, so they stay disabled until a
            # run has been saved to the account.
            self.assess_explain_btn = QPushButton("Explain findings")
            self.assess_explain_btn.setEnabled(False)
            self.assess_explain_btn.setToolTip(
                "Ask the server to write a plain-language explanation and fix for every "
                "finding. Needs the run to be saved to your account.")
            self.assess_explain_btn.clicked.connect(self._explain_last_run)
            self.assess_save_report_btn = QPushButton("Save report from account")
            self.assess_save_report_btn.setEnabled(False)
            self.assess_save_report_btn.setToolTip(
                "Download this run's report from your account. Part of the premium plan.")
            self.assess_save_report_btn.clicked.connect(self._save_server_report)
            # Only shown while a run is going, so the row is not cluttered when idle.
            self.assess_cancel_btn = QPushButton("Cancel")
            self.assess_cancel_btn.setToolTip(
                "Stop after the current step finishes. A step already talking to the "
                "device cannot be interrupted part way.")
            self.assess_cancel_btn.clicked.connect(self._cancel_job)
            self.assess_cancel_btn.hide()
            # Only shown when the automatic upload failed, since BioAudit keeps no local
            # copy and this is the only way to get the run saved after that.
            self.assess_retry_btn = QPushButton("Retry saving to your account")
            self.assess_retry_btn.clicked.connect(self._retry_upload)
            self.assess_retry_btn.hide()

            action.addWidget(self.assess_btn)
            action.addWidget(self.assess_cancel_btn)
            action.addWidget(self.assess_retry_btn)
            action.addWidget(self.assess_open_report)
            action.addWidget(self.assess_explain_btn)
            action.addWidget(self.assess_save_report_btn)
            action.addStretch(1)
            layout.addLayout(action)

            # Naming the current step is what stops a long run looking like a freeze.
            self.assess_stage = QLabel("")
            self.assess_stage.setObjectName("hint")
            self.assess_stage.hide()
            layout.addWidget(self.assess_stage)

            self.assess_progress = QProgressBar()
            self.assess_progress.setRange(0, 0)
            self.assess_progress.setTextVisible(False)
            self.assess_progress.hide()
            layout.addWidget(self.assess_progress)

            # --- results ----------------------------------------------
            self.assess_summary = QLabel("")
            self.assess_summary.setTextFormat(Qt.RichText)
            self.assess_summary.hide()
            layout.addWidget(self.assess_summary)

            self.assess_results = QTextBrowser()
            self.assess_results.setOpenExternalLinks(True)
            self.assess_results.setHtml(theme.empty_state_html(
                "Test an app on a real phone",
                ["Connect a phone with USB debugging on, then click Refresh and Load apps.",
                 "This tries to open the app's private screens directly, checks whether any "
                 "part of it gives away answers to guesses, and reads the phone's log.",
                 "Tick the authorisation box before running."],
                self.palette_colours))
            layout.addWidget(self.assess_results, 1)

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

            # Honour the device selected in the combo box for this run.
            cfg = self.cfg
            selected_serial = serial if self.device_combo.isEnabled() else None
            sync_result: dict = {}
            apk_name = os.path.basename(apk) if apk else None

            def job(report) -> TestRun:
                stop = self._cancel_event
                adb = Adb(cfg.device["adb_path"], selected_serial or cfg.device["serial"])
                run_ = core.build_assess(
                    package, apk, cfg, adb=adb, on_progress=report,
                    should_cancel=(stop.is_set if stop else None))
                core.process_findings(run_, on_progress=report)
                report("Saving to your account")
                # The authorisation box was ticked to get here, and the server refuses a
                # device assessment that does not carry that confirmation. Uploading is
                # not optional: BioAudit keeps no local copy of a run.
                self._upload(run_, authorised=True, apk_file_name=apk_name,
                             into=sync_result)
                return run_

            self._start_job(job, self.assess_btn, self.assess_progress, self.assess_results,
                            self.assess_open_report, "Starting",
                            sync_result=sync_result, summary_label=self.assess_summary,
                            stage_label=self.assess_stage, cancel_btn=self.assess_cancel_btn,
                            retry_btn=self.assess_retry_btn, apk_file_name=apk_name)

        # ---- History tab -------------------------------------------------- #

        def _build_history_tab(self) -> QWidget:
            w = QWidget()
            layout = QVBoxLayout(w)
            layout.setContentsMargins(16, 12, 16, 12)
            layout.setSpacing(10)

            picker, pl = _section("Your saved runs")
            top = QHBoxLayout()
            top.setSpacing(8)
            self.history_combo = QComboBox()
            reload_btn = QPushButton("Reload")
            reload_btn.clicked.connect(self._reload_history)
            top.addWidget(self.history_combo, 1)
            top.addWidget(reload_btn)
            pl.addLayout(top)

            actions = QHBoxLayout()
            actions.setSpacing(8)
            self.compare_btn = QPushButton("Compare two runs…")
            self.compare_btn.setEnabled(False)
            self.compare_btn.clicked.connect(self._compare_runs)
            self.delete_run_btn = QPushButton("Delete this run")
            self.delete_run_btn.clicked.connect(self._delete_history_run)
            self.clear_history_btn = QPushButton("Clear all history")
            self.clear_history_btn.clicked.connect(self._clear_history)
            actions.addWidget(self.compare_btn)
            actions.addStretch(1)
            actions.addWidget(self.delete_run_btn)
            actions.addWidget(self.clear_history_btn)
            pl.addLayout(actions)
            layout.addWidget(picker)

            self.history_combo.currentIndexChanged.connect(self._show_history_run)

            self.history_results = QTextBrowser()
            self.history_results.setOpenExternalLinks(True)
            layout.addWidget(self.history_results, 1)

            self._history_ids: list[str] = []
            self._reload_history()
            return w

        def _reload_history(self) -> None:
            """Refill the picker from the account's history on the server.

            The only history there is: BioAudit keeps no local copy of a scan. Called
            before the welcome gate has necessarily resolved (during tab construction),
            so it tolerates `self.api` still being None rather than assuming sign-in.
            """
            self.history_combo.blockSignals(True)
            self.history_combo.clear()
            self._history_ids = []
            limit = None
            load_error = None
            if self.api is not None:
                try:
                    data = self.api.list_history(limit=100)
                    limit = data.get("historyLimit")
                    for scan in data.get("scans", []):
                        counts = scan.get("counts") or {}
                        sev = " ".join(
                            f"{name[0].upper()}{counts.get(name, 0)}"
                            for name in ("critical", "high", "medium", "low", "info")
                            if counts.get(name)
                        ) or "no findings"
                        target = scan.get("target") or {}
                        label = target.get("packageName") or target.get("apkFileName") or "unknown"
                        when = str(scan.get("createdAt", ""))[:19]
                        self.history_combo.addItem(f"{when}  {label} — {sev}")
                        self._history_ids.append(scan["id"])
                except Exception as exc:  # noqa: BLE001
                    # Deliberately not the status bar: this can run right after a job
                    # finished and left a more important message there (e.g. "not saved
                    # to your account"), and a background history refresh failing is not
                    # worth overwriting that with.
                    load_error = str(exc)
                    _log_diag(f"history reload failed: {load_error}")
            self.history_combo.blockSignals(False)
            if load_error:
                self.history_results.setHtml(theme.empty_state_html(
                    "Could not load your history",
                    [load_error, "Click Reload to try again."], self.palette_colours))
            elif self._history_ids:
                self._show_history_run(0)
            else:
                lines = ["Run a scan or an assessment first.",
                         "Every finished run is saved to your account automatically."]
                if limit is not None:
                    lines.append(f"Your plan keeps the newest {limit} runs.")
                self.history_results.setHtml(
                    theme.empty_state_html("No runs yet", lines, self.palette_colours))

        def _show_history_run(self, index: int) -> None:
            if self.api is None or index < 0 or index >= len(self._history_ids):
                return
            try:
                scan = self.api.get_scan(self._history_ids[index])
            except Exception as exc:  # noqa: BLE001
                self.history_results.setHtml(
                    f"<pre style='color:#b00020; white-space:pre-wrap'>{_escape(exc)}</pre>")
                return
            self.history_results.setHtml(_payload_to_html(scan))

        def _delete_history_run(self) -> None:
            if self.api is None:
                return
            index = self.history_combo.currentIndex()
            if index < 0 or index >= len(self._history_ids):
                QMessageBox.information(self, "Nothing selected", "Pick a run from the list first.")
                return

            run_id = self._history_ids[index]
            label = self.history_combo.currentText()
            if QMessageBox.question(
                self, "Delete run",
                f"Permanently delete this run from your account?\n\n{label}",
            ) != QMessageBox.Yes:
                return

            try:
                self.api.delete_scan(run_id)
            except Exception as exc:  # noqa: BLE001
                QMessageBox.warning(self, "Could not delete", str(exc))
                return

            self.statusBar().showMessage("Run deleted from your account.")
            self._reload_history()

        def _clear_history(self) -> None:
            if self.api is None:
                return
            if not self._history_ids:
                QMessageBox.information(self, "Nothing to clear", "There is no history yet.")
                return

            if QMessageBox.question(
                self, "Clear history",
                f"Permanently delete all {len(self._history_ids)} run(s) saved to your "
                "account?\n\nThis cannot be undone. Exported report files on this "
                "computer are not affected.",
            ) != QMessageBox.Yes:
                return

            try:
                removed = self.api.clear_history()
            except Exception as exc:  # noqa: BLE001
                QMessageBox.warning(self, "Could not clear history", str(exc))
                return

            self.statusBar().showMessage(f"Cleared {removed} run(s) from your account.")
            self._reload_history()

        def _compare_runs(self) -> None:
            """Premium. Compare two runs saved to the account.

            Uses the server's copies rather than the local database, because the comparison
            itself is a server feature and matching is done there by category and component.
            """
            if self.api is None:
                return
            from PySide6.QtWidgets import QDialog, QDialogButtonBox, QFormLayout

            try:
                self.setCursor(Qt.WaitCursor)
                scans = self.api.list_history(limit=100).get("scans", [])
            except Exception as exc:  # noqa: BLE001
                QMessageBox.warning(self, "Could not load your runs", str(exc))
                return
            finally:
                self.setCursor(Qt.ArrowCursor)

            if len(scans) < 2:
                QMessageBox.information(
                    self, "Not enough runs",
                    "You need at least two runs saved to your account before they can be "
                    "compared. Run a scan or an assessment first — every finished run is "
                    "saved automatically.")
                return

            def describe(scan: dict) -> str:
                target = scan.get("target") or {}
                label = target.get("packageName") or target.get("apkFileName") or "unknown"
                return f"{str(scan.get('createdAt', ''))[:19]}  {label}"

            labels = [describe(s) for s in scans]

            dialog = QDialog(self)
            dialog.setWindowTitle("Compare two runs")
            dialog.setMinimumWidth(520)
            dl = QVBoxLayout(dialog)
            intro = QLabel(
                "Pick the earlier run as the baseline and the later one as the current "
                "result. Findings are matched by category and component, so a fix shows up "
                "as resolved even though each run generates fresh identifiers.")
            intro.setWordWrap(True)
            dl.addWidget(intro)

            form = QFormLayout()
            baseline_combo = QComboBox()
            baseline_combo.addItems(labels)
            baseline_combo.setCurrentIndex(min(1, len(labels) - 1))
            current_combo = QComboBox()
            current_combo.addItems(labels)
            current_combo.setCurrentIndex(0)
            form.addRow("Baseline (earlier):", baseline_combo)
            form.addRow("Current (later):", current_combo)
            dl.addLayout(form)

            buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            buttons.button(QDialogButtonBox.Ok).setText("Compare")
            buttons.accepted.connect(dialog.accept)
            buttons.rejected.connect(dialog.reject)
            dl.addWidget(buttons)

            if dialog.exec() != QDialog.Accepted:
                return

            a, b = baseline_combo.currentIndex(), current_combo.currentIndex()
            if a == b:
                QMessageBox.information(self, "Same run", "Pick two different runs.")
                return

            try:
                self.setCursor(Qt.WaitCursor)
                comparison = self.api.compare_scans(scans[a]["id"], scans[b]["id"])
            except Exception as exc:  # noqa: BLE001
                QMessageBox.warning(self, "Could not compare", str(exc))
                return
            finally:
                self.setCursor(Qt.ArrowCursor)

            self.history_results.setHtml(_comparison_html(comparison, self.palette_colours))
            summary = comparison["summary"]
            self.statusBar().showMessage(
                f"Comparison: {summary['resolved']} fixed, {summary['introduced']} new, "
                f"{summary['unchanged']} unchanged.")


        # ---- Shared job machinery ----------------------------------------- #

        def _start_job(self, job, button, progress, results_view, open_btn, status_msg,
                       sync_result: dict | None = None, summary_label=None,
                       stage_label=None, cancel_btn=None, retry_btn=None,
                       apk_file_name: str | None = None) -> None:
            import threading

            if self._thread is not None:
                QMessageBox.information(self, "Busy", "A task is already running.")
                return

            self._cancel_event = threading.Event()

            button.setEnabled(False)
            button.hide()
            open_btn.setEnabled(False)
            if cancel_btn is not None:
                cancel_btn.setEnabled(True)
                cancel_btn.show()
            if retry_btn is not None:
                # A previous failed run's retry button must not linger once a fresh run
                # starts; it gets its own chance to show again if this one fails too.
                retry_btn.hide()
            if stage_label is not None:
                stage_label.setText(status_msg)
                stage_label.show()
            progress.show()
            # Clear the previous run's badges so a stale summary is never shown beside
            # a run that is still going.
            if summary_label is not None:
                summary_label.hide()
            results_view.setHtml(
                f"<div style='padding:18px 20px;color:{self.palette_colours['muted']};"
                f"font-family:\"Segoe UI\",Arial,sans-serif'>{status_msg}</div>")
            self.statusBar().showMessage(status_msg)

            # Remember which widgets this job drives; the finished/failed handlers
            # (which run on the MAIN thread) read this. `sync_result` is filled in by the
            # worker thread and read here afterwards; the finished signal orders the two.
            self._job_ctx = {
                "button": button, "progress": progress,
                "results_view": results_view, "open_btn": open_btn,
                "sync": sync_result if sync_result is not None else {},
                "summary": summary_label,
                "stage": stage_label,
                "cancel_btn": cancel_btn,
                "retry_btn": retry_btn,
                "apk_file_name": apk_file_name,
                "run": None,
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
            self._worker.progress.connect(self._on_job_progress)
            self._worker.cancelled.connect(self._on_job_cancelled)
            self._thread.start()

        def _on_job_progress(self, stage: str) -> None:
            """Show the step the worker has just started. Runs on the main thread."""
            ctx = self._job_ctx or {}
            label = ctx.get("stage")
            if label is not None:
                label.setText(stage + "…")
            self.statusBar().showMessage(stage + "…")

        def _cancel_job(self) -> None:
            """Ask the running job to stop at its next step boundary."""
            if self._cancel_event is None:
                return
            self._cancel_event.set()
            ctx = self._job_ctx or {}
            if ctx.get("cancel_btn") is not None:
                # Disabled rather than hidden, so the user can see the request landed
                # instead of wondering whether the click registered.
                ctx["cancel_btn"].setEnabled(False)
            if ctx.get("stage") is not None:
                ctx["stage"].setText("Stopping after the current step…")
            self.statusBar().showMessage("Stopping after the current step…")

        def _on_job_cancelled(self) -> None:
            ctx = self._job_ctx
            if ctx.get("stage") is not None:
                ctx["stage"].hide()
            ctx["results_view"].setHtml(theme.empty_state_html(
                "Stopped",
                ["You cancelled this run, so no findings were produced.",
                 "Nothing was saved and nothing on the device was changed.",
                 "Start it again whenever you are ready."],
                self.palette_colours))
            self.statusBar().showMessage("Run cancelled.")
            self._cleanup_thread(ctx["button"], ctx["progress"])

        def _on_job_finished(self, run_: object) -> None:
            ctx = self._job_ctx
            ctx["run"] = run_   # kept for the retry button, whether or not the upload worked
            if ctx.get("stage") is not None:
                ctx["stage"].hide()
            try:
                self._last_report_path = core.write_report(run_, self.cfg)
            except Exception as exc:  # noqa: BLE001 - findings still shown
                self._last_report_path = None
                _log_diag(f"write_report failed: {exc}")
                self.statusBar().showMessage(f"Report export failed: {exc}")
            html = generator.render_html(run_)

            # Prepend the sync outcome so a failed upload is visible without hiding the
            # findings, which are the point of the run.
            sync = ctx.get("sync") or {}
            html = _sync_banner_html(sync) + html
            if ctx.get("retry_btn") is not None:
                ctx["retry_btn"].setVisible(bool(sync.get("error")))
                ctx["retry_btn"].setEnabled(True)

            ctx["results_view"].setHtml(html)
            ctx["open_btn"].setEnabled(self._last_report_path is not None)
            counts = run_.counts()

            # Coloured count badges above the report, so the shape of the result is
            # readable at a glance before anyone starts reading findings.
            summary_label = ctx.get("summary")
            if summary_label is not None:
                summary_label.setText(
                    f"<span style='color:{self.palette_colours['muted']}'>"
                    f"{_escape(run_.package)}</span>&nbsp;&nbsp;&nbsp;"
                    + theme.severity_chips_html(counts, self.palette_colours)
                )
                summary_label.show()

            # The server-backed actions only make sense once the run exists there.
            self._last_scan_id = sync.get("scan_id")
            premium = bool(self.api and self.api.account and self.api.account.is_premium)
            for explain_btn, save_btn in (
                (self.scan_explain_btn, self.scan_save_report_btn),
                (self.assess_explain_btn, self.assess_save_report_btn),
            ):
                explain_btn.setEnabled(bool(self._last_scan_id))
                save_btn.setEnabled(bool(self._last_scan_id) and premium)

            summary = ", ".join(f"{k} {v}" for k, v in counts.items() if v) or "no findings"
            status = f"Done: {run_.package} — {summary}"
            if sync.get("error"):
                status += "  (not saved to account)"
            elif sync.get("scan_id"):
                status += "  (saved to account)"
            self.statusBar().showMessage(status)
            self._cleanup_thread(ctx["button"], ctx["progress"])

        def _on_job_failed(self, msg: str) -> None:
            ctx = self._job_ctx
            if ctx.get("stage") is not None:
                ctx["stage"].hide()
            ctx["results_view"].setHtml(
                f"<pre style='color:#b00020; white-space:pre-wrap'>{msg}</pre>")
            self.statusBar().showMessage("Failed")
            self._cleanup_thread(ctx["button"], ctx["progress"])

        def _cleanup_thread(self, button, progress) -> None:
            progress.hide()
            button.setEnabled(True)
            button.show()
            ctx = self._job_ctx or {}
            if ctx.get("cancel_btn") is not None:
                ctx["cancel_btn"].hide()
            self._cancel_event = None
            if self._thread is not None:
                self._thread.quit()
                self._thread.wait()
            self._thread = None
            self._worker = None
            self._reload_history()

        def _explain_last_run(self) -> None:
            """Ask the server to explain every finding of the last saved run.

            Done server-side so the AI key stays on the server, and every finding's evidence
            is stripped of secrets before it is sent. Explanations already generated are
            reused rather than paid for twice.
            """
            if self.api is None or not self._last_scan_id:
                return
            try:
                self.setCursor(Qt.WaitCursor)
                scan = self.api.get_scan(self._last_scan_id)
                findings = scan.get("findings", [])
                if not findings:
                    QMessageBox.information(self, "Nothing to explain",
                                            "That run has no findings.")
                    return

                explained = 0
                failures = []
                for index, finding in enumerate(findings):
                    if finding.get("explanation") and finding.get("mitigation"):
                        continue    # already has one
                    try:
                        self.api.explain_finding(self._last_scan_id, index)
                        explained += 1
                    except Exception as exc:  # noqa: BLE001 - keep going through the rest
                        failures.append(f"{finding.get('title', 'finding')}: {exc}")
            finally:
                self.setCursor(Qt.ArrowCursor)

            if explained == 0 and not failures:
                QMessageBox.information(
                    self, "Already explained",
                    "Every finding in that run already has an explanation.")
                return

            message = f"Explained {explained} finding(s)."
            if failures:
                joined = chr(10).join(failures[:3])
                message += f"{chr(10)}{chr(10)}Some could not be explained:{chr(10)}{joined}"
            QMessageBox.information(self, "Explanations generated", message)
            self.statusBar().showMessage(
                f"{explained} finding(s) explained. Open the report to read them.")

        def _save_server_report(self) -> None:
            """Premium. Download the report the server holds for the last saved run."""
            if self.api is None or not self._last_scan_id:
                return
            path, _ = QFileDialog.getSaveFileName(
                self, "Save report", f"bioaudit-{self._last_scan_id}.html",
                "Web page (*.html);;All files (*)")
            if not path:
                return
            try:
                self.setCursor(Qt.WaitCursor)
                html = self.api.export_report(self._last_scan_id)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(html)
            except Exception as exc:  # noqa: BLE001
                QMessageBox.warning(self, "Could not save the report", str(exc))
                return
            finally:
                self.setCursor(Qt.ArrowCursor)
            self.statusBar().showMessage(f"Report saved to {path}")
            if QMessageBox.question(self, "Report saved",
                                    "Open it now?") == QMessageBox.Yes:
                QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.abspath(path)))

        def _open_last_report(self) -> None:
            if self._last_report_path and os.path.exists(self._last_report_path):
                QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.abspath(self._last_report_path)))
            else:
                QMessageBox.information(self, "No report", "No report file is available yet.")

    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("BioAudit")

    # Styling must not be able to stop the app opening, so a failure here degrades to
    # Qt's default look rather than raising.
    try:
        palette_colours = theme.apply_theme(app)
    except Exception as exc:  # noqa: BLE001
        _log_diag(f"could not apply theme: {exc}")
        palette_colours = theme.LIGHT

    window = MainWindow()
    window.show()
    return app.exec()


def _comparison_html(comparison: dict, palette: dict) -> str:
    """Render a run-to-run comparison.

    Resolved comes first because that is the question a developer actually has after a fix:
    did the thing I changed go away? New findings come second, since a regression matters
    more than a list of what stayed the same.
    """
    from . import theme

    summary = comparison["summary"]

    def group(title: str, findings: list, colour: str, empty: str) -> str:
        if not findings:
            return (f"<h3 style='color:{palette['muted']};font-size:11pt'>{title}</h3>"
                    f"<p style='color:{palette['muted']}'>{empty}</p>")
        items = []
        for f in findings:
            sev = str(f.get("severity", "info")).lower()
            sev_colour = theme.SEVERITY_COLOURS.get(sev, theme.SEVERITY_COLOURS["info"])
            component = f.get("component")
            items.append(
                f"<li style='margin-bottom:6px'>"
                f"<span style='background:{sev_colour};color:#fff;padding:1px 7px;"
                f"border-radius:9px;font-size:8pt;font-weight:700'>{_escape(sev.upper())}</span> "
                f"{_escape(f.get('title', ''))}"
                + (f"<br><span style='color:{palette['muted']};font-size:9pt'>"
                   f"{_escape(component)}</span>" if component else "")
                + "</li>"
            )
        return (f"<h3 style='color:{colour};font-size:11pt'>{title} ({len(findings)})</h3>"
                f"<ul style='padding-left:18px;margin-top:4px'>{''.join(items)}</ul>")

    return f"""
    <div style="font-family:'Segoe UI',Arial,sans-serif;padding:14px 18px">
      <h2 style="color:{palette['text']};font-size:14pt;margin:0 0 4px 0">Run comparison</h2>
      <p style="color:{palette['muted']};margin:0 0 14px 0">
        Baseline {_escape(str(comparison['baseline'].get('createdAt', ''))[:19])}
        &nbsp;→&nbsp;
        Current {_escape(str(comparison['current'].get('createdAt', ''))[:19])}
      </p>
      <p style="margin-bottom:16px">
        <span style="background:#188038;color:#fff;padding:2px 9px;border-radius:10px;
              font-weight:700;font-size:9pt">{summary['resolved']} fixed</span>&nbsp;&nbsp;
        <span style="background:#d93025;color:#fff;padding:2px 9px;border-radius:10px;
              font-weight:700;font-size:9pt">{summary['introduced']} new</span>&nbsp;&nbsp;
        <span style="background:{palette['muted']};color:#fff;padding:2px 9px;
              border-radius:10px;font-weight:700;font-size:9pt">
              {summary['unchanged']} unchanged</span>
      </p>
      {group("Fixed since the baseline", comparison.get("resolved", []), "#188038",
             "Nothing was fixed between these two runs.")}
      {group("New in the current run", comparison.get("introduced", []), "#d93025",
             "No new problems appeared. Good.")}
      {group("Still present", comparison.get("unchanged", []), palette["muted"],
             "Nothing carried over.")}
    </div>
    """


def _escape(value: object) -> str:
    """Escape text before it goes into the on-screen HTML.

    Server messages and target names both end up in these views, and a package name or
    an error string is not something to trust as markup.
    """
    import html

    return html.escape(str(value if value is not None else ""))


def _sync_banner_html(sync: dict) -> str:
    """The strip shown above a run's findings reporting whether it saved.

    Shared between a fresh run and a retry, so both look identical. There is no local
    fallback to reassure the user about on failure: the account is the only place a run
    is stored, so the banner says that plainly and points at the retry button instead.
    """
    if sync.get("error"):
        return (
            "<div style='background:#fce8e6;border-left:4px solid #d93025;"
            "padding:8px 12px;margin-bottom:12px'>"
            f"<b>Not saved to your account:</b> {_escape(sync['error'])}<br>"
            "This run is not stored anywhere yet — BioAudit does not keep a local copy. "
            "The findings are still shown below; use \"Retry saving\" once you are back "
            "online, or before you close this run.</div>"
        )
    if sync.get("message"):
        return (
            "<div style='background:#e6f4ea;border-left:4px solid #188038;"
            "padding:8px 12px;margin-bottom:12px'>"
            f"{_escape(sync['message'])}</div>"
        )
    return ""


def _payload_to_html(payload: dict) -> str:
    """Reconstruct a TestRun from a scan fetched from the server and render it via the
    report generator, so a history entry looks identical to a fresh result.

    The shape here is whatever `ApiClient.get_scan` returns — a package/device name
    nested under `target`, and each finding's severity stored as its lower-case enum
    name (see `_finding_to_payload` in `api/client.py`), not the capitalised label a
    fresh `TestRun` uses on screen.
    """
    from ..models import Finding, Severity

    def severity_from(value: str) -> Severity:
        try:
            return Severity[str(value).upper()]
        except KeyError:
            return Severity.INFO

    target = payload.get("target") or {}
    package = target.get("packageName") or target.get("apkFileName") or "?"
    run = TestRun(package=package, device_serial=target.get("deviceSerial"))
    run.id = payload.get("id", run.id)
    for fd in payload.get("findings", []):
        run.add(Finding(
            category=fd.get("category", ""),
            title=fd.get("title", ""),
            severity=severity_from(fd.get("severity", "info")),
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
