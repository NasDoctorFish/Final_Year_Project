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
        QGroupBox, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QMainWindow,
        QMessageBox, QProgressBar, QPushButton, QSizePolicy, QTabWidget,
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
    # Files, a read-only mount, etc.), which would make the SQLite history and the
    # report export raise. Anchor both under the user's home so writes always work.
    from pathlib import Path
    _base = Path(os.path.expanduser("~")) / "BioAudit"
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
            if not self.cfg.api.get("enabled", False):
                return
            try:
                from .signin import restore_session
                client = restore_session(self._session_dir, self.cfg.api["base_url"])
            except Exception as exc:  # noqa: BLE001
                _log_diag(f"session restore failed: {exc}")
                return
            if client is not None:
                self.api = client
                self.statusBar().showMessage("Signed in from a saved session.")

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

            # The sync checkboxes only mean something with somewhere to sync to.
            for box in (self.scan_sync, self.assess_sync):
                box.setEnabled(signed_in)
                box.setToolTip(
                    "Upload this run to your account when it finishes."
                    if signed_in
                    else "Sign in from the Account menu to save results to the server."
                )
            self.cloud_history_btn.setEnabled(signed_in)

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
            self.statusBar().showMessage("Signed out. Results stay on this computer.")

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

        def _sync_enabled(self, checkbox) -> bool:
            return self.api is not None and checkbox.isChecked()

        def _upload(self, run_, *, authorised: bool, apk_file_name: str | None,
                    into: dict) -> None:
            """Upload a finished run, recording the outcome in `into`.

            Called from the worker thread, so it must not touch a widget. The result is
            left in the dict the caller passed, which the main thread reads once the
            finished signal arrives. Emitting that signal is the handover point, so no
            further synchronisation is needed.

            An upload failure must never lose the scan, which is why every error is
            captured rather than raised.
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

            # --- options ----------------------------------------------
            options, ol = _section("Options")
            self.scan_explain = QCheckBox("Explain each finding in plain language (uses the AI layer)")
            self.scan_sync = QCheckBox("Save this run to my account")
            self.scan_sync.setChecked(bool(self.cfg.api.get("auto_sync", True)))
            ol.addWidget(self.scan_explain)
            ol.addWidget(self.scan_sync)
            layout.addWidget(options)

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
            action.addWidget(self.scan_btn)
            action.addWidget(self.scan_open_report)
            action.addWidget(self.scan_explain_btn)
            action.addWidget(self.scan_save_report_btn)
            action.addStretch(1)
            layout.addLayout(action)

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
                 "Nothing is sent anywhere unless you sign in and tick the save box."],
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

            explain = self.scan_explain.isChecked()
            sync = self._sync_enabled(self.scan_sync)
            sync_result: dict = {}
            apk_name = os.path.basename(apk)

            def job() -> TestRun:
                # Heavy work on the worker thread; the report (weasyprint/GTK) is
                # written later on the main thread in _start_job's finished handler.
                run_ = core.build_scan_apk(apk, self.cfg)
                core.process_findings(run_, self.cfg, explain)
                if sync:
                    # A static scan reads a file the user chose, so there is no live app
                    # to authorise probing against.
                    self._upload(run_, authorised=True, apk_file_name=apk_name,
                                 into=sync_result)
                return run_

            self._start_job(job, self.scan_btn, self.scan_progress, self.scan_results,
                            self.scan_open_report, "Reading the app's files…",
                            sync_result=sync_result, summary_label=self.scan_summary)

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

            # --- options ----------------------------------------------
            options, ol = _section("Options")
            self.assess_ai = QCheckBox("Explain each finding in plain language (uses the AI layer)")
            self.assess_ai.setChecked(True)
            self.assess_sync = QCheckBox("Save this run to my account")
            self.assess_sync.setChecked(bool(self.cfg.api.get("auto_sync", True)))
            ol.addWidget(self.assess_ai)
            ol.addWidget(self.assess_sync)
            layout.addWidget(options)

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
            action.addWidget(self.assess_btn)
            action.addWidget(self.assess_open_report)
            action.addWidget(self.assess_explain_btn)
            action.addWidget(self.assess_save_report_btn)
            action.addStretch(1)
            layout.addLayout(action)

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
            explain = self.assess_ai.isChecked()

            # Honour the device selected in the combo box for this run.
            cfg = self.cfg
            selected_serial = serial if self.device_combo.isEnabled() else None
            sync = self._sync_enabled(self.assess_sync)
            sync_result: dict = {}
            apk_name = os.path.basename(apk) if apk else None

            def job() -> TestRun:
                adb = Adb(cfg.device["adb_path"], selected_serial or cfg.device["serial"])
                run_ = core.build_assess(package, apk, cfg, adb=adb)
                core.process_findings(run_, cfg, explain)   # report written on main thread
                if sync:
                    # The authorisation box was ticked to get here, and the server
                    # refuses a device assessment that does not carry that confirmation.
                    self._upload(run_, authorised=True, apk_file_name=apk_name,
                                 into=sync_result)
                return run_

            self._start_job(job, self.assess_btn, self.assess_progress, self.assess_results,
                            self.assess_open_report, "Testing the app on the device…",
                            sync_result=sync_result, summary_label=self.assess_summary)

        # ---- History tab -------------------------------------------------- #

        def _build_history_tab(self) -> QWidget:
            w = QWidget()
            layout = QVBoxLayout(w)
            layout.setContentsMargins(16, 12, 16, 12)
            layout.setSpacing(10)

            picker, pl = _section("Past runs on this computer")
            top = QHBoxLayout()
            top.setSpacing(8)
            self.history_combo = QComboBox()
            reload_btn = QPushButton("Reload")
            reload_btn.clicked.connect(self._reload_history)
            self.cloud_history_btn = QPushButton("Show account history")
            self.cloud_history_btn.setToolTip(
                "List the runs saved to your account, which may include runs from "
                "another computer."
            )
            self.cloud_history_btn.clicked.connect(self._show_cloud_history)
            top.addWidget(self.history_combo, 1)
            top.addWidget(reload_btn)
            top.addWidget(self.cloud_history_btn)
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

        def _delete_history_run(self) -> None:
            """Delete the selected run from this computer, and optionally from the account.

            The two copies are removed separately and asked about separately, because a user
            clearing their local history does not necessarily want to lose the copy their
            team can see, or the other way round.
            """
            from ..storage.history import History

            index = self.history_combo.currentIndex()
            if index < 0 or index >= len(self._history_ids):
                QMessageBox.information(self, "Nothing selected", "Pick a run from the list first.")
                return

            run_id = self._history_ids[index]
            label = self.history_combo.currentText()
            if QMessageBox.question(
                self, "Delete run",
                f"Delete this run from this computer?\n\n{label}",
            ) != QMessageBox.Yes:
                return

            try:
                History(self.cfg.storage["database"]).delete(run_id)
            except Exception as exc:  # noqa: BLE001
                QMessageBox.warning(self, "Could not delete", str(exc))
                return

            self.statusBar().showMessage("Run deleted from this computer.")
            self._reload_history()

        def _clear_history(self) -> None:
            from ..storage.history import History

            if not self._history_ids:
                QMessageBox.information(self, "Nothing to clear", "There is no history yet.")
                return

            if QMessageBox.question(
                self, "Clear history",
                f"Delete all {len(self._history_ids)} run(s) from this computer?\n\n"
                "This cannot be undone. Exported report files are not affected.",
            ) != QMessageBox.Yes:
                return

            try:
                removed = History(self.cfg.storage["database"]).clear()
            except Exception as exc:  # noqa: BLE001
                QMessageBox.warning(self, "Could not clear history", str(exc))
                return

            # Offer the server copy separately rather than assuming.
            if self.api is not None:
                if QMessageBox.question(
                    self, "Clear account history",
                    "Also delete the runs saved to your account on the server?",
                ) == QMessageBox.Yes:
                    try:
                        server_removed = self.api.clear_history()
                        self.statusBar().showMessage(
                            f"Cleared {removed} local and {server_removed} account run(s).")
                    except Exception as exc:  # noqa: BLE001
                        QMessageBox.warning(self, "Could not clear account history", str(exc))
                    self._reload_history()
                    return

            self.statusBar().showMessage(f"Cleared {removed} run(s) from this computer.")
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
                    "compared. Tick \"Save this run to my account\" when you scan.")
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

        def _show_cloud_history(self) -> None:
            """List what the account has stored on the server.

            Deliberately a separate view rather than merged into the local list. The two
            can legitimately differ: a free account is trimmed to its newest runs on the
            server while the local database keeps everything, and merging them would hide
            that difference instead of showing it.
            """
            if self.api is None:
                QMessageBox.information(
                    self, "Not signed in",
                    "Sign in from the Account menu to see the runs saved to your account."
                )
                return

            try:
                data = self.api.list_history(limit=100)
            except Exception as exc:  # noqa: BLE001
                QMessageBox.warning(self, "Could not load history", str(exc))
                return

            scans = data.get("scans", [])
            limit = data.get("historyLimit")
            rows = []
            for scan in scans:
                counts = scan.get("counts") or {}
                severities = " ".join(
                    f"{name[0].upper()}{counts.get(name, 0)}"
                    for name in ("critical", "high", "medium", "low", "info")
                    if counts.get(name)
                ) or "no findings"
                target = (scan.get("target") or {})
                # Show the package name as the identity, but keep the file or device it
                # came from as well. Without that, two runs of the same app from
                # different APK builds look identical in this list.
                label = target.get("packageName") or target.get("apkFileName") or "unknown target"
                source = target.get("apkFileName") or target.get("deviceSerial")
                if source and source != label:
                    label = f"{label}<br><span style='color:#5f6368;font-size:11px'>{_escape(source)}</span>"
                else:
                    label = _escape(label)

                kind = "device" if scan.get("type") == "device" else "file"
                rows.append(
                    f"<tr><td>{_escape(str(scan.get('createdAt', ''))[:19])}</td>"
                    f"<td>{label}</td><td>{kind}</td>"
                    f"<td>{_escape(severities)}</td>"
                    f"<td style='color:#5f6368'>{_escape(scan.get('id', ''))}</td></tr>"
                )

            note = (
                f"Your plan keeps the newest {limit} runs on the server. "
                "Older ones are removed there, though this computer still has them below."
                if limit is not None
                else "Your plan keeps your full history on the server."
            )

            if rows:
                body = (
                    "<table cellpadding='5' cellspacing='0' border='0'>"
                    "<tr style='background:#f1f3f4'><th align='left'>When</th>"
                    "<th align='left'>Target</th><th align='left'>Kind</th>"
                    "<th align='left'>Findings</th><th align='left'>Reference</th></tr>"
                    + "".join(rows) + "</table>"
                )
            else:
                body = "<p>No runs have been saved to this account yet.</p>"

            self.history_results.setHtml(
                f"<h2>Account history</h2><p style='color:#5f6368'>{note}</p>{body}"
            )
            self.statusBar().showMessage(f"{len(scans)} run(s) saved to your account.")

        # ---- Shared job machinery ----------------------------------------- #

        def _start_job(self, job, button, progress, results_view, open_btn, status_msg,
                       sync_result: dict | None = None, summary_label=None) -> None:
            if self._thread is not None:
                QMessageBox.information(self, "Busy", "A task is already running.")
                return

            button.setEnabled(False)
            open_btn.setEnabled(False)
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
            html = generator.render_html(run_)

            # Prepend the sync outcome so a failed upload is visible without hiding the
            # findings, which are the point of the run and are already safe on disk.
            sync = ctx.get("sync") or {}
            if sync.get("error"):
                html = (
                    "<div style='background:#fce8e6;border-left:4px solid #d93025;"
                    "padding:8px 12px;margin-bottom:12px'>"
                    f"<b>Not saved to your account:</b> {_escape(sync['error'])}<br>"
                    "The findings below are saved on this computer and the report was "
                    "still written.</div>" + html
                )
            elif sync.get("message"):
                html = (
                    "<div style='background:#e6f4ea;border-left:4px solid #188038;"
                    "padding:8px 12px;margin-bottom:12px'>"
                    f"{_escape(sync['message'])}</div>" + html
                )

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
