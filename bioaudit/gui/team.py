"""The Team tab: everything an organisation admin can do.

Covers the whole Admin branch of the functional hierarchy: invite a team member, cancel a
pending invitation, view member data, flag member data, review flagged items, remove a
member, delete a member's account, and add another admin. The audit log is shown too,
because these are the only powers in the product that reach beyond the caller's own data
and a record of them is what makes that acceptable.

A note on threading: these are small requests, so they run on the UI thread with a wait
cursor rather than through the worker machinery the scans use. That keeps the code
readable at the cost of a brief pause. The client's timeout bounds the worst case, so a
dead server fails with a message instead of hanging forever.

A note on privacy: a member's run list shows only summaries, and an admin reads a run's
findings by opening it on purpose. The server allows that only while the run's owner is a
member of the admin's organisation and records every read in the activity log. Findings
are evidence, not code: an app's code never leaves the machine it was scanned on.
"""

from __future__ import annotations

from typing import Optional

from ..api import ApiClient, ApiClientError
from .formatting import format_when
from .theme import ERROR_TEXT, SEVERITY_COLOURS

# The Status cell's text for a blocked account. Named because it is both written into
# the table and read back out of it to decide which way the suspend button acts.
_SUSPENDED = "suspended"


def _run_labels(scans: list[dict]) -> list[str]:
    """One selectable label per run. Shared so the pick lists cannot drift apart."""
    labels = []
    for s in scans:
        target = s.get("target") or {}
        name = target.get("packageName") or target.get("apkFileName") or "unknown"
        labels.append(f"{format_when(s.get('createdAt'))}  ·  {name}")
    return labels


def _findings_html(findings: list[dict], palette: dict) -> str:
    """Render a member's findings read-only, in the same shape as the owner's report.

    Deliberately plain: an admin is reviewing evidence, so severity, confidence and the
    raw evidence string matter more than presentation, and nothing here offers an edit.
    """
    import html as _html

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ranked = sorted(findings, key=lambda f: order.get(str(f.get("severity", "")).lower(), 9))

    parts = [f"<div style='font-family:\"Segoe UI\",Arial,sans-serif;color:{palette['text']}'>"]
    for f in ranked:
        sev = str(f.get("severity", "info")).lower()
        colour = SEVERITY_COLOURS.get(sev, SEVERITY_COLOURS["info"])
        owasp = ", ".join(f.get("owasp") or []) or "not mapped"
        parts.append(
            f"<p style='margin:14px 0 2px'>"
            f"<span style='background:{colour};color:#fff;padding:1px 7px;"
            f"border-radius:3px;font-size:11px'>{_html.escape(sev.capitalize())}</span>"
            f"&nbsp;<b>{_html.escape(str(f.get('title', 'Finding')))}</b>"
            f"&nbsp;<span style='color:{palette['muted']};font-size:11px'>"
            f"{_html.escape(owasp)} &middot; {_html.escape(str(f.get('confidence', '')))}"
            f"</span></p>"
        )
        if f.get("component"):
            parts.append(
                f"<p style='margin:0 0 2px;color:{palette['muted']};font-size:12px'>"
                f"Component: {_html.escape(str(f['component']))}</p>")
        parts.append(
            f"<p style='margin:0 0 2px;font-size:12px'><i>Evidence:</i> "
            f"{_html.escape(str(f.get('evidence', '')))}</p>")
        if f.get("mitigation"):
            parts.append(
                f"<p style='margin:0 0 2px;font-size:12px'><i>Fix:</i> "
                f"{_html.escape(str(f['mitigation']))}</p>")
        if f.get("explanation"):
            parts.append(
                f"<p style='margin:0 0 2px;font-size:12px;color:{palette['muted']}'>"
                f"{_html.escape(str(f['explanation']))}</p>")
    parts.append("</div>")
    return "".join(parts)


def make_team_tab(parent_window, palette: dict):
    """Build the Team tab. Returns the widget; it reads the client from parent_window.api."""
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import (
        QAbstractItemView, QDialog, QDialogButtonBox, QComboBox, QFormLayout,
        QHBoxLayout, QInputDialog, QLabel, QLineEdit,
        QMessageBox, QPushButton, QTableWidget, QTableWidgetItem, QTabWidget,
        QTextEdit, QVBoxLayout, QWidget,
    )

    def _table(headers: list[str]) -> QTableWidget:
        t = QTableWidget(0, len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.setSelectionBehavior(QAbstractItemView.SelectRows)
        t.setSelectionMode(QAbstractItemView.SingleSelection)
        t.setEditTriggers(QAbstractItemView.NoEditTriggers)
        t.verticalHeader().setVisible(False)
        t.horizontalHeader().setStretchLastSection(True)
        t.setAlternatingRowColors(True)
        return t

    def _fill(table: QTableWidget, rows: list[list[str]], keys: list[str] | None = None) -> None:
        """Replace the table's contents. `keys` are stashed on column 0 for lookups."""
        table.setRowCount(0)
        for i, row in enumerate(rows):
            table.insertRow(i)
            for j, value in enumerate(row):
                item = QTableWidgetItem(str(value))
                if j == 0 and keys:
                    item.setData(Qt.UserRole, keys[i])
                table.setItem(i, j, item)
        table.resizeColumnsToContents()
        table.horizontalHeader().setStretchLastSection(True)

    def _selected_key(table: QTableWidget) -> Optional[str]:
        row = table.currentRow()
        if row < 0:
            return None
        item = table.item(row, 0)
        return item.data(Qt.UserRole) if item else None

    class TeamTab(QWidget):
        def __init__(self) -> None:
            super().__init__()
            self.org_id: Optional[str] = None

            layout = QVBoxLayout(self)
            layout.setContentsMargins(16, 12, 16, 12)
            layout.setSpacing(10)

            # Header showing which organisation is being managed.
            top = QHBoxLayout()
            self.org_label = QLabel("")
            self.org_label.setTextFormat(Qt.RichText)
            self.refresh_btn = QPushButton("Refresh")
            self.refresh_btn.clicked.connect(self.reload)
            top.addWidget(self.org_label, 1)
            top.addWidget(self.refresh_btn)
            layout.addLayout(top)

            # Shown instead of the tabs when the signed-in user is not an admin, so the tab
            # explains itself rather than presenting empty tables.
            self.placeholder = QLabel(
                "This tab is for organisation admins.\n\n"
                "Sign in with an admin account to manage members, invitations, and flagged "
                "runs. You can create one from the sign-in window by giving an organisation "
                "name when you register."
            )
            self.placeholder.setWordWrap(True)
            self.placeholder.setAlignment(Qt.AlignCenter)
            self.placeholder.setStyleSheet(f"color: {palette['muted']}; padding: 40px;")
            layout.addWidget(self.placeholder, 1)

            self.tabs = QTabWidget()
            self.tabs.addTab(self._members_tab(), "Members")
            self.tabs.addTab(self._invitations_tab(), "Invitations")
            self.tabs.addTab(self._flags_tab(), "Flagged runs")
            self.tabs.addTab(self._audit_tab(), "Activity log")
            self._subscription_index = self.tabs.addTab(
                self._subscription_tab(), "Subscription")
            self.tabs.hide()
            layout.addWidget(self.tabs, 1)

        # --- shared -----------------------------------------------------
        @property
        def client(self) -> Optional[ApiClient]:
            return parent_window.api

        def _busy(self, on: bool) -> None:
            self.setCursor(Qt.WaitCursor if on else Qt.ArrowCursor)

        def _fail(self, title: str, exc: Exception) -> None:
            QMessageBox.warning(self, title, str(exc))

        def _status(self, text: str) -> None:
            parent_window.statusBar().showMessage(text)

        # --- visibility -------------------------------------------------
        def refresh_visibility(self) -> None:
            """Show the admin tools only when they apply."""
            account = self.client.account if self.client else None
            is_admin = bool(account and account.is_admin and account.organisation_id)

            self.tabs.setVisible(is_admin)
            self.placeholder.setVisible(not is_admin)
            self.refresh_btn.setEnabled(is_admin)

            if is_admin:
                self.org_id = account.organisation_id
                self.reload()
            else:
                self.org_id = None
                self.org_label.setText("")

        def reload(self) -> None:
            if not (self.client and self.org_id):
                return
            try:
                self._busy(True)
                org = self.client.my_organisation()
                if org:
                    self.org_label.setText(
                        f"<b>{org['name']}</b>"
                        f"<span style='color:{palette['muted']}'> &nbsp;·&nbsp; "
                        f"{org['memberCount']} member(s)"
                        f"{' · you are the owner' if org.get('isOwner') else ''}</span>"
                    )
                subscription = (org or {}).get("subscription") or {}
                self._show_subscription(subscription)
                # While suspended the server refuses everything but the subscription, so
                # the other tabs are locked rather than left to fail one by one.
                suspended = subscription.get("active") is False
                for i in range(self.tabs.count()):
                    if i != self._subscription_index:
                        self.tabs.setTabEnabled(i, not suspended)
                if suspended:
                    self.tabs.setCurrentIndex(self._subscription_index)
                    return
                self._load_members()
                self._load_invitations()
                self._load_flags()
                self._load_audit()
            except ApiClientError as exc:
                self._fail("Could not load your organisation", exc)
            finally:
                self._busy(False)

        # =============== members =====================================
        def _members_tab(self) -> QWidget:
            w = QWidget()
            layout = QVBoxLayout(w)

            self.members_table = _table(
                ["Email", "Name", "Role", "Scans", "Status"])
            self.members_table.itemSelectionChanged.connect(self._member_selection_changed)
            layout.addWidget(self.members_table, 1)

            buttons = QHBoxLayout()
            self.view_data_btn = QPushButton("View their runs")
            self.view_data_btn.clicked.connect(self._view_member_data)
            self.make_admin_btn = QPushButton("Make admin")
            self.make_admin_btn.clicked.connect(self._add_admin)
            # Label flips to "Reinstate" when the selected member is already suspended,
            # so one button covers both directions of a reversible action.
            self.suspend_btn = QPushButton("Suspend")
            self.suspend_btn.clicked.connect(self._toggle_member_suspended)
            self.remove_btn = QPushButton("Remove from team")
            self.remove_btn.clicked.connect(self._remove_member)
            self.delete_acct_btn = QPushButton("Delete their account")
            self.delete_acct_btn.clicked.connect(self._delete_member_account)
            for b in (self.view_data_btn, self.make_admin_btn, self.suspend_btn,
                      self.remove_btn, self.delete_acct_btn):
                b.setEnabled(False)
                buttons.addWidget(b)
            buttons.addStretch(1)
            layout.addLayout(buttons)

            note = QLabel(
                "Suspending blocks sign-in but keeps everything, and can be undone. "
                "Removing someone from the team leaves their account and their runs intact. "
                "Deleting their account cannot be undone, and is recorded in the activity log."
            )
            note.setObjectName("hint")
            note.setWordWrap(True)
            layout.addWidget(note)
            return w

        def _member_selection_changed(self) -> None:
            uid = _selected_key(self.members_table)
            own = self.client.account.id if (self.client and self.client.account) else None
            # Acting on yourself here is never what the user means: their own account is
            # managed from the Account menu, and the server refuses it anyway.
            enabled = bool(uid) and uid != own
            for b in (self.view_data_btn, self.remove_btn, self.delete_acct_btn):
                b.setEnabled(enabled)

            row = self.members_table.currentRow()
            role = self.members_table.item(row, 2).text() if row >= 0 else ""
            self.make_admin_btn.setEnabled(enabled and role != "admin")

            suspended = self.members_table.item(row, 4).text() == _SUSPENDED if row >= 0 else False
            self.suspend_btn.setEnabled(enabled)
            self.suspend_btn.setText("Reinstate" if suspended else "Suspend")

        def _load_members(self) -> None:
            members = self.client.list_members(self.org_id)
            rows, keys = [], []
            for m in members:
                rows.append([
                    m.get("email", ""),
                    m.get("displayName") or "",
                    m.get("role", ""),
                    str(m.get("scanCount", 0)),
                    _SUSPENDED if m.get("disabled") else "active",
                ])
                keys.append(m.get("id", ""))
            _fill(self.members_table, rows, keys)
            self._member_selection_changed()

        def _view_member_data(self) -> None:
            uid = _selected_key(self.members_table)
            if not uid:
                return
            try:
                self._busy(True)
                scans = self.client.member_scans(self.org_id, uid)
            except ApiClientError as exc:
                return self._fail("Could not load their runs", exc)
            finally:
                self._busy(False)

            if not scans:
                QMessageBox.information(self, "No runs", "That member has not saved any runs.")
                return

            lines = []
            for s in scans:
                counts = s.get("counts") or {}
                summary = " ".join(
                    f"{k[0].upper()}{v}" for k, v in counts.items() if v) or "no findings"
                target = (s.get("target") or {})
                label = target.get("packageName") or target.get("apkFileName") or "unknown"
                when = format_when(s.get("createdAt"))
                lines.append(f"{when}   {label}   {summary}")

            dialog = QDialog(self)
            dialog.setWindowTitle("Member runs")
            dialog.setMinimumSize(620, 420)
            dl = QVBoxLayout(dialog)
            heading = QLabel(
                f"<b>{len(scans)} run(s)</b><br>"
                f"<span style='color:{palette['muted']}'>This list shows summaries. Open a run "
                f"to read its findings. Both the list and each run you open are recorded in the "
                f"activity log, and findings cannot be edited from here.</span>")
            heading.setTextFormat(Qt.RichText)
            heading.setWordWrap(True)
            dl.addWidget(heading)
            body = QTextEdit()
            body.setReadOnly(True)
            body.setFontFamily("Consolas")
            body.setPlainText("\n".join(lines))
            dl.addWidget(body, 1)

            flag_row = QHBoxLayout()
            open_btn = QPushButton("Open a run…")
            open_btn.clicked.connect(lambda: self._view_member_findings(scans))
            flag_row.addWidget(open_btn)
            flag_btn = QPushButton("Flag one of these runs…")
            flag_btn.clicked.connect(lambda: self._flag_run(scans, dialog))
            flag_row.addWidget(flag_btn)
            flag_row.addStretch(1)
            close = QPushButton("Close")
            close.clicked.connect(dialog.accept)
            flag_row.addWidget(close)
            dl.addLayout(flag_row)
            dialog.exec()
            self._load_audit()

        def _view_member_findings(self, scans: list[dict]) -> None:
            """Open one of a member's runs and show its findings.

            The summary list carries no findings, so the chosen run is fetched on its own.
            The server authorises this for an admin of the same organisation and records
            the read, which is why nothing here needs to re-check the caller's role.
            """
            choice, ok = QInputDialog.getItem(
                self, "Open a run", "Which run?", _run_labels(scans), 0, False)
            if not ok:
                return
            scan = scans[_run_labels(scans).index(choice)]

            try:
                self._busy(True)
                full = self.client.get_scan(scan["id"])
            except ApiClientError as exc:
                return self._fail("Could not open that run", exc)
            finally:
                self._busy(False)

            findings = full.get("findings") or []
            target = (full.get("target") or {})
            label = target.get("packageName") or target.get("apkFileName") or "unknown"

            if not findings:
                QMessageBox.information(
                    self, "No findings", f"That run of {label} recorded no findings.")
                return

            dialog = QDialog(self)
            dialog.setWindowTitle(f"Findings - {label}")
            dialog.setMinimumSize(760, 560)
            dl = QVBoxLayout(dialog)
            note = QLabel(
                f"<b>{label}</b> &nbsp; {format_when(full.get('createdAt'))}<br>"
                f"<span style='color:{palette['muted']}'>Read-only. Opening this run has been "
                f"recorded in the activity log.</span>")
            note.setTextFormat(Qt.RichText)
            note.setWordWrap(True)
            dl.addWidget(note)

            body = QTextEdit()
            body.setReadOnly(True)
            body.setHtml(_findings_html(findings, palette))
            dl.addWidget(body, 1)

            row = QHBoxLayout()
            row.addStretch(1)
            close = QPushButton("Close")
            close.clicked.connect(dialog.accept)
            row.addWidget(close)
            dl.addLayout(row)
            dialog.exec()
            self._load_audit()

        def _flag_run(self, scans: list[dict], owner_dialog) -> None:
            """Raise a flag on a member's run, with a reason."""
            labels = _run_labels(scans)
            choice, ok = QInputDialog.getItem(
                self, "Flag a run", "Which run?", labels, 0, False)
            if not ok:
                return
            scan = scans[labels.index(choice)]

            reason, ok = QInputDialog.getText(
                self, "Flag a run",
                "Why are you flagging it? (at least 5 characters)")
            if not ok:
                return
            if len(reason.strip()) < 5:
                QMessageBox.warning(self, "Reason too short",
                                    "Give a reason of at least 5 characters.")
                return

            try:
                self._busy(True)
                self.client.flag_scan(self.org_id, scan["id"], reason.strip())
            except ApiClientError as exc:
                return self._fail("Could not flag that run", exc)
            finally:
                self._busy(False)

            self._status("Run flagged for review.")
            self._load_flags()
            owner_dialog.accept()

        def _add_admin(self) -> None:
            uid = _selected_key(self.members_table)
            if not uid:
                return
            row = self.members_table.currentRow()
            email = self.members_table.item(row, 0).text()
            if QMessageBox.question(
                self, "Make admin",
                f"Give {email} admin rights over this organisation?\n\n"
                "They will be able to see member activity and remove members.",
            ) != QMessageBox.Yes:
                return
            try:
                self._busy(True)
                self.client.add_admin(self.org_id, uid)
            except ApiClientError as exc:
                return self._fail("Could not add that admin", exc)
            finally:
                self._busy(False)
            QMessageBox.information(
                self, "Admin added",
                f"{email} is now an admin. They need to sign in again for it to take effect.")
            self.reload()

        def _remove_member(self) -> None:
            uid = _selected_key(self.members_table)
            if not uid:
                return
            row = self.members_table.currentRow()
            email = self.members_table.item(row, 0).text()
            if QMessageBox.question(
                self, "Remove member",
                f"Remove {email} from this organisation?\n\n"
                "Their account and their saved runs are kept. They simply stop being part of "
                "the team.",
            ) != QMessageBox.Yes:
                return
            try:
                self._busy(True)
                self.client.remove_member(self.org_id, uid)
            except ApiClientError as exc:
                return self._fail("Could not remove that member", exc)
            finally:
                self._busy(False)
            self._status(f"{email} removed from the organisation.")
            self.reload()

        def _toggle_member_suspended(self) -> None:
            """Block or restore a member's sign-in, depending on their current state."""
            uid = _selected_key(self.members_table)
            if not uid:
                return
            row = self.members_table.currentRow()
            email = self.members_table.item(row, 0).text()
            suspended_now = self.members_table.item(row, 4).text() == _SUSPENDED
            suspend = not suspended_now

            if suspend:
                question = (
                    f"Suspend {email}?\n\n"
                    "They will be signed out immediately and cannot sign back in until you "
                    "reinstate them. Their account and saved runs are kept, and this can be "
                    "undone at any time."
                )
            else:
                question = f"Reinstate {email}?\n\nThey will be able to sign in again."
            if QMessageBox.question(self, "Suspend member" if suspend else "Reinstate member",
                                    question) != QMessageBox.Yes:
                return

            reason = ""
            if suspend:
                # Optional, but recorded in the activity log, which is the whole point of
                # suspending rather than quietly removing someone.
                reason, ok = QInputDialog.getText(
                    self, "Reason (optional)",
                    "Recorded in the activity log:")
                if not ok:
                    return

            try:
                self._busy(True)
                self.client.set_member_suspended(self.org_id, uid, suspend, reason.strip())
            except ApiClientError as exc:
                return self._fail(
                    "Could not suspend that member" if suspend
                    else "Could not reinstate that member", exc)
            finally:
                self._busy(False)

            self._status(f"{email} {'suspended' if suspend else 'reinstated'}.")
            self.reload()

        def _delete_member_account(self) -> None:
            uid = _selected_key(self.members_table)
            if not uid:
                return
            row = self.members_table.currentRow()
            email = self.members_table.item(row, 0).text()

            confirm = QMessageBox.warning(
                self, "Delete account",
                f"Permanently delete the account for {email}, including every run saved to "
                f"it?\n\nThis cannot be undone.",
                QMessageBox.Yes | QMessageBox.Cancel, QMessageBox.Cancel,
            )
            if confirm != QMessageBox.Yes:
                return

            reason, ok = QInputDialog.getText(
                self, "Delete account",
                "Record why this account is being deleted (at least 5 characters):")
            if not ok:
                return
            if len(reason.strip()) < 5:
                QMessageBox.warning(self, "Reason required",
                                    "A reason of at least 5 characters is required, because "
                                    "this action is recorded.")
                return

            try:
                self._busy(True)
                self.client.delete_member_account(self.org_id, uid, reason.strip())
            except ApiClientError as exc:
                return self._fail("Could not delete that account", exc)
            finally:
                self._busy(False)
            self._status(f"Account for {email} deleted.")
            self.reload()

        # =============== invitations =================================
        def _invitations_tab(self) -> QWidget:
            w = QWidget()
            layout = QVBoxLayout(w)

            self.invitations_table = _table(["Email", "Role", "Status", "Expires"])
            self.invitations_table.itemSelectionChanged.connect(
                self._invitation_selection_changed)
            layout.addWidget(self.invitations_table, 1)

            buttons = QHBoxLayout()
            invite = QPushButton("Invite a member…")
            invite.setObjectName("primary")
            invite.clicked.connect(self._invite_member)
            self.cancel_invite_btn = QPushButton("Cancel invitation")
            self.cancel_invite_btn.setEnabled(False)
            self.cancel_invite_btn.clicked.connect(self._cancel_invitation)
            buttons.addWidget(invite)
            buttons.addWidget(self.cancel_invite_btn)
            buttons.addStretch(1)
            layout.addLayout(buttons)
            return w

        def _invitation_selection_changed(self) -> None:
            row = self.invitations_table.currentRow()
            status = self.invitations_table.item(row, 2).text() if row >= 0 else ""
            self.cancel_invite_btn.setEnabled(status == "pending")

        def _load_invitations(self) -> None:
            invites = self.client.list_invitations(self.org_id, status="all")
            rows, keys = [], []
            for inv in invites:
                rows.append([
                    inv.get("email", ""),
                    inv.get("role", ""),
                    inv.get("status", ""),
                    format_when(inv.get("expiresAt")),
                ])
                keys.append(inv.get("id", ""))
            _fill(self.invitations_table, rows, keys)
            self._invitation_selection_changed()

        def _invite_member(self) -> None:
            dialog = QDialog(self)
            dialog.setWindowTitle("Invite a member")
            dialog.setMinimumWidth(420)
            dl = QVBoxLayout(dialog)
            form = QFormLayout()
            email_edit = QLineEdit()
            email_edit.setPlaceholderText("colleague@example.com")
            role_combo = QComboBox()
            role_combo.addItems(["member", "admin"])
            form.addRow("Email:", email_edit)
            form.addRow("Role:", role_combo)
            dl.addLayout(form)
            buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            buttons.button(QDialogButtonBox.Ok).setText("Create invitation")
            buttons.accepted.connect(dialog.accept)
            buttons.rejected.connect(dialog.reject)
            dl.addWidget(buttons)

            if dialog.exec() != QDialog.Accepted:
                return
            email = email_edit.text().strip()
            if not email:
                return

            try:
                self._busy(True)
                created = self.client.invite_member(self.org_id, email, role_combo.currentText())
            except ApiClientError as exc:
                return self._fail("Could not create that invitation", exc)
            finally:
                self._busy(False)

            # The token is returned once and stored only as a hash, so it can never be shown
            # again. Presenting it in a selectable box is the only chance the admin gets.
            token_dialog = QDialog(self)
            token_dialog.setWindowTitle("Invitation created")
            token_dialog.setMinimumWidth(560)
            tl = QVBoxLayout(token_dialog)
            # Emailing is best-effort on the server (it may have no mail configured), so
            # what the admin is told to do next depends on whether it actually went out.
            emailed = bool(created.get("emailed"))
            sent_line = (
                f"This token has been emailed to <b>{email}</b>. Keep a copy until they have "
                f"joined, in case it does not arrive."
                if emailed else
                f"Send this token to <b>{email}</b>. They paste it into Account, then "
                f"Join an organisation."
            )
            label = QLabel(
                f"{sent_line}<br><br>"
                f"<span style='color:{ERROR_TEXT}'>This is shown once. It is stored only as a hash, "
                f"so it cannot be retrieved later.</span>")
            label.setTextFormat(Qt.RichText)
            label.setWordWrap(True)
            tl.addWidget(label)
            token_box = QTextEdit()
            token_box.setPlainText(created["token"])
            token_box.setReadOnly(True)
            token_box.setFixedHeight(70)
            tl.addWidget(token_box)
            copy_row = QHBoxLayout()
            copy = QPushButton("Copy to clipboard")

            def _copy():
                from PySide6.QtWidgets import QApplication as _QA
                _QA.clipboard().setText(created["token"])
                copy.setText("Copied")

            copy.clicked.connect(_copy)
            copy_row.addWidget(copy)
            copy_row.addStretch(1)
            done = QPushButton("Done")
            done.clicked.connect(token_dialog.accept)
            copy_row.addWidget(done)
            tl.addLayout(copy_row)
            token_dialog.exec()

            self._load_invitations()
            self._load_audit()

        def _cancel_invitation(self) -> None:
            invite_id = _selected_key(self.invitations_table)
            if not invite_id:
                return
            row = self.invitations_table.currentRow()
            email = self.invitations_table.item(row, 0).text()
            if QMessageBox.question(
                self, "Cancel invitation",
                f"Cancel the pending invitation for {email}?\n\n"
                "Their token stops working immediately.",
            ) != QMessageBox.Yes:
                return
            try:
                self._busy(True)
                self.client.cancel_invitation(self.org_id, invite_id)
            except ApiClientError as exc:
                return self._fail("Could not cancel that invitation", exc)
            finally:
                self._busy(False)
            self._status(f"Invitation for {email} cancelled.")
            self._load_invitations()
            self._load_audit()

        # =============== flags =======================================
        def _flags_tab(self) -> QWidget:
            w = QWidget()
            layout = QVBoxLayout(w)

            self.flags_table = _table(["Raised", "Reason", "Status"])
            self.flags_table.itemSelectionChanged.connect(self._flag_selection_changed)
            layout.addWidget(self.flags_table, 1)

            buttons = QHBoxLayout()
            self.uphold_btn = QPushButton("Uphold")
            self.uphold_btn.clicked.connect(lambda: self._review("uphold"))
            self.dismiss_btn = QPushButton("Dismiss")
            self.dismiss_btn.clicked.connect(lambda: self._review("dismiss"))
            self.show_all_flags = QPushButton("Show reviewed too")
            self.show_all_flags.setCheckable(True)
            self.show_all_flags.clicked.connect(self._load_flags)
            for b in (self.uphold_btn, self.dismiss_btn):
                b.setEnabled(False)
                buttons.addWidget(b)
            buttons.addWidget(self.show_all_flags)
            buttons.addStretch(1)
            layout.addLayout(buttons)

            note = QLabel(
                "Raising and reviewing are two steps on purpose, so a decision is recorded "
                "rather than a run quietly disappearing. Flag a run from Members, then "
                "View their runs."
            )
            note.setObjectName("hint")
            note.setWordWrap(True)
            layout.addWidget(note)
            return w

        def _flag_selection_changed(self) -> None:
            row = self.flags_table.currentRow()
            status = self.flags_table.item(row, 2).text() if row >= 0 else ""
            open_flag = status == "open"
            self.uphold_btn.setEnabled(open_flag)
            self.dismiss_btn.setEnabled(open_flag)

        def _load_flags(self) -> None:
            status = "all" if self.show_all_flags.isChecked() else "open"
            flags = self.client.list_flags(self.org_id, status=status)
            rows, keys = [], []
            for f in flags:
                rows.append([format_when(f.get("createdAt")), f.get("reason", ""),
                             f.get("status", "")])
                keys.append(f.get("id", ""))
            _fill(self.flags_table, rows, keys)
            self._flag_selection_changed()

        def _review(self, decision: str) -> None:
            flag_id = _selected_key(self.flags_table)
            if not flag_id:
                return
            note, ok = QInputDialog.getText(
                self, f"{decision.capitalize()} flag", "Note (optional):")
            if not ok:
                return
            try:
                self._busy(True)
                self.client.review_flag(self.org_id, flag_id, decision, note.strip() or None)
            except ApiClientError as exc:
                return self._fail("Could not review that flag", exc)
            finally:
                self._busy(False)
            self._status(f"Flag {decision}d.")
            self._load_flags()
            self._load_audit()

        # =============== audit =======================================
        def _audit_tab(self) -> QWidget:
            w = QWidget()
            layout = QVBoxLayout(w)
            self.audit_table = _table(["When", "Action", "By", "Affected", "Details"])
            layout.addWidget(self.audit_table, 1)
            note = QLabel(
                "Every admin action that touches another person is recorded here, and entries "
                "cannot be edited or removed. Reading a member's data is recorded too."
            )
            note.setObjectName("hint")
            note.setWordWrap(True)
            layout.addWidget(note)
            return w

        def _load_audit(self) -> None:
            try:
                entries = self.client.audit_log(self.org_id, limit=200)
            except ApiClientError:
                return    # the rest of the tab is still useful without it
            rows = []
            for e in entries:
                # The server names both people by email. An id with no email left is an
                # account deleted since; one without an id is simply not part of the entry.
                # A server too old to send the email fields leaves both columns blank.
                named = "actorEmail" in e
                by = e.get("actorEmail") or (
                    "deleted account" if named and e.get("actorId") else "")
                affected = e.get("subjectEmail") or (
                    "deleted account" if named and e.get("subjectId") else "")
                # The affected email is already its own column, so not repeated here.
                meta = {k: v for k, v in (e.get("metadata") or {}).items() if k != "email"
                        or v != affected}
                detail = ", ".join(f"{k}={v}" for k, v in meta.items() if v not in (None, ""))
                rows.append([format_when(e.get("at")), e.get("action", ""), by, affected, detail])
            _fill(self.audit_table, rows)

        # =============== subscription ================================
        def _subscription_tab(self) -> QWidget:
            w = QWidget()
            layout = QVBoxLayout(w)
            self.sub_status = QLabel("")
            self.sub_status.setTextFormat(Qt.RichText)
            self.sub_status.setWordWrap(True)
            layout.addWidget(self.sub_status)

            buttons = QHBoxLayout()
            self.sub_cancel_btn = QPushButton("Cancel subscription…")
            self.sub_cancel_btn.clicked.connect(self._cancel_subscription)
            self.sub_resume_btn = QPushButton("Keep subscription")
            self.sub_resume_btn.clicked.connect(self._resume_subscription)
            self.sub_renew_btn = QPushButton("Renew subscription…")
            self.sub_renew_btn.clicked.connect(self._renew_subscription)
            self.sub_portal_btn = QPushButton("Manage billing online")
            self.sub_portal_btn.setToolTip(
                "Opens Stripe's billing page, where you can also cancel or change the card.")
            self.sub_portal_btn.clicked.connect(self._open_billing_portal)
            for b in (self.sub_cancel_btn, self.sub_resume_btn, self.sub_renew_btn,
                      self.sub_portal_btn):
                buttons.addWidget(b)
            buttons.addStretch(1)
            layout.addLayout(buttons)

            note = QLabel(
                "One subscription covers the whole organisation: you and every member share "
                "the same paid year. It renews and is charged automatically each year until "
                "you cancel. Cancelling keeps everyone's access until the end of the year "
                "already paid; after that, all accounts in the organisation are suspended "
                "until the subscription is renewed. Only admins can cancel."
            )
            note.setObjectName("hint")
            note.setWordWrap(True)
            layout.addWidget(note)
            layout.addStretch(1)
            return w

        def _show_subscription(self, sub: dict) -> None:
            state = sub.get("state") or "none"
            when = _date(sub.get("periodEnd"))
            text = {
                "active": f"<b>Active.</b> Renews automatically on <b>{when}</b>, when the "
                          f"organisation is charged for another year.",
                "cancelling": f"<b>Cancelled.</b> Everyone keeps access until <b>{when}</b>. "
                              f"After that you and every member are suspended until the "
                              f"subscription is renewed.",
                "ended": f"<b style='color:{SEVERITY_COLOURS['high']}'>Ended{' on ' + when if when != 'unknown' else ''}.</b> "
                         f"You and every member of this organisation are suspended until "
                         f"the subscription is renewed.",
                "unpaid": f"<b style='color:{SEVERITY_COLOURS['high']}'>Payment needed.</b> "
                          f"Your organisation's yearly subscription has not been paid yet. "
                          f"Pay for it to start using BioAudit and invite your team.",
                "none": "<b>No subscription on record.</b> This organisation was not set up "
                        "through the website's checkout, so it is not billed.",
            }.get(state, f"Subscription state: {state}")
            self.sub_status.setText(text)
            self.sub_cancel_btn.setVisible(state == "active")
            self.sub_resume_btn.setVisible(state == "cancelling")
            self.sub_renew_btn.setText("Pay for subscription…" if state == "unpaid"
                                       else "Renew subscription…")
            self.sub_renew_btn.setVisible(state in ("ended", "unpaid"))
            self.sub_portal_btn.setVisible(state not in ("none", "unpaid"))

        def _cancel_subscription(self) -> None:
            try:
                sub = self.client.org_subscription(self.org_id)
            except ApiClientError as exc:
                return self._fail("Could not load the subscription", exc)
            when = _date(sub.get("periodEnd"))
            if QMessageBox.question(
                self, "Cancel subscription",
                f"Cancel your organisation's subscription?\n\n"
                f"It will not renew, and you will not be charged again. You and every "
                f"member keep access until {when}. After that, all accounts in the "
                f"organisation are suspended until the subscription is renewed.\n\n"
                f"You can undo this any time before {when}.",
            ) != QMessageBox.Yes:
                return
            reason, ok = QInputDialog.getText(
                self, "Cancel subscription", "Reason (optional):")
            if not ok:
                return
            try:
                self._busy(True)
                result = self.client.cancel_org_subscription(self.org_id, reason.strip() or None)
            except ApiClientError as exc:
                return self._fail("Could not cancel the subscription", exc)
            finally:
                self._busy(False)
            QMessageBox.information(self, "Subscription cancelled", result.get("message", ""))
            self.reload()

        def _resume_subscription(self) -> None:
            try:
                self._busy(True)
                result = self.client.resume_org_subscription(self.org_id)
            except ApiClientError as exc:
                return self._fail("Could not keep the subscription", exc)
            finally:
                self._busy(False)
            QMessageBox.information(self, "Subscription kept", result.get("message", ""))
            self.reload()

        def _open_link(self, fetch, title: str, after: str) -> bool:
            """Fetch a Stripe link from the server and open it in the browser."""
            from PySide6.QtCore import QUrl
            from PySide6.QtGui import QDesktopServices
            try:
                self._busy(True)
                url = fetch(self.org_id)
            except ApiClientError as exc:
                self._fail(title, exc)
                return False
            finally:
                self._busy(False)
            QDesktopServices.openUrl(QUrl(url))
            self._status(after)
            return True

        def _open_billing_portal(self) -> None:
            self._open_link(self.client.billing_portal_url, "Could not open billing",
                            "Opened the billing page in your browser.")

        def _renew_subscription(self) -> None:
            if not self._open_link(
                    self.client.renewal_url, "Could not start the renewal",
                    "Opened the payment page in your browser. After paying, press Refresh."):
                return
            QMessageBox.information(
                self, "Payment page opened",
                "The payment page has opened in your browser. Once payment goes through, "
                "press Refresh here: access opens for you and every member.")

    return TeamTab()


def _date(iso: Optional[str]) -> str:
    """'17 Oct 2027' from an ISO timestamp, or 'unknown'."""
    if not iso:
        return "unknown"
    from datetime import datetime
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone().strftime("%d %b %Y")
    except ValueError:
        return "unknown"
