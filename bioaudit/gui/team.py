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

A note on privacy: the members view deliberately shows only that a member ran a scan and
how many problems it found. The server does not return their findings to an admin, because
the product promises an app's code never leaves the machine it was scanned on.
"""

from __future__ import annotations

from typing import Optional

from ..api import ApiClient, ApiClientError


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
                ["Email", "Name", "Plan", "Role", "Scans"])
            self.members_table.itemSelectionChanged.connect(self._member_selection_changed)
            layout.addWidget(self.members_table, 1)

            buttons = QHBoxLayout()
            self.view_data_btn = QPushButton("View their runs")
            self.view_data_btn.clicked.connect(self._view_member_data)
            self.make_admin_btn = QPushButton("Make admin")
            self.make_admin_btn.clicked.connect(self._add_admin)
            self.remove_btn = QPushButton("Remove from team")
            self.remove_btn.clicked.connect(self._remove_member)
            self.delete_acct_btn = QPushButton("Delete their account")
            self.delete_acct_btn.clicked.connect(self._delete_member_account)
            for b in (self.view_data_btn, self.make_admin_btn, self.remove_btn,
                      self.delete_acct_btn):
                b.setEnabled(False)
                buttons.addWidget(b)
            buttons.addStretch(1)
            layout.addLayout(buttons)

            note = QLabel(
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
            role = self.members_table.item(row, 3).text() if row >= 0 else ""
            self.make_admin_btn.setEnabled(enabled and role != "admin")

        def _load_members(self) -> None:
            members = self.client.list_members(self.org_id)
            rows, keys = [], []
            for m in members:
                rows.append([
                    m.get("email", ""),
                    m.get("displayName") or "",
                    m.get("tier", ""),
                    m.get("role", ""),
                    str(m.get("scanCount", 0)),
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
                when = str(s.get("createdAt", ""))[:19]
                lines.append(f"{when}   {label}   {summary}")

            dialog = QDialog(self)
            dialog.setWindowTitle("Member runs")
            dialog.setMinimumSize(620, 420)
            dl = QVBoxLayout(dialog)
            heading = QLabel(
                f"<b>{len(scans)} run(s)</b><br>"
                f"<span style='color:{palette['muted']}'>Findings are not shown. An admin can "
                f"see that a scan happened and how many problems it found, but not the evidence "
                f"taken from the member's own app. This view is recorded in the activity log."
                f"</span>")
            heading.setTextFormat(Qt.RichText)
            heading.setWordWrap(True)
            dl.addWidget(heading)
            body = QTextEdit()
            body.setReadOnly(True)
            body.setFontFamily("Consolas")
            body.setPlainText("\n".join(lines))
            dl.addWidget(body, 1)

            flag_row = QHBoxLayout()
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

        def _flag_run(self, scans: list[dict], owner_dialog) -> None:
            """Raise a flag on a member's run, with a reason."""
            labels = []
            for s in scans:
                target = (s.get("target") or {})
                label = target.get("packageName") or target.get("apkFileName") or "unknown"
                labels.append(f"{str(s.get('createdAt', ''))[:19]}  {label}")

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
                expires = inv.get("expiresAt")
                if isinstance(expires, dict):           # Firestore timestamp shape
                    expires = expires.get("_seconds", "")
                rows.append([
                    inv.get("email", ""),
                    inv.get("role", ""),
                    inv.get("status", ""),
                    str(expires)[:19],
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
            label = QLabel(
                f"Send this token to <b>{email}</b>. They paste it into Account, then "
                f"Join an organisation.<br><br>"
                f"<span style='color:#b00020'>This is shown once. It is stored only as a hash, "
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
                created = f.get("createdAt")
                if isinstance(created, dict):
                    created = created.get("_seconds", "")
                rows.append([str(created)[:19], f.get("reason", ""), f.get("status", "")])
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
            self.audit_table = _table(["When", "Action", "Details"])
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
                at = e.get("at")
                if isinstance(at, dict):
                    at = at.get("_seconds", "")
                meta = e.get("metadata") or {}
                detail = ", ".join(f"{k}={v}" for k, v in meta.items() if v not in (None, ""))
                rows.append([str(at)[:19], e.get("action", ""), detail])
            _fill(self.audit_table, rows)

    return TeamTab()
