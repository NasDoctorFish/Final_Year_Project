"""Sign-in dialog and session storage for the desktop app.

Kept out of app.py so that file stays about scanning, and so PySide6 is still only
imported when the GUI actually runs.

On storing the session: signing in returns a refresh token, which is long-lived and can
mint new access tokens. Writing it to disk is therefore a real trade-off, so it is opt-in
through a checkbox that defaults to off. When the user does opt in, the file goes in their
home directory with permissions narrowed as far as the platform allows. This is a security
testing tool, so the honest position is to make the choice visible rather than quietly
convenient.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Optional

from ..api import Account, ApiClient, ApiClientError, Session

SESSION_FILENAME = "session.json"


def session_path(base_dir: str | os.PathLike) -> Path:
    return Path(base_dir) / SESSION_FILENAME


def save_session(base_dir: str | os.PathLike, client: ApiClient) -> Optional[Path]:
    """Write the session so the next launch does not need a password.

    Returns the path written, or None if it could not be saved. A failure here is not
    worth interrupting the user for: they are already signed in for this run.
    """
    if client.session is None:
        return None

    path = session_path(base_dir)
    payload = {
        "base_url": client.base_url,
        "session": client.session.to_dict(),
        "email": client.account.email if client.account else None,
    }

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        # Narrow to owner-only. This is the main protection on POSIX; on Windows the
        # call is accepted but the real control is the user's own profile directory.
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        return path
    except OSError:
        return None


def clear_session(base_dir: str | os.PathLike) -> None:
    try:
        session_path(base_dir).unlink(missing_ok=True)
    except OSError:
        pass


def restore_session(base_dir: str | os.PathLike, default_base_url: str) -> Optional[ApiClient]:
    """Rebuild a signed-in client from a saved session, or return None.

    The stored access token has almost certainly expired, so this refreshes before
    handing the client back. If the refresh fails, for any reason from a revoked session
    to the server being down, the stored file is useless and is removed.
    """
    path = session_path(base_dir)
    if not path.exists():
        return None

    try:
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        client = ApiClient(payload.get("base_url") or default_base_url)
        client.session = Session.from_dict(payload["session"])
    except (OSError, KeyError, ValueError, json.JSONDecodeError):
        clear_session(base_dir)
        return None

    try:
        client.refresh()
        client.get_profile()
    except ApiClientError:
        clear_session(base_dir)
        return None

    return client


def show_signin_dialog(parent, *, base_url: str, base_dir: str | os.PathLike):
    """Show the sign-in dialog.

    Returns (client, remember) on success, or (None, False) if the user cancelled.
    """
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import (
        QCheckBox, QDialog, QDialogButtonBox, QFormLayout, QLabel, QLineEdit,
        QMessageBox, QTabWidget, QVBoxLayout, QWidget,
    )

    class SignInDialog(QDialog):
        def __init__(self) -> None:
            super().__init__(parent)
            self.setWindowTitle("Sign in to BioAudit")
            self.setMinimumWidth(440)
            self.client: Optional[ApiClient] = None

            layout = QVBoxLayout(self)

            intro = QLabel(
                "Signing in lets the app save your results to the server, keep a history "
                "across machines, and generate plain-language explanations. Everything "
                "else works without an account."
            )
            intro.setWordWrap(True)
            layout.addWidget(intro)

            server_row = QFormLayout()
            self.server_edit = QLineEdit(base_url)
            server_row.addRow("Server:", self.server_edit)
            layout.addLayout(server_row)

            self.tabs = QTabWidget()
            self.tabs.addTab(self._build_signin_tab(), "Sign in")
            self.tabs.addTab(self._build_register_tab(), "Create account")
            layout.addWidget(self.tabs)

            self.remember = QCheckBox("Keep me signed in on this computer")
            self.remember.setToolTip(
                "Saves your session to a file in your home folder so you do not have to "
                "sign in again. Leave this off on a shared computer."
            )
            layout.addWidget(self.remember)

            self.status = QLabel("")
            self.status.setWordWrap(True)
            self.status.setStyleSheet("color: #b00020;")
            layout.addWidget(self.status)

            buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            buttons.button(QDialogButtonBox.Ok).setText("Continue")
            buttons.accepted.connect(self._submit)
            buttons.rejected.connect(self.reject)
            layout.addWidget(buttons)
            self._ok_button = buttons.button(QDialogButtonBox.Ok)

        def _build_signin_tab(self) -> QWidget:
            w = QWidget()
            form = QFormLayout(w)
            self.login_email = QLineEdit()
            self.login_email.setPlaceholderText("you@example.com")
            self.login_password = QLineEdit()
            self.login_password.setEchoMode(QLineEdit.Password)
            self.login_password.returnPressed.connect(self._submit)
            form.addRow("Email:", self.login_email)
            form.addRow("Password:", self.login_password)
            return w

        def _build_register_tab(self) -> QWidget:
            w = QWidget()
            form = QFormLayout(w)
            self.reg_name = QLineEdit()
            self.reg_name.setPlaceholderText("Optional")
            self.reg_email = QLineEdit()
            self.reg_email.setPlaceholderText("you@example.com")
            self.reg_password = QLineEdit()
            self.reg_password.setEchoMode(QLineEdit.Password)
            self.reg_password.setPlaceholderText("At least 8 characters")
            self.reg_confirm = QLineEdit()
            self.reg_confirm.setEchoMode(QLineEdit.Password)
            self.reg_org = QLineEdit()
            self.reg_org.setPlaceholderText("Leave blank unless you are setting up a team")

            form.addRow("Name:", self.reg_name)
            form.addRow("Email:", self.reg_email)
            form.addRow("Password:", self.reg_password)
            form.addRow("Confirm:", self.reg_confirm)
            form.addRow("Organisation:", self.reg_org)

            note = QLabel(
                "Giving an organisation name creates a team account and makes you its "
                "admin, so you can invite colleagues."
            )
            note.setWordWrap(True)
            note.setStyleSheet("color: #5f6368; font-size: 11px;")
            form.addRow("", note)
            return w

        def _fail(self, message: str) -> None:
            self.status.setText(message)
            self._ok_button.setEnabled(True)
            self.setCursor(Qt.ArrowCursor)

        def _submit(self) -> None:
            self.status.setText("")
            self._ok_button.setEnabled(False)
            self.setCursor(Qt.WaitCursor)

            client = ApiClient(self.server_edit.text().strip() or base_url)
            registering = self.tabs.currentIndex() == 1

            try:
                if registering:
                    email = self.reg_email.text().strip()
                    password = self.reg_password.text()
                    if password != self.reg_confirm.text():
                        return self._fail("Those passwords do not match.")
                    if len(password) < 8:
                        return self._fail("Use a password of at least 8 characters.")
                    if not email:
                        return self._fail("Enter an email address.")

                    org = self.reg_org.text().strip()
                    name = self.reg_name.text().strip() or None
                    if org:
                        client.register_admin(email, password, org, name)
                    else:
                        client.register(email, password, name)
                else:
                    email = self.login_email.text().strip()
                    password = self.login_password.text()
                    if not email or not password:
                        return self._fail("Enter your email address and password.")
                    client.login(email, password)

            except ApiClientError as exc:
                # exc.message is written for a person to read, so show it directly.
                return self._fail(str(exc))
            except Exception as exc:  # noqa: BLE001 - never let the dialog die silently
                return self._fail(f"Unexpected problem: {exc}")

            self.client = client
            self.setCursor(Qt.ArrowCursor)
            self.accept()

    dialog = SignInDialog()
    if dialog.exec() == QDialog.Accepted and dialog.client is not None:
        remember = dialog.remember.isChecked()
        if remember:
            save_session(base_dir, dialog.client)
        else:
            clear_session(base_dir)
        return dialog.client, remember
    return None, False


def account_summary(account: Optional[Account]) -> str:
    """One-line description of who is signed in, for the status bar."""
    if account is None:
        return "Not signed in (results stay on this computer)"
    parts = [account.email or account.id]
    parts.append("premium" if account.is_premium else "free")
    if account.is_admin:
        parts.append("admin")
    return "Signed in: " + " · ".join(parts)
