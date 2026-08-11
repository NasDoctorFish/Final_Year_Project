"""Sign-in and welcome dialogs for the desktop app.

Kept out of app.py so that file stays about scanning, and so PySide6 is still only
imported when the GUI actually runs.

Session persistence itself (`save_session`/`clear_session`/`restore_session`) lives in
`..session`, which the CLI shares, so both front ends read and write the same file
without either one depending on Qt.
"""

from __future__ import annotations

import os
from typing import Optional

from ..api import Account, ApiClient, ApiClientError
from ..session import clear_session, save_session

__all__ = [
    "account_summary", "clear_session", "save_session",
    "show_signin_dialog", "show_welcome_dialog",
]


def show_signin_dialog(parent, *, base_url: str, base_dir: str | os.PathLike):
    """Show the sign-in dialog.

    Returns (client, remember) on success, or (None, False) if the user cancelled.
    """
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import (
        QCheckBox, QDialog, QDialogButtonBox, QFormLayout, QLabel, QLineEdit,
        QTabWidget, QVBoxLayout, QWidget,
    )

    class SignInDialog(QDialog):
        def __init__(self) -> None:
            super().__init__(parent)
            self.setWindowTitle("Sign in to BioAudit")
            self.setMinimumWidth(440)
            self.client: Optional[ApiClient] = None

            layout = QVBoxLayout(self)

            intro = QLabel(
                "Switch to a different account. Your results are stored on the server "
                "under whichever account is signed in, so switching changes which "
                "history and settings you see."
            )
            intro.setWordWrap(True)
            layout.addWidget(intro)

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

            client = ApiClient(base_url)
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


def show_welcome_dialog(parent, *, base_url: str, base_dir: str | os.PathLike):
    """The front door shown at startup when nobody is signed in.

    An account is required: BioAudit keeps no local copy of a scan, so with nobody
    signed in there is nowhere to put a result. The functional hierarchy gives an
    unregistered user exactly two doors in that case: register an account, or join an
    organisation from an invite. This dialog puts both front and centre and adds a
    sign-in tab for people who already have an account, so a returning user is not
    forced to register again. There is no way to dismiss it without succeeding at one
    of the three; the caller is expected to quit if it is closed unsatisfied.

    Returns (client, remember):
      * (client, remember) when the user signed in / registered / joined,
      * (None, False)      if the dialog was closed without completing one.
    """
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import (
        QCheckBox, QDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit,
        QPushButton, QTabWidget, QTextEdit, QVBoxLayout, QWidget,
    )

    CREATE, JOIN, SIGNIN = 0, 1, 2

    class WelcomeDialog(QDialog):
        def __init__(self) -> None:
            super().__init__(parent)
            self.setWindowTitle("Welcome to BioAudit")
            self.setMinimumWidth(500)
            self.client: Optional[ApiClient] = None

            layout = QVBoxLayout(self)
            layout.setContentsMargins(24, 22, 24, 18)
            layout.setSpacing(14)

            title = QLabel("BioAudit")
            title.setStyleSheet("font-size: 22px; font-weight: 700;")
            layout.addWidget(title)

            intro = QLabel(
                "Sign in to run a scan. Your results are stored on the server rather "
                "than on this computer, which is what lets your history follow you "
                "between machines and, on a team account, gives your admin oversight. "
                "Create an account, or join one from a team invite, below."
            )
            intro.setWordWrap(True)
            intro.setObjectName("hint")
            layout.addWidget(intro)

            self.tabs = QTabWidget()
            self.tabs.addTab(self._build_create_tab(), "Create account")
            self.tabs.addTab(self._build_join_tab(), "Join with an invite")
            self.tabs.addTab(self._build_signin_tab(), "Sign in")
            self.tabs.currentChanged.connect(self._on_tab_changed)
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

            bar = QHBoxLayout()
            bar.addStretch(1)

            self.primary_btn = QPushButton("Create account")
            self.primary_btn.setDefault(True)
            self.primary_btn.setMinimumWidth(150)
            self.primary_btn.clicked.connect(self._submit)
            bar.addWidget(self.primary_btn)
            layout.addLayout(bar)

        # ---- tabs --------------------------------------------------------- #

        def _build_create_tab(self) -> QWidget:
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
            self.reg_confirm.returnPressed.connect(self._submit)
            self.reg_org = QLineEdit()
            self.reg_org.setPlaceholderText("Leave blank unless you are setting up a team")

            form.addRow("Name:", self.reg_name)
            form.addRow("Email:", self.reg_email)
            form.addRow("Password:", self.reg_password)
            form.addRow("Confirm:", self.reg_confirm)
            form.addRow("Organisation:", self.reg_org)

            note = QLabel(
                "Giving an organisation name creates a team account and makes you its "
                "admin, so you can invite colleagues.")
            note.setWordWrap(True)
            note.setObjectName("hint")
            form.addRow("", note)
            return w

        def _build_join_tab(self) -> QWidget:
            w = QWidget()
            form = QFormLayout(w)
            self.join_name = QLineEdit()
            self.join_name.setPlaceholderText("Optional")
            self.join_email = QLineEdit()
            self.join_email.setPlaceholderText("The email your invite was sent to")
            self.join_password = QLineEdit()
            self.join_password.setEchoMode(QLineEdit.Password)
            self.join_password.setPlaceholderText("Choose a password, at least 8 characters")
            self.join_confirm = QLineEdit()
            self.join_confirm.setEchoMode(QLineEdit.Password)
            self.join_token = QTextEdit()
            self.join_token.setPlaceholderText("Paste the invitation token an admin sent you")
            self.join_token.setFixedHeight(60)

            form.addRow("Name:", self.join_name)
            form.addRow("Email:", self.join_email)
            form.addRow("Password:", self.join_password)
            form.addRow("Confirm:", self.join_confirm)
            form.addRow("Invite token:", self.join_token)

            note = QLabel(
                "This creates your account and joins the team in one step. The team's admin "
                "will see that you ran a scan and how many problems it found, but never the "
                "findings themselves.")
            note.setWordWrap(True)
            note.setObjectName("hint")
            form.addRow("", note)
            return w

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

        def _on_tab_changed(self, index: int) -> None:
            self.status.setText("")
            self.primary_btn.setText(
                {CREATE: "Create account", JOIN: "Join team", SIGNIN: "Sign in"}[index])

        # ---- actions ------------------------------------------------------ #

        def _fail(self, message: str) -> None:
            self.status.setText(message)
            self.primary_btn.setEnabled(True)
            self.setCursor(Qt.ArrowCursor)

        def _submit(self) -> None:
            self.status.setText("")
            self.primary_btn.setEnabled(False)
            self.setCursor(Qt.WaitCursor)

            client = ApiClient(base_url)
            tab = self.tabs.currentIndex()

            try:
                if tab == CREATE:
                    email = self.reg_email.text().strip()
                    password = self.reg_password.text()
                    if not email:
                        return self._fail("Enter an email address.")
                    if password != self.reg_confirm.text():
                        return self._fail("Those passwords do not match.")
                    if len(password) < 8:
                        return self._fail("Use a password of at least 8 characters.")
                    org = self.reg_org.text().strip()
                    name = self.reg_name.text().strip() or None
                    if org:
                        client.register_admin(email, password, org, name)
                    else:
                        client.register(email, password, name)

                elif tab == JOIN:
                    email = self.join_email.text().strip()
                    password = self.join_password.text()
                    token = self.join_token.toPlainText().strip()
                    if not email:
                        return self._fail("Enter the email your invite was sent to.")
                    if password != self.join_confirm.text():
                        return self._fail("Those passwords do not match.")
                    if len(password) < 8:
                        return self._fail("Use a password of at least 8 characters.")
                    if len(token) < 16:
                        return self._fail("That does not look like a valid invite token.")
                    name = self.join_name.text().strip() or None
                    # Create the account, redeem the invite, then sign in again: joining
                    # revokes the session server-side so the new team permissions take
                    # effect on the next sign-in.
                    client.register(email, password, name)
                    client.join_organisation(token)
                    client.login(email, password)

                else:  # SIGNIN
                    email = self.login_email.text().strip()
                    password = self.login_password.text()
                    if not email or not password:
                        return self._fail("Enter your email address and password.")
                    client.login(email, password)

            except ApiClientError as exc:
                return self._fail(str(exc))
            except Exception as exc:  # noqa: BLE001 - never let the dialog die silently
                return self._fail(f"Unexpected problem: {exc}")

            self.client = client
            self.setCursor(Qt.ArrowCursor)
            self.accept()

    dialog = WelcomeDialog()
    accepted = dialog.exec() == QDialog.Accepted

    if accepted and dialog.client is not None:
        remember = dialog.remember.isChecked()
        if remember:
            save_session(base_dir, dialog.client)
        else:
            clear_session(base_dir)
        return dialog.client, remember

    # The dialog was closed without signing in. There is no guest fallback to drop back
    # to, so the caller is expected to treat this as "give up", not "carry on".
    return None, False


def account_summary(account: Optional[Account]) -> str:
    """One-line description of who is signed in, for the status bar."""
    if account is None:
        return "Not signed in"
    parts = [account.email or account.id]
    parts.append("premium" if account.is_premium else "free")
    if account.is_admin:
        parts.append("admin")
    return "Signed in: " + " · ".join(parts)
