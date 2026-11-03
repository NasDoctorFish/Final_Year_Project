"""The "Create account" form, shared by the welcome and sign-in dialogs.

Modelled on the way GitHub Education and Apple's student pricing work: you say which
university you attend by picking it from a searchable list, and the email you register
with has to be one that university issues. Send code has the server email a six-digit
code to prove you can read that inbox, and the account is only created once that code
is entered. The address is typed twice, and if the email bounces anyway, the form
says so. A second mode covers the other kind of account, a team whose creator
becomes its admin, which needs no student check at all.

PySide6 is imported inside make_register_form so this module, like the rest of gui/,
costs nothing to import when the GUI is not running.
"""

from __future__ import annotations

import re
import time
from typing import Optional

from ..api import ApiClient, ApiClientError
from .theme import ERROR_TEXT, SUCCESS_TEXT

NOT_LISTED = "My university isn't listed"

# Fetched once per run: the list only changes when the server is redeployed.
_university_cache: Optional[list[dict]] = None


def load_universities(base_url: str) -> Optional[list[dict]]:
    """The server's university list, or None if it could not be reached."""
    global _university_cache
    if _university_cache is None:
        try:
            _university_cache = ApiClient(base_url).list_universities()
        except ApiClientError:
            return None
    return _university_cache


def email_matches(email: str, domains: list[str]) -> bool:
    """Same rule as the server: the domain itself or any subdomain of it."""
    domain = email.rsplit("@", 1)[-1].lower() if "@" in email else ""
    return bool(domain) and any(f".{domain}".endswith(f".{d}") for d in domains)


def make_register_form(base_url: str):
    """Build the form. Call `.submit(client)`; it returns an error message or None."""
    from PySide6.QtCore import Qt, QTimer
    from PySide6.QtWidgets import (
        QButtonGroup, QCheckBox, QComboBox, QCompleter, QFormLayout, QHBoxLayout, QLabel,
        QLineEdit, QPushButton, QStackedWidget, QVBoxLayout, QWidget,
    )

    STUDENT, TEAM = 0, 1
    # After a code goes out, how often and for how long to ask whether it bounced. A
    # mailbox that does not exist is usually refused within seconds, rarely minutes.
    BOUNCE_POLL_MS = 5_000
    BOUNCE_WATCH_SECONDS = 120

    def password_field(placeholder: str = "") -> QLineEdit:
        field = QLineEdit()
        field.setEchoMode(QLineEdit.Password)
        if placeholder:
            field.setPlaceholderText(placeholder)
        return field

    def hint(text: str) -> QLabel:
        label = QLabel(text)
        label.setWordWrap(True)
        label.setObjectName("hint")
        return label

    class RegisterForm(QWidget):
        def __init__(self) -> None:
            super().__init__()
            layout = QVBoxLayout(self)
            layout.setContentsMargins(0, 8, 0, 0)
            layout.setSpacing(10)

            # Segmented "who are you" switch, the first question on both GitHub's and
            # Apple's education sign-up.
            seg = QHBoxLayout()
            seg.setSpacing(0)
            self.student_btn = QPushButton("I'm a student")
            self.team_btn = QPushButton("I'm setting up a team")
            self.mode_group = QButtonGroup(self)
            for index, (button, pos) in enumerate(
                ((self.student_btn, "left"), (self.team_btn, "right"))
            ):
                button.setCheckable(True)
                button.setObjectName("segment")
                button.setProperty("segmentPos", pos)
                button.setCursor(Qt.PointingHandCursor)
                self.mode_group.addButton(button, index)
                seg.addWidget(button, 1)
            self.student_btn.setChecked(True)
            layout.addLayout(seg)

            self.pages = QStackedWidget()
            self.pages.addWidget(self._build_student_page())
            self.pages.addWidget(self._build_team_page())
            layout.addWidget(self.pages)
            self.tos_box = QCheckBox(
                "I accept the Terms of Use: I will only test apps I own or am "
                "authorised to test.")
            self.tos_box.setToolTip("See docs/TERMS.md")
            layout.addWidget(self.tos_box)
            self.mode_group.idClicked.connect(self.pages.setCurrentIndex)

            # (email, sendId, deadline) of the code being watched for a bounce.
            self._watching = None
            self._bounce_timer = QTimer(self)
            self._bounce_timer.setInterval(BOUNCE_POLL_MS)
            self._bounce_timer.timeout.connect(self._check_bounce)

        # ---- pages -------------------------------------------------------- #

        def _build_student_page(self) -> QWidget:
            page = QWidget()
            form = QFormLayout(page)
            form.setContentsMargins(0, 4, 0, 0)

            self.uni_combo = QComboBox()
            self.uni_combo.setEditable(True)
            self.uni_combo.setInsertPolicy(QComboBox.NoInsert)
            self.uni_combo.setMaxVisibleItems(12)
            self.uni_combo.lineEdit().setPlaceholderText("Search for your university")

            universities = load_universities(base_url)
            for uni in sorted(universities or [], key=lambda u: u["name"]):
                self.uni_combo.addItem(f"{uni['name']}  ·  {uni['country']}", uni)
            self.uni_combo.addItem(NOT_LISTED, None)

            # Type-to-search anywhere in the name, the way the education sign-up pages
            # behave, rather than Qt's default of matching only from the start.
            completer = QCompleter(self.uni_combo.model(), self.uni_combo)
            completer.setFilterMode(Qt.MatchContains)
            completer.setCaseSensitivity(Qt.CaseInsensitive)
            completer.setCompletionMode(QCompleter.PopupCompletion)
            self.uni_combo.setCompleter(completer)
            self.uni_combo.setCurrentIndex(-1)
            self.uni_combo.setEditText("")
            self.uni_combo.currentIndexChanged.connect(self._on_university_changed)

            self.uni_hint = QLabel()
            self.uni_hint.setWordWrap(True)
            self.uni_hint.setObjectName("universityHint")
            self.uni_hint.setVisible(universities is None)
            if universities is None:
                self.uni_hint.setText(
                    "Could not load the university list from the server. You can still "
                    "register with your university email address.")

            self.stu_name = QLineEdit()
            self.stu_name.setPlaceholderText("Optional")
            self.stu_email = QLineEdit()
            self.stu_email.setPlaceholderText("you@university.ac.uk")
            # Typed twice because a typo here sends the code to someone else's inbox, or
            # to none, and nothing can tell that apart from a slow one until it bounces.
            self.stu_email_again = QLineEdit()
            self.stu_email_again.setPlaceholderText("Type it again to catch typos")
            self.stu_password = password_field("At least 8 characters")
            self.stu_confirm = password_field()

            self.stu_code = QLineEdit()
            self.stu_code.setPlaceholderText("Six-digit code from the email")
            self.stu_code.setMaxLength(6)
            self.send_code_btn = QPushButton("Send code")
            self.send_code_btn.setCursor(Qt.PointingHandCursor)
            self.send_code_btn.clicked.connect(self._send_code)
            code_row = QHBoxLayout()
            code_row.addWidget(self.stu_code, 1)
            code_row.addWidget(self.send_code_btn)
            self.code_status = QLabel()
            self.code_status.setWordWrap(True)
            self.code_status.setVisible(False)

            form.addRow("University:", self.uni_combo)
            form.addRow("", self.uni_hint)
            form.addRow("Name:", self.stu_name)
            form.addRow("Uni email:", self.stu_email)
            form.addRow("Email again:", self.stu_email_again)
            form.addRow("Password:", self.stu_password)
            form.addRow("Confirm:", self.stu_confirm)
            form.addRow("Code:", code_row)
            form.addRow("", self.code_status)
            form.addRow("", hint(
                "BioAudit is free for students. Press Send code and we will email a "
                "six-digit code to your university address to confirm you study there. "
                "Your account is created once you enter it."))
            return page

        def _build_team_page(self) -> QWidget:
            page = QWidget()
            form = QFormLayout(page)
            form.setContentsMargins(0, 4, 0, 0)

            self.team_org = QLineEdit()
            self.team_org.setPlaceholderText("Your organisation's name")
            self.team_name = QLineEdit()
            self.team_name.setPlaceholderText("Optional")
            self.team_email = QLineEdit()
            self.team_email.setPlaceholderText("you@company.com")
            self.team_password = password_field("At least 8 characters")
            self.team_confirm = password_field()
            self.team_solo = QCheckBox("I work alone (freelancer or consultant)")

            form.addRow("Organisation:", self.team_org)
            form.addRow("Name:", self.team_name)
            form.addRow("Work email:", self.team_email)
            form.addRow("Password:", self.team_password)
            form.addRow("Confirm:", self.team_confirm)
            form.addRow("", self.team_solo)
            form.addRow("", hint(
                "Creates a team and makes you its admin, so you can invite colleagues "
                "and oversee their assessments. Joining someone else's team? Use the "
                "invite token they sent you instead."))
            return page

        # ---- behaviour ---------------------------------------------------- #

        def _selected_university(self):
            """(found, university-or-None). found is False if the text matches no entry."""
            index = self.uni_combo.findText(self.uni_combo.currentText().strip())
            if index < 0:
                return False, None
            return True, self.uni_combo.itemData(index)

        def _on_university_changed(self, _index: int) -> None:
            found, uni = self._selected_university()
            if not found:
                return
            if uni is None:
                self.uni_hint.setText(
                    "Use the email address your university gave you. Most end in "
                    ".ac.uk, .edu, or similar.")
                self.stu_email.setPlaceholderText("you@university.ac.uk")
            else:
                endings = " or ".join(f"<b>@{d}</b>" for d in uni["domains"])
                self.uni_hint.setText(
                    f"Use your {uni['name']} email address. It should end in {endings}.")
                self.stu_email.setPlaceholderText(f"you@{uni['domains'][0]}")
            self.uni_hint.setVisible(True)

        def _student_details(self):
            """(problem, email, university). problem is a message to show, or None."""
            found, uni = self._selected_university()
            if not found:
                return (f"Choose your university from the list, or pick \"{NOT_LISTED}\".",
                        "", None)
            email = self.stu_email.text().strip()
            if not email:
                return "Enter your university email address.", email, uni
            if email.lower() != self.stu_email_again.text().strip().lower():
                return ("The two email addresses do not match. Check them for typos.",
                        email, uni)
            if uni is not None and not email_matches(email, uni["domains"]):
                endings = " or ".join(f"@{d}" for d in uni["domains"])
                return (f"Use your {uni['name']} email address. It should end in {endings}.",
                        email, uni)
            return None, email, uni

        def _show_code_status(self, message: str, error: bool) -> None:
            colour = ERROR_TEXT if error else SUCCESS_TEXT
            self.code_status.setText(f"<span style='color:{colour}'>{message}</span>")
            self.code_status.setVisible(True)

        def _send_code(self) -> None:
            """Email the sign-up code to the address entered so far."""
            problem, email, uni = self._student_details()
            if problem:
                self._show_code_status(problem, error=True)
                return
            self._bounce_timer.stop()
            self.setCursor(Qt.WaitCursor)
            try:
                sent = ApiClient(base_url).send_signup_code(
                    email, uni["id"] if uni else None)
            except ApiClientError as exc:
                self._show_code_status(str(exc), error=True)
                return
            finally:
                self.setCursor(Qt.ArrowCursor)
            self.send_code_btn.setText("Send again")
            # The address in bold, so a typo in it stands out before the student sits
            # waiting for a code that went somewhere else.
            message = re.sub(re.escape(email), lambda m: f"<b>{m.group(0)}</b>",
                             sent.get("message", ""), flags=re.IGNORECASE)
            self._show_code_status(message, error=False)
            self.stu_code.setFocus()

            # Only a code that really went out can bounce; a development server just
            # writes it to its log.
            if sent.get("delivered") and sent.get("sendId"):
                self._watching = (email, sent["sendId"],
                                  time.monotonic() + BOUNCE_WATCH_SECONDS)
                self._bounce_timer.start()

        def _check_bounce(self) -> None:
            """Ask whether the code just sent bounced, and say so if it did."""
            email, send_id, deadline = self._watching
            if time.monotonic() > deadline:
                self._bounce_timer.stop()
                return
            try:
                status = ApiClient(base_url).signup_code_status(email, send_id)
            except ApiClientError:
                # The code was used or replaced, or the server is out of reach. Either
                # way there is nothing more to learn about this send.
                self._bounce_timer.stop()
                return
            if status.get("status") == "bounced":
                self._bounce_timer.stop()
                self._show_code_status(status.get("message", ""), error=True)

        def set_return_action(self, callback) -> None:
            """Pressing Enter in the last field of either page submits the dialog."""
            self.stu_code.returnPressed.connect(callback)
            self.team_confirm.returnPressed.connect(callback)

        def submit(self, client: ApiClient) -> Optional[str]:
            """Validate, then register. Returns a message to show, or None on success."""
            if not self.tos_box.isChecked():
                return "Accept the Terms of Use to create an account."
            if self.pages.currentIndex() == TEAM:
                org = self.team_org.text().strip()
                email = self.team_email.text().strip()
                password = self.team_password.text()
                if not org:
                    return "Give your organisation a name."
                if not email:
                    return "Enter your work email address."
                if problem := _password_problem(password, self.team_confirm.text()):
                    return problem
                client.register_admin(email, password, org,
                                      self.team_name.text().strip() or None,
                                      tos_accepted=True,
                                      solo=self.team_solo.isChecked())
                return None

            problem, email, uni = self._student_details()
            if problem:
                return problem
            password = self.stu_password.text()
            if problem := _password_problem(password, self.stu_confirm.text()):
                return problem
            code = self.stu_code.text().strip()
            if len(code) != 6 or not code.isdigit():
                return ("Press Send code, then enter the six-digit code we email to your "
                        "university address.")
            client.register(email, password, self.stu_name.text().strip() or None,
                            university_id=uni["id"] if uni else None, code=code,
                            tos_accepted=True)
            return None

    return RegisterForm()


def _password_problem(password: str, confirm: str) -> Optional[str]:
    if password != confirm:
        return "Those passwords do not match."
    if len(password) < 8:
        return "Use a password of at least 8 characters."
    return None
