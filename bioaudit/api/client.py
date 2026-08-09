"""HTTP client for the BioAudit backend.

The desktop app runs the scans locally, because the APK file and the USB-connected
phone are both on this machine. This client is how it talks to the server for
everything else: signing in, saving results, reading history, and asking for a
plain-language explanation of a finding.

Design notes:

* Only the standard library is used. The deterministic core of this project already
  degrades gracefully without third-party packages, and adding `requests` just for a
  handful of calls would work against that.
* An expired ID token is refreshed and the request retried once, automatically. Tokens
  last an hour, so without this a long session would start failing partway through and
  the interface would have to handle it in a dozen places.
* Every failure raises an ApiClientError carrying the server's own message, which is
  written for a person to read, so the GUI can show it directly.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional

from ..models import Finding, TestRun

DEFAULT_BASE_URL = "http://127.0.0.1:4000/api"
DEFAULT_TIMEOUT = 30.0


class ApiClientError(RuntimeError):
    """A request failed. `message` is safe to show the user as-is."""

    def __init__(self, message: str, status: Optional[int] = None,
                 details: Optional[list] = None):
        super().__init__(message)
        self.message = message
        self.status = status
        self.details = details or []

    def __str__(self) -> str:  # pragma: no cover - trivial
        if self.details:
            lines = "\n".join(f"  {d.get('field', '?')}: {d.get('message', '')}"
                              for d in self.details)
            return f"{self.message}\n{lines}"
        return self.message


class AuthRequiredError(ApiClientError):
    """The session is gone and could not be refreshed. The user has to sign in again."""


@dataclass
class Session:
    """Tokens from a successful sign-in.

    `id_token` is sent on every request and expires after about an hour.
    `refresh_token` is long-lived and is used to get a new id_token without asking
    the user for their password again.
    """

    id_token: str
    refresh_token: str
    expires_at: float = 0.0
    uid: Optional[str] = None

    @classmethod
    def from_payload(cls, payload: dict) -> "Session":
        expires_in = float(payload.get("expiresInSeconds") or 3600)
        return cls(
            id_token=payload["idToken"],
            refresh_token=payload["refreshToken"],
            # Refresh a minute early rather than waiting for a request to fail.
            expires_at=time.time() + expires_in - 60,
            uid=payload.get("uid"),
        )

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires_at

    def to_dict(self) -> dict:
        return {
            "id_token": self.id_token,
            "refresh_token": self.refresh_token,
            "expires_at": self.expires_at,
            "uid": self.uid,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Session":
        return cls(
            id_token=data["id_token"],
            refresh_token=data["refresh_token"],
            expires_at=float(data.get("expires_at", 0)),
            uid=data.get("uid"),
        )


@dataclass
class Account:
    """The signed-in user, as the server describes them."""

    id: str
    email: Optional[str]
    display_name: Optional[str]
    tier: str
    role: str
    organisation_id: Optional[str]
    scan_count: int = 0
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_payload(cls, payload: dict) -> "Account":
        return cls(
            id=payload.get("id", ""),
            email=payload.get("email"),
            display_name=payload.get("displayName"),
            tier=payload.get("tier", "free"),
            role=payload.get("role", "member"),
            organisation_id=payload.get("organisationId"),
            scan_count=int(payload.get("scanCount") or 0),
            raw=payload,
        )

    @property
    def is_premium(self) -> bool:
        return self.tier == "premium"

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


class ApiClient:
    """Talks to the BioAudit backend.

    Typical use from the GUI::

        client = ApiClient()
        account = client.login("dev@example.com", "password")
        client.upload_run(test_run, authorised=True)
        history = client.list_history()
    """

    def __init__(self, base_url: str = DEFAULT_BASE_URL, timeout: float = DEFAULT_TIMEOUT):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session: Optional[Session] = None
        self.account: Optional[Account] = None

    # --- plumbing ---------------------------------------------------------

    def _request(self, method: str, path: str, *, body: Any = None,
                 authenticated: bool = True, expect_json: bool = True,
                 _retried: bool = False) -> Any:
        """Send one request, refreshing an expired token once if needed."""
        if authenticated:
            if self.session is None:
                raise AuthRequiredError("You are not signed in.")
            # Refresh proactively when the token is known to be stale, so the common
            # case does not rely on catching a 401.
            if self.session.expired and not _retried:
                self.refresh()

        url = f"{self.base_url}{path}"
        data = None
        headers = {"Accept": "application/json"}

        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if authenticated and self.session:
            headers["Authorization"] = f"Bearer {self.session.id_token}"

        request = urllib.request.Request(url, data=data, headers=headers, method=method)

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = response.read().decode("utf-8", errors="replace")
                if not expect_json:
                    return payload
                return json.loads(payload) if payload else {}

        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(raw).get("error", {})
            except json.JSONDecodeError:
                parsed = {}

            message = parsed.get("message") or f"Request failed with status {exc.code}."
            details = parsed.get("details")

            # A revoked or expired session gets one automatic retry. This happens
            # legitimately whenever the tier or role changes, since the server revokes
            # sessions so the new permissions take effect.
            if exc.code == 401 and authenticated and not _retried and self.session:
                try:
                    self.refresh()
                except ApiClientError:
                    raise AuthRequiredError(message, exc.code) from exc
                return self._request(method, path, body=body,
                                     authenticated=authenticated,
                                     expect_json=expect_json, _retried=True)

            if exc.code == 401:
                raise AuthRequiredError(message, exc.code, details) from exc
            raise ApiClientError(message, exc.code, details) from exc

        except urllib.error.URLError as exc:
            raise ApiClientError(
                f"Could not reach the server at {self.base_url}. Is it running? ({exc.reason})"
            ) from exc

    # --- authentication ---------------------------------------------------

    def register(self, email: str, password: str,
                 display_name: Optional[str] = None) -> Account:
        payload = {"email": email, "password": password}
        if display_name:
            payload["displayName"] = display_name

        data = self._request("POST", "/auth/register", body=payload, authenticated=False)
        self.session = Session.from_payload(data["session"])
        self.account = Account.from_payload(data["user"])
        return self.account

    def register_admin(self, email: str, password: str, organisation_name: str,
                       display_name: Optional[str] = None) -> tuple[Account, dict]:
        """Create an admin account together with the organisation it administers."""
        payload = {"email": email, "password": password,
                   "organisationName": organisation_name}
        if display_name:
            payload["displayName"] = display_name

        data = self._request("POST", "/auth/register-admin", body=payload,
                             authenticated=False)
        self.session = Session.from_payload(data["session"])
        self.account = Account.from_payload(data["user"])
        return self.account, data["organisation"]

    def login(self, email: str, password: str) -> Account:
        data = self._request("POST", "/auth/login",
                             body={"email": email, "password": password},
                             authenticated=False)
        self.session = Session.from_payload(data["session"])
        self.account = Account.from_payload(data["user"])
        return self.account

    def refresh(self) -> None:
        """Swap the refresh token for a new ID token."""
        if self.session is None:
            raise AuthRequiredError("You are not signed in.")

        data = self._request("POST", "/auth/refresh",
                             body={"refreshToken": self.session.refresh_token},
                             authenticated=False)
        self.session = Session.from_payload(data["session"])

    def logout(self) -> None:
        """End the session on the server as well as locally.

        The local tokens are cleared even if the call fails, since the user has asked
        to be signed out and leaving them in place would be worse than a stale
        server-side session.
        """
        try:
            if self.session:
                self._request("POST", "/auth/logout")
        except ApiClientError:
            pass
        finally:
            self.session = None
            self.account = None

    @property
    def signed_in(self) -> bool:
        return self.session is not None

    # --- account ----------------------------------------------------------

    def get_profile(self) -> Account:
        data = self._request("GET", "/users/me")
        self.account = Account.from_payload(data["user"])
        return self.account

    def update_display_name(self, display_name: str) -> Account:
        data = self._request("PATCH", "/users/me", body={"displayName": display_name})
        self.account = Account.from_payload(data["user"])
        return self.account

    def change_email(self, new_email: str, current_password: str) -> Account:
        data = self._request("POST", "/users/me/email",
                             body={"newEmail": new_email,
                                   "currentPassword": current_password})
        self.account = Account.from_payload(data["user"])
        return self.account

    def change_password(self, current_password: str, new_password: str) -> str:
        """Change the password. Every session is signed out, including this one."""
        data = self._request("POST", "/users/me/password",
                             body={"currentPassword": current_password,
                                   "newPassword": new_password})
        self.session = None
        self.account = None
        return data.get("message", "Password changed. Sign in again.")

    def delete_account(self, current_password: str) -> str:
        data = self._request("DELETE", "/users/me",
                             body={"currentPassword": current_password,
                                   "confirm": "DELETE"})
        self.session = None
        self.account = None
        return data.get("message", "Account deleted.")

    # --- scans ------------------------------------------------------------

    @staticmethod
    def _finding_to_payload(finding: Finding) -> dict:
        return {
            "category": finding.category,
            "title": finding.title,
            "severity": finding.severity.name.lower(),
            "owasp": list(finding.owasp),
            "evidence": finding.evidence,
            "source": finding.source,
            "confidence": finding.confidence,
            "component": finding.component,
            "explanation": finding.explanation,
            "mitigation": finding.mitigation,
            "references": list(finding.references),
        }

    def upload_run(self, run: TestRun, *, authorised: bool,
                   apk_file_name: Optional[str] = None,
                   tool_version: Optional[str] = None) -> dict:
        """Save a completed TestRun to the server.

        `authorised` records that the user confirmed they own or may test the app. The
        server refuses a device assessment without it, so this mirrors the same gate the
        CLI and GUI already enforce before running one.
        """
        scan_type = "device" if run.device_serial else "apk"

        payload = {
            "type": scan_type,
            "authorisationConfirmed": bool(authorised),
            "target": {
                "packageName": run.package or None,
                "apkFileName": apk_file_name,
                "deviceSerial": run.device_serial,
            },
            "findings": [self._finding_to_payload(f) for f in run.ranked()],
            "toolVersion": tool_version,
        }
        if run.started_at:
            payload["startedAt"] = _iso(run.started_at)
        if run.finished_at:
            payload["finishedAt"] = _iso(run.finished_at)

        return self._request("POST", "/scans", body=payload)

    def list_history(self, limit: int = 50,
                     scan_type: Optional[str] = None) -> dict:
        """Return recent scans, newest first, plus the account's history limit."""
        query = f"?limit={int(limit)}"
        if scan_type:
            query += f"&type={scan_type}"
        return self._request("GET", f"/scans{query}")

    def get_scan(self, scan_id: str) -> dict:
        return self._request("GET", f"/scans/{scan_id}")["scan"]

    def explain_finding(self, scan_id: str, finding_index: int,
                        force: bool = False) -> dict:
        """Ask the server for a plain-language explanation and fix.

        The AI runs server-side so the API key is never shipped in the desktop app, and
        secrets are stripped from the evidence before the call. A previously generated
        explanation is reused unless `force` is set.
        """
        return self._request(
            "POST",
            f"/scans/{scan_id}/findings/{int(finding_index)}/explain",
            body={"force": bool(force)},
        )

    def compare_scans(self, baseline_id: str, current_id: str) -> dict:
        """Premium. Report what was resolved, introduced, or unchanged between two scans."""
        return self._request(
            "GET", f"/scans/compare/results?baseline={baseline_id}&current={current_id}"
        )["comparison"]

    def export_report(self, scan_id: str) -> str:
        """Premium. Return the report as HTML.

        The server sends HTML rather than PDF so it needs no rendering engine. Pass the
        result to report/generator.py if a PDF is wanted, since this app already has one.
        """
        return self._request("GET", f"/scans/{scan_id}/report",
                            expect_json=False)

    def delete_scan(self, scan_id: str) -> None:
        self._request("DELETE", f"/scans/{scan_id}")

    def clear_history(self) -> int:
        data = self._request("DELETE", "/scans", body={"confirm": "DELETE_ALL"})
        return int(data.get("removed", 0))

    # --- subscription -----------------------------------------------------

    def get_subscription(self) -> dict:
        return self._request("GET", "/subscription")

    def upgrade(self) -> Account:
        """Move to premium. Sessions are revoked, so this signs in again automatically."""
        data = self._request("POST", "/subscription/upgrade", body={})
        self.account = Account.from_payload(data["user"])
        return self.account

    def cancel_subscription(self, reason: Optional[str] = None) -> dict:
        payload = {"confirm": "CANCEL"}
        if reason:
            payload["reason"] = reason
        return self._request("POST", "/subscription/cancel", body=payload)

    # --- organisations ----------------------------------------------------

    def join_organisation(self, invitation_token: str) -> dict:
        return self._request("POST", "/organisations/join",
                             body={"token": invitation_token})

    def my_organisation(self) -> Optional[dict]:
        return self._request("GET", "/organisations/mine").get("organisation")

    def list_members(self, org_id: str) -> list[dict]:
        return self._request("GET", f"/organisations/{org_id}/members")["members"]

    def invite_member(self, org_id: str, email: str, role: str = "member") -> dict:
        """Admin. Returns the invitation together with its one-time token.

        The token is shown once and is not retrievable later, so the interface has to
        present it to the admin immediately.
        """
        return self._request("POST", f"/organisations/{org_id}/invitations",
                             body={"email": email, "role": role})

    def list_invitations(self, org_id: str, status: str = "pending") -> list[dict]:
        return self._request(
            "GET", f"/organisations/{org_id}/invitations?status={status}"
        )["invitations"]

    def cancel_invitation(self, org_id: str, invitation_id: str) -> None:
        self._request("DELETE", f"/organisations/{org_id}/invitations/{invitation_id}")

    def member_scans(self, org_id: str, uid: str, limit: int = 50) -> list[dict]:
        """Admin. Scan summaries for one member.

        Findings are not included. An admin can see that a scan happened and how many
        problems it found, but not the evidence taken from the member's own app, and the
        server records this read in its audit log.
        """
        return self._request(
            "GET", f"/organisations/{org_id}/members/{uid}/scans?limit={int(limit)}"
        )["scans"]

    def flag_scan(self, org_id: str, scan_id: str, reason: str) -> dict:
        return self._request("POST", f"/organisations/{org_id}/scans/{scan_id}/flag",
                             body={"reason": reason})["flag"]

    def list_flags(self, org_id: str, status: str = "open") -> list[dict]:
        return self._request("GET",
                            f"/organisations/{org_id}/flags?status={status}")["flags"]

    def review_flag(self, org_id: str, flag_id: str, decision: str,
                    note: Optional[str] = None) -> dict:
        payload: dict[str, Any] = {"decision": decision}
        if note:
            payload["note"] = note
        return self._request("POST", f"/organisations/{org_id}/flags/{flag_id}/review",
                             body=payload)["flag"]

    def add_admin(self, org_id: str, uid: str) -> str:
        return self._request("POST", f"/organisations/{org_id}/admins",
                             body={"uid": uid}).get("message", "")

    def remove_member(self, org_id: str, uid: str) -> str:
        return self._request("DELETE",
                             f"/organisations/{org_id}/members/{uid}").get("message", "")

    def delete_member_account(self, org_id: str, uid: str, reason: str) -> str:
        return self._request(
            "DELETE", f"/organisations/{org_id}/members/{uid}/account",
            body={"confirm": "DELETE_ACCOUNT", "reason": reason},
        ).get("message", "")

    def audit_log(self, org_id: str, limit: int = 100) -> list[dict]:
        return self._request("GET",
                             f"/organisations/{org_id}/audit?limit={int(limit)}")["entries"]

    # --- health -----------------------------------------------------------

    def health(self) -> dict:
        """Check the server is up and whether AI explanations are configured."""
        return self._request("GET", "/health", authenticated=False)


def _iso(timestamp: float) -> str:
    """Format a Unix timestamp the way the server's validation expects."""
    from datetime import datetime, timezone

    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
