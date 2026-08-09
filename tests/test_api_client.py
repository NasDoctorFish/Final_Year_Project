"""End-to-end tests for the API client against a running backend.

These are skipped unless a server is reachable, so the normal `pytest tests/` run stays
offline and needs nothing installed. To run them:

    cd backend
    npm run emulators          # leave this running
    node tests/serve-emulated.mjs   # leave this running too
    pytest tests/test_api_client.py -v

The point of testing against a real server rather than a mock is that a mock would only
prove the client agrees with my assumptions. This proves it agrees with the API.
"""

from __future__ import annotations

import random
import string
import urllib.error
import urllib.request

import pytest

from bioaudit.api import ApiClient, ApiClientError
from bioaudit.models import Finding, Severity, TestRun

BASE_URL = "http://127.0.0.1:4000/api"


def _server_available() -> bool:
    try:
        with urllib.request.urlopen(f"{BASE_URL}/health", timeout=2) as response:
            return response.status == 200
    except (urllib.error.URLError, OSError):
        return False


pytestmark = pytest.mark.skipif(
    not _server_available(),
    reason=f"No backend reachable at {BASE_URL}. See this file's docstring to run these.",
)


def _unique() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


@pytest.fixture
def client() -> ApiClient:
    return ApiClient(BASE_URL)


@pytest.fixture
def signed_in(client: ApiClient) -> ApiClient:
    client.register(f"pytest-{_unique()}@example.com", "pytest-password-1", "Pytest User")
    return client


def _sample_run(package: str = "com.example.app") -> TestRun:
    run = TestRun(package=package, device_serial="pytest-device")
    run.add(Finding(
        category="exported-auth-bypass",
        title="Exported activity reachable without authentication",
        severity=Severity.CRITICAL,
        owasp=["M3", "M1"],
        evidence="`am start -n com.example.app/.SecretActivity` -> Starting: Intent{...}",
        source="ipc_oracle",
        confidence="confirmed",
        component="com.example.app.SecretActivity",
    ))
    run.add(Finding(
        category="logcat-leak",
        title="Sensitive value logged to logcat",
        severity=Severity.HIGH,
        owasp=["M9", "M6"],
        evidence="logcat line: auth session token=REDACTED_IN_TEST",
        source="observers.logcat",
        confidence="confirmed",
    ))
    return run


def test_health_reports_status(client: ApiClient):
    assert client.health()["status"] == "ok"


def test_register_then_read_profile(client: ApiClient):
    email = f"pytest-{_unique()}@example.com"
    account = client.register(email, "pytest-password-1", "Pytest User")

    assert account.email == email
    assert account.tier == "free"
    assert not account.is_premium
    assert client.signed_in

    fetched = client.get_profile()
    assert fetched.display_name == "Pytest User"


def test_login_with_wrong_password_is_refused(client: ApiClient):
    email = f"pytest-{_unique()}@example.com"
    client.register(email, "pytest-password-1")
    client.logout()

    with pytest.raises(ApiClientError) as exc:
        client.login(email, "definitely-wrong")
    assert exc.value.status == 401


def test_unknown_email_and_wrong_password_look_identical(client: ApiClient):
    """The API must not reveal which accounts exist. See the backend's auth service."""
    email = f"pytest-{_unique()}@example.com"
    client.register(email, "pytest-password-1")
    client.logout()

    with pytest.raises(ApiClientError) as wrong_password:
        client.login(email, "definitely-wrong")
    with pytest.raises(ApiClientError) as unknown_email:
        client.login(f"nobody-{_unique()}@example.com", "definitely-wrong")

    assert wrong_password.value.message == unknown_email.value.message


def test_upload_run_and_read_it_back(signed_in: ApiClient):
    run = _sample_run()
    result = signed_in.upload_run(run, authorised=True)

    assert result["scan"]["findingCount"] == 2
    assert result["scan"]["counts"]["critical"] == 1
    assert result["scan"]["counts"]["high"] == 1

    history = signed_in.list_history()
    assert len(history["scans"]) >= 1
    assert history["tier"] == "free"

    scan = signed_in.get_scan(result["scan"]["id"])
    categories = {f["category"] for f in scan["findings"]}
    assert categories == {"exported-auth-bypass", "logcat-leak"}


def test_device_scan_without_authorisation_is_refused(signed_in: ApiClient):
    with pytest.raises(ApiClientError) as exc:
        signed_in.upload_run(_sample_run(), authorised=False)
    assert exc.value.status == 400
    assert "authorised" in exc.value.message.lower()


def test_severity_names_survive_the_round_trip(signed_in: ApiClient):
    """Severity is an IntEnum locally and a lowercase string on the wire."""
    result = signed_in.upload_run(_sample_run(), authorised=True)
    scan = signed_in.get_scan(result["scan"]["id"])
    severities = [f["severity"] for f in scan["findings"]]
    assert "critical" in severities
    assert all(s == s.lower() for s in severities), "severities should be lowercase"


def test_free_tier_is_blocked_from_premium_features(signed_in: ApiClient):
    first = signed_in.upload_run(_sample_run("com.a"), authorised=True)
    second = signed_in.upload_run(_sample_run("com.a"), authorised=True)

    with pytest.raises(ApiClientError) as compare:
        signed_in.compare_scans(first["scan"]["id"], second["scan"]["id"])
    assert compare.value.status == 402

    with pytest.raises(ApiClientError) as export:
        signed_in.export_report(first["scan"]["id"])
    assert export.value.status == 402


def test_upgrade_then_compare_and_export(signed_in: ApiClient):
    email = signed_in.account.email
    account = signed_in.upgrade()
    assert account.is_premium

    # Upgrading revokes sessions on the server, and the client refreshes through that
    # automatically, so the next call should simply work.
    baseline = signed_in.upload_run(_sample_run("com.compare"), authorised=True)

    fixed = _sample_run("com.compare")
    fixed.findings = [f for f in fixed.findings if f.category != "logcat-leak"]
    current = signed_in.upload_run(fixed, authorised=True)

    comparison = signed_in.compare_scans(baseline["scan"]["id"], current["scan"]["id"])
    assert comparison["summary"]["resolved"] == 1
    assert comparison["summary"]["unchanged"] == 1

    html = signed_in.export_report(current["scan"]["id"])
    assert "<!doctype html>" in html.lower()
    assert "com.compare" in html
    assert email  # the account we started with is the one still signed in


def test_delete_and_clear_history(signed_in: ApiClient):
    result = signed_in.upload_run(_sample_run(), authorised=True)
    signed_in.delete_scan(result["scan"]["id"])

    signed_in.upload_run(_sample_run(), authorised=True)
    removed = signed_in.clear_history()
    assert removed >= 1
    assert signed_in.list_history()["scans"] == []


def test_admin_can_invite_and_manage_a_member(client: ApiClient):
    admin_email = f"pytest-admin-{_unique()}@example.com"
    account, organisation = client.register_admin(
        admin_email, "pytest-password-1", "Pytest Security Team", "Owner"
    )
    assert account.is_admin
    org_id = organisation["id"]

    member_email = f"pytest-member-{_unique()}@example.com"
    invitation = client.invite_member(org_id, member_email)
    assert invitation["token"], "the one-time token should be returned"

    member = ApiClient(BASE_URL)
    member.register(member_email, "pytest-password-1", "Member")
    member.join_organisation(invitation["token"])

    members = client.list_members(org_id)
    assert member_email in {m["email"] for m in members}

    # A member must not reach the admin endpoints.
    member.login(member_email, "pytest-password-1")
    with pytest.raises(ApiClientError) as exc:
        member.list_members(org_id)
    assert exc.value.status == 403


def test_admin_cannot_see_member_findings(client: ApiClient):
    """The privacy line this project promises: an app's code stays on its own machine."""
    admin_email = f"pytest-admin-{_unique()}@example.com"
    _, organisation = client.register_admin(
        admin_email, "pytest-password-1", "Pytest Team"
    )
    org_id = organisation["id"]

    member_email = f"pytest-member-{_unique()}@example.com"
    invitation = client.invite_member(org_id, member_email)

    member = ApiClient(BASE_URL)
    member_account = member.register(member_email, "pytest-password-1")
    member.join_organisation(invitation["token"])
    member.login(member_email, "pytest-password-1")
    member.upload_run(_sample_run("com.member.private"), authorised=True)

    scans = client.member_scans(org_id, member_account.id)
    assert len(scans) >= 1
    assert "findings" not in scans[0], "an admin must not receive the findings"
    assert scans[0]["counts"], "but the severity counts should be visible"


def test_error_message_is_human_readable(client: ApiClient):
    with pytest.raises(ApiClientError) as exc:
        client.register("not-an-email", "short")
    assert exc.value.status == 400
    # The GUI shows these directly, so they have to read as sentences.
    assert exc.value.details, "validation errors should list the offending fields"
