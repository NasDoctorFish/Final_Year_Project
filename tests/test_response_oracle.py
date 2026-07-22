"""Tests for the auth-state / response oracle detector (no device needed).

A tiny fake Adb scripts `content query` responses so the pure detection logic can
be exercised deterministically, mirroring how the real detector reads adb output.
"""

from bioauthguard.adb import AdbResult
from bioauthguard.runtime import response_oracle
from bioauthguard.static_analysis.manifest import Component, ManifestInfo


class FakeAdb:
    """Returns a scripted AdbResult for `content query --uri <uri>` calls.

    `responses` maps the last path segment of the queried URI to (stdout, stderr).
    """

    def __init__(self, responses):
        self.responses = responses

    def shell(self, *args, timeout: int = 60):
        uri = args[args.index("--uri") + 1]
        segment = uri.rsplit("/", 1)[-1]
        stdout, stderr = self.responses.get(segment, ("", ""))
        return AdbResult(0, stdout, stderr)


def _provider(**kwargs):
    base = dict(kind="provider", name=".TokenCheckProvider", exported=True,
                authority="com.example.tokens")
    base.update(kwargs)
    return ManifestInfo(package="com.example", components=[Component(**base)])


def test_flags_distinguishable_response_as_oracle():
    adb = FakeAdb({
        "admin": ("Row: 0 status=valid", ""),
        "zzzzzzzz9999": ("No result found.", ""),
    })
    findings = response_oracle.probe(adb, "com.example", _provider())
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "auth-state-oracle"
    assert f.confidence == "confirmed"
    assert "com.example.tokens" in f.evidence


def test_no_finding_when_responses_identical():
    adb = FakeAdb({
        "admin": ("No result found.", ""),
        "zzzzzzzz9999": ("No result found.", ""),
    })
    assert response_oracle.probe(adb, "com.example", _provider()) == []


def test_no_finding_on_permission_denial():
    denial = ("", "java.lang.SecurityException: Permission Denial: opening provider")
    adb = FakeAdb({"admin": denial, "zzzzzzzz9999": denial})
    assert response_oracle.probe(adb, "com.example", _provider()) == []


def test_no_finding_when_valid_probe_returns_no_data():
    # Distinguishable, but the valid-looking guess itself returned nothing useful —
    # not an exploitable oracle, so stay silent.
    adb = FakeAdb({
        "admin": ("No result found.", ""),
        "zzzzzzzz9999": ("Error while accessing provider", ""),
    })
    # (the invalid side differs, but valid_has_data is False)
    assert response_oracle.probe(adb, "com.example", _provider()) == []


def test_skips_permission_guarded_provider():
    adb = FakeAdb({
        "admin": ("Row: 0 status=valid", ""),
        "zzzzzzzz9999": ("No result found.", ""),
    })
    guarded = _provider(permission="com.example.permission.PRIVATE")
    assert response_oracle.probe(adb, "com.example", guarded) == []


def test_skips_provider_without_authority():
    adb = FakeAdb({})
    no_auth = _provider(authority=None)
    assert response_oracle.probe(adb, "com.example", no_auth) == []
