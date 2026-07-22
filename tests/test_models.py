"""Smoke tests for the deterministic core (no device or network needed)."""

from bioauthguard.models import Finding, Severity, TestRun
from bioauthguard.engine import severity
from bioauthguard.ai.redaction import redact


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO


def test_run_ranks_most_severe_first():
    run = TestRun(package="com.example")
    run.add(Finding("a", "low one", Severity.LOW, ["M8"], "e", "t"))
    run.add(Finding("b", "critical one", Severity.CRITICAL, ["M3"], "e", "t"))
    ranked = run.ranked()
    assert ranked[0].severity == Severity.CRITICAL
    assert run.counts()["Critical"] == 1


def test_confidence_downgrade():
    f = Finding("x", "t", Severity.HIGH, ["M3"], "e", "s", confidence="likely")
    severity.adjust_for_confidence(f)
    assert f.severity == Severity.MEDIUM


def test_redaction_strips_secrets():
    out = redact("token=abcdef123456 and key: AKIA1234567890ABCDEF")
    assert "abcdef123456" not in out
    assert "[REDACTED]" in out
