"""Smoke tests for the deterministic core (no device or network needed)."""

from bioaudit.models import Finding, Severity, TestRun
from bioaudit.engine import severity


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
