"""Lockout / attempt-counter oracle.

Two checks: does the app leak attempt state, and does lockout reset improperly
(e.g. on restart) enabling brute force? (OWASP M3.)
"""

from __future__ import annotations

from ..models import Finding, Severity
from ..runtime.scenarios import Scenario, ScenarioLog


def analyze(log: ScenarioLog, reset_after_restart: bool | None = None) -> list[Finding]:
    findings: list[Finding] = []

    # Attempt-state leakage: distinct outcomes as failures accumulate.
    lockout_outcomes = [t.outcome for t in log.by_scenario(Scenario.LOCKOUT)]
    if len(set(lockout_outcomes)) > 1:
        findings.append(Finding(
            category="lockout-state-leak",
            title="Lockout progress is observable",
            severity=Severity.LOW,
            owasp=["M3"],
            evidence=f"Observable lockout outcomes varied across trials: {sorted(set(lockout_outcomes))}",
            source="analysis.lockout",
            confidence="likely",
        ))

    if reset_after_restart:
        findings.append(Finding(
            category="lockout-improper-reset",
            title="Lockout counter resets on restart",
            severity=Severity.HIGH,
            owasp=["M3"],
            evidence="Failed-attempt counter reset after the app was killed/reinstalled, enabling brute force",
            source="analysis.lockout",
            confidence="confirmed",
        ))
    return findings
