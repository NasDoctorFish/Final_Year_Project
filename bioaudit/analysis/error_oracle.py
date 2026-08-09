"""Behavioural error-oracle: are failure modes externally distinguishable?

Without instrumentation we can't read internal return values, but if wrong-biometric,
lockout, and key-failure produce *observably* different outcomes, that is an
information oracle an attacker can use. (OWASP M3.)
"""

from __future__ import annotations

from ..models import Finding, Severity
from ..runtime.scenarios import Scenario, ScenarioLog


def analyze(log: ScenarioLog) -> list[Finding]:
    """Flag distinguishable observable outcomes across failure scenarios."""
    outcomes: dict[Scenario, set[str]] = {}
    for scenario in (Scenario.FAILURE, Scenario.LOCKOUT, Scenario.FALLBACK):
        outcomes[scenario] = {t.outcome for t in log.by_scenario(scenario)}

    distinct = {s: o for s, o in outcomes.items() if o}
    labels = {frozenset(o) for o in distinct.values()}
    if len(labels) > 1:
        return [Finding(
            category="error-oracle",
            title="Failure modes are externally distinguishable",
            severity=Severity.MEDIUM,
            owasp=["M3"],
            evidence="Different failure scenarios produced different observable outcomes: "
                     + "; ".join(f"{s.value}={sorted(o)}" for s, o in distinct.items()),
            source="analysis.error_oracle",
            confidence="likely",
        )]
    return []
