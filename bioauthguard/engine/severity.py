"""Severity model.

Detectors assign an initial severity; this module can adjust it based on
confidence (a "likely" static finding is dialled back one step from a "confirmed"
runtime finding of the same kind), keeping the ranking honest.
"""

from __future__ import annotations

from ..models import Finding, Severity


def adjust_for_confidence(finding: Finding) -> Finding:
    if finding.confidence == "likely" and finding.severity > Severity.LOW:
        finding.severity = Severity(finding.severity - 1)
    return finding


def apply(findings: list[Finding]) -> list[Finding]:
    return [adjust_for_confidence(f) for f in findings]
