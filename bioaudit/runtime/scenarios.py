"""Scenario driver: success / failure / lockout / fallback.

Mode B is black-box, so the tool cannot inject a fingerprint. It reaches the
biometric prompt through the app UI. The realistic model for a course project is
manual-navigation-assisted: the operator drives the app to the auth screen and
hands off, then the tool records observable outcomes across repeated trials.

Automatic UI navigation across arbitrary apps is out of scope; this module records
what it observes rather than promising unattended triggering.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Scenario(Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    LOCKOUT = "lockout"
    FALLBACK = "fallback"


@dataclass
class Trial:
    scenario: Scenario
    duration_ms: float          # UI-level round-trip only (NOT a side-channel signal)
    outcome: str                # observable result label
    detail: str = ""


@dataclass
class ScenarioLog:
    """Collected trials, consumed by the behavioural analysers."""

    trials: list[Trial] = field(default_factory=list)

    def add(self, trial: Trial) -> None:
        self.trials.append(trial)

    def by_scenario(self, scenario: Scenario) -> list[Trial]:
        return [t for t in self.trials if t.scenario == scenario]


def run_manual_assisted(package: str, trials_per_scenario: int) -> ScenarioLog:
    """Placeholder for the operator-driven scenario loop.

    A full implementation prompts the operator to reach the auth screen, then uses
    uiautomator2 to detect the system BiometricPrompt dialog and record the
    observable outcome per trial. Left as a stub so the rest of the pipeline (which
    doesn't depend on live scenarios) runs end-to-end.
    """
    raise NotImplementedError(
        "Manual-assisted scenario driving is not implemented in this scaffold; "
        "the static, IPC, and passive-observer paths run without it."
    )
