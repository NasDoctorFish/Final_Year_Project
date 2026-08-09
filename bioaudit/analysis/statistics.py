"""Statistical baseline + outlier detection (no ML).

Establishes normal observable behaviour across trials and flags statistical
deviations using robust z-scores. Deliberately NOT machine-learning: at realistic
trial counts there is not enough data to train anything meaningful.
"""

from __future__ import annotations

import numpy as np

from ..runtime.scenarios import Scenario, ScenarioLog


def outlier_report(log: ScenarioLog, z_threshold: float = 3.5) -> dict:
    """Return per-scenario robust-z outlier flags over UI round-trip durations.

    Uses the median/MAD robust z-score. Note: these UI-level durations are a
    consistency signal only — they are explicitly NOT a timing side-channel measure
    (that requires on-device instrumentation, which Mode B does not have).
    """
    report: dict[str, dict] = {}
    for scenario in Scenario:
        durations = np.array([t.duration_ms for t in log.by_scenario(scenario)], dtype=float)
        if durations.size < 3:
            continue
        median = float(np.median(durations))
        mad = float(np.median(np.abs(durations - median))) or 1e-9
        robust_z = 0.6745 * (durations - median) / mad
        report[scenario.value] = {
            "n": int(durations.size),
            "median_ms": median,
            "mad": mad,
            "outlier_count": int(np.sum(np.abs(robust_z) > z_threshold)),
        }
    return report
