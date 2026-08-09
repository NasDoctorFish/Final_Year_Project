"""Core data models shared across every module.

A Finding is the unit of everything: detectors emit Findings, the engine ranks
them, the AI layer explains them, and the report renders them. Detection is
deterministic — a Finding only exists because a rule confirmed it.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


class Severity(IntEnum):
    """Ordered so findings sort most-severe-first with `sorted(..., reverse=True)`."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()


class TestMode(IntEnum):
    """Mode B (select-app, black-box, no root) is the default and only mode:
    point the tool at an installed app / APK you own or are authorized to test."""

    SELECT_APP = 1


# OWASP Mobile Top 10 (2024) categories this tool legitimately covers.
OWASP = {
    "M1": "Improper Credential Usage",
    "M3": "Insecure Authentication/Authorization",
    "M6": "Inadequate Privacy Controls",
    "M8": "Security Misconfiguration",
    "M9": "Insecure Data Storage",
    "M10": "Insufficient Cryptography",
}


@dataclass
class Finding:
    """A single confirmed weakness.

    `evidence` is the raw proof the detector captured (a manifest snippet, an
    `am start` result, a matched logcat line). It is what the AI layer explains and
    what a reviewer audits — never a guess.
    """

    category: str                       # kebab-case detector slug, e.g. "exported-auth-bypass"
    title: str                          # short human label
    severity: Severity
    owasp: list[str]                    # e.g. ["M3", "M1"]
    evidence: str                       # the proof, verbatim
    source: str                         # which detector produced it, e.g. "ipc_oracle"
    confidence: str = "confirmed"       # "confirmed" | "likely" (APK static analysis)
    component: Optional[str] = None     # affected component/screen if applicable

    # Filled in by the engine + AI layer (never by detectors).
    explanation: Optional[str] = None   # plain-language, AI-generated
    mitigation: Optional[str] = None    # concrete fix, AI-generated
    references: list[str] = field(default_factory=list)

    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["severity"] = self.severity.label
        return d


@dataclass
class TestRun:
    """One assessment of one target, holding all findings."""

    __test__ = False  # not a pytest test class despite the name

    package: str
    mode: TestMode = TestMode.SELECT_APP
    device_serial: Optional[str] = None
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    findings: list[Finding] = field(default_factory=list)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def ranked(self) -> list[Finding]:
        """Findings most-severe-first."""
        return sorted(self.findings, key=lambda f: f.severity, reverse=True)

    def counts(self) -> dict[str, int]:
        out = {s.label: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.label] += 1
        return out

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "package": self.package,
            "mode": self.mode.name,
            "device_serial": self.device_serial,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "counts": self.counts(),
            "findings": [f.to_dict() for f in self.ranked()],
        }
