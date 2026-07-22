"""Passive, no-root observers: logcat leakage, FLAG_SECURE, allowBackup.

These need no instrumentation — they watch the app from an unprivileged ADB
session while scenarios run.
"""

from __future__ import annotations

import re

from ..adb import Adb
from ..models import Finding, Severity
from ..static_analysis.manifest import ManifestInfo

# Heuristic patterns for secret / auth-state leakage in logs.
_SECRET_PATTERNS = [
    re.compile(r"(?i)\b(token|secret|api[_-]?key|password|passwd)\b\s*[:=]\s*\S+"),
    re.compile(r"(?i)auth(entication)?\s+(succe|success|passed|granted)"),
    re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),  # long base64-ish blob (possible key)
]


def scan_logcat(adb: Adb, package: str) -> list[Finding]:
    """Scan recent logcat for leaked secrets / auth state.

    `adb logcat` reads system-wide logs without root (the shell holds READ_LOGS).
    """
    res = adb.shell("logcat", "-d", "-t", "2000")
    findings: list[Finding] = []
    for line in res.stdout.splitlines():
        if package not in line and "Biometric" not in line and "auth" not in line.lower():
            continue
        for pat in _SECRET_PATTERNS:
            if pat.search(line):
                findings.append(Finding(
                    category="logcat-leak",
                    title="Sensitive value logged to logcat",
                    severity=Severity.HIGH,
                    owasp=["M9", "M6"],
                    evidence=f"logcat line: {line.strip()[:200]}",
                    source="observers.logcat",
                    confidence="confirmed",
                ))
                break
    return _dedupe(findings)


def check_flag_secure(adb: Adb, package: str, screenshot_dir: str) -> list[Finding]:
    """Detect whether the current (auth) screen is capturable (FLAG_SECURE absent).

    A screencap that succeeds while a sensitive screen is foregrounded indicates
    FLAG_SECURE is not set. Callers should foreground the prompt first.
    """
    remote = "/sdcard/bioauthguard_cap.png"
    res = adb.shell("screencap", "-p", remote)
    if res.ok:
        adb.run("pull", remote, screenshot_dir)
        adb.shell("rm", remote)
        return [Finding(
            category="flag-secure-missing",
            title="Sensitive screen is capturable (FLAG_SECURE likely not set)",
            severity=Severity.MEDIUM,
            owasp=["M8"],
            evidence="adb screencap succeeded while the biometric/post-auth screen was foregrounded",
            source="observers.screencap",
            confidence="likely",
        )]
    return []


def check_allow_backup(adb: Adb, package: str, manifest: ManifestInfo) -> list[Finding]:
    """If allowBackup is on, note that data is extractable without root (version-gated)."""
    if not manifest.allow_backup:
        return []
    return [Finding(
        category="backup-extractable",
        title="App data extractable via adb backup",
        severity=Severity.MEDIUM,
        owasp=["M9"],
        evidence="allowBackup=true; `adb backup` can extract private data without root on supported Android versions",
        source="observers.backup",
        confidence="likely",
    )]


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen = set()
    out = []
    for f in findings:
        key = (f.category, f.evidence[:60])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
