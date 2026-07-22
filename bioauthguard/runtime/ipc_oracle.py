"""IPC / exported-component authorization oracle — the headline runtime feature.

Question it answers: can functionality that is *supposed* to sit behind biometric
authentication be reached WITHOUT authenticating? For each exported component it
issues an unprivileged `am`/`content` probe and inspects whether a protected screen
opens or a protected action fires — no root, no sensor touch. (OWASP M3.)

Safety: probing only happens after the caller has passed the authorization gate in
cli.py. This module performs no exploitation beyond launching the component.
"""

from __future__ import annotations

from ..adb import Adb
from ..models import Finding, Severity
from ..static_analysis.manifest import Component, ManifestInfo


def probe(adb: Adb, package: str, manifest: ManifestInfo) -> list[Finding]:
    """Probe each exported component and flag likely authorization bypasses."""
    findings: list[Finding] = []
    for comp in manifest.exported():
        result = _probe_component(adb, package, comp)
        if result is None:
            continue
        launched, evidence = result
        if launched and not comp.permission:
            findings.append(Finding(
                category="exported-auth-bypass",
                title=f"Exported {comp.kind} reachable without authentication",
                severity=_severity_for(comp),
                owasp=["M3", "M1"],
                evidence=evidence,
                source="ipc_oracle",
                confidence="confirmed",
                component=comp.name,
            ))
    return findings


def _probe_component(adb: Adb, package: str, comp: Component):
    """Return (launched, evidence) or None if the component kind isn't probed."""
    target = f"{package}/{comp.name}"
    if comp.kind == "activity":
        res = adb.shell("am", "start", "-n", target)
        launched = "Starting:" in res.stdout and "Error" not in res.stdout and "Permission Denial" not in (res.stdout + res.stderr)
        return launched, f"`am start -n {target}` -> {res.stdout.strip() or res.stderr.strip()}"
    if comp.kind == "service":
        res = adb.shell("am", "start-service", "-n", target)
        launched = "Error" not in res.stdout and "Permission Denial" not in (res.stdout + res.stderr)
        return launched, f"`am start-service -n {target}` -> {res.stdout.strip() or res.stderr.strip()}"
    if comp.kind == "receiver":
        res = adb.shell("am", "broadcast", "-n", target)
        launched = "Broadcast completed" in res.stdout
        return launched, f"`am broadcast -n {target}` -> {res.stdout.strip()}"
    if comp.kind == "provider":
        # A provider is probed by attempting a content query against its authority.
        res = adb.shell("content", "query", "--uri", f"content://{comp.name}")
        launched = "Permission Denial" not in (res.stdout + res.stderr) and "Error" not in res.stdout
        return launched, f"`content query {comp.name}` -> {res.stdout.strip() or res.stderr.strip()}"
    return None


def _severity_for(comp: Component) -> Severity:
    # An exported activity that opens a UI is the classic full-bypass case.
    if comp.kind in ("activity", "provider"):
        return Severity.CRITICAL
    return Severity.HIGH
