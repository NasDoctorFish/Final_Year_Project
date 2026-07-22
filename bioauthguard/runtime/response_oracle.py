"""Auth-state / response oracle — a black-box side-channel detector (Mode B).

An oracle attack *is* a side-channel attack: the app's externally-observable
*response* leaks secret auth state. Where the headline `ipc_oracle` asks "can I
reach a protected component at all?", this asks the sharper question: "does an
exported, unguarded component answer *differently* for a valid vs an invalid
credential/identifier?" A component that does is an oracle an attacker can query
to enumerate accounts or brute-force a token — the classic error/enumeration
oracle class (padding/username/auth oracles), applied to Android's IPC surface.

Unlike a timing side channel, this needs no on-device instrumentation and no
rebuild: it is fully automatable over an unprivileged adb session, and it is
*deterministic* — a differing response is a hard fact, not a noisy statistic. It
reuses the exported-component list the IPC oracle already enumerates.

Scope: ContentProviders are the reliable, adb-readable channel (`content query`
prints the returned rows to stdout, so a valid-vs-invalid difference is directly
observable). Activities/Services are deliberately not probed here — their `am`
output rarely varies by input, so probing them would risk false positives. Like
every other detector, this never emits a "no leak" finding: silence on a
no-difference result, consistent with the project's philosophy. (OWASP M3, M1.)
"""

from __future__ import annotations

from ..adb import Adb
from ..models import Finding, Severity
from ..static_analysis.manifest import Component, ManifestInfo

# A plausible-valid identifier vs an obviously-invalid one. If an unguarded
# provider answers these two differently (and the valid-looking one returns
# data), it is behaving as an auth-state / enumeration oracle.
_VALID_GUESS = "admin"
_INVALID_GUESS = "zzzzzzzz9999"

_DENIAL_MARKERS = ("Permission Denial", "SecurityException", "requires the provider")


def probe(adb: Adb, package: str, manifest: ManifestInfo) -> list[Finding]:
    """Probe exported, unguarded providers and flag distinguishable responses."""
    findings: list[Finding] = []
    for comp in manifest.exported():
        if comp.permission:
            continue  # guarded — not an unauthenticated oracle
        if comp.kind != "provider" or not comp.authority:
            continue
        finding = _probe_provider(adb, comp)
        if finding is not None:
            findings.append(finding)
    return findings


def _probe_provider(adb: Adb, comp: Component) -> Finding | None:
    """Query the provider with a valid-looking vs invalid identifier and flag a
    distinguishable, non-error response as an auth-state oracle."""
    valid_uri = f"content://{comp.authority}/{_VALID_GUESS}"
    invalid_uri = f"content://{comp.authority}/{_INVALID_GUESS}"

    valid = adb.shell("content", "query", "--uri", valid_uri)
    invalid = adb.shell("content", "query", "--uri", invalid_uri)

    valid_out = (valid.stdout + valid.stderr).strip()
    invalid_out = (invalid.stdout + invalid.stderr).strip()

    # A permission wall on either probe means it isn't an unauthenticated oracle.
    if any(m in valid_out or m in invalid_out for m in _DENIAL_MARKERS):
        return None

    # Oracle == the two inputs yield distinguishable responses AND the
    # valid-looking guess returns actual data (not the empty "No result found.").
    distinguishable = valid_out != invalid_out
    valid_has_data = bool(valid_out) and "No result found" not in valid_out
    if not (distinguishable and valid_has_data):
        return None

    return Finding(
        category="auth-state-oracle",
        title="Exported provider leaks auth state (distinguishable response oracle)",
        severity=Severity.HIGH,
        owasp=["M3", "M1"],
        evidence=(
            f"Unguarded provider authority '{comp.authority}' answered a valid-looking "
            f"identifier and an invalid one differently:\n"
            f"  `content query --uri {valid_uri}` -> {valid_out!r}\n"
            f"  `content query --uri {invalid_uri}` -> {invalid_out!r}\n"
            f"An unauthenticated caller can use this difference to enumerate valid "
            f"identifiers / brute-force a token."
        ),
        source="response_oracle",
        confidence="confirmed",
        component=comp.name,
    )
