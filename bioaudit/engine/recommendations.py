"""Turn raw findings into ranked, remediated findings.

Pipeline: severity adjustment -> deterministic fallback mitigation -> ranking. AI
explanation is no longer done here or anywhere on the client: it runs entirely on the
backend (see `backend/src/services/gemini.service.js`), called through
`ApiClient.explain_finding` once a run is saved to an account. A local explainer used
to exist alongside it, reading a `GEMINI_API_KEY` from the machine's own environment,
but that meant a checkbox that worked only on whichever PC happened to have that
variable set and silently did nothing everywhere else -- the opposite of the
one-shared-backend design the rest of the app now follows.
"""

from __future__ import annotations

from ..models import Finding
from . import severity

# Deterministic fallback mitigations, used when the AI layer is unavailable so the
# report is never empty of guidance.
_FALLBACK_MITIGATIONS = {
    "boolean-only-auth": "Gate access on a biometric-bound key: wrap a Cipher in a "
                         "CryptoObject and pass it to BiometricPrompt.authenticate(); "
                         "generate the key with setUserAuthenticationRequired(true).",
    "exported-auth-bypass": "Set android:exported=\"false\" on the component, or guard "
                            "it with a signature-level permission, and re-check auth "
                            "state at every entry point.",
    "logcat-leak": "Remove sensitive logging from release builds; never log keys, "
                   "tokens, or auth state.",
    "flag-secure-missing": "Set FLAG_SECURE on windows showing the prompt or post-auth "
                           "secrets.",
    "backup-extractable": "Set android:allowBackup=\"false\".",
    "allow-backup": "Set android:allowBackup=\"false\".",
    "key-not-auth-bound": "Add setUserAuthenticationRequired(true) to the key spec so "
                          "the key is unusable without a fresh biometric.",
    "auth-state-oracle": "Return an identical, generic response for valid and invalid "
                         "inputs so the response can't be used to enumerate accounts or "
                         "brute-force a token; require a signature-level permission or a "
                         "real auth check on the component, and rate-limit queries.",
    "debuggable-release": "Remove android:debuggable from the manifest and let the build "
                          "system set it, so release builds ship without it; a debuggable "
                          "build lets anyone attach a debugger and step over every check.",
    "exported-unguarded-component": "Set android:exported=\"false\" if no other app needs "
                                    "the component, or guard it with a signature-level "
                                    "permission; validate every Intent field it receives.",
    "error-oracle": "Return one generic failure message for every authentication error, "
                    "so a wrong password cannot be told apart from an unknown account; "
                    "keep the real reason in server-side logs only.",
    "lockout-state-leak": "Track lockout server-side and never expose the attempt count "
                          "or locked state to an unauthenticated caller; return the same "
                          "generic failure whether locked out or simply wrong.",
    "lockout-improper-reset": "Hold the failed-attempt counter server-side, keyed to the "
                              "account rather than the install, and reset it only on a "
                              "genuine success or a server-side timeout; add backoff.",
}


def process(findings: list[Finding]) -> list[Finding]:
    findings = severity.apply(findings)

    # Ensure every finding has at least a deterministic mitigation. AI explanation, when
    # wanted, happens later and server-side (see module docstring).
    for f in findings:
        if not f.mitigation:
            f.mitigation = _FALLBACK_MITIGATIONS.get(f.category, "See OWASP MASVS guidance for this category.")

    return sorted(findings, key=lambda f: f.severity, reverse=True)
