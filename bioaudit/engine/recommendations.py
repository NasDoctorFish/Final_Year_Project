"""Turn raw findings into ranked, explained, remediated findings.

Pipeline: severity adjustment -> AI explanation/mitigation -> ranking. This is the
bridge between the deterministic detectors and the report/dashboard.
"""

from __future__ import annotations

from ..ai.explainer import Explainer
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
}


def process(findings: list[Finding], explainer: Explainer | None = None) -> list[Finding]:
    findings = severity.apply(findings)

    if explainer and explainer.available:
        findings = explainer.explain_all(findings)

    # Ensure every finding has at least a deterministic mitigation.
    for f in findings:
        if not f.mitigation:
            f.mitigation = _FALLBACK_MITIGATIONS.get(f.category, "See OWASP MASVS guidance for this category.")

    return sorted(findings, key=lambda f: f.severity, reverse=True)
