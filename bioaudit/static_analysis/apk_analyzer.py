"""Scan decompiled APK bytecode for insecure biometric patterns.

Mode B has no source, so fidelity is lower than white-box analysis (obfuscation,
decompiler noise). Findings from here are marked confidence="likely".
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..models import Finding, Severity

# (regex, category, title, severity, owasp) — matched against decompiled smali/text.
# These are intentionally conservative heuristics; each match is "likely", not proof.
_PATTERNS: list[tuple[str, str, str, Severity, list[str]]] = [
    (
        r"onAuthenticationSucceeded",
        "boolean-success-check",
        "Uses onAuthenticationSucceeded callback",
        Severity.INFO,
        ["M3"],
    ),
    (
        r"CryptoObject",
        "crypto-object-present",
        "References BiometricPrompt.CryptoObject",
        Severity.INFO,
        ["M10"],
    ),
    (
        r"setUserAuthenticationRequired",
        "user-auth-required",
        "Calls setUserAuthenticationRequired",
        Severity.INFO,
        ["M10"],
    ),
]


@dataclass
class _Signals:
    uses_success_callback: bool = False
    uses_crypto_object: bool = False
    sets_user_auth_required: bool = False


def analyze_apk(apk_path: str) -> list[Finding]:
    """Return biometric-implementation findings from the APK's identifiers."""
    text = _identifier_text(apk_path)
    signals = _Signals(
        uses_success_callback=bool(re.search(_PATTERNS[0][0], text)),
        uses_crypto_object=bool(re.search(_PATTERNS[1][0], text)),
        sets_user_auth_required=bool(re.search(_PATTERNS[2][0], text)),
    )

    findings: list[Finding] = []

    # The core insecure pattern: a success callback with no crypto binding.
    if signals.uses_success_callback and not signals.uses_crypto_object:
        findings.append(Finding(
            category="boolean-only-auth",
            title="Biometric result trusted without a bound cryptographic key",
            severity=Severity.HIGH,
            owasp=["M3", "M10", "M1"],
            evidence="onAuthenticationSucceeded is used but no CryptoObject reference was found in the APK",
            source="apk_analyzer",
            confidence="likely",
        ))

    if signals.uses_crypto_object and not signals.sets_user_auth_required:
        findings.append(Finding(
            category="key-not-auth-bound",
            title="Cryptographic key may not be bound to biometric enrolment",
            severity=Severity.MEDIUM,
            owasp=["M10"],
            evidence="CryptoObject is used but setUserAuthenticationRequired was not found",
            source="apk_analyzer",
            confidence="likely",
        ))

    return findings


def _identifier_text(apk_path: str) -> str:
    """Concatenate the APK's DEX string pool(s) for fast pattern scanning.

    The signals we look for (onAuthenticationSucceeded, CryptoObject,
    setUserAuthenticationRequired) are all *identifiers* — method names, type
    descriptors, or string constants — which live verbatim in the DEX string pool,
    including framework methods the app merely calls. Reading that pool is
    near-instant.

    The previous implementation ran androguard's DAD decompiler over every method
    (`AnalyzeAPK` + `get_source()`), which grinds for minutes on a real-world APK
    with tens of thousands of methods — the cause of `scan-apk` appearing to hang.
    The string pool is also *more* complete than decompiled source, which silently
    skips any method the decompiler chokes on. Kept isolated so the heavy androguard
    import only happens when static analysis actually runs.
    """
    from androguard.core.apk import APK
    from androguard.core.dex import DEX

    apk = APK(apk_path)
    chunks: list[str] = []
    for dex_bytes in apk.get_all_dex():
        chunks.extend(str(s) for s in DEX(dex_bytes).get_strings())
    return "\n".join(chunks)
