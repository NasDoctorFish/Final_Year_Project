# Android Biometric Security — Grounding Knowledge Base

This file grounds the AI explanation/mitigation layer. Each finding is paired with
the relevant entries below so explanations and fixes cite real guidance rather than
model memory. Keep entries short, factual, and reference-anchored.

## Core principle: bind a key, don't trust a boolean

A secure biometric flow must gate access on a **biometric-bound cryptographic key**
unlocked inside `BiometricPrompt.authenticate(CryptoObject)`. Treating the
`onAuthenticationSucceeded` callback as proof — without a `CryptoObject` — means an
attacker who can invoke the callback path (instrumentation, exported entry point,
tampered flow) bypasses auth entirely. (OWASP M3, M10, M1.)

- Generate keys with `KeyGenParameterSpec.Builder(...).setUserAuthenticationRequired(true)`.
- Prefer hardware-backed / StrongBox keys (`setIsStrongBoxBacked(true)` where available).
- Pass a `CryptoObject` wrapping the `Cipher`/`Signature`/`Mac` to `authenticate()`.

## Exported-component authorization (IPC oracle)

Functionality behind biometric auth must not be reachable without authenticating.
An `Activity`/`Service`/`Receiver`/`Provider` marked `android:exported="true"`
(or exported implicitly via an intent-filter) that leads to a protected screen or
action is an **authorization-bypass channel**. (OWASP M3.)

- Set `android:exported="false"` unless the component is genuinely a public entry point.
- Guard exported components with a signature-level permission.
- Re-check authentication state at every entry point, not only the login screen.

## Logcat / data leakage

Keys, tokens, decrypted secrets, or "auth succeeded" state must never be written to
logs, screenshots, recents thumbnails, or backups. (OWASP M9, M6, M8.)

- Never log secrets; strip debug logging from release builds.
- Set `FLAG_SECURE` on windows showing the prompt or post-auth secrets.
- Set `android:allowBackup="false"` to prevent `adb backup` extraction.

## Fallback handling

Weak fallback (device credential accepted where biometric strength is required)
undermines the guarantee. Use `setAllowedAuthenticators(BIOMETRIC_STRONG)` and only
add `DEVICE_CREDENTIAL` when the threat model permits it. (OWASP M3.)
