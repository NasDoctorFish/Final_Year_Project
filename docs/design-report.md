# BioAuthGuard — Design Report

**A pure-Python security testing tool for Android biometric authentication (Mode B).**
It inspects an app you own or are authorized to test — an installed app on a real
device, or an APK on disk — and reports whether its biometric authentication is
*secure*, not merely whether it *works*. Detection is deterministic; an AI layer
turns each confirmed finding into a plain-language explanation, a severity rank, and
a concrete fix.

---

## 1. Problem

Developers add biometric login in a few lines with `BiometricPrompt` + `KeyStore`,
but most can't judge whether the result is *secure*. The dangerous failures are
subtle: trusting the `onAuthenticationSucceeded` boolean instead of unlocking a
biometric-bound key; keys not hardware-backed or not enrolment-bound; weak fallback;
and — the one code review misses most — the auth check being **decorative** while
the protected functionality is reachable through an exposed component. Existing
tools do functional QA; BioAuthGuard does security analysis with remediation, for
developers without security expertise.

## 2. Scope decisions (final)

| Decision | Choice | Why |
|---|---|---|
| Testing mode | **Mode B only** — select an installed app / APK, black-box | No harness to build/maintain; works on any app; a pure Python + ADB tool. |
| Root | **Not required** | All runtime checks use an unprivileged ADB session; widens the usable audience. |
| Timing side-channel | **Dropped** | Needs on-device instrumentation (harness or Frida+root); impossible black-box, no-root without measuring noise. Emitting a "no leak" verdict would be a false sense of security. |
| Headline runtime feature | **IPC / exported-component authorization oracle** | Runtime, observable, no root; catches "auth is decorative, the real entry point is exposed." Survives every constraint. |
| Target device | **Real physical device** (Pixel, Android 12+) | Hardware-backed Keystore and true runtime behaviour only exist on real hardware; emulator reserved for tool development. |
| AI role | **Explanation + mitigation only**, grounded, redacted | Security verdicts must be deterministic/reproducible; AI translates confirmed findings, never decides them. |
| Stack | Python 3 + ADB + `androguard` + Streamlit + SQLite + WeasyPrint | Fastest path to a clean, editable tool. |

## 3. Architecture

```
Python host (pure ADB, no root)
  static_analysis/  androguard: manifest + decompiled-bytecode patterns
  runtime/          ipc_oracle (headline) · scenarios · passive observers
  analysis/         error-oracle · lockout · statistics (no ML)
  ai/               redaction -> grounded Claude explanation/mitigation
  engine/           severity model -> recommendation orchestration
  report/ storage/ dashboard/   HTML+PDF · SQLite history · Streamlit
         │ ADB
Real Android device: the installed app under test (driven black-box)
```

**Principle:** detection is deterministic; the real device makes runtime verdicts
trustworthy; nothing needs root.

## 4. Features and OWASP mapping

| Feature | Module | OWASP | Notes |
|---|---|---|---|
| APK static analysis | `static_analysis/apk_analyzer.py` | M3, M10, M1 | Decompiled; findings marked "likely". |
| Manifest / misconfig checks | `static_analysis/manifest.py` | M8, M3, M9 | Exported components, debuggable, allowBackup. |
| **IPC authorization oracle** | `runtime/ipc_oracle.py` | M3, M1 | Probes exported components for auth bypass. |
| Scenario testing | `runtime/scenarios.py` | M3 | Manual-navigation-assisted (black-box). |
| Logcat leakage | `runtime/observers.py` | M9, M6 | `adb logcat`, no root. |
| FLAG_SECURE / recents | `runtime/observers.py` | M8 | `adb screencap`. |
| allowBackup extraction | `runtime/observers.py` | M9 | Version-gated. |
| Behavioural error-oracle | `analysis/error_oracle.py` | M3 | Observable-outcome distinguishability. |
| Lockout oracle | `analysis/lockout.py` | M3 | Attempt-state leak / improper reset. |
| Statistical baseline | `analysis/statistics.py` | — | Robust-z outlier detection, no ML. |
| AI explanation + mitigation | `ai/` | — | Grounded, redacted, `gemini-flash-latest`. |
| Severity + recommendations | `engine/` | — | Confidence-adjusted ranking. |
| Dashboard + history | `dashboard/`, `storage/` | — | Streamlit + SQLite. |
| Report export | `report/` | — | HTML → PDF. |

**Out of scope (stated for credibility):** timing/cache/power side channels;
direct `/data/data` inspection (root only); OWASP M2, M4, M5, M7.

## 5. The AI layer (bounded)

- **Detection first, AI second.** The engine emits confirmed findings; the model
  only ever sees them — never "go find bugs."
- **Grounded.** Each finding is paired with `config/knowledge_base/android_biometric_kb.md`
  so explanations/fixes cite real guidance, not model memory.
- **Structured + low-variance.** Uses the Gemini SDK's structured output
  (`response_schema` → a Pydantic `Explanation`) with the `gemini-flash-latest`
  model, auto-discovering an available model if that one is ever retired.
- **Privacy.** Secrets are redacted from evidence before any API call
  (`ai/redaction.py`); the layer degrades gracefully with no SDK/key.

## 6. Severity model

Critical (auth fully bypassable) · High (secret/key exposure or boolean-only auth) ·
Medium (conditional weakness) · Low (hardening gap) · Info (observation). Static
"likely" findings are dialled back one step from "confirmed" runtime findings.

## 7. Workflow

1. Confirm authorization (`--i-am-authorized`).
2. Static pass on the APK (manifest + decompiled patterns).
3. Enumerate exported components; probe them (IPC oracle).
4. Passive observers: logcat, screencap, allowBackup.
5. Engine: severity adjust → AI explain/remediate → rank.
6. Persist to SQLite; export HTML/PDF; show in the dashboard.

## 8. Limitations

Decompiled-APK fidelity is lower than source; scenario triggering is
operator-assisted, not unattended; no timing/micro-architectural side channels;
`allowBackup` extraction is Android-version dependent; the statistical module is
robust outlier detection, not ML.

## 9. Ethics

Developer-facing; only test apps you own or are authorized to test. The IPC-probing
flow is gated behind explicit authorization and performs no exploitation beyond
demonstrating a finding.
