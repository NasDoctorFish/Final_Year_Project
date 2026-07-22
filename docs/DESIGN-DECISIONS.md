# Design Decisions Log

This log captures the reasoning trail from the design conversation that produced
BioAuthGuard, so the "why" travels with the code. Newest decisions are the ones the
scaffold implements; earlier rows record options considered and rejected.

## Decision trail

1. **Feasibility of the original proposal.** A Python app can be the brain
   (orchestration, analysis, ML, dashboard, reporting) but **cannot touch the
   biometric sensor** — `BiometricPrompt`/Keystore run on-device behind the TEE.
   Original idea assumed a hybrid: an on-device Kotlin harness the developer adds
   their code to, plus a Python host over ADB.

2. **Where timing is measured.** A timing side-channel signal is microseconds;
   USB + OS scheduling noise between the Python host and the app is milliseconds.
   Measuring timing from the host buries the signal — you'd get a confident but
   meaningless "no leak." Conclusion: the stopwatch must live **on the device**
   (harness `System.nanoTime()`), not in Python.

3. **OWASP mapping.** The tool honestly covers **M3 (primary)**, reinforced by
   **M10** and **M1**, with secondary **M8 / M9 / M6** scoped to the auth surface.
   Explicitly out of scope: **M2, M4, M5, M7**. Stating the boundary is a strength.

4. **Other side channels.** Physical channels (power/EM/acoustic/cache) need lab
   hardware or root and are out. Software-observable channels feasible for the tool:
   IPC authorization oracle, logcat leakage, FLAG_SECURE/recents, behavioural
   error-oracle, lockout oracle, allowBackup.

5. **No-root constraint → timing dropped.** With no root and no harness there is no
   way to instrument for meaningful timing. Timing was **removed** and the **IPC /
   exported-component authorization oracle** promoted to the headline runtime
   feature. It preserves the "runtime, can't-find-by-reading-code" differentiator.

6. **Platform.** Real physical device (Pixel, Android 12+) is required for
   trustworthy runtime verdicts; emulator only for tool development and static
   checks. No root anywhere.

7. **Mode B only.** Dropped the Kotlin harness (Mode A) entirely. Trade-offs
   accepted: lower static fidelity (decompiled APK, "likely" confidence) and
   operator-assisted (not unattended) scenario triggering. Wins: no Android-side
   deliverable, zero developer integration, works on any app, single clean Python
   codebase. Positioning shifts to a black-box scanner → the **authorization gate**
   becomes central.

8. **AI layer — bounded.** Added, but only in the explanation/mitigation/reporting
   layer, never as the detector. Detection stays deterministic and reproducible; the
   AI is grounded on a knowledge base + finding evidence, uses structured output,
   redacts secrets before any call, and uses the Gemini API (`gemini-flash-latest`).
   This avoids "AI-washing" and directly serves the "accessible to non-experts" goal.

9. **The practical Mode-B side channel — auth-state / response oracle.** A brief
   experiment reopened the on-device timing harness (decision #2's stopwatch) as an
   opt-in `assess-harness` mode; it was **removed** because on real consumer hardware
   the nanosecond signal is swamped by scheduling/thermal noise, so it detected the
   planted leak only intermittently and required rebuilding the target app — failing
   the "practical" bar and breaking the Mode-B-only line (decision #7). It is
   replaced by the **auth-state / response oracle** (`runtime/response_oracle.py`),
   the one side-channel class that is Mode B (unprivileged adb, no root, no rebuild,
   no fingerprint), *deterministic* (a differing response is a hard fact, not a noisy
   p-value), and fully automatable. An oracle attack **is** a side channel: the app's
   observable *response* leaks secret auth state. It reuses the exported-component
   surface the IPC oracle (decision #5) enumerates and asks the sharper question —
   does an unguarded component answer a valid identifier differently from an invalid
   one? — the classic error/enumeration oracle, applied to Android's IPC surface.

## What the scaffold implements

Mode B only · no root · IPC oracle as headline · **auth-state / response oracle**
(the practical Mode-B side channel, `runtime/response_oracle.py`) · passive
observers (logcat, screencap, allowBackup) · decompiled static analysis ·
deterministic engine · grounded+redacted AI explanation layer · severity model ·
SQLite history · Streamlit dashboard · HTML/PDF report.

## Open items for the next iteration

- Implement `runtime/scenarios.py` operator-assisted loop (uiautomator2 detection
  of the system BiometricPrompt dialog).
- Wire `analysis/error_oracle.py`, `analysis/lockout.py`, `analysis/statistics.py`
  into `assess` once scenario data is available.
- Add `adb backup` extraction to confirm (not just flag) allowBackup exposure.
- Broaden decompiled-pattern coverage in `static_analysis/apk_analyzer.py`.
