/**
 * Curated guidance the AI explanation layer is grounded against.
 *
 * The model is told to explain a finding the scanner has already confirmed, and it is
 * given the entry for that finding's category as source material. This is what stops
 * explanations drifting into invented APIs or generic advice: the fix it describes has
 * to be the one written here, checked by us against OWASP MASVS.
 *
 * Retrieval is a plain lookup rather than anything cleverer because the detection engine
 * emits a fixed, closed set of categories -- every one of them has an entry below. A new
 * detector needs a new entry here, which is deliberate: it keeps the guidance a reviewed
 * artefact rather than whatever the model happens to recall.
 *
 * Kept separate from gemini.service.js so it can be revised as MASVS guidance evolves
 * without touching the code that calls the model (see URS 4.4, maintainability).
 */

const ENTRIES = {
  "boolean-only-auth": {
    title: "Biometric result trusted as a boolean",
    what:
      "The app calls BiometricPrompt and decides what to do based only on whether " +
      "onAuthenticationSucceeded() fired. No cryptographic object is tied to the result.",
    why:
      "That callback is just a method call in the app's own process. Anyone who can run " +
      "code in that process -- a repackaged build, a hooking framework such as Frida on a " +
      "rooted device -- can call it directly or force it to return success, without any " +
      "fingerprint ever being presented. The check is advisory, not enforced.",
    fix:
      "Bind the outcome to a key the hardware will only release after a real " +
      "authentication. Generate the key with setUserAuthenticationRequired(true), wrap a " +
      "Cipher (or Signature/Mac) in a BiometricPrompt.CryptoObject, pass that to " +
      "authenticate(), and use the unlocked Cipher to decrypt or sign the thing being " +
      "protected. If the biometric did not really happen, the key is never released and " +
      "the operation cannot complete regardless of what the callback claims.",
    references: ["MASVS-AUTH-2", "MASVS-CRYPTO-1"],
  },

  "key-not-auth-bound": {
    title: "Keystore key not bound to authentication",
    what:
      "A key exists in the Android Keystore, but its spec does not set " +
      "setUserAuthenticationRequired(true).",
    why:
      "The key can be used at any time by anything running as the app, whether or not " +
      "the user has authenticated. The Keystore protects the key material from being " +
      "exported, but it places no condition on its use, so a biometric prompt shown " +
      "beforehand is decoration rather than a gate.",
    fix:
      "Add setUserAuthenticationRequired(true) to the KeyGenParameterSpec. Choose a " +
      "validity window deliberately: setUserAuthenticationParameters(0, ...) (or the " +
      "deprecated setUserAuthenticationValidityDurationSeconds(-1)) requires a fresh " +
      "authentication for every single use, which is the right choice for a high-value " +
      "operation; a positive duration keeps the key usable for that many seconds after an " +
      "unlock. Also set setInvalidatedByBiometricEnrolment(true) so enrolling a new " +
      "fingerprint invalidates the key rather than silently granting a new finger access.",
    references: ["MASVS-AUTH-2", "MASVS-CRYPTO-1", "MASVS-STORAGE-1"],
  },

  "exported-auth-bypass": {
    title: "Protected screen reachable without authenticating",
    what:
      "A component holding post-authentication functionality is exported and was " +
      "launched directly over ADB, reaching its content without any login step.",
    why:
      "An exported component with no permission can be started by any other app on the " +
      "device with a single intent. If the only thing standing between a launcher screen " +
      "and a protected screen is the app's own navigation, that protection disappears the " +
      "moment someone navigates straight to the destination.",
    fix:
      "Set android:exported=\"false\" in the manifest if nothing outside the app needs " +
      "to start it. If it genuinely must be reachable externally, guard it with a " +
      "signature-level permission (android:protectionLevel=\"signature\") so only your own " +
      "apps qualify. Either way, re-check the session or auth state inside the component's " +
      "own onCreate()/onStart() and finish() it if the check fails -- never rely on the " +
      "path the user took to arrive.",
    references: ["MASVS-AUTH-1", "MASVS-PLATFORM-1"],
  },

  "exported-unguarded-component": {
    title: "Component exported without a permission",
    what:
      "The manifest declares an activity, service, receiver, or provider with " +
      "android:exported=\"true\" and no android:permission attribute.",
    why:
      "Any installed app can interact with it. Whether that matters depends on what the " +
      "component does, but it is attack surface that was very likely not intended: since " +
      "Android 12 (API 31) exported must be declared explicitly, so this is a deliberate " +
      "setting rather than an accident of defaults.",
    fix:
      "If no other app needs it, set android:exported=\"false\". If it is exported to " +
      "serve a specific caller, add android:permission with a signature-level custom " +
      "permission so only apps signed with your key can reach it. Validate every field of " +
      "any Intent it receives -- an exported component must treat its input as hostile.",
    references: ["MASVS-PLATFORM-1", "MASVS-CODE-4"],
  },

  "auth-state-oracle": {
    title: "Response reveals valid credentials or identifiers",
    what:
      "An exported, unguarded component answered differently for a valid-looking input " +
      "than for an obviously invalid one, without requiring any authentication.",
    why:
      "The difference itself is the leak. An attacker does not need to get in to benefit: " +
      "they can send candidate values and read the response to learn which usernames, " +
      "tokens, or account identifiers exist. That converts a blind guess into a search, " +
      "and it is the enumeration step that usually precedes credential stuffing.",
    fix:
      "Return an identical, generic response for valid and invalid inputs -- same shape, " +
      "same status, same timing where practical. Require a real authentication check or a " +
      "signature-level permission before the component will answer at all. Rate-limit " +
      "queries so bulk probing is impractical, and log repeated failures for monitoring.",
    references: ["MASVS-AUTH-1", "MASVS-PLATFORM-1", "MASVS-PRIVACY-1"],
  },

  "error-oracle": {
    title: "Error messages distinguish failure causes",
    what:
      "The app returns materially different errors for different failure reasons, such " +
      "as separating 'no such account' from 'wrong password'.",
    why:
      "A distinct error for each cause tells an attacker which half of a credential pair " +
      "was right. Confirming an account exists is worth as much as a partial password: it " +
      "narrows every subsequent guess and identifies which accounts are worth attacking.",
    fix:
      "Collapse authentication failures into one message and one status code -- the " +
      "standard wording is 'Incorrect email or password' regardless of which was wrong. " +
      "Keep the detailed reason in server-side logs where the defender can see it and the " +
      "attacker cannot. Apply the same rule to password reset and registration, where " +
      "'that address is already registered' leaks the same fact.",
    references: ["MASVS-AUTH-1", "MASVS-PRIVACY-1"],
  },

  "lockout-state-leak": {
    title: "Lockout state observable from outside",
    what:
      "Whether the app is in a failed-attempt lockout can be read from an external " +
      "signal such as a response difference or a log line.",
    why:
      "Lockout state is a side channel onto authentication activity. Being able to see it " +
      "tells an attacker how many attempts remain before their probing is noticed, which " +
      "lets them pace an attack to stay under the threshold indefinitely.",
    fix:
      "Track attempt counts and lockout server-side, and do not expose the counter or the " +
      "locked/unlocked state to unauthenticated callers. Return the same generic failure " +
      "whether the account is locked or the credential was simply wrong.",
    references: ["MASVS-AUTH-1", "MASVS-AUTH-3"],
  },

  "lockout-improper-reset": {
    title: "Lockout counter resets on the client",
    what:
      "The failed-attempt counter is cleared by something the client controls -- " +
      "restarting the app, clearing its data, or the passage of local device time.",
    why:
      "A lockout that the attacker can reset is not a lockout. If force-stopping the app " +
      "returns the allowance to zero attempts used, brute force is limited only by how " +
      "fast the app can be restarted.",
    fix:
      "Hold the counter server-side, keyed to the account rather than the installation, " +
      "and reset it only on a genuinely successful authentication or after a server-side " +
      "timeout measured against server time. Apply exponential backoff so each failure " +
      "costs more than the last.",
    references: ["MASVS-AUTH-3"],
  },

  "logcat-leak": {
    title: "Sensitive data written to the device log",
    what:
      "Values such as tokens, credentials, keys, or authentication state were found in " +
      "logcat output while exercising the app.",
    why:
      "The log is not a private channel. Anything written there can be read over ADB by " +
      "anyone with physical access or debugging enabled, and is routinely swept up by " +
      "crash and analytics SDKs that ship it off the device. A token in a log line is a " +
      "token that has left your control.",
    fix:
      "Remove the logging rather than lowering its level -- Log.d() still executes and " +
      "still writes in a release build. Strip logging at build time with a ProGuard/R8 " +
      "rule that discards android.util.Log calls, or route logging through a wrapper that " +
      "compiles to nothing when BuildConfig.DEBUG is false. Never log a key, token, " +
      "password, or the result of an authentication check.",
    references: ["MASVS-STORAGE-2", "MASVS-PRIVACY-1"],
  },

  "flag-secure-missing": {
    title: "FLAG_SECURE not set on a sensitive window",
    what:
      "A window showing the biometric prompt or post-authentication content does not set " +
      "WindowManager.LayoutParams.FLAG_SECURE.",
    why:
      "Without it the window can be screenshotted, screen-recorded, and captured into the " +
      "recent-apps thumbnail, which is written to disk. Sensitive content then persists " +
      "somewhere the app never intended and does not control.",
    fix:
      "Call getWindow().setFlags(FLAG_SECURE, FLAG_SECURE) in onCreate(), before " +
      "setContentView(), for every screen showing protected content. This blocks " +
      "screenshots and recording, and blanks the entry in the recents overview.",
    references: ["MASVS-PLATFORM-3", "MASVS-PRIVACY-1"],
  },

  "backup-extractable": {
    title: "App data extractable via backup",
    what:
      "android:allowBackup is not set to false, and app data was confirmed retrievable " +
      "through the backup mechanism.",
    why:
      "With backup enabled, the app's private files can be pulled off the device with " +
      "adb backup, no root required. Anything stored under the app's sandbox -- tokens, " +
      "cached credentials, a local database -- leaves with it, defeating the sandbox that " +
      "was supposed to protect it.",
    fix:
      "Set android:allowBackup=\"false\" in the manifest's <application> tag. If backup " +
      "is a product requirement, keep it enabled but exclude every sensitive path using " +
      "android:dataExtractionRules (API 31+) and android:fullBackupContent, and make sure " +
      "secrets live in the Keystore rather than in files that could be included.",
    references: ["MASVS-STORAGE-1", "MASVS-STORAGE-2"],
  },

  "allow-backup": {
    title: "Backup not disabled in the manifest",
    what:
      "android:allowBackup is absent or true, so the platform default allows the app's " +
      "private data to be included in backups.",
    why:
      "This is the manifest-level version of the same exposure as an extractable backup: " +
      "it means app-private data may be copied off the device, out of the sandbox, by " +
      "anyone able to run adb backup against it.",
    fix:
      "Set android:allowBackup=\"false\" on the <application> element. Where backup must " +
      "stay on, restrict what it covers with android:dataExtractionRules and " +
      "android:fullBackupContent, and keep credentials in the Keystore instead of files.",
    references: ["MASVS-STORAGE-1"],
  },

  "debuggable-release": {
    title: "Application is debuggable",
    what: "The manifest sets android:debuggable=\"true\".",
    why:
      "A debuggable build lets anyone attach a debugger to the running process with no " +
      "root and no special tooling, then read memory, inspect variables, and change " +
      "control flow at will. Every other protection in the app -- including the biometric " +
      "gate -- can be stepped over from a debugger. It also permits run-as access to the " +
      "app's private data directory. This flag is for development only and should never " +
      "reach a shipped build.",
    fix:
      "Remove android:debuggable from the manifest entirely and let the build system " +
      "decide: Gradle sets it automatically for debug builds and omits it for release. If " +
      "it is being set explicitly, delete the attribute and confirm the release variant " +
      "has debuggable false. Verify the shipped artefact rather than the source, since a " +
      "manifest merger or a build flavour can reintroduce it.",
    references: ["MASVS-RESILIENCE-1", "MASVS-CODE-4"],
  },
};

/** Look up the reviewed guidance for a finding category, or null if it has none. */
export function lookup(category) {
  return ENTRIES[category] ?? null;
}

/**
 * Render an entry as prompt source material.
 *
 * Returns an empty string for an unknown category so the caller can fall back to an
 * ungrounded prompt rather than failing -- a detector added without a matching entry
 * should degrade to a plainer explanation, not to no explanation at all.
 */
export function promptSection(category) {
  const entry = lookup(category);
  if (!entry) return "";

  return [
    "Reviewed guidance for this finding category. Base your explanation and fix on this",
    "material; do not contradict it and do not introduce APIs it does not mention.",
    "",
    `Category: ${entry.title}`,
    `What the scanner found: ${entry.what}`,
    `Why it matters: ${entry.why}`,
    `Correct fix: ${entry.fix}`,
    `Relevant controls: ${entry.references.join(", ")}`,
  ].join("\n");
}

export const KNOWN_CATEGORIES = Object.keys(ENTRIES);
