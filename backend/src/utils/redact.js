/**
 * Strips secrets out of finding evidence before it is sent to the AI provider.
 *
 * BioAudit tells users their app's secrets never leave their machine, so this runs on
 * every string handed to the AI layer. It is intentionally aggressive: a false
 * redaction only costs the model a little context, while a missed one leaks a real
 * credential to a third party.
 */

const PLACEHOLDER = "[REDACTED]";

const PATTERNS = [
  // key = value / key: value, for anything that names itself a secret.
  /\b(token|secret|api[_-]?key|apikey|password|passwd|pwd|auth|bearer|session|credential)\b\s*[:=]\s*\S+/gi,
  // Authorization headers.
  /\bBearer\s+[A-Za-z0-9._~+/-]{10,}=*/gi,
  // Long base64-ish blobs, which are usually keys or encoded payloads.
  /\b[A-Za-z0-9+/]{40,}={0,2}\b/g,
  // JSON web tokens.
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  // Cloud provider access key ids.
  /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g,
  // Google API keys.
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
  // Private key blocks.
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  // Long hex strings, typically hashes or raw keys.
  /\b[0-9a-fA-F]{32,}\b/g,
];

/** Replace anything that looks like a secret in a single string. */
export function redact(text) {
  if (typeof text !== "string" || text.length === 0) return text;
  let out = text;
  for (const pattern of PATTERNS) {
    out = out.replace(pattern, (match) => {
      // For "key: value" forms keep the label, so the model still knows what kind of
      // value sat there. Everything else is replaced outright.
      const labelled = match.match(/^([A-Za-z_-]+)\s*[:=]/);
      return labelled ? `${labelled[1]}=${PLACEHOLDER}` : PLACEHOLDER;
    });
  }
  return out;
}

/** Redact the free-text fields of a finding, leaving its structured fields intact. */
export function redactFinding(finding) {
  return {
    ...finding,
    evidence: redact(finding.evidence),
    title: redact(finding.title),
    component: finding.component ? redact(finding.component) : finding.component,
  };
}
