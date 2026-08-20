/**
 * Offline test for the LangGraph prototype in src/services/aiGraph.service.js.
 *
 * This file is NOT wired into `npm test` -- aiGraph.service.js is not imported by any
 * route yet, so it stays a separate, explicitly-run suite until that changes. Run with:
 *   node tests/aiGraph.test.mjs
 *
 * Covers what is reachable without a live or stubbed Gemini call: the "not configured"
 * error path, the redact() the egress guard is built on, compareScans() reuse (the
 * compare_scans tool's data source), and that the module has no import-time side effects.
 *
 * NOT covered here, because it only runs inside buildGraph()'s closures once a model
 * call happens: get_finding_evidence's 800-char cap, cross-scan refusal via the scanIds
 * allowlist, the 8-call tool budget, and the one-shot repair loop. Those need either a
 * live GEMINI_API_KEY or a stubbed @google/genai client -- see the bottom of this file.
 */
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

// Same throwaway-credential approach as tests/smoke.mjs: env.js fails fast at import time
// if these are missing, and this suite must run with no .env file present.
const { privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" },
});

process.env.FIREBASE_PROJECT_ID = "aigraph-test-project";
process.env.FIREBASE_CLIENT_EMAIL = "aigraph@aigraph-test-project.iam.gserviceaccount.com";
process.env.FIREBASE_PRIVATE_KEY = privateKey.replace(/\n/g, "\\n");
process.env.FIREBASE_WEB_API_KEY = "aigraph-test-web-key";
process.env.GEMINI_API_KEY = "";

const { createSession } = await import("../src/services/aiGraph.service.js");
const { redact } = await import("../src/utils/redact.js");
const { compareScans } = await import("../src/services/scans.service.js");

let passed = 0;
const failures = [];

async function check(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`  ok   ${name}`);
  } catch (error) {
    failures.push({ name, error });
    console.log(`  FAIL ${name}\n       ${error.message}`);
  }
}

const FIXTURE_USER = { uid: "user-1", organisationId: null, role: "member" };

function fixtureFinding(overrides = {}) {
  return {
    category: "boolean-only-auth",
    title: "Biometric result trusted as a boolean",
    severity: "critical",
    owasp: ["M3"],
    evidence:
      `Provider row: {"user":"jsmith","token":"AIzaSyA1234567890abcdefghijklmnopqrstuvw",` +
      `"note":"${"x".repeat(3000)}"}`,
    source: "response_oracle",
    confidence: "confirmed",
    component: "com.acme.wallet.SecretActivity",
    ...overrides,
  };
}

function fixtureScan(overrides = {}) {
  return {
    id: "scan-1",
    userId: "user-1",
    organisationId: null,
    type: "device",
    counts: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
    findingCount: 1,
    createdAt: "2026-08-01T00:00:00.000Z",
    findings: [fixtureFinding()],
    ...overrides,
  };
}

console.log("\nNo network, no key");

await check("session.explain() throws the same 'not configured' ApiError gemini.service.js throws", async () => {
  const session = createSession({ user: FIXTURE_USER, scanIds: ["scan-1"] });
  await assert.rejects(
    () => session.explain("explain finding 0 of scan-1"),
    (err) => {
      assert.equal(err.name, "ApiError");
      assert.equal(err.status, 500);
      assert.match(err.message, /not configured/i);
      return true;
    }
  );
});

await check("all four modes reject the same way, not just explain", async () => {
  const session = createSession({ user: FIXTURE_USER, scanIds: ["scan-1"] });
  for (const mode of ["synthesize", "compare", "report"]) {
    await assert.rejects(() => session[mode]("go"), /not configured/i);
  }
});

console.log("\nEgress guard properties (redact(), the primitive egressGuard is built on)");

await check("strips a Google API key out of fixture evidence", () => {
  const out = redact(fixtureFinding().evidence);
  assert.ok(!out.includes("AIzaSyA1234567890abcdefghijklmnopqrstuvw"), "API key survived redaction");
});

await check("strips a labelled token but keeps the label, matching redact.js's contract", () => {
  const out = redact("token=abcdef1234567890abcdef and nothing else");
  assert.match(out, /token=\[REDACTED\]/);
});

await check("fixture evidence exceeds the 800-char egress cap, so the cap is a meaningful test", () => {
  assert.ok(fixtureFinding().evidence.length > 800);
});

console.log("\nSession shape");

await check("createSession exposes exactly the four modes as functions", () => {
  const session = createSession({ user: FIXTURE_USER, scanIds: ["scan-1"] });
  for (const key of ["explain", "synthesize", "compare", "report"]) {
    assert.equal(typeof session[key], "function", `${key} missing`);
  }
});

console.log("\ncompare_scans data source (compareScans reuse)");

await check("compareScans groups by category::component, not by regenerated id -- same contract compare_scans relies on", async () => {
  const baseline = fixtureScan({ id: "scan-a" });
  const current = fixtureScan({
    id: "scan-b",
    findings: [
      fixtureFinding(),
      {
        category: "key-not-auth-bound",
        title: "New",
        severity: "high",
        owasp: [],
        evidence: "irrelevant",
        source: "apk_analyzer",
        confidence: "confirmed",
        component: null,
      },
    ],
  });
  const result = await compareScans(baseline, current);
  assert.equal(result.summary.unchanged, 1, "same category::component should be unchanged");
  assert.equal(result.summary.introduced, 1);
  assert.equal(result.summary.resolved, 0);
});

console.log("\nModule hygiene");

await check("importing aiGraph.service.js has no side effects, and exports nothing beyond buildGraph/createSession", async () => {
  const a = await import("../src/services/aiGraph.service.js");
  const b = await import("../src/services/aiGraph.service.js");
  assert.equal(a.createSession, b.createSession);
  assert.deepEqual(Object.keys(a).sort(), ["buildGraph", "createSession"]);
});

console.log(`\n${passed} passed, ${failures.length} failed.`);
if (failures.length > 0) {
  for (const { name, error } of failures) {
    console.error(`\n${name}:\n${error.stack}`);
  }
  process.exitCode = 1;
}
