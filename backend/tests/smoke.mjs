/**
 * Offline smoke test.
 *
 * Boots the real Express app and exercises the paths that need no Firebase round trip:
 * the health check, the 404 handler, authentication rejection, and request validation.
 * Anything that reads or writes Firestore is out of scope here, since that needs a live
 * project. Run with: node tests/smoke.mjs
 *
 * A throwaway RSA key is generated so the Admin SDK accepts the credential format and
 * initialises without contacting Google. No real project is touched.
 */
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

const { privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" },
});

process.env.NODE_ENV = "test";
process.env.PORT = "0";
process.env.FIREBASE_PROJECT_ID = "smoke-test-project";
process.env.FIREBASE_CLIENT_EMAIL = "smoke@smoke-test-project.iam.gserviceaccount.com";
process.env.FIREBASE_PRIVATE_KEY = privateKey.replace(/\n/g, "\\n");
process.env.FIREBASE_WEB_API_KEY = "smoke-test-web-key";
process.env.GEMINI_API_KEY = "";
process.env.FREE_HISTORY_LIMIT = "10";

const { createApp } = await import("../src/app.js");
const { redact } = await import("../src/utils/redact.js");
const { renderScanReportHtml } = await import("../src/services/report.service.js");
const { compareScans } = await import("../src/services/scans.service.js");

const app = createApp();
const server = app.listen(0);
await new Promise((resolve) => server.once("listening", resolve));
const base = `http://127.0.0.1:${server.address().port}`;

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

console.log("\nHTTP layer");

await check("GET /api/health returns ok and reports the AI layer as disabled", async () => {
  const res = await fetch(`${base}/api/health`);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.status, "ok");
  assert.equal(body.aiExplanations, "disabled");
});

await check("unknown route returns a 404 in the standard error shape", async () => {
  const res = await fetch(`${base}/api/does-not-exist`);
  assert.equal(res.status, 404);
  const body = await res.json();
  assert.equal(body.error.status, 404);
  assert.match(body.error.message, /No route for GET/);
});

await check("a protected route with no token returns 401", async () => {
  const res = await fetch(`${base}/api/users/me`);
  assert.equal(res.status, 401);
  const body = await res.json();
  assert.match(body.error.message, /Bearer/);
});

await check("a protected route with a malformed token returns 401", async () => {
  const res = await fetch(`${base}/api/scans`, {
    headers: { Authorization: "Bearer not-a-real-token" },
  });
  assert.equal(res.status, 401);
});

await check("login with an invalid body is rejected by validation, not by Firebase", async () => {
  const res = await fetch(`${base}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "not-an-email", password: "" }),
  });
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error.status, 400);
  assert.ok(Array.isArray(body.error.details), "expected a details array");
  const fields = body.error.details.map((d) => d.field);
  assert.ok(fields.includes("email"), "expected the email field to be flagged");
});

await check("registering with a short password is rejected with a clear message", async () => {
  const res = await fetch(`${base}/api/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "someone@example.com", password: "short" }),
  });
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.match(JSON.stringify(body.error.details), /at least 8 characters/);
});

console.log("\nSecret redaction");

await check("redacts a token assignment but keeps its label", () => {
  const out = redact("token=abcdef1234567890abcdef and nothing else");
  assert.ok(!out.includes("abcdef1234567890abcdef"), "the secret survived redaction");
  assert.match(out, /token=\[REDACTED\]/);
});

await check("redacts a Google API key", () => {
  const out = redact("key AIzaSyA1234567890abcdefghijklmnopqrstuvw found in strings");
  assert.ok(!out.includes("AIzaSyA1234567890abcdefghijklmnopqrstuvw"));
  assert.match(out, /\[REDACTED\]/);
});

await check("redacts a JWT", () => {
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r";
  const out = redact(`Authorization: Bearer ${jwt}`);
  assert.ok(!out.includes(jwt), "the JWT survived redaction");
});

await check("leaves ordinary evidence text alone", () => {
  const text = "`am start -n com.example.app/.SecretActivity` -> Starting: Intent";
  assert.equal(redact(text), text);
});

console.log("\nScan comparison");

await check("matches findings by category and component, not by generated id", async () => {
  const baseline = {
    id: "a",
    counts: {},
    findings: [
      { id: "id-1", category: "exported-auth-bypass", component: "A", severity: "critical", evidence: "x", title: "t", source: "s" },
      { id: "id-2", category: "logcat-leak", component: null, severity: "high", evidence: "y", title: "t", source: "s" },
    ],
  };
  const current = {
    id: "b",
    counts: {},
    findings: [
      // Same finding, different generated id. Must count as unchanged, not as both
      // resolved and introduced.
      { id: "id-9", category: "exported-auth-bypass", component: "A", severity: "critical", evidence: "x", title: "t", source: "s" },
      { id: "id-8", category: "allow-backup", component: null, severity: "medium", evidence: "z", title: "t", source: "s" },
    ],
  };

  const result = await compareScans(baseline, current);
  assert.equal(result.summary.unchanged, 1, "the shared finding should be unchanged");
  assert.equal(result.summary.resolved, 1, "logcat-leak should be resolved");
  assert.equal(result.summary.introduced, 1, "allow-backup should be introduced");
});

console.log("\nReport rendering");

await check("renders a report and escapes markup in the evidence", () => {
  const html = renderScanReportHtml(
    {
      id: "scan-123",
      type: "device",
      counts: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
      authorisationConfirmed: true,
      target: { packageName: "com.example.app" },
      findings: [
        {
          category: "exported-auth-bypass",
          title: "Exported activity reachable without authentication",
          severity: "critical",
          owasp: ["M3", "M1"],
          evidence: "<script>alert('xss')</script>",
          source: "ipc_oracle",
          confidence: "confirmed",
        },
      ],
    },
    { owner: { email: "dev@example.com" } }
  );

  assert.match(html, /<!doctype html>/i);
  assert.match(html, /com\.example\.app/);
  assert.match(html, /CRITICAL/);
  assert.ok(!html.includes("<script>alert"), "evidence was not escaped");
  assert.match(html, /&lt;script&gt;/);
});

await check("says so plainly when a scan found nothing", () => {
  const html = renderScanReportHtml({ id: "s", type: "apk", counts: {}, findings: [] });
  assert.match(html, /No problems were found/);
});

server.close();

console.log(`\n${passed} passed, ${failures.length} failed.`);
if (failures.length > 0) {
  for (const { name, error } of failures) {
    console.error(`\n${name}:\n${error.stack}`);
  }
  process.exitCode = 1;
}
