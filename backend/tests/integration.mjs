/**
 * Integration tests against the Firebase emulator suite.
 *
 * These cover everything the offline smoke test cannot: real registration, sign-in,
 * Firestore reads and writes, tier limits, and the whole organisation workflow. Nothing
 * here touches a live Firebase project.
 *
 * Run with:  npm run test:integration
 * That script starts the emulators, runs this file, and shuts them down again.
 */
import assert from "node:assert/strict";

const EMULATOR_PROJECT = "bioaudit-test";

// Point the Admin SDK and the sign-in REST calls at the emulators. These have to be set
// before any application module is imported, since both are read at module load.
process.env.NODE_ENV = "test";
process.env.GCLOUD_PROJECT = EMULATOR_PROJECT;
process.env.FIREBASE_PROJECT_ID = EMULATOR_PROJECT;
process.env.FIRESTORE_EMULATOR_HOST = process.env.FIRESTORE_EMULATOR_HOST || "127.0.0.1:8080";
process.env.FIREBASE_AUTH_EMULATOR_HOST = process.env.FIREBASE_AUTH_EMULATOR_HOST || "127.0.0.1:9099";
// No service account is set. The emulators accept any caller, and config/firebase.js
// skips the credential entirely when the emulator variables above are present.
process.env.FIREBASE_WEB_API_KEY = "emulator-key";
process.env.GEMINI_API_KEY = "";
process.env.FREE_HISTORY_LIMIT = "3"; // small, so retention is quick to prove

const { createApp } = await import("../src/app.js");
const { db, auth } = await import("../src/config/firebase.js");

const app = createApp();
const server = app.listen(0);
await new Promise((resolve) => server.once("listening", resolve));
const BASE = `http://127.0.0.1:${server.address().port}/api`;

// --- test harness ----------------------------------------------------------

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

function group(title) {
  console.log(`\n${title}`);
}

/** Thin request helper that returns status and parsed body together. */
async function call(method, path, { token, body } = {}) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const text = await res.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = text;
  }
  return { status: res.status, body: parsed };
}

/** Wipe the emulator between runs so tests do not depend on leftover state. */
async function clearEmulator() {
  const fsHost = process.env.FIRESTORE_EMULATOR_HOST;
  const authHost = process.env.FIREBASE_AUTH_EMULATOR_HOST;
  await fetch(
    `http://${fsHost}/emulator/v1/projects/${EMULATOR_PROJECT}/databases/(default)/documents`,
    { method: "DELETE" }
  );
  await fetch(`http://${authHost}/emulator/v1/projects/${EMULATOR_PROJECT}/accounts`, {
    method: "DELETE",
  });
}

await clearEmulator();

const unique = () => Math.random().toString(36).slice(2, 8);

// --- registration and sign-in ---------------------------------------------

group("Registration and sign-in");

const userEmail = `dev-${unique()}@example.com`;
const userPassword = "correct-horse-battery";
let userToken;
let userUid;

await check("registering creates the account and returns a usable session", async () => {
  const { status, body } = await call("POST", "/auth/register", {
    body: { email: userEmail, password: userPassword, displayName: "Test Dev" },
  });
  assert.equal(status, 201, JSON.stringify(body));
  assert.equal(body.user.email, userEmail);
  assert.equal(body.user.tier, "free");
  assert.equal(body.user.role, "member");
  assert.ok(body.session.idToken, "expected an idToken");
  userToken = body.session.idToken;
  userUid = body.user.id;
});

await check("the same email cannot register twice", async () => {
  const { status, body } = await call("POST", "/auth/register", {
    body: { email: userEmail, password: userPassword },
  });
  assert.equal(status, 409);
  assert.match(body.error.message, /already exists/i);
});

await check("signing in with the right password works", async () => {
  const { status, body } = await call("POST", "/auth/login", {
    body: { email: userEmail, password: userPassword },
  });
  assert.equal(status, 200, JSON.stringify(body));
  assert.equal(body.user.id, userUid);
  userToken = body.session.idToken;
});

await check("signing in with the wrong password is refused", async () => {
  const { status } = await call("POST", "/auth/login", {
    body: { email: userEmail, password: "not-the-password" },
  });
  assert.equal(status, 401);
});

await check("an unknown email gives the same answer as a wrong password", async () => {
  // If these differed, the API would be a response oracle: an attacker could discover
  // which accounts exist. That is the weakness this project detects in other apps.
  const wrongPassword = await call("POST", "/auth/login", {
    body: { email: userEmail, password: "not-the-password" },
  });
  const unknownEmail = await call("POST", "/auth/login", {
    body: { email: `nobody-${unique()}@example.com`, password: "not-the-password" },
  });
  assert.equal(wrongPassword.status, unknownEmail.status);
  assert.equal(wrongPassword.body.error.message, unknownEmail.body.error.message);
});

group("Own account");

await check("the profile can be read back", async () => {
  const { status, body } = await call("GET", "/users/me", { token: userToken });
  assert.equal(status, 200, JSON.stringify(body));
  assert.equal(body.user.email, userEmail);
  assert.equal(body.user.displayName, "Test Dev");
});

await check("the display name can be updated", async () => {
  const { status, body } = await call("PATCH", "/users/me", {
    token: userToken,
    body: { displayName: "Renamed Dev" },
  });
  assert.equal(status, 200, JSON.stringify(body));
  assert.equal(body.user.displayName, "Renamed Dev");
});

await check("changing the password needs the current one", async () => {
  const { status } = await call("POST", "/users/me/password", {
    token: userToken,
    body: { currentPassword: "wrong", newPassword: "a-brand-new-password" },
  });
  assert.equal(status, 401, "a wrong current password should be refused");
});

// --- scans and history ----------------------------------------------------

group("Scans and history");

function scanPayload(pkg, findings = []) {
  return {
    type: "device",
    authorisationConfirmed: true,
    target: { packageName: pkg, deviceSerial: "emulator-1" },
    findings,
  };
}

const sampleFinding = {
  category: "exported-auth-bypass",
  title: "Exported activity reachable without authentication",
  severity: "critical",
  owasp: ["M3", "M1"],
  evidence: "`am start -n com.example.app/.SecretActivity` -> Starting: Intent{...}",
  source: "ipc_oracle",
  confidence: "confirmed",
  component: "com.example.app.SecretActivity",
};

let firstScanId;

await check("a scan is stored with its severity counts worked out", async () => {
  const { status, body } = await call("POST", "/scans", {
    token: userToken,
    body: scanPayload("com.example.app", [
      sampleFinding,
      { ...sampleFinding, category: "logcat-leak", severity: "high", component: null },
    ]),
  });
  assert.equal(status, 201, JSON.stringify(body));
  assert.equal(body.scan.findingCount, 2);
  assert.equal(body.scan.counts.critical, 1);
  assert.equal(body.scan.counts.high, 1);
  firstScanId = body.scan.id;
});

await check("a device assessment without an authorisation confirmation is refused", async () => {
  const { status, body } = await call("POST", "/scans", {
    token: userToken,
    body: { ...scanPayload("com.example.app"), authorisationConfirmed: false },
  });
  assert.equal(status, 400);
  assert.match(body.error.message, /authorised/i);
});

await check("history comes back newest first", async () => {
  const { status, body } = await call("GET", "/scans", { token: userToken });
  assert.equal(status, 200, JSON.stringify(body));
  assert.ok(body.scans.length >= 1);
  assert.equal(body.tier, "free");
  assert.equal(body.historyLimit, 3, "the free limit should be reported");
});

await check("a stored scan can be fetched with its findings", async () => {
  const { status, body } = await call("GET", `/scans/${firstScanId}`, { token: userToken });
  assert.equal(status, 200, JSON.stringify(body));
  assert.equal(body.scan.findings.length, 2);
  assert.equal(body.scan.findings[0].category, "exported-auth-bypass");
});

await check("the free tier trims the oldest scan once past its limit", async () => {
  // The limit is 3 for this run, and one scan already exists. Saving three more should
  // push the total over and drop the oldest.
  for (let i = 0; i < 3; i += 1) {
    const { status } = await call("POST", "/scans", {
      token: userToken,
      body: scanPayload(`com.example.app${i}`, [sampleFinding]),
    });
    assert.equal(status, 201);
  }

  const { body } = await call("GET", "/scans", { token: userToken });
  assert.equal(body.scans.length, 3, "a free account should keep only 3 scans");

  const gone = await call("GET", `/scans/${firstScanId}`, { token: userToken });
  assert.equal(gone.status, 404, "the oldest scan should have been removed");
});

await check("comparing scans is refused on a free account", async () => {
  const { body: list } = await call("GET", "/scans", { token: userToken });
  const [a, b] = list.scans;
  const { status } = await call("GET", `/scans/compare/results?baseline=${b.id}&current=${a.id}`, {
    token: userToken,
  });
  assert.equal(status, 402, "a paid feature should return 402 on the free tier");
});

await check("exporting a report is refused on a free account", async () => {
  const { body: list } = await call("GET", "/scans", { token: userToken });
  const { status } = await call("GET", `/scans/${list.scans[0].id}/report`, { token: userToken });
  assert.equal(status, 402);
});

// --- premium --------------------------------------------------------------

group("Premium features");

await check("upgrading to premium changes the tier", async () => {
  const { status, body } = await call("POST", "/subscription/upgrade", {
    token: userToken,
    body: {},
  });
  assert.equal(status, 200, JSON.stringify(body));
  assert.equal(body.user.tier, "premium");
});

await check("the old token stops working once the tier changes", async () => {
  // Changing tier revokes sessions on purpose, so a token issued before the change
  // cannot keep using the old permissions.
  const { status } = await call("GET", "/users/me", { token: userToken });
  assert.equal(status, 401, "the pre-upgrade token should have been revoked");
});

await check("signing in again returns a token carrying the premium tier", async () => {
  const { status, body } = await call("POST", "/auth/login", {
    body: { email: userEmail, password: userPassword },
  });
  assert.equal(status, 200, JSON.stringify(body));
  assert.equal(body.user.tier, "premium");
  userToken = body.session.idToken;
});

await check("premium keeps history beyond the free limit", async () => {
  for (let i = 0; i < 3; i += 1) {
    await call("POST", "/scans", {
      token: userToken,
      body: scanPayload(`com.premium.app${i}`, [sampleFinding]),
    });
  }
  const { body } = await call("GET", "/scans", { token: userToken });
  assert.ok(body.scans.length > 3, `expected more than 3 scans, got ${body.scans.length}`);
  assert.equal(body.historyLimit, null, "premium should report no limit");
});

let premiumScanA;
let premiumScanB;

await check("comparing two scans reports what changed", async () => {
  const a = await call("POST", "/scans", {
    token: userToken,
    body: scanPayload("com.compare.app", [
      sampleFinding,
      { ...sampleFinding, category: "logcat-leak", severity: "high", component: null },
    ]),
  });
  const b = await call("POST", "/scans", {
    token: userToken,
    body: scanPayload("com.compare.app", [
      sampleFinding, // still present
      { ...sampleFinding, category: "allow-backup", severity: "medium", component: null }, // new
    ]),
  });
  premiumScanA = a.body.scan.id;
  premiumScanB = b.body.scan.id;

  const { status, body } = await call(
    "GET",
    `/scans/compare/results?baseline=${premiumScanA}&current=${premiumScanB}`,
    { token: userToken }
  );
  assert.equal(status, 200, JSON.stringify(body));
  assert.equal(body.comparison.summary.unchanged, 1);
  assert.equal(body.comparison.summary.resolved, 1, "logcat-leak should read as resolved");
  assert.equal(body.comparison.summary.introduced, 1, "allow-backup should read as introduced");
});

await check("exporting a report returns HTML with the findings in it", async () => {
  const res = await fetch(`${BASE}/scans/${premiumScanB}/report`, {
    headers: { Authorization: `Bearer ${userToken}` },
  });
  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type") || "", /html/);
  const html = await res.text();
  assert.match(html, /com\.compare\.app/);
  assert.match(html, /CRITICAL/);
});

await check("cancelling the subscription drops back to free and warns about trimming", async () => {
  const { status, body } = await call("POST", "/subscription/cancel", {
    token: userToken,
    body: { confirm: "CANCEL", reason: "testing" },
  });
  assert.equal(status, 200, JSON.stringify(body));
  assert.equal(body.user.tier, "free");
  assert.ok(body.warning, "expected a warning that history will be trimmed");
  assert.match(body.warning, /export anything you need first/);
});

// --- organisations and admin ---------------------------------------------

group("Organisations and admin");

const adminEmail = `admin-${unique()}@example.com`;
const adminPassword = "admin-password-1234";
let adminToken;
let orgId;

await check("registering an admin also creates their organisation", async () => {
  const { status, body } = await call("POST", "/auth/register-admin", {
    body: {
      email: adminEmail,
      password: adminPassword,
      displayName: "Org Owner",
      organisationName: "Test Security Team",
    },
  });
  assert.equal(status, 201, JSON.stringify(body));
  assert.equal(body.user.role, "admin");
  assert.equal(body.organisation.name, "Test Security Team");
  assert.equal(body.user.organisationId, body.organisation.id);
  adminToken = body.session.idToken;
  orgId = body.organisation.id;
});

let inviteToken;

await check("an admin can invite a team member and gets a one-time token", async () => {
  const { status, body } = await call("POST", `/organisations/${orgId}/invitations`, {
    token: adminToken,
    body: { email: "invitee@example.com", role: "member" },
  });
  assert.equal(status, 201, JSON.stringify(body));
  assert.ok(body.token, "expected an invitation token");
  inviteToken = body.token;
});

await check("the invitation token is stored hashed, not in the clear", async () => {
  const snap = await db.collection("invitations").get();
  assert.ok(snap.size >= 1);
  const doc = snap.docs[0].data();
  assert.ok(doc.tokenHash, "expected a tokenHash field");
  assert.equal(doc.token, undefined, "the raw token must not be stored");
  assert.notEqual(doc.tokenHash, inviteToken, "the stored value must not equal the token");
});

await check("a duplicate pending invitation is refused", async () => {
  const { status } = await call("POST", `/organisations/${orgId}/invitations`, {
    token: adminToken,
    body: { email: "invitee@example.com", role: "member" },
  });
  assert.equal(status, 409);
});

let memberToken;
let memberUid;

await check("an invited person registers and joins with the token", async () => {
  const registered = await call("POST", "/auth/register", {
    body: { email: "invitee@example.com", password: "member-password-1", displayName: "Member" },
  });
  assert.equal(registered.status, 201, JSON.stringify(registered.body));
  memberUid = registered.body.user.id;

  const joined = await call("POST", "/organisations/join", {
    token: registered.body.session.idToken,
    body: { token: inviteToken },
  });
  assert.equal(joined.status, 200, JSON.stringify(joined.body));
  assert.equal(joined.body.organisation.id, orgId);

  // Joining changes the claims, so a fresh sign-in is needed.
  const relogin = await call("POST", "/auth/login", {
    body: { email: "invitee@example.com", password: "member-password-1" },
  });
  memberToken = relogin.body.session.idToken;
});

await check("the same invitation token cannot be used twice", async () => {
  const other = await call("POST", "/auth/register", {
    body: { email: `other-${unique()}@example.com`, password: "other-password-1" },
  });
  const { status } = await call("POST", "/organisations/join", {
    token: other.body.session.idToken,
    body: { token: inviteToken },
  });
  assert.equal(status, 409, "a redeemed invitation should be refused");
});

await check("an admin can list the members of their own organisation", async () => {
  const { status, body } = await call("GET", `/organisations/${orgId}/members`, {
    token: adminToken,
  });
  assert.equal(status, 200, JSON.stringify(body));
  const emails = body.members.map((m) => m.email);
  assert.ok(emails.includes(adminEmail));
  assert.ok(emails.includes("invitee@example.com"));
});

await check("a plain member cannot use the admin endpoints", async () => {
  const { status } = await call("GET", `/organisations/${orgId}/members`, { token: memberToken });
  assert.equal(status, 403);
});

await check("an admin cannot manage a different organisation", async () => {
  const { status } = await call("GET", "/organisations/some-other-org/members", {
    token: adminToken,
  });
  assert.equal(status, 403, "passing another org id in the URL must be refused");
});

let memberScanId;

await check("an admin sees a member's scan summaries but not their findings", async () => {
  const saved = await call("POST", "/scans", {
    token: memberToken,
    body: scanPayload("com.member.app", [sampleFinding]),
  });
  assert.equal(saved.status, 201, JSON.stringify(saved.body));
  memberScanId = saved.body.scan.id;

  const { status, body } = await call("GET", `/organisations/${orgId}/members/${memberUid}/scans`, {
    token: adminToken,
  });
  assert.equal(status, 200, JSON.stringify(body));
  assert.ok(body.scans.length >= 1);
  // This is the privacy line the project promises: an admin sees that a scan happened
  // and how many problems it found, never the evidence taken from the member's app.
  assert.equal(body.scans[0].findings, undefined, "findings must not be exposed to an admin");
  assert.ok(body.scans[0].counts, "but the counts should be visible");
});

await check("reading a member's data is written to the audit log", async () => {
  const { status, body } = await call("GET", `/organisations/${orgId}/audit`, {
    token: adminToken,
  });
  assert.equal(status, 200, JSON.stringify(body));
  const actions = body.entries.map((e) => e.action);
  assert.ok(actions.includes("member.data_viewed"), `audit actions were: ${actions.join(", ")}`);
  assert.ok(actions.includes("member.invited"));
  assert.ok(actions.includes("member.joined"));
});

let flagId;

await check("an admin can flag a member's scan", async () => {
  const { status, body } = await call("POST", `/organisations/${orgId}/scans/${memberScanId}/flag`, {
    token: adminToken,
    body: { reason: "Checking this was an authorised target" },
  });
  assert.equal(status, 201, JSON.stringify(body));
  assert.equal(body.flag.status, "open");
  flagId = body.flag.id;
});

await check("the open flag appears in the review list", async () => {
  const { status, body } = await call("GET", `/organisations/${orgId}/flags`, { token: adminToken });
  assert.equal(status, 200);
  assert.equal(body.flags.length, 1);
  assert.equal(body.flags[0].id, flagId);
});

await check("reviewing the flag closes it and records the decision", async () => {
  const { status, body } = await call(
    "POST",
    `/organisations/${orgId}/flags/${flagId}/review`,
    { token: adminToken, body: { decision: "dismiss", note: "Target was authorised" } }
  );
  assert.equal(status, 200, JSON.stringify(body));
  assert.equal(body.flag.status, "dismissed");

  const list = await call("GET", `/organisations/${orgId}/flags`, { token: adminToken });
  assert.equal(list.body.flags.length, 0, "a reviewed flag should leave the open list");
});

await check("the same flag cannot be reviewed twice", async () => {
  const { status } = await call("POST", `/organisations/${orgId}/flags/${flagId}/review`, {
    token: adminToken,
    body: { decision: "uphold" },
  });
  assert.equal(status, 409);
});

await check("an admin can promote a member to admin", async () => {
  const { status, body } = await call("POST", `/organisations/${orgId}/admins`, {
    token: adminToken,
    body: { uid: memberUid },
  });
  assert.equal(status, 200, JSON.stringify(body));

  const snap = await db.collection("users").doc(memberUid).get();
  assert.equal(snap.data().role, "admin");
});

await check("removing a member leaves their account and scans intact", async () => {
  const { status } = await call("DELETE", `/organisations/${orgId}/members/${memberUid}`, {
    token: adminToken,
  });
  assert.equal(status, 200);

  const profile = await db.collection("users").doc(memberUid).get();
  assert.ok(profile.exists, "the account should still exist");
  assert.equal(profile.data().organisationId, null);
  assert.equal(profile.data().role, "member", "they should be demoted back to member");

  const stillThere = await db.collection("scans").doc(memberScanId).get();
  assert.ok(stillThere.exists, "their scans should not have been deleted");
});

await check("an admin cannot remove themselves", async () => {
  const owner = await auth.getUserByEmail(adminEmail);
  const { status } = await call("DELETE", `/organisations/${orgId}/members/${owner.uid}`, {
    token: adminToken,
  });
  assert.equal(status, 400);
});

await check("deleting a member account needs an explicit confirmation and a reason", async () => {
  // Re-invite so there is a member to act on.
  const invite = await call("POST", `/organisations/${orgId}/invitations`, {
    token: adminToken,
    body: { email: `doomed-${unique()}@example.com` },
  });
  const email = invite.body.invitation.email;
  const registered = await call("POST", "/auth/register", {
    body: { email, password: "doomed-password-1" },
  });
  await call("POST", "/organisations/join", {
    token: registered.body.session.idToken,
    body: { token: invite.body.token },
  });
  const doomedUid = registered.body.user.id;

  const missingConfirm = await call(
    "DELETE",
    `/organisations/${orgId}/members/${doomedUid}/account`,
    { token: adminToken, body: { reason: "no confirmation supplied" } }
  );
  assert.equal(missingConfirm.status, 400, "a missing confirmation must be refused");

  const done = await call("DELETE", `/organisations/${orgId}/members/${doomedUid}/account`, {
    token: adminToken,
    body: { confirm: "DELETE_ACCOUNT", reason: "Left the company" },
  });
  assert.equal(done.status, 200, JSON.stringify(done.body));

  const gone = await db.collection("users").doc(doomedUid).get();
  assert.ok(!gone.exists, "the account record should be gone");

  const audit = await call("GET", `/organisations/${orgId}/audit`, { token: adminToken });
  const deletion = audit.body.entries.find((e) => e.action === "member.account_deleted");
  assert.ok(deletion, "the deletion should be in the audit log");
  assert.equal(deletion.metadata.reason, "Left the company");
});

group("Account deletion");

await check("deleting your own account removes your scan history with it", async () => {
  const email = `throwaway-${unique()}@example.com`;
  const password = "throwaway-password-1";
  const registered = await call("POST", "/auth/register", { body: { email, password } });
  const token = registered.body.session.idToken;
  const uid = registered.body.user.id;

  await call("POST", "/scans", { token, body: scanPayload("com.throwaway.app", [sampleFinding]) });

  const before = await db.collection("scans").where("userId", "==", uid).get();
  assert.ok(before.size >= 1, "expected a scan to exist before deletion");

  const { status } = await call("DELETE", "/users/me", {
    token,
    body: { currentPassword: password, confirm: "DELETE" },
  });
  assert.equal(status, 200);

  const after = await db.collection("scans").where("userId", "==", uid).get();
  assert.equal(after.size, 0, "their scans should have been deleted too");

  const profile = await db.collection("users").doc(uid).get();
  assert.ok(!profile.exists);
});

// --- done ------------------------------------------------------------------

server.close();

console.log(`\n${passed} passed, ${failures.length} failed.`);
if (failures.length > 0) {
  for (const { name, error } of failures) {
    console.error(`\n--- ${name} ---\n${error.stack}`);
  }
  process.exitCode = 1;
}
