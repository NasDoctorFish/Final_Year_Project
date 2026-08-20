# BioAudit Backend

REST API for the BioAudit biometric authentication security tool. Built with **Express.js**,
**Cloud Firestore**, and **Firebase Authentication**.

## What this service does, and what it does not

The backend **does not run the security scans**. The APK file and the USB-connected phone are
both on the user's own machine, so scanning stays in the desktop app. This service handles
everything around it:

| The API does | The desktop app does |
|---|---|
| Accounts, sign-in, sessions | Reading the APK's manifest and code |
| Storing and serving scan history | Talking to the phone over ADB |
| Enforcing free and premium limits | Deciding what counts as a finding |
| Generating AI explanations | Converting an exported report to PDF |
| Organisations, invitations, member oversight | |

Two consequences worth noting. The Gemini API key lives on the server, so it is never shipped
inside a downloadable program and can be replaced centrally. And detection stays deterministic:
the rules in the desktop app decide what a problem is, and the AI here only puts a confirmed
finding into readable words.

## Requirements

- Node.js 18.17 or newer
- A Firebase project with **Firestore** and **Email/Password authentication** enabled
- A Gemini API key, only if you want AI explanations

## Setup

```bash
cd backend
npm install
cp .env.example .env      # then fill it in
npm run dev
```

Filling in `.env` needs three things from the Firebase console:

1. **Service account key.** Project settings, Service accounts, Generate new private key. Save
   the JSON as `backend/serviceAccountKey.json`. It is gitignored, and it must stay that way:
   the key grants full access to your project.
2. **Web API key.** Project settings, General, Web API Key. The Admin SDK cannot check a
   password, so sign-in calls Google's Identity Toolkit with this key.
3. **Gemini API key**, if you want explanations. Leave it blank and the rest of the API works
   normally, with the explain endpoint reporting that the feature is switched off.

Then deploy the database rules:

```bash
firebase deploy --only firestore:rules
```

## Testing

Two suites, neither of which touches a live Firebase project.

```bash
npm test                 # 13 offline checks, no emulator needed
npm run test:integration # 42 checks against the Firebase emulators
```

**`npm test`** boots the real Express app and exercises the health check, the 404 handler,
authentication rejection, request validation, secret redaction, scan comparison, and report
rendering. It generates a throwaway RSA key at runtime so the Admin SDK accepts the
credential format offline, which means it runs anywhere with no setup.

**`npm run test:integration`** starts the auth and Firestore emulators, runs the full
workflow against them, and shuts them down again. It needs Java 11 or newer, which the
Firestore emulator requires. This covers what the offline suite cannot: real registration
and sign-in, tier limits and history trimming, the premium features, and the whole
organisation flow including invitations and the flag and review cycle.

This suite has already earned its keep. It caught a response oracle in our own login
endpoint, where an unknown email address produced a different message from a wrong
password, which would have let anyone enumerate accounts. There is now a test that fails
if that difference ever comes back.

To run the Python client's tests you need a server the client can reach:

```bash
npm run dev:emulated     # emulators plus the API on port 4000, leave running
# then, from the repository root:
pytest tests/test_api_client.py -v
```

Those tests skip themselves when no server is listening, so a normal `pytest tests/` run
stays offline.

`.env.emulated` raises the rate limits, because the test suites make far more sign-ins
than a person would and the production defaults would stop a run partway through. The
limits are configurable through `API_RATE_LIMIT_PER_MINUTE` and
`AUTH_RATE_LIMIT_PER_15MIN`; leave them unset in production to get the defaults.

## How authentication works

```
Desktop app                          This API                       Firebase
     |                                   |                              |
     |-- POST /api/auth/login ---------->|                              |
     |                                   |-- verify password ---------->|
     |<-- idToken + refreshToken --------|                              |
     |                                   |                              |
     |-- GET /api/scans ---------------->|                              |
     |   Authorization: Bearer <idToken> |-- verify token ------------->|
     |<-- history ----------------------|                              |
```

The app signs in once and sends the ID token on every later request. Tokens expire after an
hour, so the app calls `POST /api/auth/refresh` with its refresh token to get a new one.

**Tier and role live in the token** as Firebase custom claims, which lets the permission check
run without a database read on each request. Because a token already in someone's hands cannot
be edited, any change to tier or role revokes existing sessions, and the user signs in again to
pick up the new permissions. Endpoints say so in their response when that applies.

## Roles and tiers

These are two separate things, which is worth keeping straight:

- **Tier** is what the account paid for: `free` or `premium`. It gates features.
- **Role** is the account's position in an organisation: `member` or `admin`. It gates
  oversight of other people.

An admin can be on either tier, and a premium user is not automatically an admin.

| | Free | Premium | Admin |
|---|---|---|---|
| Scan an APK, assess a device | Yes | Yes | Yes |
| View test history | Newest 10 | Unlimited | Own, plus members' summaries |
| View AI explanation | Yes | Yes | Own scans only |
| Compare scan results | No | Yes | If premium |
| Export scan report | No | Yes | If premium |
| Manage organisation members | No | No | Yes |

## API reference

All paths are prefixed with `/api`. Every endpoint except registration, login, and refresh needs
`Authorization: Bearer <idToken>`.

### Health

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Service status, and whether AI explanations are configured |

### Authentication

| Method | Path | Diagram function |
|---|---|---|
| POST | `/auth/register` | Unregistered: Register user account |
| POST | `/auth/register-admin` | Admin: Register admin account (also creates the organisation) |
| POST | `/auth/login` | User: Log in |
| POST | `/auth/refresh` | Keep a session alive |
| POST | `/auth/logout` | User: Log out |

### Own account

| Method | Path | Diagram function |
|---|---|---|
| GET | `/users/me` | User: View profile |
| PATCH | `/users/me` | User: Update account details |
| POST | `/users/me/email` | User: Change email address |
| POST | `/users/me/password` | User: Change password |
| DELETE | `/users/me` | User: Delete account |

Changing an email address or password requires the current password as well as a valid session,
since a stolen token alone should not be enough to take an account over.

### Scans and history

| Method | Path | Diagram function |
|---|---|---|
| POST | `/scans` | User: Scan APK file, Assess connected device |
| GET | `/scans` | Free and Premium: View test history |
| GET | `/scans/:scanId` | One scan with all findings |
| POST | `/scans/:scanId/findings/:index/explain` | Free and Premium: View AI explanation |
| GET | `/scans/compare/results` | Premium: Compare scan results |
| GET | `/scans/:scanId/report` | Premium: Export scan report |
| DELETE | `/scans/:scanId` | User: Delete test history (one) |
| DELETE | `/scans` | User: Delete test history (all) |

### Organisations

| Method | Path | Diagram function |
|---|---|---|
| POST | `/organisations/join` | Join organisation, Join organisation via invite |
| GET | `/organisations/mine` | The caller's own organisation |
| GET | `/organisations/:orgId/members` | Admin: View member data |
| GET | `/organisations/:orgId/members/:uid/scans` | Admin: View member data (their scans) |
| POST | `/organisations/:orgId/invitations` | Admin: Invite team member |
| GET | `/organisations/:orgId/invitations` | Admin: see pending invitations |
| DELETE | `/organisations/:orgId/invitations/:id` | Admin: Cancel pending invitation |
| POST | `/organisations/:orgId/scans/:scanId/flag` | Admin: Flag member data |
| GET | `/organisations/:orgId/flags` | Admin: Review flagged items (list) |
| POST | `/organisations/:orgId/flags/:flagId/review` | Admin: Review flagged items (decide) |
| POST | `/organisations/:orgId/admins` | Admin: Add additional admin |
| DELETE | `/organisations/:orgId/members/:uid` | Admin: Remove organisation member |
| DELETE | `/organisations/:orgId/members/:uid/account` | Admin: Delete member account |
| GET | `/organisations/:orgId/audit` | The record of admin actions |

### Subscription

| Method | Path | Diagram function |
|---|---|---|
| GET | `/subscription` | Current tier and limits |
| POST | `/subscription/upgrade` | Move to premium |
| POST | `/subscription/cancel` | Premium: Cancel subscription |

Payment processing is **not** implemented. Taking card details needs a payment provider and its
own compliance work, so `upgrade` records the tier change and marks where a provider such as
Stripe would call in from its webhook.

## Example: saving a scan

```bash
curl -X POST http://localhost:4000/api/scans \
  -H "Authorization: Bearer $ID_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "device",
    "authorisationConfirmed": true,
    "target": { "packageName": "com.example.app", "deviceSerial": "1b541277" },
    "findings": [
      {
        "category": "exported-auth-bypass",
        "title": "Exported activity reachable without authentication",
        "severity": "critical",
        "owasp": ["M3", "M1"],
        "evidence": "`am start -n com.example.app/.SecretActivity` -> Starting: Intent{...}",
        "source": "ipc_oracle",
        "confidence": "confirmed",
        "component": "com.example.app.SecretActivity"
      }
    ]
  }'
```

A device assessment is rejected unless `authorisationConfirmed` is `true`, so a stored record can
never show an unconfirmed run against a live app.

## Data model

```
users/{uid}                 email, displayName, tier, role, organisationId,
                            subscription, scanCount, disabled
organisations/{orgId}       name, ownerId, adminIds[], memberIds[]
invitations/{id}            organisationId, email, role, tokenHash, status, expiresAt
scans/{id}                  userId, organisationId, type, target, findings[],
                            counts, flagged, authorisationConfirmed
flags/{id}                  scanId, organisationId, subjectId, reason, status, review
auditLog/{id}               action, actorId, subjectId, organisationId, metadata, at
```

Invitation tokens are stored **hashed**, so a copy of the database does not hand out working
invitations. The token itself is returned once when the invitation is created and cannot be
retrieved again.

## Security decisions worth knowing

**Admins cannot read their members' findings.** The tool promises that an app's code never
leaves the machine it was scanned on. An admin can see that a member ran a scan and how many
problems it found, which is what oversight needs, but not the evidence pulled out of the
member's app. That read is also written to the audit log.

**The audit log is append-only.** Nothing in the API updates or deletes an entry, and the
Firestore rules deny client writes outright. Reading a member's data, flagging it, removing a
member, and deleting an account are all recorded.

**Login does not say whether an account exists.** A wrong password and an unknown email address
produce the same message. Telling them apart would be a response oracle, which is exactly the
weakness this project detects in other apps, so the API does not have one of its own.

**The Admin SDK bypasses Firestore rules.** Because this service runs with full privileges,
every permission check is enforced in Express. The rules in `firestore.rules` deny almost
everything by default and exist as a second line of defence.

**Rate limits.** 120 requests a minute across the API, and 20 attempts per 15 minutes on
registration and login, since those are the two endpoints worth guessing at.

## Project layout

```
backend/
  src/
    server.js              entry point, graceful shutdown
    app.js                 middleware and route mounting
    config/
      env.js               loads and validates configuration at startup
      firebase.js          Admin SDK setup
    middleware/
      auth.js              token verification, tier and role gates
      validate.js          request validation with zod
      errorHandler.js      one response shape for every failure
    routes/                one file per group, mapped to the diagram
    services/
      firebaseAuth.service.js   password sign-in and token refresh
      users.service.js          accounts and custom claims
      organisations.service.js  membership, invitations, flag and review
      scans.service.js          history, retention, comparison
      gemini.service.js         AI explanations, with redaction (the live path)
      aiGraph.service.js        LangGraph orchestration prototype, not wired in (see below)
      report.service.js         HTML report rendering
      audit.service.js          append-only record of admin actions
    utils/
      redact.js            strips secrets before anything reaches the AI
      ApiError.js          errors that carry an HTTP status
      asyncHandler.js      forwards async errors to the error handler
  firestore.rules          deny-by-default database rules
```

## AI orchestration prototype (not wired in)

`src/services/aiGraph.service.js` is a LangGraph rebuild of the explanation layer, sitting
next to `gemini.service.js` rather than replacing it. **No route imports it.** It exists to
be reviewed and exercised standalone before any endpoint is switched over to it.

What it adds over `gemini.service.js`: tool calls instead of one fixed prompt (the model
asks for a finding's evidence, a scan's summary, guidance for a category, or a diff between
two scans, rather than having everything handed to it up front), an output `responseSchema`
per mode instead of prose-described JSON, and a one-shot repair loop for a malformed reply
instead of a hard failure.

```js
import { createSession } from "./services/aiGraph.service.js";

const session = createSession({
  user: req.user,        // bound from the request, never model-supplied
  scanIds: [scan.id],    // allowlist: a tool call naming any other scan is refused
});

const { result } = await session.explain(`Explain finding ${index} in scan ${scan.id}.`);
// result: { explanation, mitigation, references } -- same shape gemini.service.js returns
```

Four modes: `explain` (one finding, matches today's endpoint), `synthesize` (a whole scan),
`compare` (the diff between two scans, narrated), `report` (feeds a future export path).

Every tool's return value passes through one egress guard before it can reach Gemini:
redacted, capped (800 characters for evidence, 200 for labels), stripped to an explicit
allowlist of keys. `compare_scans` drops evidence from both scans entirely — a diff needs
categories, not two scans' worth of provider rows. This matters because a tool call's return
is appended to the conversation and sent back to Gemini on the next turn regardless of which
tool ran first, so the guard has to sit on every tool's output, not just the first one
called.

## Connecting the desktop app

A Python client is already written: `bioaudit/api/client.py`. It uses only the standard
library, so it does not add a dependency to a project whose core deliberately runs without
any.

```python
from bioaudit.api import ApiClient, ApiClientError

client = ApiClient("http://127.0.0.1:4000/api")

try:
    account = client.login("dev@example.com", "password")
    print(account.tier, account.is_premium)

    # run_ is a TestRun the local scanning engine produced
    result = client.upload_run(run_, authorised=True)

    explanation = client.explain_finding(result["scan"]["id"], finding_index=0)
    print(explanation["explanation"])
    print(explanation["mitigation"])

    for scan in client.list_history()["scans"]:
        print(scan["createdAt"], scan["counts"])

except ApiClientError as exc:
    # exc.message is written for a person, so a dialog can show it directly
    show_error(exc.message)
```

The client refreshes an expired token and retries the request once, automatically. That
matters because the server revokes sessions whenever a tier or role changes, so without it
an upgrade would break the next call the user made.

CORS allows requests with no `Origin` header, which is what a desktop client sends. Browser
front ends have to be listed in `CORS_ORIGINS`.
