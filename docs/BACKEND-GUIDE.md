# BioAudit — Editing the Back End

The back end is a Node.js REST API: Express + Firebase Authentication + Cloud Firestore,
deployed on Google Cloud Run. It holds accounts, scan history, teams, and the AI
explanation layer.

This guide is about **changing** it. For what the API already exposes — every endpoint,
the data model, the auth flow — see [backend/README.md](../backend/README.md), which is
the reference. For the desktop app, see [FRONTEND-GUIDE.md](FRONTEND-GUIDE.md).

---

## 1. Getting set up

```bash
cd backend
npm install
```

Then pick how you want to run it.

### Against the Firebase emulator (recommended for development)

No credentials, no cost, no risk to real data. Needs **Java 11+** installed (the emulator
is a Java program).

```bash
npm run dev:emulated
```

That starts the Auth and Firestore emulators and the API together on port 4000, using
`.env.emulated`. Everything is in-memory, so **all accounts and data vanish when you stop
it** — which is exactly what you want for testing, and confusing if you forget.

### Against real Firebase

```bash
cp .env.example .env     # then fill it in
npm run dev              # or: npm start
```

You need, from the [Firebase console](https://console.firebase.google.com):

| Setting | Where to get it |
|---|---|
| `FIREBASE_PROJECT_ID` | Project settings → General |
| `FIREBASE_CLIENT_EMAIL`, `FIREBASE_PRIVATE_KEY` | Project settings → Service accounts → Generate new private key |
| `FIREBASE_WEB_API_KEY` | Project settings → General → Web API Key (register a web app if none is shown) |

Keep the `\n` escapes intact when pasting the private key into a single line. `.env` is
gitignored and must never be committed.

Point the desktop app at your local server by putting this in `config/config.yaml` at the
repo root:

```yaml
api:
  base_url: http://127.0.0.1:4000/api
```

---

## 2. The map

```
backend/src/
  server.js           starts the HTTP listener
  app.js              Express setup: helmet, cors, rate limit, routes, error handler
  config/
    env.js            reads + validates all configuration, fails fast at startup
    firebase.js       Admin SDK init and credential resolution
  constants/index.js  collection names, tiers, roles, statuses, severities
  middleware/
    auth.js           requireAuth, loadProfile, requirePremium, requireAdmin, ...
    validate.js       zod request validation
    errorHandler.js   one response shape for every failure
  routes/             HTTP layer: paths, validation, permissions
  services/           business logic + all Firestore access
  utils/
    ApiError.js       typed errors with status codes
    asyncHandler.js   forwards async errors to the error handler
    redact.js         strips secrets before anything reaches the AI

backend/
  firestore.rules         second line of defence (see §6)
  firestore.indexes.json  composite index definitions (see §6)
  scripts/                index creation + polling helpers
  tests/                  smoke.mjs (offline) + integration.mjs (emulator)
```

### The one architectural rule

**Routes handle HTTP. Services handle data. Nothing else touches Firestore.**

A route validates input, checks permissions, calls a service, and shapes the response. A
service does the work and owns every `db.collection(...)` call. Keeping Firestore access in
one layer is what makes retention limits, audit logging, and access rules enforceable in
one place instead of scattered across route handlers.

---

## 3. Adding an endpoint

Follow the existing shape exactly — it is the same in every route file.

```js
/** POST /api/things/:thingId/do-something -- what a user would call this */
router.post(
  "/:thingId/do-something",
  requireAdmin,                                  // permissions first
  validate({                                     // then shape
    params: z.object({ thingId: z.string().min(1) }),
    body: z.object({ reason: z.string().trim().min(1).max(500) }),
  }),
  asyncHandler(async (req, res) => {             // then the work
    const result = await thingsService.doSomething({
      thingId: req.params.thingId,
      reason: req.body.reason,
      actorId: req.user.uid,
    });
    res.json({ thing: result });
  })
);
```

### Why each piece is not optional

**`asyncHandler`** — Express 4 does not catch rejected promises. Without it, an async
throw becomes an unhandled rejection: the request hangs, the client times out, and nothing
useful appears in the log. It is a three-line wrapper; always use it.

**`validate`** — refuses malformed input with a clear per-field list, and replaces
`req.body` with the *parsed* value, so zod defaults are applied and unknown keys are
dropped. Skipping it means writing half-formed documents to Firestore and discovering it
much later.

**`ApiError`** for anything expected: `ApiError.notFound(...)`, `.forbidden(...)`,
`.conflict(...)`, `.badRequest(msg, details)`, `.paymentRequired(...)`. The error handler
turns these into the right status and passes your message through. Anything else becomes a
generic 500 with the detail logged but **not** returned, because internal messages tend to
quote database paths and configuration.

### The middleware, in the order you apply it

| Middleware | Gives you | Use when |
|---|---|---|
| `requireAuth` | `req.user` (uid, tier, role, organisationId from token claims) | any authenticated route |
| `loadProfile` | `req.profile` (the live Firestore user document) | you need current data, not a possibly-stale token claim |
| `requirePremium` | — | premium-only features |
| `requireAdmin` | — | admin-only |
| `requireOwnOrganisation` | — | the `:orgId` in the path must be the caller's own org |

Most route files apply the common ones once at the top: `router.use(requireAuth, loadProfile)`.

**Tier and role live in the token as custom claims**, so the usual path needs no database
read. But a claim can be stale — it only updates when the token is refreshed. Anything that
must not act on stale data (a billing change, a permission check with consequences) should
use `req.profile` from `loadProfile` instead of `req.user`.

---

## 4. Adding a service function

Services own Firestore. Keep them free of `req`/`res` — pass plain arguments so they stay
testable and callable from anywhere.

```js
const things = () => db.collection(COLLECTIONS.THINGS);

export async function doSomething({ thingId, reason, actorId }) {
  const snap = await things().doc(thingId).get();
  if (!snap.exists) throw ApiError.notFound("That thing does not exist.");

  await things().doc(thingId).update({
    reason,
    updatedAt: FieldValue.serverTimestamp(),
  });

  await audit.record({
    action: audit.AUDIT_ACTIONS.THING_CHANGED,
    actorId,
    subjectId: thingId,
  });

  return { id: thingId, ...snap.data(), reason };
}
```

Use `FieldValue.serverTimestamp()` for times, not `new Date()` — the server's clock is the
only one every client agrees on. Add new collection names to `constants/index.js` rather
than typing string literals.

**Log admin actions to the audit service.** Any action one user takes that affects another
— viewing their data, changing their role, deleting their account — goes in the audit log.
That is what makes team oversight accountable rather than just powerful.

---

## 5. Two security rules that are easy to break by accident

### Never leak which accounts exist

`firebaseAuth.service.js` collapses `EMAIL_NOT_FOUND`, `INVALID_PASSWORD`,
`INVALID_LOGIN_CREDENTIALS`, and `USER_DISABLED` into **one** message:

> That email address or password is incorrect.

Google's API distinguishes them. Passing that difference through would let anyone discover
which email addresses have accounts by watching which message comes back. That is a
*response oracle* — precisely the vulnerability class this whole tool exists to detect in
other people's apps. Shipping one in our own login would be indefensible, and an
integration test enforces it.

`USER_DISABLED` is folded in for the same reason: Firebase refuses a suspended account
*before* checking the password, so reporting suspension would confirm the account exists to
someone who never knew the password. Suspension is reported plainly only *after* the
password verifies, in the login route.

If you add an auth-adjacent endpoint, apply the same discipline: **the error message must
not depend on whether the account exists.**

### Redact before anything reaches the AI

`utils/redact.js` strips tokens, keys, and JWTs from finding evidence before it is sent to
Gemini. Scan evidence comes out of someone else's app and can contain real secrets. Any new
path that sends user content to a third party runs through `redact()` first.

---

## 6. Firestore indexes — the thing that will bite you

Firestore refuses any query that combines an equality filter with `orderBy` on a
*different* field unless a matching composite index exists.

**The emulator does not enforce this.** So a query works perfectly in development and then
returns HTTP 500 against real Firestore. This has already happened once on this project:
"Compare two runs" broke immediately after going live, because
`.where("userId", "==", uid).orderBy("createdAt", "desc")` had no index.

So: **if you add a query with `where` + `orderBy`, add the index in the same commit.**

1. Add it to `backend/firestore.indexes.json`:

```json
{
  "collectionGroup": "things",
  "queryScope": "COLLECTION",
  "fields": [
    { "fieldPath": "userId", "order": "ASCENDING" },
    { "fieldPath": "createdAt", "order": "DESCENDING" }
  ]
}
```

2. Create it, by whichever route works for you:

```bash
firebase deploy --only firestore:indexes    # needs an interactive `firebase login`
node scripts/create-indexes.mjs             # uses the service-account key in .env
```

`create-indexes.mjs` needs the service account to hold the **Cloud Datastore Index Admin**
IAM role; the default Firebase Admin SDK account does not, and you will get
`PERMISSION_DENIED`. Grant it in Google Cloud Console → IAM, or fall back to the console
link Firestore puts in the error message, which opens the creation form pre-filled.

3. Wait. Index builds take minutes, and queries fail with "index is currently building"
   until done. `node scripts/poll-indexes.mjs` watches until they are all `READY`.

An optional filter means a *second* index — `where(org) + orderBy` and
`where(org) + where(status) + orderBy` are different queries needing different indexes.
That is why `firestore.indexes.json` has pairs.

### The rules file

`firestore.rules` denies essentially everything. The API uses the Admin SDK, which
**bypasses these rules entirely**, so every permission check that actually matters lives in
`middleware/auth.js`. The rules are the second line of defence: if anything ever talks to
Firestore directly, or a database URL leaks, the default answer is no. Deploy with
`firebase deploy --only firestore:rules`.

---

## 7. Testing

```bash
npm test                  # smoke.mjs — pure unit tests, no server, no network
npm run test:integration  # integration.mjs — real emulated Auth + Firestore
npm run lint
```

`test:integration` boots the emulators itself, runs the suite, and tears them down. This is
where the response-oracle check lives, among others.

From the repo root you can also drive the Python client against a running backend:

```bash
pytest tests/test_api_client.py -v
```

Point that at the **emulator**, not production. It registers a lot of accounts and will hit
the sign-in rate limit (20 per 15 minutes per IP) and lock you out for a while.

---

## 8. Configuration and deployment

### `env.js` fails fast on purpose

A missing web API key surfaces at startup with a clear message, rather than as a confusing
error on the first sign-in attempt hours later. If you add a required setting, add it to
`env.js` and to `.env.example` in the same commit.

Credentials resolve in four ways, in this order:

1. `FIRESTORE_EMULATOR_HOST` / `FIREBASE_AUTH_EMULATOR_HOST` → emulator, no credentials
   needed
2. `FIREBASE_PROJECT_ID` + `CLIENT_EMAIL` + `PRIVATE_KEY` → inline service account
3. `GOOGLE_APPLICATION_CREDENTIALS` → a service-account JSON file
4. **Running on Google Cloud** (`K_SERVICE` is set, which Cloud Run does automatically) →
   Application Default Credentials from the instance metadata server, **no key anywhere**

Option 4 is why the deployment carries no service-account key. If you deploy somewhere
other than Google Cloud, you need option 2 or 3.

### Deploying to Cloud Run

```bash
gcloud run deploy bioaudit-api \
  --source . \
  --region us-central1 \
  --project <your-project-id> \
  --allow-unauthenticated \
  --set-env-vars "NODE_ENV=production,FIREBASE_PROJECT_ID=<id>,FIREBASE_WEB_API_KEY=<key>"
```

No Dockerfile needed — Cloud Run's buildpacks read `package.json`. Two things make this
work, and both are easy to break:

- The server reads `PORT` from the environment (`env.js` defaults to 4000, Cloud Run
  injects 8080). Hard-coding a port breaks the deploy with a "failed to start and listen"
  error.
- `--allow-unauthenticated` means the *service* is reachable. It does not weaken your app's
  own auth: every route still requires a valid Firebase token.

Add a new env var to an existing deployment without disturbing the others:

```bash
gcloud run services update bioaudit-api --region us-central1 \
  --update-env-vars "GEMINI_API_KEY=..."
```

Check what you deployed:

```bash
curl https://<your-service-url>/api/health
```

It reports the environment and whether the AI layer has a key — which is the question that
comes up most when explanations stop appearing in the desktop app.

### Rate limits

Two limiters, both configurable: `API_RATE_LIMIT_PER_MINUTE` (default 120, all routes) and
`AUTH_RATE_LIMIT_PER_15MIN` (default 20, on register/login only, per IP). The tight one on
auth is deliberate — without it an attacker could try passwords as fast as the network
allows. Raise it in `.env` for heavy local testing if you must, but leave the deployed
default alone.

### AI explanations

Set `GEMINI_API_KEY` and optionally `GEMINI_MODEL` (default `gemini-flash-latest`). Without
a key the layer degrades gracefully: findings still get the deterministic fallback fixes
from the Python engine, and `/api/health` reports `aiExplanations: disabled`.

The key belongs **only** on the server. The Python client has no AI dependency at all — a
local explainer existed once and was removed precisely because it only worked on whichever
machine happened to have a key set.
