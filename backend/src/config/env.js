/**
 * Loads and validates configuration once at startup.
 *
 * Failing fast here is deliberate. A missing service account or web API key would
 * otherwise surface much later as a confusing runtime error on the first request.
 */
import dotenv from "dotenv";

dotenv.config();

function required(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(
      `Missing required environment variable ${name}. Copy .env.example to .env and fill it in.`
    );
  }
  return value;
}

function optional(name, fallback = "") {
  return process.env[name] || fallback;
}

function int(name, fallback) {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  return Number.isNaN(parsed) ? fallback : parsed;
}

const serviceAccountPath = optional("GOOGLE_APPLICATION_CREDENTIALS");
const hasInlineCredentials =
  process.env.FIREBASE_PROJECT_ID &&
  process.env.FIREBASE_CLIENT_EMAIL &&
  process.env.FIREBASE_PRIVATE_KEY;

/**
 * The Firebase emulators accept any caller, so credentials are neither needed nor
 * checked when these variables are present. The emulator sets them itself, which is what
 * lets the integration tests run with no service account anywhere.
 */
const usingEmulators = Boolean(
  process.env.FIRESTORE_EMULATOR_HOST || process.env.FIREBASE_AUTH_EMULATOR_HOST
);

/**
 * A fourth credential source: Google Cloud's own hosting products (Cloud Run, Cloud
 * Functions, App Engine, GCE) hand every process Application Default Credentials via
 * an on-instance metadata server, so no key ever needs to exist on disk or in an env
 * var. K_SERVICE/K_REVISION/K_CONFIGURATION are set automatically by Cloud Run;
 * GOOGLE_CLOUD_PROJECT and GAE_SERVICE cover Cloud Functions and App Engine.
 */
const runningOnGoogleCloud = Boolean(
  process.env.K_SERVICE || process.env.GOOGLE_CLOUD_PROJECT || process.env.GAE_SERVICE
);

if (!usingEmulators && !serviceAccountPath && !hasInlineCredentials && !runningOnGoogleCloud) {
  throw new Error(
    "No Firebase credentials found. Set GOOGLE_APPLICATION_CREDENTIALS to a service " +
      "account JSON path, or set FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL and " +
      "FIREBASE_PRIVATE_KEY."
  );
}

export const env = {
  port: int("PORT", 4000),
  nodeEnv: optional("NODE_ENV", "development"),
  isProduction: optional("NODE_ENV", "development") === "production",

  corsOrigins: optional("CORS_ORIGINS")
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean),

  usingEmulators,

  firebase: {
    serviceAccountPath,
    projectId: optional("FIREBASE_PROJECT_ID") || optional("GCLOUD_PROJECT"),
    clientEmail: optional("FIREBASE_CLIENT_EMAIL"),
    // Hosting panels usually store the key as one line with literal \n sequences.
    privateKey: optional("FIREBASE_PRIVATE_KEY").replace(/\\n/g, "\n"),
    webApiKey: required("FIREBASE_WEB_API_KEY"),
  },

  gemini: {
    apiKey: optional("GEMINI_API_KEY"),
    // A pinned model rather than a "-latest" alias. The alias is steered by Google and
    // can land on a pool that is overloaded, which shows up as calls hanging for a
    // minute or more before returning 503 -- far past any sensible client timeout.
    model: optional("GEMINI_MODEL", "gemini-3.5-flash"),
    // Ceiling on a single attempt. Without one the SDK waits indefinitely, so an
    // overloaded model stalls the request instead of failing and letting us retry.
    timeoutMs: int("GEMINI_TIMEOUT_MS", 20000),
    get enabled() {
      return Boolean(this.apiKey);
    },
  },

  /**
   * Outbound email. Optional in the same way the AI layer is: with no host configured
   * the app runs normally and simply does not send, so a developer running locally is
   * never blocked by not having SMTP credentials. Nothing in the product depends on a
   * message arriving -- an invitation token is shown on screen as well as emailed.
   */
  email: {
    host: optional("SMTP_HOST"),
    port: int("SMTP_PORT", 587),
    user: optional("SMTP_USER"),
    pass: optional("SMTP_PASS"),
    from: optional("SMTP_FROM", "BioAudit <no-reply@bioaudit.app>"),
    get enabled() {
      return Boolean(this.host && this.user && this.pass);
    },
  },

  limits: {
    freeHistory: int("FREE_HISTORY_LIMIT", 10),
    // Free-tier ceiling on AI explanations per calendar month. Premium is uncapped, so
    // there is no matching setting for it. Reflects the running cost of the Gemini API.
    freeAiPerMonth: int("FREE_AI_MONTHLY_LIMIT", 20),
  },

  /**
   * Rate limits, configurable so a test run is not fighting production tuning.
   *
   * The auth limit is deliberately much tighter than the general one, since sign-in and
   * registration are the two endpoints worth guessing at. Raise them only for local
   * testing against the emulators.
   */
  rateLimits: {
    apiPerMinute: int("API_RATE_LIMIT_PER_MINUTE", 120),
    authPer15Min: int("AUTH_RATE_LIMIT_PER_15MIN", 20),
  },
};
