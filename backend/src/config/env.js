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

if (!usingEmulators && !serviceAccountPath && !hasInlineCredentials) {
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
    model: optional("GEMINI_MODEL", "gemini-flash-latest"),
    get enabled() {
      return Boolean(this.apiKey);
    },
  },

  limits: {
    freeHistory: int("FREE_HISTORY_LIMIT", 10),
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
