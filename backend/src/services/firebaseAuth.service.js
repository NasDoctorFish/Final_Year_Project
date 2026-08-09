/**
 * Email and password sign-in against Google's Identity Toolkit REST API.
 *
 * Why this exists: the Admin SDK can create and inspect users but cannot verify a
 * password, and our front end is a Python desktop app rather than a browser. Rather
 * than embed a JavaScript Firebase client in the desktop app, the app posts
 * credentials to this API once and gets back the ID token it then sends on every
 * later request.
 */
import { env } from "../config/env.js";
import { ApiError } from "../utils/ApiError.js";

/**
 * Endpoint bases.
 *
 * When FIREBASE_AUTH_EMULATOR_HOST is set, the emulator serves the same two APIs under a
 * path prefix on its own host. Honouring that variable is what lets the integration tests
 * exercise real sign-in without a live Firebase project or a real password anywhere.
 */
const emulatorHost = process.env.FIREBASE_AUTH_EMULATOR_HOST;

const IDENTITY_BASE = emulatorHost
  ? `http://${emulatorHost}/identitytoolkit.googleapis.com/v1`
  : "https://identitytoolkit.googleapis.com/v1";

const TOKEN_BASE = emulatorHost
  ? `http://${emulatorHost}/securetoken.googleapis.com/v1`
  : "https://securetoken.googleapis.com/v1";

/**
 * One message for every way a credential can be wrong.
 *
 * This is deliberate, and an integration test enforces it. Google's Identity Toolkit
 * distinguishes EMAIL_NOT_FOUND from INVALID_PASSWORD, and passing that difference
 * through would let anyone discover which email addresses have accounts by watching
 * which message came back. That is a response oracle, the exact weakness this project
 * detects in other apps, so the API must not ship one of its own.
 *
 * USER_DISABLED is folded in here too. Firebase refuses a suspended account before it
 * checks the password, so telling the caller it is suspended would leak that the account
 * exists to someone who never knew the password. A genuinely suspended user is told
 * plainly by the login route instead, which runs only after the password has been
 * verified.
 */
const CREDENTIAL_FAILURE = "That email address or password is incorrect.";

const CREDENTIAL_CODES = [
  "EMAIL_NOT_FOUND",
  "INVALID_PASSWORD",
  "INVALID_LOGIN_CREDENTIALS",
  "USER_DISABLED",
];

/** Turns Google's error codes into messages a user can act on. */
function translateAuthError(message) {
  if (CREDENTIAL_CODES.some((code) => message.startsWith(code))) {
    return { message: CREDENTIAL_FAILURE, status: 401 };
  }

  const map = {
    // Registration has to say when an address is taken, otherwise a person cannot tell a
    // typo from an existing account. This is a known, accepted trade-off and it is why
    // registration is rate limited more tightly than the rest of the API.
    EMAIL_EXISTS: "An account already exists for that email address.",
    WEAK_PASSWORD: "That password is too short. Use at least six characters.",
    INVALID_EMAIL: "That email address is not valid.",
    TOKEN_EXPIRED: "Your session has expired. Sign in again.",
    INVALID_REFRESH_TOKEN: "Your session is no longer valid. Sign in again.",
  };
  const key = Object.keys(map).find((code) => message.startsWith(code));
  if (key) return { message: map[key], status: key === "EMAIL_EXISTS" ? 409 : 401 };

  if (message.includes("TOO_MANY_ATTEMPTS")) {
    return { message: "Too many failed attempts. Wait a moment and try again.", status: 429 };
  }
  return { message: CREDENTIAL_FAILURE, status: 401 };
}

async function callIdentityApi(path, payload, base = IDENTITY_BASE) {
  const response = await fetch(`${base}/${path}?key=${env.firebase.webApiKey}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const rawMessage = data?.error?.message || "UNKNOWN";
    const { message, status } = translateAuthError(rawMessage);
    throw new ApiError(status, message);
  }
  return data;
}

/** Exchange an email and password for an ID token and a refresh token. */
export async function signInWithPassword(email, password) {
  const data = await callIdentityApi("accounts:signInWithPassword", {
    email,
    password,
    returnSecureToken: true,
  });
  return {
    uid: data.localId,
    idToken: data.idToken,
    refreshToken: data.refreshToken,
    expiresInSeconds: Number.parseInt(data.expiresIn, 10),
  };
}

/** Exchange a refresh token for a fresh ID token, so users are not asked to sign in again. */
export async function refreshIdToken(refreshToken) {
  const response = await fetch(`${TOKEN_BASE}/token?key=${env.firebase.webApiKey}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken }),
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const { message, status } = translateAuthError(data?.error?.message || "INVALID_REFRESH_TOKEN");
    throw new ApiError(status, message);
  }

  return {
    uid: data.user_id,
    idToken: data.id_token,
    refreshToken: data.refresh_token,
    expiresInSeconds: Number.parseInt(data.expires_in, 10),
  };
}

/**
 * Confirms a password before a sensitive change.
 *
 * Changing an email address or password should not be possible with only a stolen
 * session token, so those endpoints ask for the current password and check it here.
 */
export async function verifyPassword(email, password) {
  await signInWithPassword(email, password);
  return true;
}
