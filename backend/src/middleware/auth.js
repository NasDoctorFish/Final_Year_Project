/**
 * Authentication and authorisation.
 *
 * The desktop app signs in once and then sends the Firebase ID token as a Bearer
 * header on every request. We verify that token here and attach the caller to req.user.
 *
 * Tier and role live in the token as custom claims, so the common path needs no
 * database read. They are refreshed on the token whenever they change (see
 * services/users.service.js), and any endpoint that must not act on a stale claim
 * reads the user document instead.
 */
import { auth, db } from "../config/firebase.js";
import { COLLECTIONS, ROLES, TIERS } from "../constants/index.js";
import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";

function readBearerToken(req) {
  const header = req.headers.authorization || "";
  if (!header.startsWith("Bearer ")) return null;
  const token = header.slice("Bearer ".length).trim();
  return token || null;
}

/** Rejects the request unless it carries a valid, unrevoked Firebase ID token. */
export const requireAuth = asyncHandler(async (req, res, next) => {
  const token = readBearerToken(req);
  if (!token) {
    throw ApiError.unauthorized("Send a Firebase ID token as 'Authorization: Bearer <token>'.");
  }

  let decoded;
  try {
    // checkRevoked makes a logout or a forced sign-out take effect immediately,
    // rather than lingering until the token would have expired on its own.
    decoded = await auth.verifyIdToken(token, true);
  } catch (error) {
    if (error.code === "auth/id-token-expired") {
      throw ApiError.unauthorized("Your session has expired. Refresh the token and retry.");
    }
    if (error.code === "auth/id-token-revoked") {
      throw ApiError.unauthorized("Your session was ended. Sign in again.");
    }
    throw ApiError.unauthorized("Invalid authentication token.");
  }

  req.user = {
    uid: decoded.uid,
    email: decoded.email || null,
    emailVerified: Boolean(decoded.email_verified),
    tier: decoded.tier || TIERS.FREE,
    role: decoded.role || ROLES.MEMBER,
    organisationId: decoded.organisationId || null,
  };

  next();
});

/** Loads the caller's Firestore profile onto req.profile. Use when claims are not enough. */
export const loadProfile = asyncHandler(async (req, res, next) => {
  const snap = await db.collection(COLLECTIONS.USERS).doc(req.user.uid).get();
  if (!snap.exists) {
    throw ApiError.notFound("Your account record is missing. Contact support.");
  }
  const profile = { id: snap.id, ...snap.data() };
  if (profile.disabled) {
    throw ApiError.forbidden("This account has been suspended.");
  }
  req.profile = profile;
  // Claims can lag behind a change made moments ago, so prefer the stored values.
  req.user.tier = profile.tier || req.user.tier;
  req.user.role = profile.role || req.user.role;
  req.user.organisationId = profile.organisationId ?? req.user.organisationId;
  next();
});

/** Gate for paid features: Compare scan results, Export scan report, Cancel subscription. */
export const requirePremium = asyncHandler(async (req, res, next) => {
  if (req.user.tier !== TIERS.PREMIUM) {
    throw ApiError.paymentRequired(
      "This feature is part of the premium plan. Upgrade your account to use it."
    );
  }
  next();
});

/**
 * Blocks an admin from the assessment features.
 *
 * An admin account is an oversight role, not a personal one: it exists to supervise a
 * team's assessments, and giving it scanning powers of its own would put the supervisor
 * inside the set of people being supervised. Someone who needs to do both keeps a
 * separate personal account, which is how admin accounts were always meant to work.
 */
export const denyAdmin = asyncHandler(async (req, res, next) => {
  if (req.user.role === ROLES.ADMIN) {
    throw ApiError.forbidden(
      "Admin accounts oversee a team's assessments rather than running their own. " +
        "Use a personal account to scan an app."
    );
  }
  next();
});

/** Gate for organisation admin features. */
export const requireAdmin = asyncHandler(async (req, res, next) => {
  if (req.user.role !== ROLES.ADMIN) {
    throw ApiError.forbidden("Only an organisation admin can do that.");
  }
  if (!req.user.organisationId) {
    throw ApiError.forbidden("Your admin account is not attached to an organisation.");
  }
  next();
});

/**
 * Confirms the admin is acting on their own organisation.
 *
 * Without this an admin could pass another organisation's id in the URL and manage
 * members who are not theirs, which is the most likely way this API could be misused.
 */
export const requireOwnOrganisation = asyncHandler(async (req, res, next) => {
  const { orgId } = req.params;
  if (orgId && orgId !== req.user.organisationId) {
    throw ApiError.forbidden("You can only manage your own organisation.");
  }
  next();
});
