/**
 * Account records and the custom claims that go with them.
 *
 * Tier and role are written twice on purpose: into the Firestore user document, which
 * is the source of truth, and into the Firebase token as custom claims, which lets the
 * auth middleware check permissions without a database read on every request. Any
 * change to either has to update both, which is what setClaims exists for.
 */
import { auth, db, FieldValue } from "../config/firebase.js";
import { COLLECTIONS, ROLES, SUBSCRIPTION_STATUS, TIERS } from "../constants/index.js";
import { ApiError } from "../utils/ApiError.js";

const users = () => db.collection(COLLECTIONS.USERS);

/** Copy tier, role and organisation onto the user's token. */
export async function setClaims(uid, { tier, role, organisationId }) {
  await auth.setCustomUserClaims(uid, { tier, role, organisationId: organisationId ?? null });
  // Force the next request to present a token carrying the new claims.
  await auth.revokeRefreshTokens(uid);
}

export async function getProfile(uid) {
  const snap = await users().doc(uid).get();
  if (!snap.exists) throw ApiError.notFound("Account not found.");
  return { id: snap.id, ...snap.data() };
}

/**
 * Create a Firebase Auth user plus their Firestore profile.
 *
 * If writing the profile fails we delete the auth user again, so a half-created
 * account cannot exist in a state where the person can sign in but has no record.
 */
export async function createAccount({
  email,
  password,
  displayName,
  role = ROLES.MEMBER,
  organisationId = null,
  tier = TIERS.FREE,
}) {
  let userRecord;
  try {
    userRecord = await auth.createUser({ email, password, displayName });
  } catch (error) {
    if (error.code === "auth/email-already-exists") {
      throw ApiError.conflict("An account already exists for that email address.");
    }
    if (error.code === "auth/invalid-password") {
      throw ApiError.badRequest("That password is too short. Use at least six characters.");
    }
    throw error;
  }

  const profile = {
    email,
    displayName: displayName || null,
    tier,
    role,
    organisationId,
    disabled: false,
    subscription: {
      status: tier === TIERS.PREMIUM ? SUBSCRIPTION_STATUS.ACTIVE : SUBSCRIPTION_STATUS.NONE,
      startedAt: tier === TIERS.PREMIUM ? FieldValue.serverTimestamp() : null,
      cancelledAt: null,
    },
    scanCount: 0,
    createdAt: FieldValue.serverTimestamp(),
    updatedAt: FieldValue.serverTimestamp(),
  };

  try {
    await users().doc(userRecord.uid).set(profile);
    await setClaims(userRecord.uid, { tier, role, organisationId });
  } catch (error) {
    await auth.deleteUser(userRecord.uid).catch(() => {});
    throw error;
  }

  return { uid: userRecord.uid, ...profile };
}

export async function updateProfile(uid, patch) {
  const allowed = {};
  if (patch.displayName !== undefined) allowed.displayName = patch.displayName;
  if (Object.keys(allowed).length === 0) {
    throw ApiError.badRequest("Nothing to update.");
  }
  allowed.updatedAt = FieldValue.serverTimestamp();

  await users().doc(uid).update(allowed);
  if (allowed.displayName !== undefined) {
    await auth.updateUser(uid, { displayName: allowed.displayName });
  }
  return getProfile(uid);
}

export async function changeEmail(uid, newEmail) {
  try {
    await auth.updateUser(uid, { email: newEmail, emailVerified: false });
  } catch (error) {
    if (error.code === "auth/email-already-exists") {
      throw ApiError.conflict("An account already exists for that email address.");
    }
    throw error;
  }
  await users().doc(uid).update({ email: newEmail, updatedAt: FieldValue.serverTimestamp() });
  return getProfile(uid);
}

export async function changePassword(uid, newPassword) {
  try {
    await auth.updateUser(uid, { password: newPassword });
  } catch (error) {
    if (error.code === "auth/invalid-password") {
      throw ApiError.badRequest("That password is too short. Use at least six characters.");
    }
    throw error;
  }
  // Sign the account out everywhere. If the password was changed because it may have
  // leaked, leaving other sessions alive would defeat the point.
  await auth.revokeRefreshTokens(uid);
}

/**
 * Attach an account to an organisation, or detach it by passing null.
 *
 * Kept separate from createAccount because an organisation's id does not exist until
 * after it has been created, so the owner's own account has to be updated afterwards.
 */
export async function setOrganisation(uid, { organisationId, role }) {
  const profile = await getProfile(uid);
  const nextRole = role ?? profile.role;

  await users().doc(uid).update({
    organisationId: organisationId ?? null,
    role: nextRole,
    updatedAt: FieldValue.serverTimestamp(),
  });
  await setClaims(uid, { tier: profile.tier, role: nextRole, organisationId });
  return getProfile(uid);
}

export async function setTier(uid, tier) {
  const profile = await getProfile(uid);
  const subscription =
    tier === TIERS.PREMIUM
      ? {
          status: SUBSCRIPTION_STATUS.ACTIVE,
          startedAt: FieldValue.serverTimestamp(),
          cancelledAt: null,
        }
      : {
          status: SUBSCRIPTION_STATUS.CANCELLED,
          startedAt: profile.subscription?.startedAt ?? null,
          cancelledAt: FieldValue.serverTimestamp(),
        };

  await users().doc(uid).update({ tier, subscription, updatedAt: FieldValue.serverTimestamp() });
  await setClaims(uid, { tier, role: profile.role, organisationId: profile.organisationId });
  return getProfile(uid);
}

export async function setDisabled(uid, disabled) {
  await auth.updateUser(uid, { disabled });
  await users().doc(uid).update({ disabled, updatedAt: FieldValue.serverTimestamp() });
  if (disabled) await auth.revokeRefreshTokens(uid);
}

/**
 * Delete an account and everything belonging to it.
 *
 * Scans are removed in batches because a heavy user could have more documents than a
 * single batched write allows.
 */
export async function deleteAccount(uid) {
  const scans = db.collection(COLLECTIONS.SCANS).where("userId", "==", uid);

  // eslint-disable-next-line no-constant-condition
  while (true) {
    const snap = await scans.limit(400).get();
    if (snap.empty) break;
    const batch = db.batch();
    snap.docs.forEach((doc) => batch.delete(doc.ref));
    await batch.commit();
    if (snap.size < 400) break;
  }

  await users().doc(uid).delete();
  await auth.deleteUser(uid).catch((error) => {
    // A missing auth user is fine here: the record is gone either way.
    if (error.code !== "auth/user-not-found") throw error;
  });
}

export function toPublicProfile(profile) {
  return {
    id: profile.id,
    email: profile.email,
    displayName: profile.displayName,
    tier: profile.tier,
    role: profile.role,
    organisationId: profile.organisationId,
    subscription: profile.subscription,
    scanCount: profile.scanCount ?? 0,
    createdAt: profile.createdAt ?? null,
  };
}
