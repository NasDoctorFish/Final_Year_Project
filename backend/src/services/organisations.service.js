/**
 * Organisations, invitations, and the flag and review workflow.
 *
 * An organisation groups members under one or more admins. Membership is stored on both
 * sides, as an array on the organisation and a field on the user, because each direction
 * answers a different question: who is in this organisation, and which organisation does
 * this person belong to. Both are updated in the same transaction so they cannot drift.
 */
import crypto from "node:crypto";

import { db, FieldValue } from "../config/firebase.js";
import {
  COLLECTIONS,
  FLAG_STATUS,
  INVITATION_STATUS,
  INVITATION_TTL_DAYS,
  ROLES,
} from "../constants/index.js";
import { ApiError } from "../utils/ApiError.js";
import { setClaims } from "./users.service.js";

const orgs = () => db.collection(COLLECTIONS.ORGANISATIONS);
const invitations = () => db.collection(COLLECTIONS.INVITATIONS);
const flags = () => db.collection(COLLECTIONS.FLAGS);
const users = () => db.collection(COLLECTIONS.USERS);

export async function createOrganisation({ name, ownerId }) {
  const doc = {
    name,
    ownerId,
    adminIds: [ownerId],
    memberIds: [ownerId],
    createdAt: FieldValue.serverTimestamp(),
  };
  const ref = await orgs().add(doc);
  return { id: ref.id, ...doc };
}

export async function getOrganisation(orgId) {
  const snap = await orgs().doc(orgId).get();
  if (!snap.exists) throw ApiError.notFound("That organisation does not exist.");
  return { id: snap.id, ...snap.data() };
}

export async function listMembers(orgId) {
  const org = await getOrganisation(orgId);
  if (org.memberIds.length === 0) return [];

  // Firestore limits an 'in' query to 30 values, so read in chunks.
  const chunks = [];
  for (let i = 0; i < org.memberIds.length; i += 30) {
    chunks.push(org.memberIds.slice(i, i + 30));
  }

  const results = [];
  for (const chunk of chunks) {
    const snap = await users().where("__name__", "in", chunk).get();
    snap.docs.forEach((doc) => {
      const data = doc.data();
      results.push({
        id: doc.id,
        email: data.email,
        displayName: data.displayName,
        tier: data.tier,
        role: data.role,
        disabled: data.disabled ?? false,
        scanCount: data.scanCount ?? 0,
        createdAt: data.createdAt ?? null,
      });
    });
  }
  return results;
}

/** Create a pending invitation and return it with its single-use token. */
export async function inviteMember({ orgId, email, role = ROLES.MEMBER, invitedBy }) {
  const existing = await invitations()
    .where("organisationId", "==", orgId)
    .where("email", "==", email)
    .where("status", "==", INVITATION_STATUS.PENDING)
    .limit(1)
    .get();

  if (!existing.empty) {
    throw ApiError.conflict("That email address already has a pending invitation.");
  }

  const expiresAt = new Date(Date.now() + INVITATION_TTL_DAYS * 24 * 60 * 60 * 1000);
  const doc = {
    organisationId: orgId,
    email,
    role,
    // Random and long enough that it cannot be guessed, and stored hashed so a leak of
    // the database does not hand out working invitations.
    tokenHash: null,
    status: INVITATION_STATUS.PENDING,
    invitedBy,
    createdAt: FieldValue.serverTimestamp(),
    expiresAt,
  };

  const token = crypto.randomBytes(32).toString("hex");
  doc.tokenHash = crypto.createHash("sha256").update(token).digest("hex");

  const ref = await invitations().add(doc);
  return { id: ref.id, ...doc, token };
}

export async function listInvitations(orgId, { status } = {}) {
  let query = invitations().where("organisationId", "==", orgId);
  if (status) query = query.where("status", "==", status);

  const snap = await query.orderBy("createdAt", "desc").limit(100).get();
  return snap.docs.map((doc) => {
    const { tokenHash, ...rest } = doc.data();
    return { id: doc.id, ...rest };
  });
}

export async function cancelInvitation({ orgId, invitationId }) {
  const ref = invitations().doc(invitationId);
  const snap = await ref.get();
  if (!snap.exists) throw ApiError.notFound("That invitation does not exist.");

  const invitation = snap.data();
  if (invitation.organisationId !== orgId) {
    throw ApiError.forbidden("That invitation belongs to another organisation.");
  }
  if (invitation.status !== INVITATION_STATUS.PENDING) {
    throw ApiError.conflict(`That invitation is already ${invitation.status}.`);
  }

  await ref.update({ status: INVITATION_STATUS.CANCELLED, cancelledAt: FieldValue.serverTimestamp() });
  return { id: invitationId, email: invitation.email };
}

/**
 * Accept an invitation and join its organisation.
 *
 * Runs as a transaction so a token cannot be redeemed twice by two requests arriving at
 * the same moment.
 */
export async function acceptInvitation({ token, uid }) {
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

  const found = await invitations().where("tokenHash", "==", tokenHash).limit(1).get();
  if (found.empty) throw ApiError.notFound("That invitation link is not valid.");

  const inviteRef = found.docs[0].ref;
  const result = await db.runTransaction(async (tx) => {
    const inviteSnap = await tx.get(inviteRef);
    const invitation = inviteSnap.data();

    if (invitation.status !== INVITATION_STATUS.PENDING) {
      throw ApiError.conflict(`That invitation has already been ${invitation.status}.`);
    }
    const expiresAt = invitation.expiresAt?.toDate?.() ?? new Date(invitation.expiresAt);
    if (expiresAt < new Date()) {
      tx.update(inviteRef, { status: INVITATION_STATUS.EXPIRED });
      throw ApiError.conflict("That invitation has expired. Ask for a new one.");
    }

    const userRef = users().doc(uid);
    const userSnap = await tx.get(userRef);
    if (!userSnap.exists) throw ApiError.notFound("Account not found.");
    if (userSnap.data().organisationId) {
      throw ApiError.conflict("You already belong to an organisation. Leave it before joining another.");
    }

    const orgRef = orgs().doc(invitation.organisationId);
    const orgSnap = await tx.get(orgRef);
    if (!orgSnap.exists) throw ApiError.notFound("That organisation no longer exists.");

    tx.update(orgRef, {
      memberIds: FieldValue.arrayUnion(uid),
      ...(invitation.role === ROLES.ADMIN ? { adminIds: FieldValue.arrayUnion(uid) } : {}),
    });
    tx.update(userRef, {
      organisationId: invitation.organisationId,
      role: invitation.role,
      updatedAt: FieldValue.serverTimestamp(),
    });
    tx.update(inviteRef, {
      status: INVITATION_STATUS.ACCEPTED,
      acceptedBy: uid,
      acceptedAt: FieldValue.serverTimestamp(),
    });

    return {
      organisationId: invitation.organisationId,
      organisationName: orgSnap.data().name,
      role: invitation.role,
      tier: userSnap.data().tier,
    };
  });

  await setClaims(uid, {
    tier: result.tier,
    role: result.role,
    organisationId: result.organisationId,
  });
  return result;
}

/** Remove a member from an organisation. Their account and scans are untouched. */
export async function removeMember({ orgId, uid, actorId }) {
  if (uid === actorId) {
    throw ApiError.badRequest("You cannot remove yourself. Ask another admin to do it.");
  }

  const org = await getOrganisation(orgId);
  if (!org.memberIds.includes(uid)) {
    throw ApiError.notFound("That person is not a member of your organisation.");
  }
  if (org.ownerId === uid) {
    throw ApiError.forbidden("The organisation owner cannot be removed.");
  }

  const userSnap = await users().doc(uid).get();
  const tier = userSnap.exists ? userSnap.data().tier : "free";

  await db.runTransaction(async (tx) => {
    tx.update(orgs().doc(orgId), {
      memberIds: FieldValue.arrayRemove(uid),
      adminIds: FieldValue.arrayRemove(uid),
    });
    tx.update(users().doc(uid), {
      organisationId: null,
      role: ROLES.MEMBER,
      updatedAt: FieldValue.serverTimestamp(),
    });
  });

  await setClaims(uid, { tier, role: ROLES.MEMBER, organisationId: null });
}

/** Promote an existing member to admin. */
export async function addAdmin({ orgId, uid }) {
  const org = await getOrganisation(orgId);
  if (!org.memberIds.includes(uid)) {
    throw ApiError.badRequest("That person must join your organisation before becoming an admin.");
  }
  if (org.adminIds.includes(uid)) {
    throw ApiError.conflict("That person is already an admin.");
  }

  const userSnap = await users().doc(uid).get();
  if (!userSnap.exists) throw ApiError.notFound("Account not found.");

  await db.runTransaction(async (tx) => {
    tx.update(orgs().doc(orgId), { adminIds: FieldValue.arrayUnion(uid) });
    tx.update(users().doc(uid), { role: ROLES.ADMIN, updatedAt: FieldValue.serverTimestamp() });
  });

  await setClaims(uid, {
    tier: userSnap.data().tier,
    role: ROLES.ADMIN,
    organisationId: orgId,
  });
}

// --- Flag and review -------------------------------------------------------
// An admin who spots something wrong in a member's scan raises a flag, and a flag is
// then reviewed and closed. Keeping the raise and the review as two steps means the
// decision is recorded rather than being an unexplained deletion.

export async function flagScan({ orgId, scanId, reason, flaggedBy }) {
  const scanRef = db.collection(COLLECTIONS.SCANS).doc(scanId);
  const scanSnap = await scanRef.get();
  if (!scanSnap.exists) throw ApiError.notFound("That scan does not exist.");

  const scan = scanSnap.data();
  if (scan.organisationId !== orgId) {
    throw ApiError.forbidden("That scan does not belong to your organisation.");
  }

  const existing = await flags()
    .where("scanId", "==", scanId)
    .where("status", "==", FLAG_STATUS.OPEN)
    .limit(1)
    .get();
  if (!existing.empty) {
    throw ApiError.conflict("That scan already has an open flag.");
  }

  const doc = {
    scanId,
    organisationId: orgId,
    subjectId: scan.userId,
    reason,
    status: FLAG_STATUS.OPEN,
    flaggedBy,
    createdAt: FieldValue.serverTimestamp(),
    reviewedBy: null,
    reviewedAt: null,
    reviewNote: null,
  };

  const ref = await flags().add(doc);
  await scanRef.update({ flagged: true });
  return { id: ref.id, ...doc };
}

export async function listFlags(orgId, { status = FLAG_STATUS.OPEN } = {}) {
  let query = flags().where("organisationId", "==", orgId);
  if (status !== "all") query = query.where("status", "==", status);

  const snap = await query.orderBy("createdAt", "desc").limit(100).get();
  return snap.docs.map((doc) => ({ id: doc.id, ...doc.data() }));
}

export async function reviewFlag({ orgId, flagId, decision, note, reviewedBy }) {
  const ref = flags().doc(flagId);
  const snap = await ref.get();
  if (!snap.exists) throw ApiError.notFound("That flag does not exist.");

  const flag = snap.data();
  if (flag.organisationId !== orgId) {
    throw ApiError.forbidden("That flag belongs to another organisation.");
  }
  if (flag.status !== FLAG_STATUS.OPEN) {
    throw ApiError.conflict(`That flag has already been ${flag.status}.`);
  }

  const status = decision === "dismiss" ? FLAG_STATUS.DISMISSED : FLAG_STATUS.REVIEWED;
  await ref.update({
    status,
    reviewNote: note ?? null,
    reviewedBy,
    reviewedAt: FieldValue.serverTimestamp(),
  });

  // Clearing the marker on the scan keeps the member's history from showing a flag that
  // has already been dealt with.
  await db.collection(COLLECTIONS.SCANS).doc(flag.scanId).update({ flagged: false });

  return { id: flagId, status, scanId: flag.scanId, subjectId: flag.subjectId };
}
