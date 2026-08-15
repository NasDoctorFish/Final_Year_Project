/**
 * Append-only record of actions that affect someone other than the person doing them.
 *
 * Admin powers in this system include reading a member's scan data and deleting their
 * account, so those actions need to leave a trace. Nothing in the API updates or
 * deletes an audit entry, and the Firestore rules deny writes from clients entirely.
 */
import { db, FieldValue } from "../config/firebase.js";
import { COLLECTIONS } from "../constants/index.js";

export const AUDIT_ACTIONS = {
  MEMBER_INVITED: "member.invited",
  INVITATION_CANCELLED: "member.invitation_cancelled",
  MEMBER_JOINED: "member.joined",
  MEMBER_REMOVED: "member.removed",
  MEMBER_DATA_VIEWED: "member.data_viewed",
  MEMBER_DATA_FLAGGED: "member.data_flagged",
  FLAG_REVIEWED: "flag.reviewed",
  MEMBER_ACCOUNT_DELETED: "member.account_deleted",
  MEMBER_SUSPENDED: "member.suspended",
  MEMBER_REINSTATED: "member.reinstated",
  ADMIN_ADDED: "admin.added",
  TIER_CHANGED: "subscription.tier_changed",
};

/**
 * @param {object} entry
 * @param {string} entry.action - one of AUDIT_ACTIONS
 * @param {string} entry.actorId - who performed it
 * @param {string} [entry.subjectId] - who or what it was performed on
 * @param {string} [entry.organisationId]
 * @param {object} [entry.metadata] - anything else worth keeping, minus secrets
 */
export async function record({ action, actorId, subjectId, organisationId, metadata }) {
  await db.collection(COLLECTIONS.AUDIT).add({
    action,
    actorId,
    subjectId: subjectId ?? null,
    organisationId: organisationId ?? null,
    metadata: metadata ?? {},
    at: FieldValue.serverTimestamp(),
  });
}

/** Read an organisation's audit trail, newest first. Admin only. */
export async function listForOrganisation(organisationId, { limit = 100, action } = {}) {
  let query = db
    .collection(COLLECTIONS.AUDIT)
    .where("organisationId", "==", organisationId)
    .orderBy("at", "desc")
    .limit(limit);

  if (action) query = query.where("action", "==", action);

  const snap = await query.get();
  return snap.docs.map((doc) => ({ id: doc.id, ...doc.data() }));
}
