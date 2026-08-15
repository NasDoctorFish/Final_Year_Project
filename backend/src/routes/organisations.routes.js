/**
 * Organisations, membership, and the admin functions that go with them.
 *
 * Diagram coverage:
 *   Unregistered User -> Join organisation via invite
 *   User              -> Join organisation
 *   Admin             -> Invite team member, Cancel pending invitation,
 *                        View member data, Flag member data, Review flagged items,
 *                        Remove organisation member, Delete member account,
 *                        Add additional admin
 *
 * Every admin action that touches another person is written to the audit log, because
 * these are the only powers in the system that reach beyond the caller's own data.
 */
import { Router } from "express";
import { z } from "zod";

import {
  FLAG_STATUS,
  INVITATION_STATUS,
  INVITATION_TTL_DAYS,
  ROLES,
} from "../constants/index.js";
import {
  loadProfile,
  requireAdmin,
  requireAuth,
  requireOwnOrganisation,
} from "../middleware/auth.js";
import { validate } from "../middleware/validate.js";
import * as audit from "../services/audit.service.js";
import * as email from "../services/email.service.js";
import * as organisations from "../services/organisations.service.js";
import * as scansService from "../services/scans.service.js";
import * as usersService from "../services/users.service.js";
import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";

const router = Router();

// --- Joining, available to any signed-in user -------------------------------

/**
 * POST /api/organisations/join -- Join organisation / Join organisation via invite
 *
 * An unregistered person registers first and then calls this with the token from their
 * invitation link, so both diagram boxes are served by one endpoint.
 */
router.post(
  "/join",
  requireAuth,
  loadProfile,
  validate({ body: z.object({ token: z.string().trim().min(16, "That invitation link is not valid.") }) }),
  asyncHandler(async (req, res) => {
    const result = await organisations.acceptInvitation({
      token: req.body.token,
      uid: req.user.uid,
    });

    await audit.record({
      action: audit.AUDIT_ACTIONS.MEMBER_JOINED,
      actorId: req.user.uid,
      subjectId: req.user.uid,
      organisationId: result.organisationId,
      metadata: { role: result.role },
    });

    res.json({
      organisation: { id: result.organisationId, name: result.organisationName },
      role: result.role,
      message:
        "You have joined the organisation. Sign in again to refresh your permissions.",
    });
  })
);

/** GET /api/organisations/mine -- the caller's own organisation, if any */
router.get(
  "/mine",
  requireAuth,
  loadProfile,
  asyncHandler(async (req, res) => {
    if (!req.profile.organisationId) {
      return res.json({ organisation: null });
    }
    const organisation = await organisations.getOrganisation(req.profile.organisationId);
    res.json({
      organisation: {
        id: organisation.id,
        name: organisation.name,
        memberCount: organisation.memberIds.length,
        isOwner: organisation.ownerId === req.user.uid,
        yourRole: req.profile.role,
      },
    });
  })
);

// --- Admin only ------------------------------------------------------------

const adminOnly = [requireAuth, loadProfile, requireAdmin, requireOwnOrganisation];

/** GET /api/organisations/:orgId/members -- View member data (the list) */
router.get(
  "/:orgId/members",
  adminOnly,
  validate({ params: z.object({ orgId: z.string().min(1) }) }),
  asyncHandler(async (req, res) => {
    const members = await organisations.listMembers(req.params.orgId);
    res.json({ members });
  })
);

/**
 * GET /api/organisations/:orgId/members/:uid/scans -- View member data (their scans)
 *
 * This is a privacy-sensitive read, so it is recorded. Findings are deliberately not
 * included: an admin can see that a member ran a scan and how many problems it found,
 * which is what oversight needs, without reading the evidence taken from the member's
 * own app.
 */
router.get(
  "/:orgId/members/:uid/scans",
  adminOnly,
  validate({
    params: z.object({ orgId: z.string().min(1), uid: z.string().min(1) }),
    query: z.object({ limit: z.coerce.number().int().min(1).max(100).default(50) }),
  }),
  asyncHandler(async (req, res) => {
    const org = await organisations.getOrganisation(req.params.orgId);
    if (!org.memberIds.includes(req.params.uid)) {
      throw ApiError.notFound("That person is not a member of your organisation.");
    }

    const scans = await scansService.listScans(req.params.uid, { limit: req.query.limit });

    await audit.record({
      action: audit.AUDIT_ACTIONS.MEMBER_DATA_VIEWED,
      actorId: req.user.uid,
      subjectId: req.params.uid,
      organisationId: req.params.orgId,
      metadata: { scanCount: scans.length },
    });

    res.json({ scans, note: "Finding details are not included in an admin view." });
  })
);

/** POST /api/organisations/:orgId/invitations -- Invite team member */
router.post(
  "/:orgId/invitations",
  adminOnly,
  validate({
    params: z.object({ orgId: z.string().min(1) }),
    body: z.object({
      email: z.string().trim().toLowerCase().email("Enter a valid email address."),
      role: z.enum([ROLES.MEMBER, ROLES.ADMIN]).default(ROLES.MEMBER),
    }),
  }),
  asyncHandler(async (req, res) => {
    const invitation = await organisations.inviteMember({
      orgId: req.params.orgId,
      email: req.body.email,
      role: req.body.role,
      invitedBy: req.user.uid,
    });

    await audit.record({
      action: audit.AUDIT_ACTIONS.MEMBER_INVITED,
      actorId: req.user.uid,
      organisationId: req.params.orgId,
      metadata: { email: req.body.email, role: req.body.role },
    });

    // Emailed as a convenience, not as the delivery mechanism: the token is returned
    // below regardless, so an admin can always pass it on by hand if mail is not
    // configured or does not arrive.
    const org = await organisations.getOrganisation(req.params.orgId);
    const emailed = await email.sendInvitation({
      to: invitation.email,
      organisationName: org?.name ?? "your organisation",
      token: invitation.token,
      role: invitation.role,
      expiresInDays: INVITATION_TTL_DAYS,
    });

    res.status(201).json({
      invitation: {
        id: invitation.id,
        email: invitation.email,
        role: invitation.role,
        expiresAt: invitation.expiresAt,
      },
      // The token is shown once. Only its hash is stored, so it cannot be shown again.
      token: invitation.token,
      emailed,
      note: emailed
        ? "The token has been emailed to them. It is not retrievable later, so keep a copy until they have joined."
        : "Send this token to the invitee. It is not retrievable later.",
    });
  })
);

/** GET /api/organisations/:orgId/invitations -- see pending invitations */
router.get(
  "/:orgId/invitations",
  adminOnly,
  validate({
    params: z.object({ orgId: z.string().min(1) }),
    query: z.object({
      status: z.enum([...Object.values(INVITATION_STATUS), "all"]).default(INVITATION_STATUS.PENDING),
    }),
  }),
  asyncHandler(async (req, res) => {
    const status = req.query.status === "all" ? undefined : req.query.status;
    res.json({ invitations: await organisations.listInvitations(req.params.orgId, { status }) });
  })
);

/** DELETE /api/organisations/:orgId/invitations/:invitationId -- Cancel pending invitation */
router.delete(
  "/:orgId/invitations/:invitationId",
  adminOnly,
  validate({
    params: z.object({ orgId: z.string().min(1), invitationId: z.string().min(1) }),
  }),
  asyncHandler(async (req, res) => {
    const cancelled = await organisations.cancelInvitation({
      orgId: req.params.orgId,
      invitationId: req.params.invitationId,
    });

    await audit.record({
      action: audit.AUDIT_ACTIONS.INVITATION_CANCELLED,
      actorId: req.user.uid,
      organisationId: req.params.orgId,
      metadata: { email: cancelled.email },
    });

    res.json({ message: `Invitation for ${cancelled.email} cancelled.` });
  })
);

/** POST /api/organisations/:orgId/scans/:scanId/flag -- Flag member data */
router.post(
  "/:orgId/scans/:scanId/flag",
  adminOnly,
  validate({
    params: z.object({ orgId: z.string().min(1), scanId: z.string().min(1) }),
    body: z.object({
      reason: z.string().trim().min(5, "Give a reason of at least 5 characters.").max(1000),
    }),
  }),
  asyncHandler(async (req, res) => {
    const flag = await organisations.flagScan({
      orgId: req.params.orgId,
      scanId: req.params.scanId,
      reason: req.body.reason,
      flaggedBy: req.user.uid,
    });

    await audit.record({
      action: audit.AUDIT_ACTIONS.MEMBER_DATA_FLAGGED,
      actorId: req.user.uid,
      subjectId: flag.subjectId,
      organisationId: req.params.orgId,
      metadata: { scanId: req.params.scanId, reason: req.body.reason },
    });

    res.status(201).json({ flag: { id: flag.id, status: flag.status, scanId: flag.scanId } });
  })
);

/** GET /api/organisations/:orgId/flags -- Review flagged items (the list) */
router.get(
  "/:orgId/flags",
  adminOnly,
  validate({
    params: z.object({ orgId: z.string().min(1) }),
    query: z.object({
      status: z.enum([...Object.values(FLAG_STATUS), "all"]).default(FLAG_STATUS.OPEN),
    }),
  }),
  asyncHandler(async (req, res) => {
    res.json({ flags: await organisations.listFlags(req.params.orgId, { status: req.query.status }) });
  })
);

/** POST /api/organisations/:orgId/flags/:flagId/review -- Review flagged items (decide) */
router.post(
  "/:orgId/flags/:flagId/review",
  adminOnly,
  validate({
    params: z.object({ orgId: z.string().min(1), flagId: z.string().min(1) }),
    body: z.object({
      decision: z.enum(["uphold", "dismiss"]),
      note: z.string().trim().max(1000).optional(),
    }),
  }),
  asyncHandler(async (req, res) => {
    const result = await organisations.reviewFlag({
      orgId: req.params.orgId,
      flagId: req.params.flagId,
      decision: req.body.decision,
      note: req.body.note,
      reviewedBy: req.user.uid,
    });

    await audit.record({
      action: audit.AUDIT_ACTIONS.FLAG_REVIEWED,
      actorId: req.user.uid,
      subjectId: result.subjectId,
      organisationId: req.params.orgId,
      metadata: { flagId: result.id, decision: req.body.decision, note: req.body.note ?? null },
    });

    res.json({ flag: { id: result.id, status: result.status } });
  })
);

/** POST /api/organisations/:orgId/admins -- Add additional admin */
router.post(
  "/:orgId/admins",
  adminOnly,
  validate({
    params: z.object({ orgId: z.string().min(1) }),
    body: z.object({ uid: z.string().min(1, "Provide the member's user id.") }),
  }),
  asyncHandler(async (req, res) => {
    await organisations.addAdmin({ orgId: req.params.orgId, uid: req.body.uid });

    await audit.record({
      action: audit.AUDIT_ACTIONS.ADMIN_ADDED,
      actorId: req.user.uid,
      subjectId: req.body.uid,
      organisationId: req.params.orgId,
    });

    res.json({
      message: "That member is now an admin. They will need to sign in again for it to take effect.",
    });
  })
);

/**
 * POST /api/organisations/:orgId/members/:uid/suspension -- Suspend or reinstate a member
 *
 * The reversible middle ground between removing someone from the organisation and
 * deleting their account: a suspended member keeps everything but cannot sign in. Meant
 * for an account under investigation, where deleting the evidence would be the wrong
 * move and doing nothing leaves it usable.
 */
router.post(
  "/:orgId/members/:uid/suspension",
  adminOnly,
  validate({
    params: z.object({ orgId: z.string().min(1), uid: z.string().min(1) }),
    body: z.object({
      suspended: z.boolean(),
      reason: z.string().trim().max(1000).optional(),
    }),
  }),
  asyncHandler(async (req, res) => {
    if (req.params.uid === req.user.uid) {
      throw ApiError.badRequest("You cannot suspend your own account.");
    }

    const org = await organisations.getOrganisation(req.params.orgId);
    if (!org.memberIds.includes(req.params.uid)) {
      throw ApiError.notFound("That person is not a member of your organisation.");
    }
    if (org.ownerId === req.params.uid) {
      throw ApiError.forbidden("The organisation owner's account cannot be suspended.");
    }

    const target = await usersService.getProfile(req.params.uid);
    await usersService.setDisabled(req.params.uid, req.body.suspended);

    await audit.record({
      action: req.body.suspended
        ? audit.AUDIT_ACTIONS.MEMBER_SUSPENDED
        : audit.AUDIT_ACTIONS.MEMBER_REINSTATED,
      actorId: req.user.uid,
      subjectId: req.params.uid,
      organisationId: req.params.orgId,
      metadata: { email: target.email, reason: req.body.reason ?? null },
    });

    if (target.email) {
      await email.sendAccountSuspended({
        to: target.email,
        organisationName: org.name ?? "your organisation",
        suspended: req.body.suspended,
      });
    }

    res.json({
      message: req.body.suspended
        ? "That account is suspended. They have been signed out and cannot sign in until it is lifted."
        : "That account has been reinstated and can sign in again.",
      suspended: req.body.suspended,
    });
  })
);

/** DELETE /api/organisations/:orgId/members/:uid -- Remove organisation member */
router.delete(
  "/:orgId/members/:uid",
  adminOnly,
  validate({ params: z.object({ orgId: z.string().min(1), uid: z.string().min(1) }) }),
  asyncHandler(async (req, res) => {
    // Read before removal, while the membership that authorises reading it still exists.
    const [target, org] = await Promise.all([
      usersService.getProfile(req.params.uid).catch(() => null),
      organisations.getOrganisation(req.params.orgId).catch(() => null),
    ]);

    await organisations.removeMember({
      orgId: req.params.orgId,
      uid: req.params.uid,
      actorId: req.user.uid,
    });

    await audit.record({
      action: audit.AUDIT_ACTIONS.MEMBER_REMOVED,
      actorId: req.user.uid,
      subjectId: req.params.uid,
      organisationId: req.params.orgId,
    });

    if (target?.email) {
      await email.sendRemovedFromOrganisation({
        to: target.email,
        organisationName: org?.name ?? "your organisation",
      });
    }

    res.json({
      message: "Member removed from the organisation. Their account and scan history are intact.",
    });
  })
);

/**
 * DELETE /api/organisations/:orgId/members/:uid/account -- Delete member account
 *
 * The strongest power an admin has, so it is separated from removal, needs an explicit
 * confirmation string, and is recorded.
 */
router.delete(
  "/:orgId/members/:uid/account",
  adminOnly,
  validate({
    params: z.object({ orgId: z.string().min(1), uid: z.string().min(1) }),
    body: z.object({
      confirm: z.literal("DELETE_ACCOUNT", {
        errorMap: () => ({ message: "Send confirm: 'DELETE_ACCOUNT' to proceed." }),
      }),
      reason: z.string().trim().min(5, "Record why this account is being deleted.").max(1000),
    }),
  }),
  asyncHandler(async (req, res) => {
    if (req.params.uid === req.user.uid) {
      throw ApiError.badRequest("Use the account settings page to delete your own account.");
    }

    const org = await organisations.getOrganisation(req.params.orgId);
    if (!org.memberIds.includes(req.params.uid)) {
      throw ApiError.notFound("That person is not a member of your organisation.");
    }
    if (org.ownerId === req.params.uid) {
      throw ApiError.forbidden("The organisation owner's account cannot be deleted this way.");
    }

    const target = await usersService.getProfile(req.params.uid);

    // Recorded before the deletion, since afterwards there is nothing left to describe.
    await audit.record({
      action: audit.AUDIT_ACTIONS.MEMBER_ACCOUNT_DELETED,
      actorId: req.user.uid,
      subjectId: req.params.uid,
      organisationId: req.params.orgId,
      metadata: { email: target.email, reason: req.body.reason },
    });

    await organisations
      .removeMember({ orgId: req.params.orgId, uid: req.params.uid, actorId: req.user.uid })
      .catch(() => {});
    await usersService.deleteAccount(req.params.uid);

    // Sent after the fact, to the address captured above: the profile it came from no
    // longer exists to read it from.
    if (target.email) {
      await email.sendAccountDeletedByAdmin({
        to: target.email,
        organisationName: org?.name ?? "your organisation",
      });
    }

    res.json({ message: "That account and all of its scan history have been deleted." });
  })
);

/** GET /api/organisations/:orgId/audit -- the record of admin actions */
router.get(
  "/:orgId/audit",
  adminOnly,
  validate({
    params: z.object({ orgId: z.string().min(1) }),
    query: z.object({
      limit: z.coerce.number().int().min(1).max(200).default(100),
      action: z.string().trim().max(60).optional(),
    }),
  }),
  asyncHandler(async (req, res) => {
    const entries = await audit.listForOrganisation(req.params.orgId, req.query);
    res.json({ entries });
  })
);

export default router;
