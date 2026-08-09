/**
 * Subscription tier.
 *
 * Diagram coverage:
 *   Premium User -> Cancel subscription
 *
 * Payment processing is deliberately not implemented here. Taking card details needs a
 * payment provider and its own compliance work, which is outside this project's scope, so
 * the upgrade endpoint records the tier change and leaves a clear seam where a provider
 * such as Stripe would be integrated.
 */
import { Router } from "express";
import { z } from "zod";

import { env } from "../config/env.js";
import { SUBSCRIPTION_STATUS, TIERS } from "../constants/index.js";
import { loadProfile, requireAuth, requirePremium } from "../middleware/auth.js";
import { validate } from "../middleware/validate.js";
import * as audit from "../services/audit.service.js";
import * as usersService from "../services/users.service.js";
import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";

const router = Router();
router.use(requireAuth, loadProfile);

/** GET /api/subscription -- what the caller is currently on */
router.get(
  "/",
  asyncHandler(async (req, res) => {
    res.json({
      tier: req.profile.tier,
      subscription: req.profile.subscription ?? { status: SUBSCRIPTION_STATUS.NONE },
      limits: {
        historyLimit: req.profile.tier === TIERS.PREMIUM ? null : env.limits.freeHistory,
        canCompareScans: req.profile.tier === TIERS.PREMIUM,
        canExportReports: req.profile.tier === TIERS.PREMIUM,
      },
    });
  })
);

/**
 * POST /api/subscription/upgrade -- move to premium
 *
 * Stands in for a real checkout. A payment provider would call this from its webhook once
 * a payment had cleared, rather than the client calling it directly.
 */
router.post(
  "/upgrade",
  validate({ body: z.object({ paymentReference: z.string().trim().max(200).optional() }).default({}) }),
  asyncHandler(async (req, res) => {
    if (req.profile.tier === TIERS.PREMIUM) {
      throw ApiError.conflict("You are already on the premium plan.");
    }

    const updated = await usersService.setTier(req.user.uid, TIERS.PREMIUM);

    await audit.record({
      action: audit.AUDIT_ACTIONS.TIER_CHANGED,
      actorId: req.user.uid,
      subjectId: req.user.uid,
      organisationId: req.profile.organisationId,
      metadata: { from: TIERS.FREE, to: TIERS.PREMIUM, paymentReference: req.body.paymentReference ?? null },
    });

    res.json({
      user: usersService.toPublicProfile(updated),
      message: "You are on the premium plan. Sign in again to refresh your permissions.",
    });
  })
);

/**
 * POST /api/subscription/cancel -- Cancel subscription
 *
 * Cancelling drops the account to the free tier, which brings back the history limit.
 * The response says how many scans would be trimmed so the user can export first,
 * rather than losing them without warning.
 */
router.post(
  "/cancel",
  requirePremium,
  validate({
    body: z
      .object({
        confirm: z.literal("CANCEL", {
          errorMap: () => ({ message: "Send confirm: 'CANCEL' to end your subscription." }),
        }),
        reason: z.string().trim().max(500).optional(),
      }),
  }),
  asyncHandler(async (req, res) => {
    const scanCount = req.profile.scanCount ?? 0;
    const willBeTrimmed = Math.max(0, scanCount - env.limits.freeHistory);

    const updated = await usersService.setTier(req.user.uid, TIERS.FREE);

    await audit.record({
      action: audit.AUDIT_ACTIONS.TIER_CHANGED,
      actorId: req.user.uid,
      subjectId: req.user.uid,
      organisationId: req.profile.organisationId,
      metadata: { from: TIERS.PREMIUM, to: TIERS.FREE, reason: req.body.reason ?? null },
    });

    res.json({
      user: usersService.toPublicProfile(updated),
      message: "Your subscription has been cancelled and your account is now on the free plan.",
      // Existing scans are left alone until the next one is saved, which gives the user
      // a chance to export anything they want to keep.
      warning: willBeTrimmed
        ? `Your next scan will trim your history to the newest ${env.limits.freeHistory}. ` +
          `About ${willBeTrimmed} older scan${willBeTrimmed === 1 ? "" : "s"} will be removed, ` +
          `so export anything you need first.`
        : null,
    });
  })
);

export default router;
