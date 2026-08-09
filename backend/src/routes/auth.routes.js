/**
 * Registration and sign-in.
 *
 * Diagram coverage:
 *   Unregistered User  -> Register user account
 *   Admin              -> Register admin account
 *   User               -> Log in, Log out
 */
import { Router } from "express";
import rateLimit from "express-rate-limit";
import { z } from "zod";

import { env } from "../config/env.js";
import { auth } from "../config/firebase.js";
import { ROLES, TIERS } from "../constants/index.js";
import { requireAuth } from "../middleware/auth.js";
import { validate } from "../middleware/validate.js";
import * as firebaseAuth from "../services/firebaseAuth.service.js";
import * as organisations from "../services/organisations.service.js";
import * as usersService from "../services/users.service.js";
import { asyncHandler } from "../utils/asyncHandler.js";

const router = Router();

/**
 * Sign-in and registration are the two endpoints worth guessing at, so they get a
 * tighter limit than the rest of the API. Without this, an attacker could try passwords
 * as fast as the network allows.
 */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: env.rateLimits.authPer15Min,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: { status: 429, message: "Too many attempts. Try again in a few minutes." } },
});

const emailSchema = z.string().trim().toLowerCase().email("Enter a valid email address.");
const passwordSchema = z
  .string()
  .min(8, "Use at least 8 characters.")
  .max(128, "That password is too long.");

/** POST /api/auth/register -- Register user account */
router.post(
  "/register",
  authLimiter,
  validate({
    body: z.object({
      email: emailSchema,
      password: passwordSchema,
      displayName: z.string().trim().min(1).max(80).optional(),
    }),
  }),
  asyncHandler(async (req, res) => {
    const profile = await usersService.createAccount({
      email: req.body.email,
      password: req.body.password,
      displayName: req.body.displayName,
      role: ROLES.MEMBER,
      tier: TIERS.FREE,
    });

    const session = await firebaseAuth.signInWithPassword(req.body.email, req.body.password);
    res.status(201).json({ user: usersService.toPublicProfile({ id: profile.uid, ...profile }), session });
  })
);

/**
 * POST /api/auth/register-admin -- Register admin account
 *
 * An admin account only means anything alongside an organisation to administer, so this
 * creates both together and makes the new account its owner.
 */
router.post(
  "/register-admin",
  authLimiter,
  validate({
    body: z.object({
      email: emailSchema,
      password: passwordSchema,
      displayName: z.string().trim().min(1).max(80).optional(),
      organisationName: z.string().trim().min(2, "Give your organisation a name.").max(120),
    }),
  }),
  asyncHandler(async (req, res) => {
    const profile = await usersService.createAccount({
      email: req.body.email,
      password: req.body.password,
      displayName: req.body.displayName,
      role: ROLES.ADMIN,
      tier: TIERS.FREE,
    });

    const organisation = await organisations.createOrganisation({
      name: req.body.organisationName,
      ownerId: profile.uid,
    });

    // The organisation id only exists once the organisation has been created, so the
    // account is attached to it here rather than at creation time.
    await usersService.setOrganisation(profile.uid, {
      organisationId: organisation.id,
      role: ROLES.ADMIN,
    });

    const session = await firebaseAuth.signInWithPassword(req.body.email, req.body.password);
    const finalProfile = await usersService.getProfile(profile.uid);

    res.status(201).json({
      user: usersService.toPublicProfile(finalProfile),
      organisation,
      session,
    });
  })
);

/** POST /api/auth/login -- Log in */
router.post(
  "/login",
  authLimiter,
  validate({ body: z.object({ email: emailSchema, password: z.string().min(1) }) }),
  asyncHandler(async (req, res) => {
    const session = await firebaseAuth.signInWithPassword(req.body.email, req.body.password);
    const profile = await usersService.getProfile(session.uid);

    if (profile.disabled) {
      // Checked after the password so a suspended account gives nothing away to
      // someone who does not already know the password.
      return res.status(403).json({
        error: { status: 403, message: "This account has been suspended." },
      });
    }

    res.json({ user: usersService.toPublicProfile(profile), session });
  })
);

/** POST /api/auth/refresh -- keep a signed-in session alive */
router.post(
  "/refresh",
  validate({ body: z.object({ refreshToken: z.string().min(1) }) }),
  asyncHandler(async (req, res) => {
    const session = await firebaseAuth.refreshIdToken(req.body.refreshToken);
    res.json({ session });
  })
);

/**
 * POST /api/auth/logout -- Log out
 *
 * Revoking the refresh tokens is what makes this more than a client-side action: the
 * current ID token stops being accepted immediately, because requireAuth checks for
 * revocation on every call.
 */
router.post(
  "/logout",
  requireAuth,
  asyncHandler(async (req, res) => {
    await auth.revokeRefreshTokens(req.user.uid);
    res.json({ message: "Signed out." });
  })
);

export default router;
