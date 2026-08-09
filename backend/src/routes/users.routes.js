/**
 * The signed-in user's own account.
 *
 * Diagram coverage (User):
 *   View profile, Update account details, Change email address,
 *   Change password, Delete account
 */
import { Router } from "express";
import { z } from "zod";

import { loadProfile, requireAuth } from "../middleware/auth.js";
import { validate } from "../middleware/validate.js";
import * as firebaseAuth from "../services/firebaseAuth.service.js";
import * as organisations from "../services/organisations.service.js";
import * as usersService from "../services/users.service.js";
import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";

const router = Router();

router.use(requireAuth, loadProfile);

/** GET /api/users/me -- View profile */
router.get(
  "/me",
  asyncHandler(async (req, res) => {
    res.json({ user: usersService.toPublicProfile(req.profile) });
  })
);

/** PATCH /api/users/me -- Update account details */
router.patch(
  "/me",
  validate({
    body: z.object({
      displayName: z.string().trim().min(1, "Enter a name.").max(80),
    }),
  }),
  asyncHandler(async (req, res) => {
    const updated = await usersService.updateProfile(req.user.uid, req.body);
    res.json({ user: usersService.toPublicProfile(updated) });
  })
);

/**
 * POST /api/users/me/email -- Change email address
 *
 * The current password is required. Changing the address on an account is enough to take
 * it over through a password reset, so a stolen session token alone must not be able to
 * do it.
 */
router.post(
  "/me/email",
  validate({
    body: z.object({
      newEmail: z.string().trim().toLowerCase().email("Enter a valid email address."),
      currentPassword: z.string().min(1, "Enter your current password."),
    }),
  }),
  asyncHandler(async (req, res) => {
    if (!req.profile.email) {
      throw ApiError.badRequest("This account has no email address on record.");
    }
    if (req.body.newEmail === req.profile.email) {
      throw ApiError.badRequest("That is already your email address.");
    }

    await firebaseAuth.verifyPassword(req.profile.email, req.body.currentPassword);
    const updated = await usersService.changeEmail(req.user.uid, req.body.newEmail);

    res.json({
      user: usersService.toPublicProfile(updated),
      message: "Email address updated. Verify the new address when prompted.",
    });
  })
);

/**
 * POST /api/users/me/password -- Change password
 *
 * Succeeding here signs the account out everywhere, including on this device, so the
 * app has to sign in again with the new password.
 */
router.post(
  "/me/password",
  validate({
    body: z.object({
      currentPassword: z.string().min(1, "Enter your current password."),
      newPassword: z.string().min(8, "Use at least 8 characters.").max(128),
    }),
  }),
  asyncHandler(async (req, res) => {
    if (req.body.currentPassword === req.body.newPassword) {
      throw ApiError.badRequest("Your new password must be different from the current one.");
    }
    if (!req.profile.email) {
      throw ApiError.badRequest("This account has no email address on record.");
    }

    await firebaseAuth.verifyPassword(req.profile.email, req.body.currentPassword);
    await usersService.changePassword(req.user.uid, req.body.newPassword);

    res.json({
      message: "Password changed. All sessions have been signed out, so sign in again.",
      sessionsRevoked: true,
    });
  })
);

/**
 * DELETE /api/users/me -- Delete account
 *
 * Removes the account, its profile, and its whole scan history. The password is required
 * because this cannot be undone.
 */
router.delete(
  "/me",
  validate({
    body: z.object({
      currentPassword: z.string().min(1, "Enter your current password to confirm."),
      confirm: z.literal("DELETE", {
        errorMap: () => ({ message: "Send confirm: 'DELETE' to proceed." }),
      }),
    }),
  }),
  asyncHandler(async (req, res) => {
    if (!req.profile.email) {
      throw ApiError.badRequest("This account has no email address on record.");
    }

    // The owner of an organisation cannot vanish and leave it unmanaged.
    if (req.profile.organisationId) {
      const org = await organisations.getOrganisation(req.profile.organisationId);
      if (org.ownerId === req.user.uid && org.memberIds.length > 1) {
        throw ApiError.conflict(
          "You own an organisation with other members. Transfer ownership or remove the " +
            "members before deleting your account."
        );
      }
    }

    await firebaseAuth.verifyPassword(req.profile.email, req.body.currentPassword);
    await usersService.deleteAccount(req.user.uid);

    res.json({ message: "Your account and all of its scan history have been deleted." });
  })
);

export default router;
