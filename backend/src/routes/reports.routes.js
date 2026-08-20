/** API Endpoint Design**/
// GET  /api/audits/:scanId/report


/**
 * Scan history, AI explanations, comparison, and report export.
 *
 * Diagram coverage:
 *   User          -> Scan APK file, Assess connected device, Delete test history
 *   Free User     -> View AI explanation, View test history
 *   Premium User  -> View AI explanation, View test history,
 *                    Compare scan results, Export scan report
 *
 * Note on where the work happens: the desktop app performs the scan on the user's own
 * machine, because the APK file and the USB-connected phone are both there. These
 * endpoints receive the result, store it, and serve it back.
 */
import { Router } from "express";
import { z } from "zod";

import { db } from "../config/firebase.js";
import { env } from "../config/env.js";
import { COLLECTIONS, SCAN_TYPES, SEVERITIES, TIERS } from "../constants/index.js";
import { denyAdmin, loadProfile, requireAuth, requirePremium } from "../middleware/auth.js";
import { validate } from "../middleware/validate.js";
import * as gemini from "../services/gemini.service.js";
import * as scansService from "../services/scans.service.js";
import * as usersService from "../services/users.service.js";
import { renderScanReportHtml } from "../services/report.service.js";
import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";

const router = Router();
router.use(requireAuth, loadProfile);

const findingSchema = z.object({
  category: z.string().trim().min(1).max(120),
  title: z.string().trim().min(1).max(300),
  severity: z.enum(SEVERITIES),
  owasp: z.array(z.string().trim().max(10)).max(10).default([]),
  evidence: z.string().max(20000),
  source: z.string().trim().max(120),
  confidence: z.enum(["confirmed", "likely"]).default("confirmed"),
  component: z.string().trim().max(300).nullish(),
  // The desktop app can attach an explanation it generated itself; otherwise these are
  // filled in later by the explain endpoint below.
  explanation: z.string().max(5000).nullish(),
  mitigation: z.string().max(5000).nullish(),
  references: z.array(z.string().max(500)).max(20).default([]),
});

/**
 * POST /api/scans -- Scan APK file / Assess connected device
 *
 * One endpoint for both, distinguished by type, because the stored record and everything
 * downstream of it are the same shape either way.
 */
router.post(
  "/",
  denyAdmin,
  validate({
    body: z.object({
      type: z.enum([SCAN_TYPES.APK, SCAN_TYPES.DEVICE]),
      target: z
        .object({
          packageName: z.string().trim().max(255).nullish(),
          apkFileName: z.string().trim().max(255).nullish(),
          deviceSerial: z.string().trim().max(120).nullish(),
        })
        .default({}),
      findings: z.array(findingSchema).max(500).default([]),
      toolVersion: z.string().trim().max(40).nullish(),
      authorisationConfirmed: z.boolean().default(false),
      startedAt: z.string().datetime().nullish(),
      finishedAt: z.string().datetime().nullish(),
    }),
  }),
  asyncHandler(async (req, res) => {
    const scan = await scansService.createScan(req.user, req.body);

    res.status(201).json({
      scan: { id: scan.id, type: scan.type, counts: scan.counts, findingCount: scan.findingCount },
      // Telling the caller when an old scan was dropped is clearer than silently
      // shortening their history.
      retention: scan.retention.removed
        ? {
            removed: scan.retention.removed,
            message:
              "Your free plan keeps the most recent scans, so the oldest one was removed. " +
              "Upgrade to keep your full history.",
          }
        : null,
    });
  })
);

/** GET /api/scans -- View test history (free and premium) */
router.get(
  "/",
  validate({
    query: z.object({
      limit: z.coerce.number().int().min(1).max(100).default(50),
      type: z.enum([SCAN_TYPES.APK, SCAN_TYPES.DEVICE]).optional(),
    }),
  }),
  asyncHandler(async (req, res) => {
    const scans = await scansService.listScans(req.user.uid, req.query);
    res.json({
      scans,
      tier: req.user.tier,
      historyLimit: req.user.tier === TIERS.PREMIUM ? null : env.limits.freeHistory,
    });
  })
);

/** GET /api/scans/:scanId -- one scan with all of its findings */
router.get(
  "/:scanId",
  validate({ params: z.object({ scanId: z.string().min(1) }) }),
  asyncHandler(async (req, res) => {
    const scan = await scansService.getScanForCaller(req.params.scanId, req.user);
    res.json({ scan });
  })
);

/**
 * POST /api/scans/:scanId/findings/:findingIndex/explain -- View AI explanation
 *
 * Available on both tiers. The finding is located by its position in the stored array,
 * since the desktop app's own finding ids are regenerated on each run and would not be
 * stable to address by.
 */
router.post(
  "/:scanId/findings/:findingIndex/explain",
  validate({
    params: z.object({
      scanId: z.string().min(1),
      findingIndex: z.coerce.number().int().min(0),
    }),
    body: z.object({ force: z.boolean().default(false) }).default({}),
  }),
  asyncHandler(async (req, res) => {
    const scan = await scansService.getScanForCaller(req.params.scanId, req.user);

    if (scan.userId !== req.user.uid) {
      // An admin may read a member's scan, but generating new AI content on someone
      // else's data is not something the diagram grants them.
      throw ApiError.forbidden("You can only generate explanations for your own scans.");
    }

    const findings = scan.findings ?? [];
    const finding = findings[req.params.findingIndex];
    if (!finding) throw ApiError.notFound("That finding does not exist in this scan.");

    // Reuse a stored explanation rather than paying for the same call twice. Deliberately
    // checked before the quota: re-reading an explanation you already paid for should not
    // cost a second one.
    if (finding.explanation && finding.mitigation && !req.body.force) {
      return res.json({
        explanation: finding.explanation,
        mitigation: finding.mitigation,
        references: finding.references ?? [],
        cached: true,
        quota: usersService.aiQuotaFor(req.profile),
      });
    }

    // Spend the allowance before calling out, so a Free account that is already at its
    // limit is refused without incurring the API cost it is not entitled to.
    const quota = await usersService.consumeAiExplanation(req.user.uid, req.profile);

    let result;
    try {
      result = await gemini.explainFinding(finding);
    } catch (error) {
      await usersService.refundAiExplanation(req.user.uid, req.profile);
      throw error;
    }

    findings[req.params.findingIndex] = {
      ...finding,
      explanation: result.explanation,
      mitigation: result.mitigation,
      references: result.references,
    };
    await db.collection(COLLECTIONS.SCANS).doc(scan.id).update({ findings });

    res.json({ ...result, cached: false, quota });
  })
);

/**
 * GET /api/scans/compare -- Compare scan results (premium)
 *
 * Registered before the parameterised delete route so "compare" is not mistaken for a
 * scan id.
 */
router.get(
  "/compare/results",
  requirePremium,
  validate({
    query: z.object({
      baseline: z.string().min(1, "Provide the earlier scan id as 'baseline'."),
      current: z.string().min(1, "Provide the later scan id as 'current'."),
    }),
  }),
  asyncHandler(async (req, res) => {
    const [baseline, current] = await Promise.all([
      scansService.getScanForCaller(req.query.baseline, req.user),
      scansService.getScanForCaller(req.query.current, req.user),
    ]);

    if (baseline.id === current.id) {
      throw ApiError.badRequest("Choose two different scans to compare.");
    }
    if (baseline.type !== current.type) {
      throw ApiError.badRequest(
        "Those scans are different kinds of check, so comparing them would be misleading."
      );
    }

    res.json({ comparison: await scansService.compareScans(baseline, current) });
  })
);

/**
 * GET /api/scans/:scanId/report -- Export scan report (premium)
 *
 * Returns HTML. The desktop app converts it to PDF locally, which avoids shipping a
 * rendering engine with this service.
 */
router.get(
  "/:scanId/report",
  requirePremium,
  validate({
    params: z.object({ scanId: z.string().min(1) }),
    query: z.object({ download: z.coerce.boolean().default(false) }),
  }),
  asyncHandler(async (req, res) => {
    const scan = await scansService.getScanForCaller(req.params.scanId, req.user);
    const owner =
      scan.userId === req.user.uid
        ? req.profile
        : await usersService.getProfile(scan.userId).catch(() => null);

    const html = renderScanReportHtml(scan, { owner });

    res.type("html");
    if (req.query.download) {
      res.setHeader("Content-Disposition", `attachment; filename="bioaudit-${scan.id}.html"`);
    }
    res.send(html);
  })
);

/** DELETE /api/scans -- Delete test history (all of it) */
router.delete(
  "/",
  validate({
    body: z.object({
      confirm: z.literal("DELETE_ALL", {
        errorMap: () => ({ message: "Send confirm: 'DELETE_ALL' to clear your whole history." }),
      }),
    }),
  }),
  asyncHandler(async (req, res) => {
    const removed = await scansService.deleteAllScans(req.user.uid);
    res.json({ removed, message: `Deleted ${removed} scan${removed === 1 ? "" : "s"}.` });
  })
);

/** DELETE /api/scans/:scanId -- Delete test history (one entry) */
router.delete(
  "/:scanId",
  validate({ params: z.object({ scanId: z.string().min(1) }) }),
  asyncHandler(async (req, res) => {
    await scansService.deleteScan(req.params.scanId, req.user.uid);
    res.json({ message: "Scan deleted." });
  })
);

export default router;
