/** Mounts every route group under /api and exposes a health check. */
import { Router } from "express";

import { env } from "../config/env.js";
import authRoutes from "./auth.routes.js";
import organisationRoutes from "./organisations.routes.js";
import scanRoutes from "./scans.routes.js";
import subscriptionRoutes from "./subscription.routes.js";
import userRoutes from "./users.routes.js";

const router = Router();

/**
 * GET /api/health
 *
 * Reports whether the optional AI layer is configured, which is the question that comes
 * up most when explanations stop appearing in the desktop app.
 */
router.get("/health", (req, res) => {
  res.json({
    status: "ok",
    environment: env.nodeEnv,
    aiExplanations: env.gemini.enabled ? "enabled" : "disabled",
    time: new Date().toISOString(),
  });
});

router.use("/auth", authRoutes);
router.use("/users", userRoutes);
router.use("/scans", scanRoutes);
router.use("/organisations", organisationRoutes);
router.use("/subscription", subscriptionRoutes);

export default router;


/** API Endpoint Design Updated Aug 18th by Juwon**/
// POST /api/audits/upload-apk
// POST /api/audits/start
// GET  /api/audits/:scanId/status
// GET  /api/audits/:scanId/report
// GET  /api/audits