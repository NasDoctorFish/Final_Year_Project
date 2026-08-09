/**
 * Server entry point.
 *
 * Configuration and Firebase are loaded before the app is built, so a missing service
 * account or web API key stops the process with a clear message instead of failing on
 * the first request.
 */
import { createApp } from "./app.js";
import { env } from "./config/env.js";
import "./config/firebase.js";

const app = createApp();

const server = app.listen(env.port, () => {
  console.log(`BioAudit API listening on port ${env.port} in ${env.nodeEnv} mode.`);
  if (!env.gemini.enabled) {
    console.log("AI explanations are disabled. Set GEMINI_API_KEY to turn them on.");
  }
});

/** Finish in-flight requests before exiting, so a deploy does not cut a scan upload short. */
function shutdown(signal) {
  console.log(`${signal} received. Closing server.`);
  server.close(() => process.exit(0));
  // If connections refuse to drain, stop anyway rather than hanging the deploy.
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

process.on("unhandledRejection", (reason) => {
  console.error("Unhandled promise rejection:", reason);
});
