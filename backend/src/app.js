/** Express application: middleware, routes, and error handling. */
import cors from "cors";
import express from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import morgan from "morgan";

import { env } from "./config/env.js";
import { errorHandler, notFoundHandler } from "./middleware/errorHandler.js";
import routes from "./routes/index.js";

export function createApp() {
  const app = express();

  // Trust the first proxy so rate limiting sees the caller's real address when this runs
  // behind a hosting platform's load balancer.
  app.set("trust proxy", 1);

  app.use(helmet());

  /**
   * The PySide6 desktop app sends no Origin header, so requests with no origin are
   * allowed through. Browsers must appear in CORS_ORIGINS.
   */
  app.use(
    cors({
      origin(origin, callback) {
        if (!origin || env.corsOrigins.length === 0 || env.corsOrigins.includes(origin)) {
          return callback(null, true);
        }
        callback(new Error(`Origin ${origin} is not allowed.`));
      },
      credentials: true,
    })
  );

  // A scan with many findings produces a sizeable body, so the default 100kb limit is
  // raised. It is still capped, since an unbounded body is a denial-of-service route.
  app.use(express.json({ limit: "4mb" }));

  app.use(morgan(env.isProduction ? "combined" : "dev"));

  // Broad limit across the whole API. Sign-in has its own tighter one in auth.routes.js.
  app.use(
    rateLimit({
      windowMs: 60 * 1000,
      limit: env.rateLimits.apiPerMinute,
      standardHeaders: true,
      legacyHeaders: false,
      message: { error: { status: 429, message: "Too many requests. Slow down and try again." } },
    })
  );

  app.use("/api", routes);

  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}
