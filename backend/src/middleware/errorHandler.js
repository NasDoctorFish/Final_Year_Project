/**
 * Central error handling.
 *
 * Two rules here. Every failure leaves the API in the same response shape, so the
 * desktop app has one thing to parse. And an unexpected error never returns its stack
 * or internal message to the caller in production, since those often quote database
 * paths or configuration.
 */
import { env } from "../config/env.js";
import { ApiError } from "../utils/ApiError.js";

export function notFoundHandler(req, res) {
  res.status(404).json({
    error: {
      status: 404,
      message: `No route for ${req.method} ${req.originalUrl}.`,
    },
  });
}

// eslint-disable-next-line no-unused-vars -- Express identifies error handlers by arity.
export function errorHandler(err, req, res, next) {
  const isKnown = err instanceof ApiError;
  const status = isKnown ? err.status : 500;

  if (!isKnown || status >= 500) {
    // Log the real error for us, regardless of what the caller is told.
    console.error(`[error] ${req.method} ${req.originalUrl}`, err);
  }

  const body = {
    error: {
      status,
      message: isKnown ? err.message : "Something went wrong on our side.",
    },
  };

  if (isKnown && err.details) {
    body.error.details = err.details;
  }
  if (!env.isProduction && !isKnown) {
    body.error.debug = { message: err.message, stack: err.stack };
  }

  res.status(status).json(body);
}
