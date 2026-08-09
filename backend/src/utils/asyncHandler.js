/**
 * Wraps an async route handler so a rejected promise reaches Express's error
 * handler instead of hanging the request. Express 4 does not catch async throws
 * on its own, which is a common source of silently stalled requests.
 */
export const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);
