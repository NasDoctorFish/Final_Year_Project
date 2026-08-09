/**
 * An error that carries an HTTP status, so route code can throw a meaningful failure
 * and let the central error handler turn it into a response.
 */
export class ApiError extends Error {
  constructor(status, message, details = undefined) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.details = details;
  }

  static badRequest(message, details) {
    return new ApiError(400, message, details);
  }

  static unauthorized(message = "Authentication required.") {
    return new ApiError(401, message);
  }

  static forbidden(message = "You do not have permission to do that.") {
    return new ApiError(403, message);
  }

  static notFound(message = "Not found.") {
    return new ApiError(404, message);
  }

  static conflict(message) {
    return new ApiError(409, message);
  }

  /** Used when a free account tries to reach a paid feature. */
  static paymentRequired(message = "This feature requires a premium account.") {
    return new ApiError(402, message);
  }

  static tooManyRequests(message = "Too many requests. Try again shortly.") {
    return new ApiError(429, message);
  }

  static internal(message = "Something went wrong on our side.") {
    return new ApiError(500, message);
  }
}
