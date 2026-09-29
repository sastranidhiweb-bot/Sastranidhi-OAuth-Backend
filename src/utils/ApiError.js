// src/utils/ApiError.js
//
// A typed error so route handlers can `throw new ApiError(400, 'invalid_request', 'message')`
// and the central error handler renders it consistently (and OAuth-spec-shaped
// where relevant, e.g. { error, error_description }).

class ApiError extends Error {
  constructor(statusCode, errorCode, message, details) {
    super(message);
    this.name = 'ApiError';
    this.statusCode = statusCode;
    this.errorCode = errorCode; // e.g. 'invalid_request', 'invalid_grant', 'unauthorized'
    this.details = details;
  }
}

module.exports = ApiError;
