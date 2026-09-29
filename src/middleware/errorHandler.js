// src/middleware/errorHandler.js
const ApiError = require('../utils/ApiError');
const logger = require('../config/logger');
const env = require('../config/env');

// 404 handler — mounted after all routes
function notFoundHandler(req, res) {
  res.status(404).json({
    error: 'not_found',
    error_description: `No route for ${req.method} ${req.originalUrl}`,
  });
}

// Central error handler — mounted last
// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  if (err instanceof ApiError) {
    logger.warn('Handled API error', {
      statusCode: err.statusCode,
      errorCode: err.errorCode,
      message: err.message,
      path: req.originalUrl,
    });
    return res.status(err.statusCode).json({
      error: err.errorCode,
      error_description: err.message,
      ...(err.details ? { details: err.details } : {}),
    });
  }

  logger.error('Unhandled error', {
    message: err.message,
    stack: err.stack,
    path: req.originalUrl,
  });

  res.status(500).json({
    error: 'server_error',
    error_description:
      env.nodeEnv === 'production' ? 'Internal server error' : err.message,
  });
}

module.exports = { notFoundHandler, errorHandler };
