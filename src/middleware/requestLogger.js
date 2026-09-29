// src/middleware/requestLogger.js
const logger = require('../config/logger');

function requestLogger(req, res, next) {
  const start = Date.now();

  res.on('finish', () => {
    logger.info('request', {
      method: req.method,
      path: req.originalUrl,
      status: res.statusCode,
      durationMs: Date.now() - start,
      ip: req.ip,
    });
  });

  next();
}

module.exports = requestLogger;
