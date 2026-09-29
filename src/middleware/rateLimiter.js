// src/middleware/rateLimiter.js
//
// General-purpose rate limiter applied to the whole API. Sensitive endpoints
// (login, token) get their own stricter limiter defined alongside those
// routes in module 2 — this one just stops casual abuse/scraping.

const rateLimit = require('express-rate-limit');
const env = require('../config/env');

const globalRateLimiter = rateLimit({
  windowMs: env.security.rateLimitWindowMs,
  max: env.security.rateLimitMax,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'too_many_requests',
    error_description: 'Too many requests, please try again later.',
  },
});

module.exports = globalRateLimiter;
