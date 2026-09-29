// src/middleware/authRateLimiter.js
//
// Tighter than the global limiter — specifically for endpoints that are
// attractive brute-force targets: /auth/login and /oauth/token.

const rateLimit = require('express-rate-limit');

const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'too_many_requests',
    error_description: 'Too many attempts, please try again later.',
  },
});

module.exports = authRateLimiter;
