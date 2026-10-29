// src/middleware/authRateLimiter.js
//
// A separate counter from the global limiter, specifically for endpoints
// that are attractive brute-force targets: /auth/login, signup, password
// reset and /oauth/token. Limits are per IP address, so they have to allow
// for many users sharing one network (a classroom, a campus Wi-Fi) and for
// a child app's server exchanging tokens on behalf of all its users.
// Per-account protection comes from the 5-failed-logins lockout instead.

const rateLimit = require('express-rate-limit');
const env = require('../config/env');

const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: env.security.authRateLimitMax,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'too_many_requests',
    error_description: 'Too many attempts, please try again later.',
  },
});

module.exports = authRateLimiter;
