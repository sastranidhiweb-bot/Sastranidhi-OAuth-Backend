// src/utils/returnTo.js
//
// Every place in this project that redirects a browser based on a
// caller-supplied "returnTo" value funnels through this one check, so the
// open-redirect defense lives in one place instead of being re-implemented
// (and potentially re-broken) at each call site.
//
// A returnTo value is safe if it's either:
//   1. A path relative to THIS backend (starts with "/", not "//" — a
//      leading "//" is a classic bypass, since browsers treat
//      "//evil.com" as protocol-relative to a different host). Used for
//      values like "/oauth/authorize?client_id=..." that the backend
//      itself needs to redirect back into.
//   2. An absolute URL whose origin exactly matches env.frontendBaseUrl —
//      the one portal this backend is configured to trust. Used for "just
//      send the browser back to the portal" cases (e.g. Google login
//      started directly from the portal with no pending child-app
//      request).
//
// Anything else (a bare "evil.com", "https://evil.com", "javascript:...",
// a different frontend origin, etc) is rejected.

const env = require('../config/env');

function isSafeReturnTo(value) {
  if (typeof value !== 'string' || value.length === 0) return false;

  if (value.startsWith('/') && !value.startsWith('//')) {
    return true;
  }

  try {
    const url = new URL(value);
    const trusted = new URL(env.frontendBaseUrl);
    return url.origin === trusted.origin;
  } catch {
    return false;
  }
}

/** Returns the value if safe, otherwise `fallback` (default: null). */
function sanitizeReturnTo(value, fallback = null) {
  return isSafeReturnTo(value) ? value : fallback;
}

module.exports = { isSafeReturnTo, sanitizeReturnTo };
