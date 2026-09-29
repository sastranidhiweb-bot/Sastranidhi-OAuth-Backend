// src/utils/stateToken.js
//
// A small, self-verifying signed token -- HMAC-SHA256 over a JSON payload,
// with an expiry -- used anywhere this server needs to hand the *caller*
// a short-lived piece of state it can't tamper with, without storing that
// state server-side. Two uses in this module:
//
//   1. The OAuth "state" param for social login: carries returnTo across
//      the redirect to Google/Microsoft and back. Deliberately NOT stored
//      in req.session, because passport's req.login() regenerates the
//      session on the callback (see the same issue documented for the
//      local login flow in modules 2-3) -- a session-stored value set
//      before the redirect would be wiped out before the callback handler
//      could read it back.
//   2. The MFA challenge token: proves the caller already passed password
//      verification for a specific user, without creating a session until
//      the second factor is also verified.
//
// This is NOT a JWT -- deliberately simpler, since neither use case needs
// JWT's algorithm negotiation or standard claim set, just "did WE issue
// this, unmodified, before it expired".

const crypto = require('crypto');
const env = require('../config/env');

function sign(payload, { expiresInSeconds = 300 } = {}) {
  const body = { ...payload, exp: Math.floor(Date.now() / 1000) + expiresInSeconds };
  const bodyB64 = Buffer.from(JSON.stringify(body)).toString('base64url');
  const signature = crypto
    .createHmac('sha256', env.session.secret)
    .update(bodyB64)
    .digest('base64url');
  return `${bodyB64}.${signature}`;
}

function verify(token) {
  if (typeof token !== 'string' || !token.includes('.')) return null;
  const [bodyB64, signature] = token.split('.');

  const expectedSignature = crypto
    .createHmac('sha256', env.session.secret)
    .update(bodyB64)
    .digest('base64url');

  // Constant-time comparison -- this guards against an attacker probing
  // for a forged signature via timing differences in a naive ===.
  const sigBuffer = Buffer.from(signature || '');
  const expectedBuffer = Buffer.from(expectedSignature);
  if (
    sigBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(sigBuffer, expectedBuffer)
  ) {
    return null;
  }

  let body;
  try {
    body = JSON.parse(Buffer.from(bodyB64, 'base64url').toString('utf8'));
  } catch {
    return null;
  }

  if (!body.exp || body.exp < Math.floor(Date.now() / 1000)) return null;
  return body;
}

module.exports = { sign, verify };
