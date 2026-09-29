// src/utils/crypto.js
const crypto = require('crypto');

/**
 * Generate a high-entropy, URL-safe opaque token (used for authorization
 * codes and refresh tokens). 32 bytes -> 43 base64url characters.
 */
function generateOpaqueToken() {
  return crypto.randomBytes(32).toString('base64url');
}

/**
 * SHA-256 hex digest. Used to store/lookup refresh tokens and authorization
 * codes. NOTE: this is intentionally not bcrypt — bcrypt's slow, salted
 * hashing exists to defend low-entropy human passwords against offline
 * guessing. These tokens are 256 bits of random data; a fast, deterministic
 * hash is what lets us look them up by equality, and brute-forcing a
 * 256-bit value is not a realistic attack regardless of hash speed.
 */
function sha256Hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

/**
 * PKCE (RFC 7636) verification for the S256 method:
 * code_challenge should equal BASE64URL(SHA256(code_verifier))
 */
function verifyPkce(codeVerifier, codeChallenge) {
  const computed = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');
  return computed === codeChallenge;
}

module.exports = { generateOpaqueToken, sha256Hex, verifyPkce };
