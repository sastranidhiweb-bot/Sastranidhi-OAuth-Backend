// src/utils/totp.js
//
// RFC 6238 (TOTP) built directly on Node's crypto.createHmac -- the whole
// algorithm is HMAC-SHA1 over a time counter plus a well-defined dynamic
// truncation step, small enough that hand-rolling it is more transparent
// than a dependency, and it's fully offline-testable (no external
// authenticator app needed to verify correctness against known vectors).

const crypto = require('crypto');
const base32 = require('./base32');

const DIGITS = 6;
const PERIOD_SECONDS = 30;

/** Generates a new random TOTP secret, base32-encoded (what authenticator apps expect). */
function generateSecret() {
  return base32.encode(crypto.randomBytes(20));
}

/** RFC 4226 HOTP: HMAC-SHA1 over an 8-byte big-endian counter, then dynamic truncation. */
function hotp(secretBase32, counter) {
  const key = base32.decode(secretBase32);

  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));

  const hmac = crypto.createHmac('sha1', key).update(counterBuffer).digest();

  const offset = hmac[hmac.length - 1] & 0x0f;
  const binaryCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  return String(binaryCode % 10 ** DIGITS).padStart(DIGITS, '0');
}

function totpAt(secretBase32, unixSeconds) {
  const counter = Math.floor(unixSeconds / PERIOD_SECONDS);
  return hotp(secretBase32, counter);
}

function generate(secretBase32) {
  return totpAt(secretBase32, Math.floor(Date.now() / 1000));
}

/**
 * Verifies a code, tolerating +/-1 time step (30s) of clock drift between
 * the server and the user's phone -- standard practice for TOTP, since
 * without it any small clock skew makes the feature unusable.
 */
function verify(secretBase32, code, { window = 1 } = {}) {
  if (!/^\d{6}$/.test(String(code))) return false;

  const now = Math.floor(Date.now() / 1000);
  for (let errorWindow = -window; errorWindow <= window; errorWindow++) {
    const candidate = totpAt(secretBase32, now + errorWindow * PERIOD_SECONDS);
    if (candidate === String(code)) return true;
  }
  return false;
}

/** Builds the otpauth:// URI that authenticator apps scan as a QR code. */
function buildOtpauthUri({ secretBase32, accountLabel, issuer }) {
  const label = encodeURIComponent(`${issuer}:${accountLabel}`);
  const params = new URLSearchParams({
    secret: secretBase32,
    issuer,
    algorithm: 'SHA1',
    digits: String(DIGITS),
    period: String(PERIOD_SECONDS),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

module.exports = { generateSecret, generate, verify, buildOtpauthUri };
