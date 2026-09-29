// src/utils/base32.js
//
// Node's crypto/Buffer support base64/base64url/hex natively but not
// base32 — which is what every authenticator app (Google Authenticator,
// Authy, 1Password, etc.) expects a TOTP secret to be encoded as. This is
// a small, direct implementation of RFC 4648 base32 rather than pulling in
// a dependency for ~30 lines of bit-shifting.

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function encode(buffer) {
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;

    while (bits >= 5) {
      output += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

function decode(base32String) {
  const clean = base32String.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];

  for (let i = 0; i < clean.length; i++) {
    const idx = ALPHABET.indexOf(clean[i]);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;

    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
}

module.exports = { encode, decode };
