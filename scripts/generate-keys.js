// scripts/generate-keys.js
//
// Generates the RSA keypair this server uses to sign access tokens and ID
// tokens (RS256). Run once per environment and keep private.pem secret —
// it never leaves this server. public.pem's content is what gets exposed,
// reshaped as a JWK, at GET /oidc/jwks.
//
// Usage: node scripts/generate-keys.js [--force]

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const KEYS_DIR = path.join(__dirname, '..', 'keys');
const PRIVATE_KEY_PATH = path.join(KEYS_DIR, 'private.pem');
const PUBLIC_KEY_PATH = path.join(KEYS_DIR, 'public.pem');

function main() {
  const force = process.argv.includes('--force');

  if (!fs.existsSync(KEYS_DIR)) {
    fs.mkdirSync(KEYS_DIR, { recursive: true });
  }

  if (!force && (fs.existsSync(PRIVATE_KEY_PATH) || fs.existsSync(PUBLIC_KEY_PATH))) {
    console.error(
      `[generate-keys] Key files already exist in ${KEYS_DIR}. Re-run with --force to overwrite.\n` +
        '[generate-keys] WARNING: overwriting invalidates every token/session signed with the old key —\n' +
        '[generate-keys]          every child app user would need to log in again.'
    );
    process.exit(1);
  }

  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  fs.writeFileSync(PRIVATE_KEY_PATH, privateKey, { mode: 0o600 });
  fs.writeFileSync(PUBLIC_KEY_PATH, publicKey, { mode: 0o644 });

  console.log(`[generate-keys] Wrote ${PRIVATE_KEY_PATH} (keep this secret, never commit it)`);
  console.log(`[generate-keys] Wrote ${PUBLIC_KEY_PATH} (this is served publicly via /oidc/jwks)`);
  console.log(
    '\n[generate-keys] Set JWT_PRIVATE_KEY_PATH / JWT_PUBLIC_KEY_PATH in .env to point at these ' +
      '(defaults in .env.example already do) and pick a JWT_KEY_ID (any short string, e.g. "sastranidhi-2026-08").'
  );
}

main();
