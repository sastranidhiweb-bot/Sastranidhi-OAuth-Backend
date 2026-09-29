// examples/child-app-express/verifyAccessToken.js
//
// Reference JWT verification middleware for a Sastranidhi child app
// (Paripraśna, and by extension Purāṇa Tilakam / Vedic Digital Library /
// IKS-LMS, since they all consume tokens the same way).
//
// This is the piece that makes RS256 + JWKS worth it: a child app never
// holds a shared secret. It fetches the IdP's public signing key once
// (cached, keyed by `kid`), and verifies every Bearer token itself, purely
// locally, with the same `algorithms: ['RS256']` pinning the IdP uses on
// its own /auth/me and /oidc/userinfo (see src/services/tokenService.js —
// mirrored here deliberately, not reinvented).
//
// Deliberately zero extra dependencies (no `jwks-rsa`, no `jose`) — only
// `jsonwebtoken` (which every child app needs anyway to call `jwt.verify`)
// and Node's built-in `crypto`, which can turn a JWK straight into a
// KeyObject via `crypto.createPublicKey({ key: jwk, format: 'jwk' })`
// (Node 18+). This keeps the same "hand-verified crypto, not an extra trust
// boundary" approach the IdP itself uses for TOTP.
//
// Usage in a child app's Express server:
//
//   const { createAccessTokenVerifier } = require('./verifyAccessToken');
//   const requireAccessToken = createAccessTokenVerifier({
//     issuer: 'https://auth.sastranidhi.org',
//     jwksUri: 'https://auth.sastranidhi.org/oidc/jwks',
//     audience: 'PARIPRASHNA', // this app's own client_id
//   });
//
//   app.get('/api/questions', requireAccessToken, (req, res) => {
//     // req.token = { sub, email, username, apps, scope, iat, exp, jti, ... }
//     const myRoles = req.token.apps?.PARIPRASHNA || [];
//     ...
//   });

const jwt = require('jsonwebtoken');
const crypto = require('crypto');

/**
 * Builds an Express middleware that verifies a Bearer access token against
 * the IdP's published JWKS. Keys are fetched lazily and cached in memory,
 * keyed by `kid`, so steady-state requests do zero network I/O — only a
 * key rotation (a new `kid` appearing) triggers a re-fetch.
 */
function createAccessTokenVerifier({ issuer, jwksUri, audience, cacheTtlMs = 10 * 60 * 1000 }) {
  if (!issuer || !jwksUri) {
    throw new Error('createAccessTokenVerifier requires both issuer and jwksUri');
  }

  // kid -> { keyObject, fetchedAt }
  const keyCache = new Map();
  let jwksFetchedAt = 0;
  let jwksPromise = null;

  async function fetchJwks() {
    const res = await fetch(jwksUri);
    if (!res.ok) {
      throw new Error(`Failed to fetch JWKS from ${jwksUri}: HTTP ${res.status}`);
    }
    const body = await res.json();
    if (!Array.isArray(body.keys)) {
      throw new Error(`Malformed JWKS response from ${jwksUri}`);
    }

    keyCache.clear();
    for (const jwk of body.keys) {
      if (!jwk.kid) continue;
      // RS256 JWKs (kty: 'RSA') convert straight to a usable public
      // KeyObject — no PEM-parsing step needed.
      const keyObject = crypto.createPublicKey({ key: jwk, format: 'jwk' });
      keyCache.set(jwk.kid, keyObject);
    }
    jwksFetchedAt = Date.now();
  }

  /** Returns a KeyObject for `kid`, fetching (or re-fetching, on a cache miss / stale cache) the JWKS as needed. Concurrent callers share one in-flight fetch. */
  async function getKey(kid) {
    const isStale = Date.now() - jwksFetchedAt > cacheTtlMs;
    if (!keyCache.has(kid) || isStale) {
      // Coalesce concurrent fetches so a burst of requests during a key
      // rotation doesn't hammer the IdP with parallel JWKS calls.
      if (!jwksPromise) {
        jwksPromise = fetchJwks().finally(() => {
          jwksPromise = null;
        });
      }
      await jwksPromise;
    }
    const key = keyCache.get(kid);
    if (!key) {
      throw new Error(`No matching key for kid "${kid}" in JWKS`);
    }
    return key;
  }

  return async function requireAccessToken(req, res, next) {
    const header = req.headers.authorization || '';
    const [scheme, token] = header.split(' ');

    if (scheme !== 'Bearer' || !token) {
      return res.status(401).json({ error: 'invalid_token', error_description: 'Missing or malformed Authorization header' });
    }

    // Read the kid from the (unverified) header first -- this only tells
    // us *which* key to check the signature against; jwt.verify() below is
    // still what actually proves the signature is valid.
    const unverifiedHeader = jwt.decode(token, { complete: true })?.header;
    if (!unverifiedHeader?.kid) {
      return res.status(401).json({ error: 'invalid_token', error_description: 'Token is missing a kid header' });
    }

    try {
      const keyObject = await getKey(unverifiedHeader.kid);

      // Same pinning the IdP itself uses (see tokenService.verifyAccessToken)
      // -- never let the token's own header dictate the algorithm.
      req.token = jwt.verify(token, keyObject, {
        algorithms: ['RS256'],
        issuer,
        audience,
      });

      next();
    } catch (err) {
      // A stale cached key rejecting a freshly-rotated token looks the same
      // as a genuinely bad signature from here -- both are correctly 401s.
      // (If key rotation false-positives become a real problem, retry once
      // here after forcing a fresh JWKS fetch.)
      return res.status(401).json({ error: 'invalid_token', error_description: err.message });
    }
  };
}

module.exports = { createAccessTokenVerifier };
