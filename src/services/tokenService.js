// src/services/tokenService.js
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const ms = require('../utils/ms');

const env = require('../config/env');
const keys = require('../config/keys');
const { redisClient } = require('../config/redis');
const userRoleModel = require('../models/userRoleModel');
const refreshTokenModel = require('../models/refreshTokenModel');
const { generateOpaqueToken } = require('../utils/crypto');

const BLACKLIST_PREFIX = 'oauth:blacklist:';

/**
 * Builds and signs the access token. Shape matches the architecture doc's
 * JWT payload example: sub, email, apps: { APP_CODE: [ROLES] }.
 *
 * Signed RS256 with this server's private key (see config/keys.js) — the
 * matching public key is exposed at GET /oidc/jwks so any child app can
 * verify a token itself, without ever holding a shared secret.
 */
async function issueAccessToken(user, { clientId, scope }) {
  const apps = await userRoleModel.getRolesGroupedByApplication(user.id);
  const jti = uuidv4();

  const payload = {
    sub: user.id,
    email: user.email,
    username: user.username,
    apps,
    scope,
  };

  const token = jwt.sign(payload, keys.privateKeyPem, {
    algorithm: 'RS256',
    issuer: env.issuer,
    audience: clientId,
    expiresIn: env.jwt.accessExpiresIn,
    jwtid: jti,
    keyid: keys.kid,
  });

  return { token, jti, expiresIn: ms(env.jwt.accessExpiresIn) };
}

/**
 * Builds and signs an OpenID Connect ID token. Unlike the access token
 * (which carries authorization data -- "apps") this carries identity/profile
 * claims about the end user, scoped to the client that requested them, and
 * is not meant to be presented to any API as a Bearer credential.
 */
async function issueIdToken(user, { clientId, nonce, scope }) {
  const scopes = (scope || '').split(' ').filter(Boolean);

  const payload = { sub: user.id };
  if (scopes.includes('email')) {
    payload.email = user.email;
    payload.email_verified = Boolean(user.email_verified_at);
  }
  if (scopes.includes('profile')) {
    payload.name = [user.first_name, user.last_name].filter(Boolean).join(' ') || undefined;
    payload.given_name = user.first_name || undefined;
    payload.family_name = user.last_name || undefined;
    payload.preferred_username = user.username;
    payload.picture = user.profile_photo || undefined;
  }
  if (nonce) payload.nonce = nonce;

  return jwt.sign(payload, keys.privateKeyPem, {
    algorithm: 'RS256',
    issuer: env.issuer,
    audience: clientId,
    expiresIn: env.jwt.accessExpiresIn,
    jwtid: uuidv4(),
    keyid: keys.kid,
  });
}

async function issueRefreshToken(user, clientId, scope) {
  const rawToken = generateOpaqueToken();
  const expiresAt = new Date(Date.now() + ms(env.jwt.refreshExpiresIn));
  await refreshTokenModel.store({ userId: user.id, clientId, rawToken, scope, expiresAt });
  return rawToken;
}

/** Verifies an access token's signature/expiry AND checks it hasn't been revoked (logout / single-logout). */
async function verifyAccessToken(token) {
  // `algorithms` is pinned explicitly -- without it, jsonwebtoken would
  // accept whatever algorithm the token header claims, which is exactly
  // the "alg confusion" class of attack. Always pin this.
  const decoded = jwt.verify(token, keys.publicKeyPem, {
    algorithms: ['RS256'],
    issuer: env.issuer,
  });

  const blacklisted = await redisClient.get(`${BLACKLIST_PREFIX}${decoded.jti}`);
  if (blacklisted) {
    const err = new Error('Token has been revoked');
    err.code = 'TOKEN_REVOKED';
    throw err;
  }

  return decoded;
}

/** Adds an access token's jti to the Redis blacklist until its natural expiry (used by /oauth/revoke and logout). */
async function blacklistAccessToken(decodedToken) {
  const secondsRemaining = decodedToken.exp - Math.floor(Date.now() / 1000);
  if (secondsRemaining <= 0) return;
  await redisClient.set(`${BLACKLIST_PREFIX}${decodedToken.jti}`, '1', 'EX', secondsRemaining);
}

module.exports = {
  issueAccessToken,
  issueIdToken,
  issueRefreshToken,
  verifyAccessToken,
  blacklistAccessToken,
};
