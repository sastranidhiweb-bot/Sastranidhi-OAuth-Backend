// src/services/authorizationCodeService.js
//
// Authorization codes are short-lived (60s) and single-use by design, so
// Redis is the right store for them (not the audit-friendly MongoDB collections) —
// this mirrors the "SSO Session Store (Redis)" box in the architecture
// diagram, which the auth-code exchange is logically part of.

const { redisClient } = require('../config/redis');
const { generateOpaqueToken } = require('../utils/crypto');

const CODE_TTL_SECONDS = 60;
const KEY_PREFIX = 'oauth:code:';

async function issueCode({ userId, clientId, redirectUri, scope, codeChallenge, codeChallengeMethod, nonce }) {
  const code = generateOpaqueToken();
  const payload = JSON.stringify({
    userId,
    clientId,
    redirectUri,
    scope,
    codeChallenge: codeChallenge || null,
    codeChallengeMethod: codeChallengeMethod || null,
    nonce: nonce || null,
  });

  await redisClient.set(`${KEY_PREFIX}${code}`, payload, 'EX', CODE_TTL_SECONDS);
  return code;
}

async function consumeCode(code) {
  const key = `${KEY_PREFIX}${code}`;
  const payload = await redisClient.get(key);
  if (!payload) return null;

  // Single-use: delete immediately on read, regardless of what happens next.
  await redisClient.del(key);
  return JSON.parse(payload);
}

module.exports = { issueCode, consumeCode };
