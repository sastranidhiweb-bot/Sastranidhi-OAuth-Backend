// src/models/oauthClientModel.js
const { OAuthClient } = require('../db/schemas');
const { toObjectId, toPlain } = require('../utils/mongo');

async function findByClientId(clientId) {
  if (typeof clientId !== 'string') return null;
  return toPlain(await OAuthClient.findOne({ client_id: clientId }).lean());
}

async function create({ clientId, clientSecretHash, applicationId, redirectUris, scopes }) {
  await OAuthClient.create({
    client_id: clientId,
    client_secret_hash: clientSecretHash,
    application_id: toObjectId(applicationId),
    redirect_uris: redirectUris,
    scopes: scopes || 'openid,profile,email',
  });
  return findByClientId(clientId);
}

/** Exact-match redirect_uri validation, per OAuth2 spec recommendation. */
function isRedirectUriRegistered(client, redirectUri) {
  const registered = client.redirect_uris.split(',').map((s) => s.trim());
  return registered.includes(redirectUri);
}

module.exports = { findByClientId, create, isRedirectUriRegistered };
