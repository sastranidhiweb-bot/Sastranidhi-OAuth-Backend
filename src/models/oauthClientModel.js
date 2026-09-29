// src/models/oauthClientModel.js
const db = require('../config/db');

async function findByClientId(clientId) {
  const rows = await db.query(
    'SELECT * FROM oauth_clients WHERE client_id = :clientId LIMIT 1',
    { clientId }
  );
  return rows[0] || null;
}

async function create({ clientId, clientSecretHash, applicationId, redirectUris, scopes }) {
  await db.query(
    `INSERT INTO oauth_clients (client_id, client_secret_hash, application_id, redirect_uris, scopes)
     VALUES (:clientId, :clientSecretHash, :applicationId, :redirectUris, :scopes)`,
    {
      clientId,
      clientSecretHash,
      applicationId,
      redirectUris,
      scopes: scopes || 'openid,profile,email',
    }
  );
  return findByClientId(clientId);
}

/** Exact-match redirect_uri validation, per OAuth2 spec recommendation. */
function isRedirectUriRegistered(client, redirectUri) {
  const registered = client.redirect_uris.split(',').map((s) => s.trim());
  return registered.includes(redirectUri);
}

module.exports = { findByClientId, create, isRedirectUriRegistered };
