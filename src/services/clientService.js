// src/services/clientService.js
const bcrypt = require('bcrypt');
const oauthClientModel = require('../models/oauthClientModel');
const ApiError = require('../utils/ApiError');

/**
 * Loads a client and verifies its secret. Used by /oauth/token and
 * /oauth/revoke, which both require client authentication.
 */
async function authenticateClient(clientId, clientSecret) {
  const client = await oauthClientModel.findByClientId(clientId);

  if (!client || !client.is_active) {
    throw new ApiError(401, 'invalid_client', 'Unknown or inactive client');
  }

  const secretMatches = await bcrypt.compare(clientSecret || '', client.client_secret_hash);
  if (!secretMatches) {
    throw new ApiError(401, 'invalid_client', 'Client authentication failed');
  }

  return client;
}

/** Loads a client without checking the secret — used at /oauth/authorize, which is a browser redirect and has no secret. */
async function loadPublicClient(clientId) {
  const client = await oauthClientModel.findByClientId(clientId);
  if (!client || !client.is_active) {
    throw new ApiError(400, 'invalid_client', 'Unknown or inactive client');
  }
  return client;
}

function assertRedirectUriRegistered(client, redirectUri) {
  if (!oauthClientModel.isRedirectUriRegistered(client, redirectUri)) {
    throw new ApiError(400, 'invalid_request', 'redirect_uri is not registered for this client');
  }
}

module.exports = { authenticateClient, loadPublicClient, assertRedirectUriRegistered };
