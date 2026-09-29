// src/models/userIdentityModel.js
const db = require('../config/db');

async function findByProvider(provider, providerUserId) {
  const rows = await db.query(
    'SELECT * FROM user_identities WHERE provider = :provider AND provider_user_id = :providerUserId LIMIT 1',
    { provider, providerUserId }
  );
  return rows[0] || null;
}

async function listForUser(userId) {
  return db.query('SELECT * FROM user_identities WHERE user_id = :userId', { userId });
}

async function create({ userId, provider, providerUserId, emailAtProvider }) {
  await db.query(
    `INSERT INTO user_identities (user_id, provider, provider_user_id, email_at_provider)
     VALUES (:userId, :provider, :providerUserId, :emailAtProvider)`,
    { userId, provider, providerUserId, emailAtProvider: emailAtProvider || null }
  );
  return findByProvider(provider, providerUserId);
}

module.exports = { findByProvider, listForUser, create };
