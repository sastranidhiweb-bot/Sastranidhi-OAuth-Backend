// src/models/userIdentityModel.js
const { UserIdentity } = require('../db/schemas');
const { toObjectId, toPlain } = require('../utils/mongo');

async function findByProvider(provider, providerUserId) {
  const identity = await UserIdentity.findOne({ provider, provider_user_id: String(providerUserId) }).lean();
  return toPlain(identity);
}

async function listForUser(userId) {
  const identities = await UserIdentity.find({ user_id: toObjectId(userId) }).lean();
  return identities.map(toPlain);
}

async function create({ userId, provider, providerUserId, emailAtProvider }) {
  await UserIdentity.create({
    user_id: toObjectId(userId),
    provider,
    provider_user_id: String(providerUserId),
    email_at_provider: emailAtProvider || null,
  });
  return findByProvider(provider, providerUserId);
}

module.exports = { findByProvider, listForUser, create };
