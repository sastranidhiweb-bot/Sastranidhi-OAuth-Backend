// src/services/socialAuthService.js
//
// Shared account-linking logic for both Google and Microsoft login. Three
// cases, in order:
//   1. This exact provider+subject has signed in before -> return the
//      already-linked local user.
//   2. No link yet, but a local user already exists with this email ->
//      link this identity to that existing account. Safe to do
//      automatically because both Google and Microsoft only report an
//      email in the profile once it's verified on their end.
//   3. Neither -> create a brand new, password-less local user
//      (password_hash stays NULL, same as any other social-only account)
//      and link it.

const userModel = require('../models/userModel');
const userIdentityModel = require('../models/userIdentityModel');

async function generateUniqueUsername(email) {
  const base = email.split('@')[0].toLowerCase().replace(/[^a-z0-9]/g, '') || 'user';

  let candidate = base;
  let suffix = 0;
  // Small, bounded loop -- collisions on a freshly-derived username are
  // rare, and this only runs once at account creation.
  while (await userModel.findByUsername(candidate)) {
    suffix += 1;
    candidate = `${base}${suffix}`;
    if (suffix > 1000) {
      // Practically unreachable, but never loop forever.
      candidate = `${base}${Date.now()}`;
      break;
    }
  }
  return candidate;
}

async function findOrCreateUser({ provider, providerUserId, email, firstName, lastName }) {
  if (!email) {
    throw new Error(`${provider} did not return an email address for this account`);
  }

  const existingIdentity = await userIdentityModel.findByProvider(provider, providerUserId);
  if (existingIdentity) {
    const user = await userModel.findById(existingIdentity.user_id);
    if (user) return user;
    // Identity row survived a deleted user somehow (shouldn't happen given
    // the FK's ON DELETE CASCADE) -- fall through and re-link below rather
    // than erroring on a state that should be unreachable.
  }

  let user = await userModel.findByEmail(email);

  if (!user) {
    const username = await generateUniqueUsername(email);
    user = await userModel.create({
      email,
      username,
      passwordHash: null,
      firstName,
      lastName,
      // The provider (Google/Microsoft) already verified this email
      // address as part of its own OAuth consent — don't make the user
      // jump through this project's own email-verification flow on top
      // of that.
      emailVerifiedAt: new Date(),
    });
  }

  await userIdentityModel.create({
    userId: user.id,
    provider,
    providerUserId,
    emailAtProvider: email,
  });

  return user;
}

module.exports = { findOrCreateUser };
