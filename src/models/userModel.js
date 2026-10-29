// src/models/userModel.js
const { User, CASE_INSENSITIVE } = require('../db/schemas');
const { toObjectId, toPlain, escapeRegex } = require('../utils/mongo');
const normalizeEmail = require('../utils/normalizeEmail');

async function findByEmail(email) {
  if (typeof email !== 'string') return null;
  return toPlain(await User.findOne({ email: normalizeEmail(email) }).lean());
}

async function findByUsername(username) {
  if (typeof username !== 'string') return null;
  return toPlain(await User.findOne({ username: username.trim() }).collation(CASE_INSENSITIVE).lean());
}

async function findById(id) {
  const _id = toObjectId(id);
  if (!_id) return null;
  return toPlain(await User.findById(_id).lean());
}

async function create({ email, username, passwordHash, firstName, lastName, mobile, emailVerifiedAt }) {
  const user = await User.create({
    email: normalizeEmail(email),
    username,
    password_hash: passwordHash,
    first_name: firstName || null,
    last_name: lastName || null,
    mobile: mobile || null,
    email_verified_at: emailVerifiedAt || null,
  });
  return toPlain(user.toObject());
}

async function recordFailedLogin(userId, { lockUntil } = {}) {
  const update = { $inc: { failed_login_attempts: 1 } };
  if (lockUntil) {
    update.$set = { locked_until: lockUntil, status: 'locked' };
  }
  await User.updateOne({ _id: toObjectId(userId) }, update);
}

async function resetFailedLogins(userId) {
  // Only clears an auto-lock (status='locked' from repeated failed
  // attempts) back to active. Deliberately does NOT blindly set
  // status='active' regardless of current status — that was a real bug:
  // it silently undid an admin's deactivation (status='inactive') the
  // moment a call reached this function after a successful login, since
  // "successful login" and "not deactivated" are different facts and this
  // function has no business overwriting the latter. With login already
  // blocking inactive accounts (see config/passport.js), this function
  // should never even be reached for one — but it should be correct on its
  // own terms regardless of what calls it.
  const _id = toObjectId(userId);
  await User.updateOne({ _id, status: 'locked' }, { $set: { status: 'active' } });
  await User.updateOne({ _id }, { $set: { failed_login_attempts: 0, locked_until: null } });
}

// ------------------------------------------------------------------
// Admin operations (module 4)
// ------------------------------------------------------------------

/** Paginated user list with optional search over email/username. */
async function listPaginated({ page = 1, pageSize = 20, search } = {}) {
  const limit = Math.min(Math.max(parseInt(pageSize, 10) || 20, 1), 100);
  const currentPage = Math.max(parseInt(page, 10) || 1, 1);
  const offset = (currentPage - 1) * limit;

  let filter = {};
  if (search) {
    // Case-insensitive "contains", like the old SQL LIKE '%search%'.
    const pattern = { $regex: escapeRegex(search), $options: 'i' };
    filter = { $or: [{ email: pattern }, { username: pattern }] };
  }

  const [rows, total] = await Promise.all([
    User.find(filter).sort({ created_at: -1, _id: -1 }).skip(offset).limit(limit).lean(),
    User.countDocuments(filter),
  ]);

  return { rows: rows.map(toPlain), total, page: currentPage, pageSize: limit };
}

/** Only fields that were actually provided are changed (null/undefined keeps the current value). */
async function updateProfile(userId, { firstName, lastName, mobile, profilePhoto }) {
  const changes = {};
  if (firstName != null) changes.first_name = firstName;
  if (lastName != null) changes.last_name = lastName;
  if (mobile != null) changes.mobile = mobile;
  if (profilePhoto != null) changes.profile_photo = profilePhoto;

  if (Object.keys(changes).length > 0) {
    await User.updateOne({ _id: toObjectId(userId) }, { $set: changes });
  }
  return findById(userId);
}

async function setPasswordHash(userId, passwordHash) {
  await User.updateOne({ _id: toObjectId(userId) }, { $set: { password_hash: passwordHash } });
}

async function setStatus(userId, status) {
  await User.updateOne(
    { _id: toObjectId(userId) },
    { $set: { status, locked_until: null, failed_login_attempts: 0 } }
  );
  return findById(userId);
}

// ------------------------------------------------------------------
// MFA operations (module 5)
// ------------------------------------------------------------------

/** Stores a newly-generated TOTP secret, but does NOT enable MFA yet — that only happens once the user proves they can generate a valid code from it (see routes/mfa.js verify-setup). */
async function setPendingMfaSecret(userId, secretBase32) {
  await User.updateOne({ _id: toObjectId(userId) }, { $set: { mfa_secret: secretBase32, mfa_enabled: false } });
}

async function enableMfa(userId) {
  await User.updateOne({ _id: toObjectId(userId) }, { $set: { mfa_enabled: true } });
}

async function disableMfa(userId) {
  await User.updateOne({ _id: toObjectId(userId) }, { $set: { mfa_enabled: false, mfa_secret: null } });
}

/** Strip sensitive fields before sending a user object back in any API response. */
function toPublic(user) {
  if (!user) return null;
  const { password_hash, failed_login_attempts, locked_until, mfa_secret, ...safe } = user;
  return safe;
}

module.exports = {
  findByEmail,
  findByUsername,
  findById,
  create,
  recordFailedLogin,
  resetFailedLogins,
  listPaginated,
  updateProfile,
  setPasswordHash,
  setStatus,
  setPendingMfaSecret,
  enableMfa,
  disableMfa,
  toPublic,
};
