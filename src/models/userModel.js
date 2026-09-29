// src/models/userModel.js
const db = require('../config/db');

async function findByEmail(email) {
  const rows = await db.query('SELECT * FROM users WHERE email = :email LIMIT 1', { email });
  return rows[0] || null;
}

async function findByUsername(username) {
  const rows = await db.query('SELECT * FROM users WHERE username = :username LIMIT 1', {
    username,
  });
  return rows[0] || null;
}

async function findById(id) {
  const rows = await db.query('SELECT * FROM users WHERE id = :id LIMIT 1', { id });
  return rows[0] || null;
}

async function create({ email, username, passwordHash, firstName, lastName, mobile, emailVerifiedAt }) {
  const result = await db.query(
    `INSERT INTO users (email, username, password_hash, first_name, last_name, mobile, email_verified_at)
     VALUES (:email, :username, :passwordHash, :firstName, :lastName, :mobile, :emailVerifiedAt)`,
    {
      email,
      username,
      passwordHash,
      firstName: firstName || null,
      lastName: lastName || null,
      mobile: mobile || null,
      emailVerifiedAt: emailVerifiedAt || null,
    }
  );
  return findById(result.insertId);
}

async function recordFailedLogin(userId, { lockUntil } = {}) {
  if (lockUntil) {
    await db.query(
      `UPDATE users SET failed_login_attempts = failed_login_attempts + 1, locked_until = :lockUntil, status = 'locked'
       WHERE id = :userId`,
      { userId, lockUntil }
    );
  } else {
    await db.query(
      'UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = :userId',
      { userId }
    );
  }
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
  await db.query(
    `UPDATE users SET
       failed_login_attempts = 0,
       locked_until = NULL,
       status = IF(status = 'locked', 'active', status)
     WHERE id = :userId`,
    { userId }
  );
}

// ------------------------------------------------------------------
// Admin operations (module 4)
// ------------------------------------------------------------------

/** Paginated user list with optional search over email/username. */
async function listPaginated({ page = 1, pageSize = 20, search } = {}) {
  const limit = Math.min(Math.max(parseInt(pageSize, 10) || 20, 1), 100);
  const offset = (Math.max(parseInt(page, 10) || 1, 1) - 1) * limit;

  const params = {};
  let whereClause = '';
  if (search) {
    whereClause = 'WHERE email LIKE :search OR username LIKE :search';
    params.search = `%${search}%`;
  }

  // LIMIT/OFFSET are computed server-side integers (clamped above), not
  // user-supplied strings, so string-interpolating them here is safe —
  // mysql2 does not reliably support named placeholders inside LIMIT/OFFSET.
  const rows = await db.query(
    `SELECT * FROM users ${whereClause} ORDER BY created_at DESC LIMIT ${limit} OFFSET ${offset}`,
    params
  );
  const [{ total }] = await db.query(`SELECT COUNT(*) AS total FROM users ${whereClause}`, params);

  return { rows, total, page: Math.max(parseInt(page, 10) || 1, 1), pageSize: limit };
}

async function updateProfile(userId, { firstName, lastName, mobile, profilePhoto }) {
  await db.query(
    `UPDATE users SET
       first_name = COALESCE(:firstName, first_name),
       last_name = COALESCE(:lastName, last_name),
       mobile = COALESCE(:mobile, mobile),
       profile_photo = COALESCE(:profilePhoto, profile_photo)
     WHERE id = :userId`,
    {
      userId,
      firstName: firstName ?? null,
      lastName: lastName ?? null,
      mobile: mobile ?? null,
      profilePhoto: profilePhoto ?? null,
    }
  );
  return findById(userId);
}

async function setPasswordHash(userId, passwordHash) {
  await db.query('UPDATE users SET password_hash = :passwordHash WHERE id = :userId', {
    userId,
    passwordHash,
  });
}

async function setStatus(userId, status) {
  await db.query(
    `UPDATE users SET status = :status, locked_until = NULL, failed_login_attempts = 0
     WHERE id = :userId`,
    { userId, status }
  );
  return findById(userId);
}

// ------------------------------------------------------------------
// MFA operations (module 5)
// ------------------------------------------------------------------

/** Stores a newly-generated TOTP secret, but does NOT enable MFA yet — that only happens once the user proves they can generate a valid code from it (see routes/mfa.js verify-setup). */
async function setPendingMfaSecret(userId, secretBase32) {
  await db.query('UPDATE users SET mfa_secret = :secretBase32, mfa_enabled = 0 WHERE id = :userId', {
    userId,
    secretBase32,
  });
}

async function enableMfa(userId) {
  await db.query('UPDATE users SET mfa_enabled = 1 WHERE id = :userId', { userId });
}

async function disableMfa(userId) {
  await db.query('UPDATE users SET mfa_enabled = 0, mfa_secret = NULL WHERE id = :userId', { userId });
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
