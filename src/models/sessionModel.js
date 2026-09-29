// src/models/sessionModel.js
const db = require('../config/db');
const { redisClient, SESSION_KEY_PREFIX } = require('../config/redis');

async function upsert({ sessionId, userId, ipAddress, deviceInfo, expiresAt }) {
  await db.query(
    `INSERT INTO user_sessions (session_id, user_id, ip_address, device_info, expires_at)
     VALUES (:sessionId, :userId, :ipAddress, :deviceInfo, :expiresAt)
     ON DUPLICATE KEY UPDATE ip_address = :ipAddress, device_info = :deviceInfo, expires_at = :expiresAt`,
    { sessionId, userId, ipAddress, deviceInfo, expiresAt }
  );
}

async function remove(sessionId) {
  await db.query('DELETE FROM user_sessions WHERE session_id = :sessionId', { sessionId });
}

async function listForUser(userId) {
  return db.query(
    'SELECT * FROM user_sessions WHERE user_id = :userId ORDER BY created_at DESC',
    { userId }
  );
}

/** All active sessions across all users, with the owning user's email/username, for the admin console. */
async function listAll() {
  return db.query(
    `SELECT us.*, u.email, u.username
     FROM user_sessions us
     JOIN users u ON u.id = us.user_id
     ORDER BY us.created_at DESC`
  );
}

async function findById(sessionId) {
  const rows = await db.query('SELECT * FROM user_sessions WHERE session_id = :sessionId LIMIT 1', {
    sessionId,
  });
  return rows[0] || null;
}

/** Deletes the live express-session entry itself, not just the MySQL mirror — this is what actually forces the browser's next request to be unauthenticated. */
async function deleteRedisSession(sessionId) {
  await redisClient.del(`${SESSION_KEY_PREFIX}${sessionId}`);
}

module.exports = { upsert, remove, listForUser, listAll, findById, deleteRedisSession };
