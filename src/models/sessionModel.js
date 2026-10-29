// src/models/sessionModel.js
const { UserSession, User } = require('../db/schemas');
const { toObjectId, toPlain } = require('../utils/mongo');
const { redisClient, SESSION_KEY_PREFIX } = require('../config/redis');

async function upsert({ sessionId, userId, ipAddress, deviceInfo, expiresAt }) {
  await UserSession.updateOne(
    { session_id: sessionId },
    {
      $set: { ip_address: ipAddress || null, device_info: deviceInfo || null, expires_at: expiresAt },
      $setOnInsert: { user_id: toObjectId(userId) },
    },
    { upsert: true }
  );
}

async function remove(sessionId) {
  if (typeof sessionId !== 'string') return;
  await UserSession.deleteOne({ session_id: sessionId });
}

async function listForUser(userId) {
  const sessions = await UserSession.find({ user_id: toObjectId(userId) }).sort({ created_at: -1 }).lean();
  return sessions.map(toPlain);
}

/** All active sessions across all users, with the owning user's email/username, for the admin console. */
async function listAll() {
  const sessions = await UserSession.find().sort({ created_at: -1 }).lean();
  const users = await User.find({ _id: { $in: sessions.map((s) => s.user_id) } }, { email: 1, username: 1 }).lean();
  const userById = new Map(users.map((u) => [String(u._id), u]));

  // Like the old SQL inner JOIN: sessions whose user no longer exists are left out.
  return sessions
    .filter((s) => userById.has(String(s.user_id)))
    .map((s) => {
      const { email, username } = userById.get(String(s.user_id));
      return { ...toPlain(s), email, username };
    });
}

async function findById(sessionId) {
  if (typeof sessionId !== 'string') return null;
  return toPlain(await UserSession.findOne({ session_id: sessionId }).lean());
}

/** Deletes the live express-session entry itself, not just the MongoDB mirror — this is what actually forces the browser's next request to be unauthenticated. */
async function deleteRedisSession(sessionId) {
  await redisClient.del(`${SESSION_KEY_PREFIX}${sessionId}`);
}

module.exports = { upsert, remove, listForUser, listAll, findById, deleteRedisSession };
