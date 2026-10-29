// src/models/auditLogModel.js
const { AuditLog, User } = require('../db/schemas');
const { toObjectId, toPlain } = require('../utils/mongo');

async function record({ userId, eventType, ipAddress, userAgent, metadata }) {
  await AuditLog.create({
    user_id: toObjectId(userId),
    event_type: eventType,
    ip_address: ipAddress || null,
    user_agent: userAgent || null,
    metadata: metadata || null,
  });
}

// ------------------------------------------------------------------
// Admin operations (module 4)
// ------------------------------------------------------------------

/** Paginated audit log query with optional filters, newest first. Each row also carries the user's email (user_email), as the old SQL JOIN did. */
async function listPaginated({ page = 1, pageSize = 20, userId, eventType } = {}) {
  const limit = Math.min(Math.max(parseInt(pageSize, 10) || 20, 1), 100);
  const currentPage = Math.max(parseInt(page, 10) || 1, 1);
  const offset = (currentPage - 1) * limit;

  const filter = {};
  if (userId) filter.user_id = toObjectId(userId);
  if (eventType) filter.event_type = String(eventType);

  const [logs, total] = await Promise.all([
    AuditLog.find(filter).sort({ created_at: -1, _id: -1 }).skip(offset).limit(limit).lean(),
    AuditLog.countDocuments(filter),
  ]);

  const userIds = [...new Set(logs.filter((l) => l.user_id).map((l) => String(l.user_id)))];
  const users = await User.find({ _id: { $in: userIds } }, { email: 1 }).lean();
  const emailById = new Map(users.map((u) => [String(u._id), u.email]));

  const rows = logs.map((log) => {
    const row = toPlain(log);
    row.user_email = row.user_id ? emailById.get(row.user_id) || null : null;
    return row;
  });

  return { rows, total, page: currentPage, pageSize: limit };
}

module.exports = { record, listPaginated };
