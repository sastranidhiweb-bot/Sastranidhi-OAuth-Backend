// src/models/auditLogModel.js
const db = require('../config/db');

async function record({ userId, eventType, ipAddress, userAgent, metadata }) {
  await db.query(
    `INSERT INTO audit_logs (user_id, event_type, ip_address, user_agent, metadata)
     VALUES (:userId, :eventType, :ipAddress, :userAgent, :metadata)`,
    {
      userId: userId || null,
      eventType,
      ipAddress: ipAddress || null,
      userAgent: userAgent || null,
      metadata: metadata ? JSON.stringify(metadata) : null,
    }
  );
}

// ------------------------------------------------------------------
// Admin operations (module 4)
// ------------------------------------------------------------------

/** Paginated audit log query with optional filters, newest first. */
async function listPaginated({ page = 1, pageSize = 20, userId, eventType } = {}) {
  const limit = Math.min(Math.max(parseInt(pageSize, 10) || 20, 1), 100);
  const offset = (Math.max(parseInt(page, 10) || 1, 1) - 1) * limit;

  const conditions = [];
  const params = {};
  if (userId) {
    conditions.push('al.user_id = :userId');
    params.userId = userId;
  }
  if (eventType) {
    conditions.push('al.event_type = :eventType');
    params.eventType = eventType;
  }
  const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  // LIMIT/OFFSET interpolated as clamped server-side integers -- see the
  // same note in userModel.listPaginated.
  const rows = await db.query(
    `SELECT al.*, u.email AS user_email
     FROM audit_logs al
     LEFT JOIN users u ON u.id = al.user_id
     ${whereClause}
     ORDER BY al.created_at DESC
     LIMIT ${limit} OFFSET ${offset}`,
    params
  );
  const [{ total }] = await db.query(
    `SELECT COUNT(*) AS total FROM audit_logs al ${whereClause}`,
    params
  );

  return { rows, total, page: Math.max(parseInt(page, 10) || 1, 1), pageSize: limit };
}

module.exports = { record, listPaginated };
