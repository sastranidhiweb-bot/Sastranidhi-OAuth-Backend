// src/routes/admin/sessions.js
const express = require('express');

const asyncHandler = require('../../utils/asyncHandler');
const ApiError = require('../../utils/ApiError');

const sessionModel = require('../../models/sessionModel');
const auditLogModel = require('../../models/auditLogModel');

const router = express.Router();

// GET /admin/sessions?user_id=
router.get(
  '/',
  asyncHandler(async (req, res) => {
    const sessions = req.query.user_id
      ? await sessionModel.listForUser(req.query.user_id)
      : await sessionModel.listAll();
    res.json({ sessions });
  })
);

// DELETE /admin/sessions/:sessionId  — force logout
router.delete(
  '/:sessionId',
  asyncHandler(async (req, res) => {
    const session = await sessionModel.findById(req.params.sessionId);
    if (!session) throw new ApiError(404, 'not_found', 'Session not found');

    // Delete the live express-session in Redis (what actually forces the
    // browser's next request to be unauthenticated) AND the MySQL mirror
    // row (what the admin console lists) — they're two different stores
    // for the same fact, both need clearing.
    await sessionModel.deleteRedisSession(session.session_id);
    await sessionModel.remove(session.session_id);

    await auditLogModel.record({
      userId: req.adminUser.id,
      eventType: 'ADMIN_FORCE_LOGOUT',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: { targetUserId: session.user_id, sessionId: session.session_id },
    });

    res.status(204).send();
  })
);

module.exports = router;
