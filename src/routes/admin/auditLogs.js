// src/routes/admin/auditLogs.js
const express = require('express');
const asyncHandler = require('../../utils/asyncHandler');
const auditLogModel = require('../../models/auditLogModel');

const router = express.Router();

// GET /admin/audit-logs?user_id=&event_type=&page=&pageSize=
router.get(
  '/',
  asyncHandler(async (req, res) => {
    const { rows, total, page, pageSize } = await auditLogModel.listPaginated({
      page: req.query.page,
      pageSize: req.query.pageSize,
      userId: req.query.user_id,
      eventType: req.query.event_type,
    });
    res.json({ auditLogs: rows, total, page, pageSize });
  })
);

module.exports = router;
