// src/routes/admin/index.js
//
// Every route under here requires a valid access token AND a matching
// global permission — see middleware/requirePermission.js for why these
// checks are done fresh against the database on every request rather than
// trusted from the access token's claims.

const express = require('express');
const asyncHandler = require('../../utils/asyncHandler');

const requireAccessToken = require('../../middleware/requireAccessToken');
const requirePermission = require('../../middleware/requirePermission');

const permissionModel = require('../../models/permissionModel');
const usersRoutes = require('./users');
const rolesRoutes = require('./roles');
const sessionsRoutes = require('./sessions');
const auditLogsRoutes = require('./auditLogs');

const router = express.Router();

// Every /admin/* route needs a valid access token first.
router.use(requireAccessToken);

router.use('/users', requirePermission('users.manage'), usersRoutes);
router.use('/roles', requirePermission('roles.manage'), rolesRoutes);
router.use('/sessions', requirePermission('sessions.manage'), sessionsRoutes);
router.use('/audit-logs', requirePermission('audit.view'), auditLogsRoutes);

// Reference list for admin UIs building role/permission-assignment forms.
// Gated on roles.manage since it's only useful alongside role editing.
router.get(
  '/permissions',
  requirePermission('roles.manage'),
  asyncHandler(async (req, res) => {
    res.json({ permissions: await permissionModel.listAll() });
  })
);

module.exports = router;
