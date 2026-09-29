// src/routes/admin/users.js
const express = require('express');
const bcrypt = require('bcrypt');

const asyncHandler = require('../../utils/asyncHandler');
const ApiError = require('../../utils/ApiError');
const env = require('../../config/env');

const userModel = require('../../models/userModel');
const userRoleModel = require('../../models/userRoleModel');
const refreshTokenModel = require('../../models/refreshTokenModel');
const auditLogModel = require('../../models/auditLogModel');

const router = express.Router();

// GET /admin/users?search=&page=&pageSize=
router.get(
  '/',
  asyncHandler(async (req, res) => {
    const { rows, total, page, pageSize } = await userModel.listPaginated({
      page: req.query.page,
      pageSize: req.query.pageSize,
      search: req.query.search,
    });
    res.json({ users: rows.map(userModel.toPublic), total, page, pageSize });
  })
);

// GET /admin/users/:id
router.get(
  '/:id',
  asyncHandler(async (req, res) => {
    const user = await userModel.findById(req.params.id);
    if (!user) throw new ApiError(404, 'not_found', 'User not found');
    const roles = await userRoleModel.listForUser(user.id);
    res.json({ user: userModel.toPublic(user), roles });
  })
);

// POST /admin/users
router.post(
  '/',
  asyncHandler(async (req, res) => {
    const { email, username, password, first_name, last_name, mobile } = req.body;

    if (!email || !username || !password) {
      throw new ApiError(400, 'invalid_request', 'email, username and password are required');
    }
    if (password.length < 8) {
      throw new ApiError(400, 'invalid_request', 'password must be at least 8 characters');
    }
    if (await userModel.findByEmail(email)) {
      throw new ApiError(409, 'user_exists', 'A user with this email already exists');
    }
    if (await userModel.findByUsername(username)) {
      throw new ApiError(409, 'user_exists', 'A user with this username already exists');
    }

    const passwordHash = await bcrypt.hash(password, env.security.bcryptSaltRounds);
    const user = await userModel.create({
      email,
      username,
      passwordHash,
      firstName: first_name,
      lastName: last_name,
      mobile,
    });

    await auditLogModel.record({
      userId: req.adminUser.id,
      eventType: 'ADMIN_USER_CREATED',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: { createdUserId: user.id },
    });

    res.status(201).json({ user: userModel.toPublic(user) });
  })
);

// PATCH /admin/users/:id
router.patch(
  '/:id',
  asyncHandler(async (req, res) => {
    const user = await userModel.findById(req.params.id);
    if (!user) throw new ApiError(404, 'not_found', 'User not found');

    const { first_name, last_name, mobile, profile_photo } = req.body;
    const updated = await userModel.updateProfile(user.id, {
      firstName: first_name,
      lastName: last_name,
      mobile,
      profilePhoto: profile_photo,
    });

    res.json({ user: userModel.toPublic(updated) });
  })
);

// POST /admin/users/:id/reset-password
router.post(
  '/:id/reset-password',
  asyncHandler(async (req, res) => {
    const user = await userModel.findById(req.params.id);
    if (!user) throw new ApiError(404, 'not_found', 'User not found');

    const { new_password } = req.body;
    if (!new_password || new_password.length < 8) {
      throw new ApiError(400, 'invalid_request', 'new_password must be at least 8 characters');
    }

    const passwordHash = await bcrypt.hash(new_password, env.security.bcryptSaltRounds);
    await userModel.setPasswordHash(user.id, passwordHash);

    // A password reset is a security event: force re-authentication
    // everywhere, the same way a compromised-password response should.
    await refreshTokenModel.revokeAllForUser(user.id);

    await auditLogModel.record({
      userId: req.adminUser.id,
      eventType: 'ADMIN_PASSWORD_RESET',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: { targetUserId: user.id },
    });

    res.json({ message: 'Password reset. All refresh tokens for this user have been revoked.' });
  })
);

// POST /admin/users/:id/deactivate
router.post(
  '/:id/deactivate',
  asyncHandler(async (req, res) => {
    const user = await userModel.findById(req.params.id);
    if (!user) throw new ApiError(404, 'not_found', 'User not found');

    const updated = await userModel.setStatus(user.id, 'inactive');
    await refreshTokenModel.revokeAllForUser(user.id);

    await auditLogModel.record({
      userId: req.adminUser.id,
      eventType: 'ADMIN_USER_DEACTIVATED',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: { targetUserId: user.id },
    });

    res.json({ user: userModel.toPublic(updated) });
  })
);

// POST /admin/users/:id/activate  (also clears any lockout)
router.post(
  '/:id/activate',
  asyncHandler(async (req, res) => {
    const user = await userModel.findById(req.params.id);
    if (!user) throw new ApiError(404, 'not_found', 'User not found');

    const updated = await userModel.setStatus(user.id, 'active');

    await auditLogModel.record({
      userId: req.adminUser.id,
      eventType: 'ADMIN_USER_ACTIVATED',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: { targetUserId: user.id },
    });

    res.json({ user: userModel.toPublic(updated) });
  })
);

// GET /admin/users/:id/roles
router.get(
  '/:id/roles',
  asyncHandler(async (req, res) => {
    const user = await userModel.findById(req.params.id);
    if (!user) throw new ApiError(404, 'not_found', 'User not found');
    res.json({ roles: await userRoleModel.listForUser(user.id) });
  })
);

// POST /admin/users/:id/roles   body: { role_name, application_code? }
router.post(
  '/:id/roles',
  asyncHandler(async (req, res) => {
    const user = await userModel.findById(req.params.id);
    if (!user) throw new ApiError(404, 'not_found', 'User not found');

    const { role_name, application_code } = req.body;
    if (!role_name) throw new ApiError(400, 'invalid_request', 'role_name is required');

    await userRoleModel.assignRole({
      userId: user.id,
      roleName: role_name,
      applicationCode: application_code,
    });

    await auditLogModel.record({
      userId: req.adminUser.id,
      eventType: 'ROLE_ASSIGNED',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: { targetUserId: user.id, role: role_name, applicationCode: application_code || null },
    });

    res.status(201).json({ roles: await userRoleModel.listForUser(user.id) });
  })
);

// DELETE /admin/users/:id/roles   body: { role_name, application_code? }
router.delete(
  '/:id/roles',
  asyncHandler(async (req, res) => {
    const user = await userModel.findById(req.params.id);
    if (!user) throw new ApiError(404, 'not_found', 'User not found');

    const { role_name, application_code } = req.body;
    if (!role_name) throw new ApiError(400, 'invalid_request', 'role_name is required');

    await userRoleModel.removeRole({
      userId: user.id,
      roleName: role_name,
      applicationCode: application_code,
    });

    await auditLogModel.record({
      userId: req.adminUser.id,
      eventType: 'ROLE_REMOVED',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: { targetUserId: user.id, role: role_name, applicationCode: application_code || null },
    });

    res.json({ roles: await userRoleModel.listForUser(user.id) });
  })
);

module.exports = router;
