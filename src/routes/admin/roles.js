// src/routes/admin/roles.js
const express = require('express');

const asyncHandler = require('../../utils/asyncHandler');
const ApiError = require('../../utils/ApiError');

const roleModel = require('../../models/roleModel');
const permissionModel = require('../../models/permissionModel');
const auditLogModel = require('../../models/auditLogModel');

const router = express.Router();

// GET /admin/roles
router.get(
  '/',
  asyncHandler(async (req, res) => {
    res.json({ roles: await roleModel.listAll() });
  })
);

// GET /admin/roles/:id
router.get(
  '/:id',
  asyncHandler(async (req, res) => {
    const role = await roleModel.findById(req.params.id);
    if (!role) throw new ApiError(404, 'not_found', 'Role not found');
    res.json({ role });
  })
);

// POST /admin/roles   body: { name, description? }
router.post(
  '/',
  asyncHandler(async (req, res) => {
    const { name, description } = req.body;
    if (!name) throw new ApiError(400, 'invalid_request', 'name is required');
    if (await roleModel.findByName(name)) {
      throw new ApiError(409, 'role_exists', `Role "${name}" already exists`);
    }

    const role = await roleModel.create({ name, description });

    await auditLogModel.record({
      userId: req.adminUser.id,
      eventType: 'ROLE_CREATED',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: { roleId: role.id, name },
    });

    res.status(201).json({ role });
  })
);

// PATCH /admin/roles/:id   body: { description }
router.patch(
  '/:id',
  asyncHandler(async (req, res) => {
    const role = await roleModel.findById(req.params.id);
    if (!role) throw new ApiError(404, 'not_found', 'Role not found');

    const updated = await roleModel.update(role.id, { description: req.body.description });

    await auditLogModel.record({
      userId: req.adminUser.id,
      eventType: 'ROLE_UPDATED',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: { roleId: role.id },
    });

    res.json({ role: updated });
  })
);

// DELETE /admin/roles/:id
router.delete(
  '/:id',
  asyncHandler(async (req, res) => {
    const role = await roleModel.findById(req.params.id);
    if (!role) throw new ApiError(404, 'not_found', 'Role not found');

    await roleModel.remove(role.id);

    await auditLogModel.record({
      userId: req.adminUser.id,
      eventType: 'ROLE_DELETED',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: { roleId: role.id, name: role.name },
    });

    res.status(204).send();
  })
);

// POST /admin/roles/:id/permissions   body: { permission_code }
router.post(
  '/:id/permissions',
  asyncHandler(async (req, res) => {
    const role = await roleModel.findById(req.params.id);
    if (!role) throw new ApiError(404, 'not_found', 'Role not found');

    const { permission_code } = req.body;
    if (!permission_code) throw new ApiError(400, 'invalid_request', 'permission_code is required');
    if (!(await permissionModel.findByCode(permission_code))) {
      throw new ApiError(404, 'not_found', `Unknown permission_code "${permission_code}"`);
    }

    await roleModel.addPermission(role.id, permission_code);

    await auditLogModel.record({
      userId: req.adminUser.id,
      eventType: 'PERMISSION_ASSIGNED',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: { roleId: role.id, permissionCode: permission_code },
    });

    res.status(201).json({ role: await roleModel.findById(role.id) });
  })
);

// DELETE /admin/roles/:id/permissions/:permissionCode
router.delete(
  '/:id/permissions/:permissionCode',
  asyncHandler(async (req, res) => {
    const role = await roleModel.findById(req.params.id);
    if (!role) throw new ApiError(404, 'not_found', 'Role not found');

    await roleModel.removePermission(role.id, req.params.permissionCode);

    await auditLogModel.record({
      userId: req.adminUser.id,
      eventType: 'PERMISSION_REMOVED',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: { roleId: role.id, permissionCode: req.params.permissionCode },
    });

    res.status(204).send();
  })
);

module.exports = router;
