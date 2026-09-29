// src/middleware/requirePermission.js
//
// Must run AFTER requireAccessToken (needs req.token.sub). Loads the
// caller's global permissions and current status fresh from the database
// on every request — deliberately not trusted from the access token's
// "apps" claim, so that revoking an admin's role or deactivating their
// account takes effect on the very next request rather than waiting out
// the token's 15-minute lifetime.

const asyncHandler = require('../utils/asyncHandler');
const ApiError = require('../utils/ApiError');
const userModel = require('../models/userModel');
const permissionModel = require('../models/permissionModel');

function requirePermission(permissionCode) {
  return asyncHandler(async (req, res, next) => {
    const user = await userModel.findById(req.token.sub);
    if (!user || user.status !== 'active') {
      throw new ApiError(403, 'account_inactive', 'Account is not active');
    }

    const permissions = await permissionModel.getGlobalPermissionCodesForUser(user.id);
    if (!permissions.includes(permissionCode)) {
      throw new ApiError(
        403,
        'insufficient_scope',
        `Missing required global permission: ${permissionCode}`
      );
    }

    req.adminUser = user;
    next();
  });
}

module.exports = requirePermission;
