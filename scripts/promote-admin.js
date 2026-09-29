// scripts/promote-admin.js
//
// Bootstraps the very first administrator. There's no API endpoint for
// this on purpose: every /admin/* route requires an existing global
// SUPER_ADMIN/ADMIN role to even call it, so the first one has to be
// granted outside the API, directly against the database.
//
// Usage:
//   node scripts/promote-admin.js --email dev@sastranidhi.org
//   node scripts/promote-admin.js --email dev@sastranidhi.org --role ADMIN

require('dotenv').config();
const db = require('../src/config/db');
const userModel = require('../src/models/userModel');
const userRoleModel = require('../src/models/userRoleModel');

function parseArgs() {
  const args = process.argv.slice(2);
  const out = {};
  for (let i = 0; i < args.length; i += 2) {
    out[args[i].replace(/^--/, '')] = args[i + 1];
  }
  return out;
}

async function main() {
  const args = parseArgs();
  const roleName = args.role || 'SUPER_ADMIN';

  if (!args.email) {
    console.error('Usage: node scripts/promote-admin.js --email <email> [--role SUPER_ADMIN|ADMIN]');
    process.exit(1);
  }

  const user = await userModel.findByEmail(args.email);
  if (!user) {
    console.error(`[promote-admin] No user with email "${args.email}". They need to register first.`);
    process.exit(1);
  }

  // No applicationCode passed -> global role (application_id IS NULL),
  // which is exactly what requirePermission.js checks for admin access.
  await userRoleModel.assignRole({ userId: user.id, roleName });

  console.log(`[promote-admin] Granted global role "${roleName}" to ${user.email} (id ${user.id}).`);
  await db.closePool();
}

main().catch((err) => {
  console.error('[promote-admin] Failed:', err.message);
  process.exit(1);
});
