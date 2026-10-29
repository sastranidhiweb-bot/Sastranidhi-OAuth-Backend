// scripts/seed.js
//
// Usage: npm run db:seed  (run after npm run db:migrate)
// Applies src/db/seedData.js to the MongoDB database named in MONGODB_URI.
// Safe to re-run — every write is an upsert, and role permissions are only
// ever added, never removed.

const mongoose = require('mongoose');
const db = require('../src/config/db');
const { Application, Permission, Role } = require('../src/db/schemas');
const seedData = require('../src/db/seedData');

async function main() {
  await db.connect();
  console.log(`[seed] Connected to database "${mongoose.connection.name}"`);

  for (const { code, name, base_url } of seedData.applications) {
    await Application.updateOne({ code }, { $set: { name, base_url } }, { upsert: true });
  }

  for (const { permission_code, permission_name } of seedData.permissions) {
    await Permission.updateOne({ permission_code }, { $set: { permission_name } }, { upsert: true });
  }

  for (const { name, description, permissions } of seedData.roles) {
    await Role.updateOne(
      { name },
      { $set: { description }, $addToSet: { permissions: { $each: permissions } } },
      { upsert: true }
    );
  }

  console.log(
    `[seed] Done. Seeded: ${seedData.applications.length} applications, ${seedData.roles.length} roles, ` +
      `${seedData.permissions.length} permissions.`
  );
  console.log('[seed] Note: oauth_clients are NOT seeded here — see scripts/create-client.js.');
  await db.disconnect();
}

main().catch((err) => {
  console.error('[seed] Failed:', err.message);
  process.exit(1);
});
