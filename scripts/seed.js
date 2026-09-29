// scripts/seed.js
//
// Usage: npm run db:seed  (run after npm run db:migrate)
// Reads src/db/seed.sql and executes it against the database configured
// in .env. Safe to re-run — every INSERT uses ON DUPLICATE KEY UPDATE.

const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');
require('dotenv').config();

async function main() {
  const sqlPath = path.join(__dirname, '..', 'src', 'db', 'seed.sql');
  const sql = fs.readFileSync(sqlPath, 'utf8');

  const connection = await mysql.createConnection({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    multipleStatements: true,
  });

  console.log(`[seed] Connected to ${process.env.DB_NAME}@${process.env.DB_HOST}`);
  console.log('[seed] Applying src/db/seed.sql ...');

  await connection.query(sql);

  console.log('[seed] Done. Seeded: applications, roles, permissions, role_permissions.');
  console.log('[seed] Note: oauth_clients are NOT seeded here — see module 2 (scripts/create-client.js).');
  await connection.end();
}

main().catch((err) => {
  console.error('[seed] Failed:', err.message);
  process.exit(1);
});
