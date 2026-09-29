// scripts/migrate.js
//
// Usage: npm run db:migrate
// Reads src/db/schema.sql and executes it statement-by-statement against
// the database configured in .env. Safe to re-run (uses CREATE TABLE IF
// NOT EXISTS throughout).

const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');
require('dotenv').config();

async function main() {
  const sqlPath = path.join(__dirname, '..', 'src', 'db', 'schema.sql');
  const sql = fs.readFileSync(sqlPath, 'utf8');

  const connection = await mysql.createConnection({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    multipleStatements: true,
  });

  console.log(`[migrate] Connected to ${process.env.DB_NAME}@${process.env.DB_HOST}`);
  console.log('[migrate] Applying src/db/schema.sql ...');

  await connection.query(sql);

  console.log('[migrate] Done.');
  await connection.end();
}

main().catch((err) => {
  console.error('[migrate] Failed:', err.message);
  process.exit(1);
});
