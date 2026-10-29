// scripts/migrate.js
//
// Usage: npm run db:migrate
// Creates every collection and its indexes (unique email, username,
// client_id, ...) in the MongoDB database named in MONGODB_URI. Safe to
// re-run: existing collections, indexes and documents are left as they
// are, and nothing is ever dropped.

const mongoose = require('mongoose');
const db = require('../src/config/db');
const schemas = require('../src/db/schemas');

async function main() {
  await db.connect();
  console.log(`[migrate] Connected to database "${mongoose.connection.name}"`);

  const models = Object.values(schemas).filter((value) => value && value.prototype instanceof mongoose.Model);
  for (const model of models) {
    await model.createCollection();
    await model.createIndexes();
    console.log(`[migrate]   ${model.collection.collectionName}: collection + indexes ready`);
  }

  console.log('[migrate] Done.');
  await db.disconnect();
}

main().catch((err) => {
  console.error('[migrate] Failed:', err.message);
  process.exit(1);
});
