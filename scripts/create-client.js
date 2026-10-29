// scripts/create-client.js
//
// Registers an OAuth2 client for an existing application (seeded in module 1).
// The plaintext client_secret is only ever shown once, here — the database
// stores only its bcrypt hash.
//
// Usage:
//   node scripts/create-client.js --app LMS --client-id LMS \
//     --redirect-uris https://lms.sastranidhi.org/callback \
//     --scopes "openid,profile,email"
//
// --client-id defaults to the application code (matches the architecture
// doc's "OAuth Client Configuration" table, where Client ID == app code).

require('dotenv').config();
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const db = require('../src/config/db');
const applicationModel = require('../src/models/applicationModel');
const oauthClientModel = require('../src/models/oauthClientModel');
const env = require('../src/config/env');

function parseArgs() {
  const args = process.argv.slice(2);
  const out = {};
  for (let i = 0; i < args.length; i += 2) {
    const key = args[i].replace(/^--/, '');
    out[key] = args[i + 1];
  }
  return out;
}

async function main() {
  const args = parseArgs();

  if (!args.app || !args['redirect-uris']) {
    console.error(
      'Usage: node scripts/create-client.js --app <APP_CODE> --redirect-uris <uri1,uri2> [--client-id <id>] [--scopes <s1,s2>]'
    );
    process.exit(1);
  }

  await db.connect();

  const application = await applicationModel.findByCode(args.app);
  if (!application) {
    console.error(`[create-client] No application with code "${args.app}". Run npm run db:seed first.`);
    process.exit(1);
  }

  const clientId = args['client-id'] || args.app;
  const clientSecret = crypto.randomBytes(32).toString('base64url');
  const clientSecretHash = await bcrypt.hash(clientSecret, env.security.bcryptSaltRounds);

  const client = await oauthClientModel.create({
    clientId,
    clientSecretHash,
    applicationId: application.id,
    redirectUris: args['redirect-uris'],
    scopes: args.scopes || 'openid,profile,email',
  });

  console.log('\n[create-client] OAuth client registered:\n');
  console.log(`  application:    ${application.name} (${application.code})`);
  console.log(`  client_id:      ${client.client_id}`);
  console.log(`  client_secret:  ${clientSecret}`);
  console.log(`  redirect_uris:  ${client.redirect_uris}`);
  console.log(`  scopes:         ${client.scopes}`);
  console.log(
    '\n[create-client] Save the client_secret now — it is hashed in the database and cannot be retrieved again.\n'
  );

  await db.disconnect();
}

main().catch((err) => {
  console.error('[create-client] Failed:', err.message);
  process.exit(1);
});
