// scripts/verify-edmingle-sso.js
//
// Local sanity check for the Edmingle SSO token, independent of a real
// login/session. Signs a sample payload exactly the way
// routes/edmingleSso.js does, then verifies algorithm, expiry window,
// and required fields against Edmingle's stated contract.
//
// Usage: node scripts/verify-edmingle-sso.js

require('dotenv').config();
const jwt = require('jsonwebtoken');

const secret = process.env.EDMINGLE_SSO_SECRET;

if (!secret) {
  console.error('❌ EDMINGLE_SSO_SECRET is not set in .env — cannot sign a test token.');
  process.exit(1);
}

const nowSeconds = Math.floor(Date.now() / 1000);

const payload = {
  iss: process.env.ISSUER || 'Sastranidhi Central IdP',
  iat: nowSeconds,
  exp: nowSeconds + 120,
  first_name: 'Test',
  last_name: 'User',
  email: 'test.user@example.com',
  contact_number: '9999999999',
};

const token = jwt.sign(payload, secret, { algorithm: 'HS256' });

console.log('\n--- Signed JWT ---');
console.log(token);

// --- Header check ---
const decodedHeader = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString());
console.log('\n--- Header ---');
console.log(decodedHeader);

if (decodedHeader.alg !== 'HS256') {
  console.error('\n❌ FAIL: algorithm is not HS256 (Edmingle requires HS256).');
  process.exit(1);
}

// --- Verify + decode ---
let verified;
try {
  verified = jwt.verify(token, secret, { algorithms: ['HS256'] });
} catch (err) {
  console.error('\n❌ FAIL: token did not verify against EDMINGLE_SSO_SECRET.', err.message);
  process.exit(1);
}

console.log('\n--- Verified Payload ---');
console.log(verified);

// --- Lifespan check (Edmingle requires exactly 120s) ---
const lifespan = verified.exp - verified.iat;
console.log(`\nLifespan: ${lifespan}s (Edmingle requires exactly 120s)`);
if (lifespan !== 120) {
  console.error('\n❌ FAIL: token lifespan is not 120 seconds.');
  process.exit(1);
}

// --- Required fields check ---
const requiredFields = ['first_name', 'last_name', 'email', 'contact_number'];
const missing = requiredFields.filter((field) => !(field in verified));
if (missing.length > 0) {
  console.error(`\n❌ FAIL: payload missing required field(s): ${missing.join(', ')}`);
  process.exit(1);
}

// --- Simulate the actual redirect URL ---
const lmsUrl = process.env.EDMINGLE_LMS_URL || 'https://your-academy.edmingle.com';
const sampleRedirect = `${lmsUrl}/?jwt=${token}&edmingle_redirect_url=${encodeURIComponent(
  `${lmsUrl}/myaccount/`
)}`;

console.log('\n✅ Token shape matches Edmingle SSO requirements.');
console.log('\n--- Sample redirect Edmingle would receive ---');
console.log(sampleRedirect);
console.log(
  `\nNote: this token expires in 120s from generation — if you're pasting the redirect URL into a browser to test manually, do it fast.`
);