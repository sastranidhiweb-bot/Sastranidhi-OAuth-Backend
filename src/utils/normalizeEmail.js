// src/utils/normalizeEmail.js
//
// MySQL compared emails case-insensitively by default; MongoDB doesn't.
// Every email is stored and looked up in this one normalized form, so
// "Dev@Sastranidhi.org " and "dev@sastranidhi.org" are the same account.

function normalizeEmail(email) {
  return typeof email === 'string' ? email.trim().toLowerCase() : email;
}

module.exports = normalizeEmail;
