// src/db/schemas.js
//
// Mongoose models for every MongoDB collection this server uses.
// Collection names match the old MySQL table names one-to-one, and fields
// keep their snake_case names, so routes, services and API responses see
// exactly the same field names as before.
//
// MySQL foreign keys used to clean up related rows automatically
// (ON DELETE CASCADE). MongoDB has no equivalent, so the model files do
// that cleanup themselves where it matters (e.g. roleModel.remove also
// deletes that role's user_roles).

const mongoose = require('mongoose');

const { Schema } = mongoose;
const { ObjectId, Mixed } = Schema.Types;

const createdOnly = { timestamps: { createdAt: 'created_at', updatedAt: false } };
const createdAndUpdated = { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } };

// Case-insensitive matching (MySQL's default collation behaved this way
// for usernames, so "DevUser" and "devuser" can't both exist).
const CASE_INSENSITIVE = { locale: 'en', strength: 2 };

const nullableString = { type: String, default: null };
const nullableDate = { type: Date, default: null };

// ------------------------------------------------------------------
// users
// ------------------------------------------------------------------
const userSchema = new Schema(
  {
    email: { type: String, required: true, lowercase: true, trim: true },
    username: { type: String, required: true, trim: true },
    password_hash: nullableString, // null for social-only accounts
    first_name: nullableString,
    last_name: nullableString,
    mobile: nullableString,
    profile_photo: nullableString,
    status: { type: String, enum: ['active', 'inactive', 'locked'], default: 'active' },
    email_verified_at: nullableDate,
    failed_login_attempts: { type: Number, default: 0 },
    locked_until: nullableDate,
    mfa_enabled: { type: Boolean, default: false },
    mfa_secret: nullableString, // base32 TOTP secret; null until MFA is set up
  },
  { ...createdAndUpdated, collection: 'users' }
);
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ username: 1 }, { unique: true, collation: CASE_INSENSITIVE });

// ------------------------------------------------------------------
// applications (the child apps registered with the IdP)
// ------------------------------------------------------------------
const applicationSchema = new Schema(
  {
    code: { type: String, required: true }, // e.g. 'LMS', 'PARIPRASHNA'
    name: { type: String, required: true },
    base_url: { type: String, required: true },
    is_active: { type: Boolean, default: true },
  },
  { ...createdOnly, collection: 'applications' }
);
applicationSchema.index({ code: 1 }, { unique: true });

// ------------------------------------------------------------------
// oauth_clients (OAuth2 client registration per application)
// ------------------------------------------------------------------
const oauthClientSchema = new Schema(
  {
    client_id: { type: String, required: true },
    client_secret_hash: { type: String, required: true },
    application_id: { type: ObjectId, ref: 'Application', required: true },
    redirect_uris: { type: String, required: true }, // comma-separated, exact-match on validation
    grant_types: { type: String, default: 'authorization_code,refresh_token' },
    scopes: { type: String, default: 'openid,profile,email' },
    token_endpoint_auth_method: { type: String, default: 'client_secret_post' },
    is_active: { type: Boolean, default: true },
  },
  { ...createdAndUpdated, collection: 'oauth_clients' }
);
oauthClientSchema.index({ client_id: 1 }, { unique: true });

// ------------------------------------------------------------------
// roles — permission codes are stored on the role itself (this replaces
// the old role_permissions join table)
// ------------------------------------------------------------------
const roleSchema = new Schema(
  {
    name: { type: String, required: true }, // SUPER_ADMIN, ADMIN, CONTENT_ADMIN, ...
    description: nullableString,
    permissions: { type: [String], default: [] }, // permission_code values, e.g. 'users.manage'
  },
  { ...createdOnly, collection: 'roles' }
);
roleSchema.index({ name: 1 }, { unique: true });

// ------------------------------------------------------------------
// permissions
// ------------------------------------------------------------------
const permissionSchema = new Schema(
  {
    permission_code: { type: String, required: true }, // e.g. 'users.manage'
    permission_name: { type: String, required: true },
  },
  { ...createdOnly, collection: 'permissions' }
);
permissionSchema.index({ permission_code: 1 }, { unique: true });

// ------------------------------------------------------------------
// user_roles (application-scoped; application_id null = global role)
// ------------------------------------------------------------------
const userRoleSchema = new Schema(
  {
    user_id: { type: ObjectId, ref: 'User', required: true },
    role_id: { type: ObjectId, ref: 'Role', required: true },
    application_id: { type: ObjectId, ref: 'Application', default: null },
  },
  { ...createdOnly, collection: 'user_roles' }
);
userRoleSchema.index({ user_id: 1, role_id: 1, application_id: 1 }, { unique: true });
userRoleSchema.index({ role_id: 1 });

// ------------------------------------------------------------------
// user_sessions (mirrors the active Redis SSO session for admin visibility)
// ------------------------------------------------------------------
const userSessionSchema = new Schema(
  {
    session_id: { type: String, required: true },
    user_id: { type: ObjectId, ref: 'User', required: true },
    ip_address: nullableString,
    device_info: nullableString,
    expires_at: { type: Date, required: true },
  },
  { ...createdOnly, collection: 'user_sessions' }
);
userSessionSchema.index({ session_id: 1 }, { unique: true });
userSessionSchema.index({ user_id: 1 });

// ------------------------------------------------------------------
// refresh_tokens (token value itself is stored hashed, never plaintext)
// ------------------------------------------------------------------
const refreshTokenSchema = new Schema(
  {
    user_id: { type: ObjectId, ref: 'User', required: true },
    client_id: { type: String, required: true },
    token_hash: { type: String, required: true },
    scope: nullableString,
    expires_at: { type: Date, required: true },
    revoked_at: nullableDate,
  },
  { ...createdOnly, collection: 'refresh_tokens' }
);
refreshTokenSchema.index({ token_hash: 1 });
refreshTokenSchema.index({ user_id: 1 });
refreshTokenSchema.index({ client_id: 1 });

// ------------------------------------------------------------------
// audit_logs
// ------------------------------------------------------------------
const auditLogSchema = new Schema(
  {
    user_id: { type: ObjectId, ref: 'User', default: null },
    event_type: { type: String, required: true }, // e.g. LOGIN_SUCCESS, LOGIN_FAILED, LOGOUT
    ip_address: nullableString,
    user_agent: nullableString,
    metadata: { type: Mixed, default: null },
  },
  { ...createdOnly, collection: 'audit_logs' }
);
auditLogSchema.index({ user_id: 1 });
auditLogSchema.index({ event_type: 1 });
auditLogSchema.index({ created_at: -1 });

// ------------------------------------------------------------------
// user_identities (links a local user to a Google/Microsoft account)
// ------------------------------------------------------------------
const userIdentitySchema = new Schema(
  {
    user_id: { type: ObjectId, ref: 'User', required: true },
    provider: { type: String, enum: ['google', 'microsoft'], required: true },
    provider_user_id: { type: String, required: true }, // the provider's stable subject/id
    email_at_provider: nullableString,
  },
  { ...createdOnly, collection: 'user_identities' }
);
userIdentitySchema.index({ provider: 1, provider_user_id: 1 }, { unique: true });
userIdentitySchema.index({ user_id: 1 });

// ------------------------------------------------------------------
// mfa_recovery_codes (one-time-use backup codes for MFA)
// ------------------------------------------------------------------
const mfaRecoveryCodeSchema = new Schema(
  {
    user_id: { type: ObjectId, ref: 'User', required: true },
    code_hash: { type: String, required: true }, // SHA-256 hex, same rationale as refresh_tokens.token_hash
    used_at: nullableDate,
  },
  { ...createdOnly, collection: 'mfa_recovery_codes' }
);
mfaRecoveryCodeSchema.index({ user_id: 1, code_hash: 1 });

// ------------------------------------------------------------------
// email_verifications (signup email-verification codes; one live
// document per email — starting again replaces the previous code)
// ------------------------------------------------------------------
const emailVerificationSchema = new Schema(
  {
    email: { type: String, required: true, lowercase: true, trim: true },
    code_hash: { type: String, required: true }, // bcrypt hash of the 6-digit code — never the code itself
    attempt_count: { type: Number, default: 0 },
    max_attempts: { type: Number, default: 5 },
    last_sent_at: { type: Date, default: Date.now }, // drives the resend cooldown
    expires_at: { type: Date, required: true },
    verified_at: nullableDate,
  },
  { ...createdOnly, collection: 'email_verifications' }
);
emailVerificationSchema.index({ email: 1 }, { unique: true });

// ------------------------------------------------------------------
// password_resets (forgot-password tokens)
// ------------------------------------------------------------------
const passwordResetSchema = new Schema(
  {
    user_id: { type: ObjectId, ref: 'User', required: true },
    token_hash: { type: String, required: true }, // SHA-256 hex of the opaque reset token
    expires_at: { type: Date, required: true },
    used_at: nullableDate,
  },
  { ...createdOnly, collection: 'password_resets' }
);
passwordResetSchema.index({ user_id: 1 });
passwordResetSchema.index({ token_hash: 1 });

module.exports = {
  CASE_INSENSITIVE,
  User: mongoose.model('User', userSchema),
  Application: mongoose.model('Application', applicationSchema),
  OAuthClient: mongoose.model('OAuthClient', oauthClientSchema),
  Role: mongoose.model('Role', roleSchema),
  Permission: mongoose.model('Permission', permissionSchema),
  UserRole: mongoose.model('UserRole', userRoleSchema),
  UserSession: mongoose.model('UserSession', userSessionSchema),
  RefreshToken: mongoose.model('RefreshToken', refreshTokenSchema),
  AuditLog: mongoose.model('AuditLog', auditLogSchema),
  UserIdentity: mongoose.model('UserIdentity', userIdentitySchema),
  MfaRecoveryCode: mongoose.model('MfaRecoveryCode', mfaRecoveryCodeSchema),
  EmailVerification: mongoose.model('EmailVerification', emailVerificationSchema),
  PasswordReset: mongoose.model('PasswordReset', passwordResetSchema),
};
