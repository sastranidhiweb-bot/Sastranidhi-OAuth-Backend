// src/config/env.js
//
// Loads .env and validates that everything the server needs to boot
// safely is actually present. Fails fast on startup instead of failing
// confusingly later (e.g. mid-request when a JWT secret is undefined).

require('dotenv').config();

const REQUIRED_IN_ALL_ENVS = [
  'PORT',
  'ISSUER',
  'DB_HOST',
  'DB_PORT',
  'DB_USER',
  'DB_PASSWORD',
  'DB_NAME',
  'REDIS_HOST',
  'REDIS_PORT',
  'SESSION_SECRET',
];

function requireEnv() {
  const missing = REQUIRED_IN_ALL_ENVS.filter((key) => !process.env[key]);

  if (missing.length > 0) {
    // eslint-disable-next-line no-console
    console.error(
      `[env] Missing required environment variables: ${missing.join(', ')}\n` +
        '[env] Copy .env.example to .env and fill in real values before starting the server.'
    );
    process.exit(1);
  }
}

requireEnv();

const env = {
  nodeEnv: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT, 10),
  issuer: process.env.ISSUER,
  allowedOrigins: (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),

  db: {
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT, 10),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    poolMin: parseInt(process.env.DB_POOL_MIN || '2', 10),
    poolMax: parseInt(process.env.DB_POOL_MAX || '10', 10),
  },

  redis: {
    host: process.env.REDIS_HOST,
    port: parseInt(process.env.REDIS_PORT, 10),
    password: process.env.REDIS_PASSWORD || undefined,
    db: parseInt(process.env.REDIS_DB || '0', 10),
  },

  session: {
    secret: process.env.SESSION_SECRET,
    cookieName: process.env.SESSION_COOKIE_NAME || 'sastranidhi.sid',
    cookieDomain: process.env.SESSION_COOKIE_DOMAIN || undefined,
    maxAgeMs: parseInt(process.env.SESSION_MAX_AGE_MS || '1800000', 10),
  },

  jwt: {
    privateKeyPath: process.env.JWT_PRIVATE_KEY_PATH || './keys/private.pem',
    publicKeyPath: process.env.JWT_PUBLIC_KEY_PATH || './keys/public.pem',
    keyId: process.env.JWT_KEY_ID || 'sastranidhi-key-1',
    accessExpiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '30d',
  },

  security: {
    bcryptSaltRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS || '12', 10),
    rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10),
    rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX || '100', 10),
  },

  // Optional -- a provider's strategy is only registered (see
  // config/passport.js) if its clientId is actually set. The server boots
  // fine with none of these configured; /auth/google and /auth/microsoft
  // simply won't exist until they are.
  google: {
    clientId: process.env.GOOGLE_CLIENT_ID || null,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET || null,
    callbackUrl: process.env.GOOGLE_CALLBACK_URL || null,
  },
  microsoft: {
    clientId: process.env.MICROSOFT_CLIENT_ID || null,
    clientSecret: process.env.MICROSOFT_CLIENT_SECRET || null,
    callbackUrl: process.env.MICROSOFT_CALLBACK_URL || null,
    tenant: process.env.MICROSOFT_TENANT || 'common',
  },
  edmingle: {
    ssoSecret: process.env.EDMINGLE_SSO_SECRET || null,
    lmsUrl: process.env.EDMINGLE_LMS_URL || null,
  },

  mfa: {
    issuerName: process.env.MFA_ISSUER_NAME || 'Sastranidhi',
    challengeExpiresInSeconds: parseInt(process.env.MFA_CHALLENGE_EXPIRES_IN_SECONDS || '300', 10),
  },

  // The portal (React app) that now owns the user-facing login/signup
  // experience. /oauth/authorize redirects here (not to the built-in
  // /auth/login-page form) when a request arrives with no valid session.
  // Also the one extra origin (beyond a relative "/..." path) that
  // returnTo values are allowed to point at — see utils/returnTo.js.
  frontendBaseUrl: process.env.FRONTEND_BASE_URL || 'http://localhost:5173',

  // Optional -- if EMAIL_TRANSPORT is unset or 'console', verification
  // codes and reset links are logged instead of sent (see
  // services/emailService.js). Set to 'smtp' + the SMTP_* vars for a real
  // deployment. Never commit real SMTP credentials.
  email: {
    transport: process.env.EMAIL_TRANSPORT || 'console',
    from: process.env.EMAIL_FROM || 'Sastranidhi <no-reply@sastranidhi.org>',
    smtp: {
      host: process.env.SMTP_HOST || null,
      port: parseInt(process.env.SMTP_PORT || '587', 10),
      secure: process.env.SMTP_SECURE === 'true',
      user: process.env.SMTP_USER || null,
      password: process.env.SMTP_PASSWORD || null,
    },
  },

  logLevel: process.env.LOG_LEVEL || 'info',
};

module.exports = env;
