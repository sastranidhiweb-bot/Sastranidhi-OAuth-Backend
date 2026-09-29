-- ============================================================
-- Sastranidhi OAuth Server — MySQL Schema
-- Run via: npm run db:migrate  (executes this file)
-- Charset utf8mb4 throughout so names/scripture text (Devanagari,
-- IAST diacritics) in profiles/app names store correctly.
-- ============================================================

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ------------------------------------------------------------
-- users
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  id                  BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  email               VARCHAR(255) NOT NULL,
  username            VARCHAR(100) NOT NULL,
  password_hash       VARCHAR(255) NULL,           -- NULL for social-only accounts
  first_name          VARCHAR(100) NULL,
  last_name           VARCHAR(100) NULL,
  mobile              VARCHAR(20) NULL,
  profile_photo       VARCHAR(500) NULL,
  status              ENUM('active', 'inactive', 'locked') NOT NULL DEFAULT 'active',
  email_verified_at    DATETIME NULL,
  failed_login_attempts SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  locked_until         DATETIME NULL,
  mfa_enabled          TINYINT(1) NOT NULL DEFAULT 0,
  mfa_secret           VARCHAR(64) NULL,            -- base32 TOTP secret; NULL until MFA is set up
  created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_users_email (email),
  UNIQUE KEY uq_users_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------------------------------------------------
-- applications  (the 4 child apps registered with the IdP)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS applications (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  code         VARCHAR(50) NOT NULL,       -- e.g. 'LMS', 'PARIPRASHNA'
  name         VARCHAR(150) NOT NULL,
  base_url     VARCHAR(255) NOT NULL,
  is_active    TINYINT(1) NOT NULL DEFAULT 1,
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_applications_code (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------------------------------------------------
-- oauth_clients  (OAuth2 client registration per application)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS oauth_clients (
  id                        BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  client_id                 VARCHAR(100) NOT NULL,
  client_secret_hash        VARCHAR(255) NOT NULL,
  application_id            BIGINT UNSIGNED NOT NULL,
  redirect_uris             TEXT NOT NULL,              -- comma-separated, exact-match on validation
  grant_types               VARCHAR(255) NOT NULL DEFAULT 'authorization_code,refresh_token',
  scopes                    VARCHAR(255) NOT NULL DEFAULT 'openid,profile,email',
  token_endpoint_auth_method VARCHAR(50) NOT NULL DEFAULT 'client_secret_post',
  is_active                 TINYINT(1) NOT NULL DEFAULT 1,
  created_at                DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at                DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_oauth_clients_client_id (client_id),
  CONSTRAINT fk_oauth_clients_application
    FOREIGN KEY (application_id) REFERENCES applications(id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------------------------------------------------
-- roles
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS roles (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name         VARCHAR(50) NOT NULL,        -- SUPER_ADMIN, ADMIN, CONTENT_ADMIN, ...
  description  VARCHAR(255) NULL,
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_roles_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------------------------------------------------
-- permissions
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS permissions (
  id                BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  permission_code   VARCHAR(100) NOT NULL,   -- e.g. 'users.manage'
  permission_name   VARCHAR(150) NOT NULL,
  created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_permissions_code (permission_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------------------------------------------------
-- role_permissions
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS role_permissions (
  role_id        BIGINT UNSIGNED NOT NULL,
  permission_id  BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (role_id, permission_id),
  CONSTRAINT fk_role_permissions_role
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
  CONSTRAINT fk_role_permissions_permission
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------------------------------------------------
-- user_roles  (application-scoped; application_id NULL = global role)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_roles (
  id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id         BIGINT UNSIGNED NOT NULL,
  role_id         BIGINT UNSIGNED NOT NULL,
  application_id  BIGINT UNSIGNED NULL,
  created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_user_roles (user_id, role_id, application_id),
  CONSTRAINT fk_user_roles_user
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_user_roles_role
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
  CONSTRAINT fk_user_roles_application
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------------------------------------------------
-- user_sessions  (mirrors the active Redis SSO session for admin visibility)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_sessions (
  session_id   VARCHAR(191) NOT NULL PRIMARY KEY,
  user_id      BIGINT UNSIGNED NOT NULL,
  ip_address   VARCHAR(45) NULL,
  device_info  VARCHAR(255) NULL,
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at   DATETIME NOT NULL,
  KEY idx_user_sessions_user (user_id),
  CONSTRAINT fk_user_sessions_user
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------------------------------------------------
-- refresh_tokens  (token value itself is stored hashed, never plaintext)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id         BIGINT UNSIGNED NOT NULL,
  client_id       VARCHAR(100) NOT NULL,
  token_hash      VARCHAR(255) NOT NULL,
  scope           VARCHAR(255) NULL,
  expires_at      DATETIME NOT NULL,
  revoked_at      DATETIME NULL,
  created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_refresh_tokens_user (user_id),
  KEY idx_refresh_tokens_client (client_id),
  CONSTRAINT fk_refresh_tokens_user
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------------------------------------------------
-- audit_logs  (addition beyond the architecture doc's table list,
-- needed to back the "Admin Features -> Audit Logs" requirement)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id      BIGINT UNSIGNED NULL,
  event_type   VARCHAR(100) NOT NULL,   -- e.g. LOGIN_SUCCESS, LOGIN_FAILED, LOGOUT, ROLE_CHANGED
  ip_address   VARCHAR(45) NULL,
  user_agent   VARCHAR(255) NULL,
  metadata     JSON NULL,
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_audit_logs_user (user_id),
  KEY idx_audit_logs_event (event_type),
  CONSTRAINT fk_audit_logs_user
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------------------------------------------------
-- user_identities  (links a local user to a Google/Microsoft account;
-- module 5 addition)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_identities (
  id                BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id           BIGINT UNSIGNED NOT NULL,
  provider          ENUM('google', 'microsoft') NOT NULL,
  provider_user_id  VARCHAR(255) NOT NULL,   -- the provider's stable subject/id for this account
  email_at_provider VARCHAR(255) NULL,
  created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_user_identities_provider_subject (provider, provider_user_id),
  KEY idx_user_identities_user (user_id),
  CONSTRAINT fk_user_identities_user
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------------------------------------------------
-- mfa_recovery_codes  (one-time-use backup codes issued when MFA is
-- enabled, in case the user loses their authenticator device; module 5
-- addition)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id      BIGINT UNSIGNED NOT NULL,
  code_hash    VARCHAR(255) NOT NULL,   -- SHA-256 hex, same rationale as refresh_tokens.token_hash
  used_at      DATETIME NULL,
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_mfa_recovery_codes_user (user_id),
  CONSTRAINT fk_mfa_recovery_codes_user
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------------------------------------------------
-- email_verifications  (module 7 — signup email-verification codes)
--
-- One pending verification per email at a time: starting a new one (or
-- resending) invalidates the previous row rather than accumulating rows,
-- so "the old code becomes invalid when a new one is requested" is just
-- "there's only ever one live row per email", not extra logic scattered
-- across the service.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS email_verifications (
  id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  email           VARCHAR(255) NOT NULL,
  code_hash       VARCHAR(255) NOT NULL,   -- SHA-256 hex of the 6-digit code — never store the code itself
  attempt_count   INT UNSIGNED NOT NULL DEFAULT 0,
  max_attempts    INT UNSIGNED NOT NULL DEFAULT 5,
  last_sent_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,  -- drives the resend cooldown
  expires_at      DATETIME NOT NULL,
  verified_at     DATETIME NULL,
  created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_email_verifications_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------------------------------------------------
-- password_resets  (module 7 — forgot-password tokens)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS password_resets (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id      BIGINT UNSIGNED NOT NULL,
  token_hash   VARCHAR(255) NOT NULL,   -- SHA-256 hex of the opaque reset token — never store the raw token
  expires_at   DATETIME NOT NULL,
  used_at      DATETIME NULL,
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_password_resets_user (user_id),
  KEY idx_password_resets_token_hash (token_hash),
  CONSTRAINT fk_password_resets_user
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

SET FOREIGN_KEY_CHECKS = 1;
