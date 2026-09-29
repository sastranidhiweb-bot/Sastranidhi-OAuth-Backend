-- ============================================================
-- Sastranidhi OAuth Server — Seed Data
-- Run via: npm run db:seed  (after db:migrate)
-- Does NOT seed oauth_clients — client secrets must be created
-- through scripts/create-client.js (module 2) so they're bcrypt-hashed,
-- never inserted as plaintext via SQL.
-- ============================================================

-- Applications (matches architecture doc; main portal is a public site,
-- not an OAuth client, so it is intentionally not listed here)
INSERT INTO applications (code, name, base_url) VALUES
  ('PURANATILAKAM', 'Purāṇa Tilakam', 'https://puranatilakam.sastranidhi.org'),
  ('EBOOK_LIBRARY', 'Vedic Digital Library', 'https://www.ebook-lib.sastranidhi.org'),
  ('PARIPRASHNA',   'Paripraśna',            'https://pariprashna.sastranidhi.org'),
  ('LMS',           'IKS-LMS',               'https://lms.sastranidhi.org')
ON DUPLICATE KEY UPDATE name = VALUES(name), base_url = VALUES(base_url);

-- Roles
INSERT INTO roles (name, description) VALUES
  ('SUPER_ADMIN',   'Full control over the Identity Provider and all applications'),
  ('ADMIN',         'Administrative access within an application'),
  ('CONTENT_ADMIN', 'Manages content within an application'),
  ('COURSE_ADMIN',  'Manages courses within the LMS'),
  ('TEACHER',       'Teaches / authors course content'),
  ('STUDENT',       'Enrolled learner'),
  ('USER',          'Default authenticated user')
ON DUPLICATE KEY UPDATE description = VALUES(description);

-- Permissions (starter set — extend as each application's needs grow)
INSERT INTO permissions (permission_code, permission_name) VALUES
  ('users.manage',       'Create, update, deactivate users'),
  ('roles.manage',       'Create, update, delete roles and assign permissions'),
  ('sessions.manage',    'View active sessions and force logout'),
  ('audit.view',         'View audit logs'),
  ('applications.manage','Manage OAuth client registrations'),
  ('content.manage',     'Manage content within an application'),
  ('courses.manage',     'Create and edit courses'),
  ('questions.create',   'Create questions (Paripraśna)'),
  ('questions.answer',   'Answer questions (Paripraśna)')
ON DUPLICATE KEY UPDATE permission_name = VALUES(permission_name);

-- Role -> Permission mapping
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p WHERE r.name = 'SUPER_ADMIN'
ON DUPLICATE KEY UPDATE role_id = role_id;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'ADMIN' AND p.permission_code IN
  ('users.manage', 'sessions.manage', 'audit.view', 'content.manage')
ON DUPLICATE KEY UPDATE role_id = role_id;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'CONTENT_ADMIN' AND p.permission_code IN ('content.manage')
ON DUPLICATE KEY UPDATE role_id = role_id;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'COURSE_ADMIN' AND p.permission_code IN ('courses.manage')
ON DUPLICATE KEY UPDATE role_id = role_id;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'TEACHER' AND p.permission_code IN ('courses.manage', 'questions.answer')
ON DUPLICATE KEY UPDATE role_id = role_id;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'STUDENT' AND p.permission_code IN ('questions.create')
ON DUPLICATE KEY UPDATE role_id = role_id;
