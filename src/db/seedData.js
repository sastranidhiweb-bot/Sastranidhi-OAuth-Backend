// src/db/seedData.js
//
// Starting data applied by `npm run db:seed` (scripts/seed.js).
// Does NOT include oauth_clients — client secrets must be created through
// scripts/create-client.js so they're bcrypt-hashed, never stored as
// plaintext seed data.

// Applications (matches architecture doc; main portal is a public site,
// not an OAuth client, so it is intentionally not listed here)
const applications = [
  { code: 'PURANATILAKAM', name: 'Purāṇa Tilakam', base_url: 'https://puranatilakam.sastranidhi.org' },
  { code: 'EBOOK_LIBRARY', name: 'Vedic Digital Library', base_url: 'https://www.ebook-lib.sastranidhi.org' },
  { code: 'PARIPRASHNA', name: 'Paripraśna', base_url: 'https://pariprashna.sastranidhi.org' },
  { code: 'LMS', name: 'IKS-LMS', base_url: 'https://lms.sastranidhi.org' },
];

// Permissions (starter set — extend as each application's needs grow)
const permissions = [
  { permission_code: 'users.manage', permission_name: 'Create, update, deactivate users' },
  { permission_code: 'roles.manage', permission_name: 'Create, update, delete roles and assign permissions' },
  { permission_code: 'sessions.manage', permission_name: 'View active sessions and force logout' },
  { permission_code: 'audit.view', permission_name: 'View audit logs' },
  { permission_code: 'applications.manage', permission_name: 'Manage OAuth client registrations' },
  { permission_code: 'content.manage', permission_name: 'Manage content within an application' },
  { permission_code: 'courses.manage', permission_name: 'Create and edit courses' },
  { permission_code: 'questions.create', permission_name: 'Create questions (Paripraśna)' },
  { permission_code: 'questions.answer', permission_name: 'Answer questions (Paripraśna)' },
];

// Roles and their permission codes. SUPER_ADMIN gets every permission above.
const roles = [
  {
    name: 'SUPER_ADMIN',
    description: 'Full control over the Identity Provider and all applications',
    permissions: permissions.map((p) => p.permission_code),
  },
  {
    name: 'ADMIN',
    description: 'Administrative access within an application',
    permissions: ['users.manage', 'sessions.manage', 'audit.view', 'content.manage'],
  },
  { name: 'CONTENT_ADMIN', description: 'Manages content within an application', permissions: ['content.manage'] },
  { name: 'COURSE_ADMIN', description: 'Manages courses within the LMS', permissions: ['courses.manage'] },
  { name: 'TEACHER', description: 'Teaches / authors course content', permissions: ['courses.manage', 'questions.answer'] },
  { name: 'STUDENT', description: 'Enrolled learner', permissions: ['questions.create'] },
  { name: 'USER', description: 'Default authenticated user', permissions: [] },
];

module.exports = { applications, permissions, roles };
