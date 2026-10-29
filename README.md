# Sastranidhi OAuth Server (`sastranidhi-oauth`)

Centralized OAuth2 / OpenID Connect Identity Provider for the Sastranidhi
ecosystem (`auth.sastranidhi.org`). Issues tokens for four OAuth2 clients —
Purāṇa Tilakam, the Vedic Digital Library, Paripraśna (the QA app), and
IKS-LMS — while `sastranidhi.org` itself stays a public site with no login.

**Current status: Module 6 in progress** (Modules 1-5 complete: OAuth2
Authorization Code flow + JWT/refresh tokens + full OpenID Connect layer
+ Admin APIs + Google/Microsoft social login + TOTP-based MFA). Module 6
— the Paripraśna (QA) app conversion guide — now has a written
integration guide and reference client-side code
(`docs/child-app-integration.md`,
`examples/child-app-express/`), covering the Authorization Code + PKCE
flow, JWKS-based token verification, refresh rotation, and logout/SLO
from a child app's perspective.

**Important scope note on Module 6:** this module's reference code was
written and reasoned through against the actual Modules 1-5
implementation (routes, token shapes, revocation semantics all read
from source, not assumed), but — like the social-login gap noted in
Module 5 below — it has **not been exercised against a real Paripraśna
codebase or a running MySQL/Redis instance** in this sandbox. What's
untested: the actual `/login` -> `/callback` -> token-exchange round
trip against a live server, and JWKS fetch/verify against real issued
tokens. Run through `docs/child-app-integration.md` end-to-end against
a real deployment before treating any child app as production-ready.

**Important scope note on this module:** Google/Microsoft's actual OAuth
endpoints are not reachable from the sandbox this was built in (no network
egress to `accounts.google.com` / `login.microsoftonline.com`), so the
live provider round-trip has never actually been exercised — only:
the account-linking logic (fully tested directly, no network needed), the
outbound redirect construction (verified to build correct authorization
URLs with real `client_id`/`redirect_uri`/`scope`/`state`), and graceful
`501` behavior when unconfigured. **You need to test the real callback
against actual Google/Microsoft OAuth apps yourself** before relying on
this in production — see the testing section below for exactly what was
and wasn't verified.

## What's implemented so far

- Express app with security middleware (helmet, CORS allow-list, rate
  limiting), Redis-backed SSO session, MongoDB (Mongoose) connection, Winston
  logging, health checks.
- MongoDB collections (`src/db/schemas.js`): `users`, `applications`,
  `oauth_clients`, `roles` (each role stores its permission codes),
  `permissions`, `user_roles`, `user_sessions`, `refresh_tokens`,
  `audit_logs`, `user_identities`, `mfa_recovery_codes`,
  `email_verifications`, `password_resets`. The server originally used
  MySQL; the collections keep the old table and column names.
- Passport local strategy (bcrypt, account locking after 5 failed logins).
- OAuth2 Authorization Code flow (`GET /oauth/authorize`, `POST
  /oauth/token`, `POST /oauth/revoke`) with Redis-stored single-use codes,
  optional PKCE (S256), and refresh token rotation.
- Full OpenID Connect layer: discovery document, JWKS, `/userinfo`, and
  `id_token`s — all signed **RS256** with a real RSA keypair, so any child
  app can verify tokens itself via the published public key, no shared
  secret required.
- `scripts/create-client.js` to register OAuth2 clients, `scripts/generate-keys.js`
  to generate the signing keypair.
- Admin APIs (`/admin/*`) for users, roles, sessions, and audit logs —
  gated by permissions checked fresh from the database on every request
  (not trusted from the access token), so revoking an admin's access takes
  effect on their very next request. `scripts/promote-admin.js` bootstraps
  the first admin, since the API itself requires one to already exist.
- Google and Microsoft social login (`GET /auth/google`, `GET
  /auth/microsoft` + callbacks), with automatic account linking by
  verified email — a user who registered locally and later signs in with
  Google (or the reverse order) ends up as one account, not two.
- TOTP-based MFA (RFC 6238), hand-implemented on Node's built-in `crypto`
  and verified against the **official RFC 6238 test vectors** — not just
  internal consistency. Includes one-time recovery codes for lost-device
  recovery.

## Prerequisites

- Node.js 18+, a MongoDB database (local or MongoDB Atlas), a running Redis
  instance (for local development: `docker run -d -p 6379:6379 redis:7`).

## Setup

```bash
npm install
cp .env.example .env
```

Edit `.env`:
- `MONGODB_URI` — your MongoDB connection string; the database name is the
  path after the host (e.g. `.../sastranidhi-outh?...`)
- `REDIS_*` — match your Redis
- `SESSION_SECRET` — any long random string
- `ISSUER` — see note below

**About `ISSUER`:** the JWT `iss` claim and every URL in the OIDC discovery
document are built from this. In production it's
`https://auth.sastranidhi.org`. For local testing, set it to wherever
you're actually running (e.g. `ISSUER=http://localhost:4000`) — otherwise
the discovery document advertises endpoints your test client can't reach,
and token issuer validation will mismatch.

Generate the RSA signing keypair:

```bash
node scripts/generate-keys.js
```

Writes `keys/private.pem` (mode 0600, gitignored, never commit) and
`keys/public.pem`. Re-running this **invalidates every existing token and
session** — it refuses to overwrite without `--force`. A real key rotation
would publish the new key in the JWKS `keys` array *alongside* the old one
for a transition window; this server only supports a single active key
today — multi-key rotation is a reasonable future enhancement, not built.

There's no separate "create the database" step: MongoDB creates the
database named in `MONGODB_URI` on first write.

Create the collections and indexes, seed, register a test client, and start
the server:

```bash
npm run db:migrate
npm run db:seed
node scripts/create-client.js --app PARIPRASHNA --redirect-uris "http://localhost:3001/callback"
npm run dev
```

**Copy the `client_secret` `create-client.js` prints — it's bcrypt-hashed
in the database and cannot be retrieved again.**

## Testing everything end-to-end

### Health checks

```bash
curl http://localhost:4000/health
curl http://localhost:4000/health/db
curl http://localhost:4000/health/redis
```

### OIDC discovery + JWKS

```bash
curl http://localhost:4000/.well-known/openid-configuration
curl http://localhost:4000/oidc/jwks
```

### Register a user

```bash
curl -X POST http://localhost:4000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"dev@sastranidhi.org","username":"devuser","password":"SuperSecret123"}'
```

### Full Authorization Code + OIDC flow

```bash
COOKIES=/tmp/cookies.txt

# 1. Log in (establishes the SSO session)
curl -c $COOKIES -b $COOKIES -X POST http://localhost:4000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"dev@sastranidhi.org","password":"SuperSecret123"}'

# 2. Hit /oauth/authorize — now authenticated, so it 302s straight to the
#    client's redirect_uri with ?code=...&state=...
curl -c $COOKIES -b $COOKIES -D - -o /dev/null \
  "http://localhost:4000/oauth/authorize?response_type=code&client_id=PARIPRASHNA&redirect_uri=http://localhost:3001/callback&scope=openid%20profile%20email&state=xyz123&nonce=abc987"
# copy "code" from the Location header, then:

# 3. Exchange the code for tokens
curl -X POST http://localhost:4000/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"authorization_code","code":"<CODE>","redirect_uri":"http://localhost:3001/callback","client_id":"PARIPRASHNA","client_secret":"<CLIENT_SECRET>"}'
```

You get back `{ access_token, token_type, expires_in, refresh_token, scope, id_token }`.
Decode either JWT with:

```bash
python3 -c "import json,base64,sys; p=sys.argv[1].split('.')[1]; p+='='*(-len(p)%4); print(json.dumps(json.loads(base64.urlsafe_b64decode(p)),indent=2))" "<TOKEN>"
```

`access_token` payload:
```json
{
  "sub": "671f3a2b9c1e4d5f6a7b8c9d",
  "email": "dev@sastranidhi.org",
  "username": "devuser",
  "apps": { "LMS": ["TEACHER"], "PARIPRASHNA": ["STUDENT"] },
  "scope": "openid profile email",
  "iss": "http://localhost:4000",
  "aud": "PARIPRASHNA"
}
```
(`sub` is the user's MongoDB id, a 24-character string. `apps` is `{}`
until roles are assigned — see the Admin APIs below.)

`id_token` payload additionally has `nonce` (echoing what you sent to
`/oauth/authorize`) and, since scope included `profile`/`email`:
`name`, `given_name`, `family_name`, `email`, `email_verified`.

### Protected endpoints

```bash
curl http://localhost:4000/auth/me -H "Authorization: Bearer <ACCESS_TOKEN>"
curl http://localhost:4000/oidc/userinfo -H "Authorization: Bearer <ACCESS_TOKEN>"
```

Request a token with bare `scope=openid` (no `profile`/`email`) and call
`/oidc/userinfo` again — you should get back only `{ sub, apps }`. That's
scope-gating working correctly.

### Verifying a token with only the public JWKS (what a child app will do)

```js
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const jwks = await fetch('http://localhost:4000/oidc/jwks').then(r => r.json());
const publicKey = crypto.createPublicKey({ key: jwks.keys[0], format: 'jwk' });
const publicPem = publicKey.export({ type: 'spki', format: 'pem' });

const decoded = jwt.verify(idToken, publicPem, { algorithms: ['RS256'] });
```

I ran exactly this during development — no server secret involved, only
the published JWKS — and it correctly verified a real issued token. That's
the actual proof RS256 + JWKS interoperate, not just that it "should work".

### Refresh token rotation

```bash
curl -X POST http://localhost:4000/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"refresh_token","refresh_token":"<REFRESH_TOKEN>","client_id":"PARIPRASHNA","client_secret":"<CLIENT_SECRET>"}'
```
Re-using the *same* refresh token a second time now fails with
`invalid_grant` — rotation revokes it on first use. Scope is inherited
from the original grant (RFC 6749 §6) if not specified.

### Revocation

```bash
curl -X POST http://localhost:4000/oauth/revoke \
  -H "Content-Type: application/json" \
  -d '{"token":"<ACCESS_TOKEN>","client_id":"PARIPRASHNA","client_secret":"<CLIENT_SECRET>"}'
# /auth/me with that same token now 401s with "Token has been revoked"
```

### Admin APIs

Bootstrap your first admin (there's no API for this on purpose — every
`/admin/*` route requires an existing global admin role):

```bash
node scripts/promote-admin.js --email dev@sastranidhi.org
```

Get an access token the normal way (login + authorize + token exchange,
as above), then:

```bash
curl http://localhost:4000/admin/users -H "Authorization: Bearer <ACCESS_TOKEN>"

curl -X POST http://localhost:4000/admin/users -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"email":"newbie@sastranidhi.org","username":"newbie","password":"NewbiePass123"}'

curl -X POST http://localhost:4000/admin/users/<ID>/roles -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"role_name":"STUDENT","application_code":"LMS"}'

curl -X POST http://localhost:4000/admin/roles -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"name":"LIBRARIAN","description":"Manages the ebook library"}'

curl http://localhost:4000/admin/sessions -H "Authorization: Bearer <ACCESS_TOKEN>"
curl -X DELETE http://localhost:4000/admin/sessions/<SESSION_ID> -H "Authorization: Bearer <ACCESS_TOKEN>"

curl http://localhost:4000/admin/audit-logs -H "Authorization: Bearer <ACCESS_TOKEN>"
```

Confirm enforcement actually works: get a token for a non-admin user and
hit any `/admin/*` route — every one should 403 with
`insufficient_scope`. I verified this for all five route groups during
development, not just assumed it from the middleware code.

Also worth testing directly: **deactivate a user while they have a live
browser session**, then check `/auth/session` with that same cookie — it
should immediately flip to `authenticated: false`, with no new login
involved. This is a fix described below, not incidental behavior.

### MFA (TOTP)

Fully self-contained — no external service involved, so this is tested
completely end-to-end, including against the official RFC 6238 vectors
(see design notes below).

```bash
COOKIES=/tmp/cookies.txt
curl -c $COOKIES -b $COOKIES -X POST http://localhost:4000/auth/login \
  -H "Content-Type: application/json" -d '{"email":"dev@sastranidhi.org","password":"SuperSecret123"}'

# 1. Start setup -- returns a secret + otpauth:// URI (scan this as a QR
#    code, or hand the secret to any RFC-6238-compatible authenticator app,
#    or generate a code programmatically for testing:
curl -c $COOKIES -b $COOKIES -X POST http://localhost:4000/auth/mfa/setup
node -e "console.log(require('./src/utils/totp').generate('<SECRET_FROM_ABOVE>'))"

# 2. Confirm setup with a real code -- this is what actually enables MFA,
#    and returns one-time recovery codes (shown exactly once)
curl -c $COOKIES -b $COOKIES -X POST http://localhost:4000/auth/mfa/verify-setup \
  -H "Content-Type: application/json" -d '{"code":"<CODE>"}'
```

From here, logging in no longer completes in one step:

```bash
# Login now returns { mfa_required: true, mfa_token } instead of a session
curl -X POST http://localhost:4000/auth/login -H "Content-Type: application/json" \
  -d '{"email":"dev@sastranidhi.org","password":"SuperSecret123"}'

# Complete the second factor -- this is what actually establishes the session
curl -c $COOKIES -b $COOKIES -X POST http://localhost:4000/auth/mfa/challenge \
  -H "Content-Type: application/json" \
  -d '{"mfa_token":"<MFA_TOKEN>","code":"<CODE_OR_A_RECOVERY_CODE>"}'
```

A recovery code works exactly once — try the same one twice and the
second attempt correctly fails. Disable MFA with either a TOTP code or an
unused recovery code:

```bash
curl -c $COOKIES -b $COOKIES -X POST http://localhost:4000/auth/mfa/disable \
  -H "Content-Type: application/json" -d '{"code":"<CODE_OR_RECOVERY_CODE>"}'
```

### Social login (Google / Microsoft)

**What was actually verified, and what wasn't — read this before relying
on this feature.** Google's and Microsoft's real OAuth endpoints aren't
reachable from the sandbox this was built in, so the following is true:

- ✅ Account-linking logic (`socialAuthService.findOrCreateUser`) — tested
  directly with fake provider profiles: new-user creation, repeat-login
  returning the same user, auto-linking to an existing local account by
  verified email, and username-collision handling. All four cases pass.
- ✅ Outbound redirect construction — confirmed `GET /auth/google` and
  `GET /auth/microsoft` build correct authorization URLs (right
  `client_id`, `redirect_uri`, `scope`, and a correctly-signed `state`
  carrying `returnTo`) against fake test credentials.
- ✅ Graceful behavior when unconfigured — `501`, not a crash.
- ❌ **The actual callback exchange with a real Google/Microsoft account
  has never been run.** You need to register real OAuth apps with both
  providers and test this yourself before trusting it in production.

To test for real:

1. **Google**: [Google Cloud Console](https://console.cloud.google.com/) →
   create an OAuth 2.0 Client ID (Web application) → set the authorized
   redirect URI to match `GOOGLE_CALLBACK_URL` exactly → put the client
   ID/secret in `.env`.
2. **Microsoft**: [Azure Portal](https://portal.azure.com/) → App
   registrations → new registration → add a redirect URI matching
   `MICROSOFT_CALLBACK_URL` → under API permissions, ensure `User.Read` is
   granted → put the client ID/secret in `.env`.
3. Restart the server, then visit `http://localhost:4000/auth/google` (or
   `/auth/microsoft`) in an actual browser — not curl, since this needs to
   run through a real login prompt.
4. After granting access, confirm you land back at `returnTo` (or `/`)
   with a live session at `/auth/session`, and check the `user_identities`
   collection in MongoDB to see the linked provider record.

## Environment variables

| Variable | Purpose |
|---|---|
| `PORT` | HTTP port |
| `ISSUER` | Canonical URL — becomes JWT `iss` and the base for OIDC discovery URLs |
| `ALLOWED_ORIGINS` | Comma-separated CORS allow-list |
| `MONGODB_URI` | MongoDB connection string, including the database name |
| `MONGODB_POOL_MAX` | Optional, max MongoDB connections (default 10) |
| `REDIS_*` | Redis connection details |
| `SESSION_SECRET`, `SESSION_COOKIE_*` | Express session (SSO session) config |
| `JWT_PRIVATE_KEY_PATH` / `JWT_PUBLIC_KEY_PATH` | RSA keypair paths (see `scripts/generate-keys.js`) |
| `JWT_KEY_ID` | `kid` used in both the JWT header and the JWKS entry |
| `JWT_ACCESS_EXPIRES_IN` / `JWT_REFRESH_EXPIRES_IN` | Token lifetimes |
| `BCRYPT_SALT_ROUNDS` | Password hashing cost factor |
| `RATE_LIMIT_WINDOW_MS` / `RATE_LIMIT_MAX` | Global rate limiter: requests per IP per window (default 1000 per 15 min) |
| `AUTH_RATE_LIMIT_MAX` | Login / signup / token endpoints: requests per IP per 15 min (default 1000) |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` / `GOOGLE_CALLBACK_URL` | Google login — leave `GOOGLE_CLIENT_ID` unset to disable `/auth/google` entirely |
| `MICROSOFT_CLIENT_ID` / `MICROSOFT_CLIENT_SECRET` / `MICROSOFT_CALLBACK_URL` / `MICROSOFT_TENANT` | Microsoft login — same opt-in behavior |
| `MFA_ISSUER_NAME` | Label shown in the authenticator app next to the account |
| `MFA_CHALLENGE_EXPIRES_IN_SECONDS` | How long an `mfa_token` from `/auth/login` stays valid before the user must restart login |
| `LOG_LEVEL` | Winston log level |

`JWT_ACCESS_SECRET` and `JWT_REFRESH_SECRET` from earlier iterations are
gone: the former is replaced by the RSA keypair, and the latter was
**dead from the start** — refresh tokens have always been opaque random
strings stored (SHA-256 hashed) in the database, never JWTs.

## Database (MongoDB)

Collections, fields and indexes are defined in `src/db/schemas.js`.
`npm run db:migrate` creates every collection and its indexes (unique
email, username, client_id, ...) and never drops anything. `npm run db:seed`
applies `src/db/seedData.js` (4 applications, 7 roles with their
permissions, 9 permissions). Both are safe to re-run. `oauth_clients` is
deliberately not seeded, since secrets must be bcrypt-hashed through code —
use `scripts/create-client.js`.

Things that differ from the original MySQL version:
- **Ids are MongoDB ObjectId strings** (e.g. `"671f3a2b9c1e4d5f6a7b8c9d"`),
  so the JWT `sub` claim and every `id` in API responses is a 24-character
  string, not a number. Booleans such as `mfa_enabled` and `is_active` are
  `true`/`false` rather than `1`/`0`.
- **Emails are stored lowercased and trimmed**, and looked up the same way
  (MySQL's collation made them case-insensitive; MongoDB doesn't), so
  `Dev@X.org ` and `dev@x.org` are one account. Usernames stay
  case-insensitive through a collation index.
- **Role permissions live on the role** (`roles.permissions` is an array of
  permission codes) instead of a `role_permissions` join table.
- **No foreign-key cascades**: deleting a role also deletes its
  `user_roles` in `roleModel.remove`.

`refresh_tokens` includes a `scope` field (added after initial design, to
support RFC 6749 §6 scope inheritance on refresh).

## API endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health`, `/health/db`, `/health/redis` | Liveness / readiness |
| POST | `/auth/register` | Create a user |
| POST | `/auth/login` | Passport local login, establishes SSO session |
| GET | `/auth/login-page` | Placeholder server-rendered login form — **replace with the real React login UI later** |
| GET | `/auth/session` | Is there a live SSO session right now? |
| POST | `/auth/logout` | Destroy the SSO session (`?everywhere=true` also revokes all refresh tokens) |
| GET | `/auth/me` | Decode the caller's own Bearer access token |
| GET | `/oauth/authorize` | Authorization Code flow entry point |
| POST | `/oauth/token` | `authorization_code` / `refresh_token` grants |
| POST | `/oauth/revoke` | Revoke an access or refresh token |
| GET | `/.well-known/openid-configuration` | OIDC discovery document |
| GET | `/oidc/jwks` | Public JWK Set |
| GET | `/oidc/userinfo` | Scope-gated profile claims for the caller |
| GET/POST | `/admin/users`, `/admin/users/:id` | List/create/view users — requires `users.manage` |
| PATCH | `/admin/users/:id` | Edit profile fields |
| POST | `/admin/users/:id/reset-password` | Admin sets a new password, revokes all refresh tokens |
| POST | `/admin/users/:id/deactivate`, `/activate` | Toggle account status |
| GET/POST/DELETE | `/admin/users/:id/roles` | View/assign/remove role assignments |
| GET/POST/PATCH/DELETE | `/admin/roles`, `/admin/roles/:id` | Role CRUD — requires `roles.manage` |
| POST/DELETE | `/admin/roles/:id/permissions[/:code]` | Assign/remove permissions on a role |
| GET | `/admin/permissions` | Reference list of all permissions |
| GET | `/admin/sessions` | List active SSO sessions — requires `sessions.manage` |
| DELETE | `/admin/sessions/:sessionId` | Force logout (kills the Redis session + its `user_sessions` record) |
| GET | `/admin/audit-logs` | Paginated, filterable audit trail — requires `audit.view` |
| GET | `/auth/google`, `/auth/microsoft` | Start social login — 501 if that provider isn't configured |
| GET | `/auth/google/callback`, `/auth/microsoft/callback` | Provider redirects back here; establishes the SSO session |
| POST | `/auth/mfa/setup` | Generate a new TOTP secret (not yet enabled) |
| POST | `/auth/mfa/verify-setup` | Confirm a code from that secret — this is what actually enables MFA, returns recovery codes once |
| POST | `/auth/mfa/challenge` | Second step of login for an MFA-enabled account — establishes the session |
| POST | `/auth/mfa/disable` | Turn MFA off (TOTP code or a recovery code) |

The Paripraśna (QA) app conversion guide (module 6) lives at
[`docs/child-app-integration.md`](docs/child-app-integration.md), with
runnable reference code in
[`examples/child-app-express/`](examples/child-app-express/). It's IdP
consumption, not new IdP surface — no new endpoints were added to this
table for it.

## npm packages

`express`, `helmet`, `cors`, `cookie-parser`, `express-session`,
`connect-redis`, `express-rate-limit`, `mongoose`, `ioredis`, `dotenv`,
`winston`, `uuid`, `bcrypt`, `jsonwebtoken`, `passport`, `passport-local`,
`passport-google-oauth20`, `passport-oauth2` (used directly, hand-configured
for Microsoft's v2.0 endpoints — see design notes). RS256 signing, JWK
export, base32, and TOTP all use Node's built-in `crypto` module — no
extra dependencies needed for any of that.

## Design notes and bugs caught during development

These were caught by actually running the server against real MySQL/Redis
during development, not just by reading the code — worth knowing before
you review or extend this.

- **`/oauth/authorize` validates the client *before* checking login.**
  Doing it the other way round means an unauthenticated request with a
  bogus `redirect_uri` still gets shown a real login page — turning the
  login form into a phishing/open-redirect primitive. The OAuth 2.0
  Security BCP calls this out explicitly.
- **`returnTo` travels through the URL/form, not the session.** Passport
  ≥0.6 calls `req.session.regenerate()` inside `req.login()` as a
  session-fixation defense, which silently wipes any custom session keys
  set before login (like a session-stored `returnTo`). Fixed by passing it
  through the login page's URL and form instead. `POST /auth/login` only
  ever honors a same-origin relative path here, never an absolute URL, so
  it can't become an open redirect either.
- **Refresh tokens are hashed with SHA-256, not bcrypt.** Unlike
  passwords, these are already 256 bits of random data — bcrypt's slow
  salted hashing defends low-entropy human input against offline
  guessing, which doesn't apply here. SHA-256 gives fast, indexable
  equality lookups.
- **`jwt.sign()` rejects a payload with `sub` alongside a `subject`
  option** — they conflict. Payload `sub` is used throughout; the
  `subject` sign option is never passed.
- **`connect-redis@7` is ESM-only under CJS `require`** — you need
  `require('connect-redis').default`, not a named `RedisStore` export.
- **RS256 + JWKS, not HS256.** JWKS only makes sense with asymmetric
  signing; this was the headline design decision of module 3, verified by
  independently checking a token's signature using nothing but the
  published public key (see the testing section above).
- **`jwt.verify()` pins `algorithms: ['RS256']` explicitly everywhere.**
  Without this, the library trusts whatever algorithm a token's header
  claims — the "algorithm confusion" attack class.
- **Admin permission checks are scoped to *global* roles only**
  (`user_roles.application_id IS NULL`). An earlier draft of the
  permission-lookup query checked any role regardless of application scope
  — which would have let an LMS-scoped `TEACHER` (who legitimately has
  `courses.manage` *within LMS*) also pass admin checks on this Identity
  Provider itself. Caught this auditing the query before it shipped.
- **Deactivating a user didn't actually stop them, in two separate ways —
  both caught by testing the actual behavior, not just reading the code:**
  1. Passport's local strategy only blocked `status === 'locked'`, never
     `'inactive'`. A deactivated user could still log in and mint brand
     new tokens.
  2. Worse: `passport.deserializeUser` never checked status at all. A
     browser session created *before* deactivation stayed fully
     authenticated on every subsequent request — including
     `/oauth/authorize`, which would keep silently issuing fresh
     authorization codes (and therefore fresh tokens) through "silent
     SSO", with no re-authentication ever required. Fixed by rejecting
     non-active users in `deserializeUser`, which is what makes
     deactivation take effect on the user's very next request rather than
     only their next *login*.
  3. A third, subtler bug fed the first one: `userModel.resetFailedLogins`
     — called on every successful login to clear a lockout — unconditionally
     set `status = 'active'`, regardless of current status. A single
     login that slipped through bug #1 silently undid an admin's
     deactivation as a side effect. Fixed by only flipping
     `locked -> active`, never touching `inactive`.
- **Bearer access tokens are intentionally NOT re-checked against the
  database on every request.** This is a deliberate scope boundary, not an
  oversight: resource-server verification (`/auth/me`, `/oidc/userinfo`,
  and eventually child apps' own APIs) stays fully self-contained JWT
  verification — that's the entire point of RS256 + JWKS. A deactivated
  user's *already-issued, unexpired* access token can keep working for up
  to its 15-minute lifetime; this is the same tradeoff every JWT-based IdP
  makes (Auth0, Okta, Google included) unless you add token introspection.
  What changed in this module is that *getting a new token* — via login or
  via an existing session at `/oauth/authorize` — is now blocked
  immediately, closing the two paths that had no time-bound at all.
- **TOTP/base32 were hand-implemented rather than using a library** — and
  verified against the **official RFC 6238 Appendix B test vectors**
  (6/6 exact matches) and RFC 4648 base32 vectors, not just checked for
  internal round-trip consistency. This matters more than usual for a
  hand-rolled crypto primitive: passing your own round-trip test proves
  encode/decode agree with *each other*, not that either is spec-correct.
- **`userModel.toPublic()` didn't strip `mfa_secret`.** Every other
  sensitive field (`password_hash`, lockout fields) was already excluded,
  but the raw base32 TOTP secret was missing from that list — meaning
  `GET /admin/users/:id` or `GET /auth/session` would have leaked it
  verbatim to anyone who could read that response. Caught before this
  shipped, not after.
- **A copy-paste typo turned a comment into a syntax error.** A few lines
  in `stateToken.js`'s header comment started with `--` instead of `//`,
  which is not a JS comment marker — Node refused to load the file at all.
  Caught immediately by actually requiring the module, which is exactly
  why every utility in this project gets run, not just read, before
  shipping.
- **MFA login is a two-step, stateless handoff, not a session held in
  limbo.** `/auth/login` for an MFA-enabled account never touches
  `req.session` — it returns a signed `mfa_token` (via the same
  `stateToken` helper used for the social-login `state` param) containing
  the userId and an expiry. `/auth/mfa/challenge` is what actually calls
  `req.login()`, only after the second factor verifies. No server-side
  "pending login" record exists in between, which sidesteps the
  session-regenerate timing issue entirely for this flow, the same way
  passing `returnTo` through `state` sidesteps it for social login.
- **Social account linking is by verified email, deliberately.** Google
  and Microsoft both only include an email in the profile they hand back
  once it's verified on their end — that's what makes it safe to
  auto-link a new social identity to an existing local account with a
  matching email, rather than requiring an explicit "link your Google
  account" step first. Tested directly (new user, repeat login, linking
  to an existing account, username collisions) without needing real
  provider network access, since the linking logic itself has no
  dependency on how the profile arrived.
- **Refresh tokens vs. recovery codes use the same hashing rationale, SHA-256
  not bcrypt** — both are high-entropy machine-generated values (a 256-bit
  opaque token, a 40-bit hex code checked against a small fixed set),
  not low-entropy human passwords, so bcrypt's deliberate slowness buys
  nothing here and fast equality lookup is what the access pattern needs.
- **What was NOT tested: the real Google/Microsoft callback exchange.**
  This sandbox has no network route to `accounts.google.com` or
  `login.microsoftonline.com`. Everything up to that boundary — account
  linking, redirect URL construction, state signing, graceful
  not-configured handling — was verified directly; the live provider
  round-trip was not, and needs testing against real registered OAuth
  apps before this feature is trusted in production.
- **Module 6's reference child-app code was written by reading the actual
  IdP source, not by re-deriving the flow from the spec alone** — the
  token shapes in `docs/child-app-integration.md` (e.g. the `apps` claim,
  refresh-token rotation behavior, revocation semantics) were taken
  directly from `tokenService.js` and `routes/oauth.js` rather than
  assumed. What's still untested: an actual `/login` -> `/callback` round
  trip against a running server (no MySQL/Redis available in this
  sandbox), and JWKS verification against a real, freshly-issued token
  rather than a hand-inspected payload shape.
