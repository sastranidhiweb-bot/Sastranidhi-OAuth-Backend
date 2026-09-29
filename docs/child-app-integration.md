# Child App Integration Guide (Module 6)

How a Sastranidhi child app — this guide is written for **Paripraśna**,
but it's identical for Purāṇa Tilakam, the Vedic Digital Library, and
IKS-LMS — integrates with `sastranidhi-oauth` for login and API
authorization.

Reference code for every step below lives in
[`examples/child-app-express/`](../examples/child-app-express/).

## 0. Prerequisites

- `sastranidhi-oauth` running and reachable at `ISSUER` (e.g.
  `https://auth.sastranidhi.org`, or `http://localhost:4000` in dev).
- The child app has its own session mechanism (cookie-based Express
  session, or equivalent) to hold the PKCE verifier across the redirect
  round trip, and — in the reference implementation — the resulting
  tokens. (An API-only app can skip a server session and hand tokens to
  its own frontend instead; see "Where you store tokens" below.)

## 1. Register the client (one-time, on the IdP)

```bash
node scripts/create-client.js \
  --app PARIPRASHNA \
  --redirect-uris "https://pariprashna.sastranidhi.org/callback" \
  --scopes "openid,profile,email"
```

This prints a `client_secret` **once** — store it in the child app's own
secrets, never in source control. The IdP only ever stores its bcrypt
hash (`oauthClientModel` / `clientService.authenticateClient`).

For local development, register a second redirect URI
(`http://localhost:3001/callback` or whatever the app's dev server uses)
in the same call, comma-separated — redirect_uri validation is
exact-match against this list (`oauthClientModel.isRedirectUriRegistered`),
so a URI not registered here will be rejected at `/oauth/authorize`.

## 2. Login: redirect to `/oauth/authorize`

`GET /login` on the child app (see `authRoutes.js`):

1. Generates a PKCE `code_verifier` + `code_challenge` (S256) and a random
   `state`, stores the verifier + state in the child app's own session.
2. Redirects the browser to:

```
${ISSUER}/oauth/authorize
  ?response_type=code
  &client_id=PARIPRASHNA
  &redirect_uri=https://pariprashna.sastranidhi.org/callback
  &scope=openid%20profile%20email
  &state=<random>
  &nonce=<random>
  &code_challenge=<S256 challenge>
  &code_challenge_method=S256
```

**Silent SSO**: if the user already has a live session from logging into
another child app (or the IdP directly), `/oauth/authorize` redirects
straight back with a `code` — no login screen. This is the whole point of
the shared Redis-backed session; nothing extra is needed on the child
app's side to get this for free.

## 3. Callback: exchange the code for tokens

`GET /callback` (see `authRoutes.js`):

1. Verify the returned `state` matches what was stored at step 2 (CSRF
   defense).
2. `POST ${ISSUER}/oauth/token` with `grant_type=authorization_code`,
   the `code`, `redirect_uri`, `client_id`, `client_secret`, and the
   stored `code_verifier`.
3. Response: `access_token` (RS256 JWT, 15 min default), `refresh_token`
   (opaque, 30 days default), `id_token` (since `openid` was requested),
   `expires_in`.

The authorization code is single-use and expires in 60 seconds
(`authorizationCodeService`) — exchange it immediately, don't cache it.

## 4. Verifying API requests: JWKS, not `/auth/me`

`/auth/me` on the IdP is explicitly a demo/debug endpoint. For real
traffic, verify the access token **locally** using the published JWKS —
that's the entire reason Module 3 moved to RS256:

```
GET ${ISSUER}/oidc/jwks
```

`examples/child-app-express/verifyAccessToken.js` does this: fetches the
JWKS once, caches the public key by `kid`, and calls
`jwt.verify(token, key, { algorithms: ['RS256'], issuer, audience })` —
the same algorithm-pinning the IdP itself uses in
`tokenService.verifyAccessToken`, so a child app can't be tricked into
accepting an unsigned or HS256-forged token either.

The verified payload (`req.token`) has the shape:

```json
{
  "sub": "42",
  "email": "user@example.com",
  "username": "someuser",
  "apps": { "PARIPRASHNA": ["STUDENT"], "LMS": ["TEACHER"] },
  "scope": "openid profile email",
  "aud": "PARIPRASHNA",
  "iss": "https://auth.sastranidhi.org",
  "jti": "...",
  "iat": ...,
  "exp": ...
}
```

`apps` is the authorization claim — check `req.token.apps.PARIPRASHNA`
for this app's own roles. Don't check roles for *other* apps as if
they applied here; a `TEACHER` role in `LMS` says nothing about
permissions inside Paripraśna.

**Deliberate scope boundary, inherited from the IdP**: an access token is
verified purely locally, with no per-request database round-trip. If a
user is deactivated mid-session, their already-issued access token keeps
working until it naturally expires (≤15 min) — the IdP's own admin APIs
have this same tradeoff (see the IdP's README, "Design notes" section).
If Paripraśna needs *immediate* revocation for something (e.g. banning a
user mid-exam), that needs an app-level check, not a token-verification
change.

## 5. Refreshing

`POST /refresh` on the child app calls
`${ISSUER}/oauth/token` with `grant_type=refresh_token`. The IdP
**rotates** refresh tokens — the old one is revoked the instant a new one
is issued (`handleRefreshTokenGrant` in `routes/oauth.js`), so:

- Always store the *new* `refresh_token` from the response, discard the
  old one.
- If a refresh call ever 400s with `invalid_grant`, treat it as "session
  expired" and send the user back through `/login` — don't retry with the
  same refresh token.

## 6. Logout and Single Logout (SLO) — read this carefully

`POST /logout` on the child app (see `authRoutes.js`) revokes *this app's*
refresh token at `${ISSUER}/oauth/revoke` and clears the child app's own
session.

**What this does NOT do**: end the shared SSO session at
`auth.sastranidhi.org`. The architecture diagram's "Single Logout (SLO)
Flow" describes the user clicking logout and every app being signed out —
that requires the child app to *also* redirect the browser through the
IdP's own logout:

```
POST ${ISSUER}/auth/logout
```

(with the SSO cookie attached, i.e. `credentials: 'include'` if calling
via `fetch` from the browser, or a full-page redirect). This destroys the
Redis session and — with `?everywhere=true` — revokes every refresh token
for that user across all four apps in one call
(`refreshTokenModel.revokeAllForUser`, wired into `POST /auth/logout` on
the IdP). Without this step, a user who "logs out" of only Paripraśna
would still be silently signed into the other three apps via silent SSO
the next time they visit one.

**Recommendation for Paripraśna's actual logout button**: call the
child app's own `/logout` first (revoke its refresh token, clear its
session), then redirect the browser to
`${ISSUER}/auth/logout?everywhere=true` (or call it via `fetch` with
credentials included) as the last step, landing the user back on
Paripraśna's own logged-out page afterward.

## 7. What's still open / not this module's job

- **Real Google/Microsoft callback exchange** (Module 5's flagged gap):
  unaffected by this module — if Paripraśna wants social login, that path
  still needs testing against real registered OAuth apps first.
- **Consent screen**: not needed yet — all four apps are first-party, so
  `/oauth/authorize` auto-approves (see the comment in `routes/oauth.js`).
  Only relevant if a third-party client is ever registered.
- **Full cross-app SLO redirect** as described in step 6 is a
  *recommendation* here, not yet wired into any child app's actual
  logout button — that's Paripraśna-side (or the other apps') work once
  they adopt this guide, not something this module changes on the IdP.
