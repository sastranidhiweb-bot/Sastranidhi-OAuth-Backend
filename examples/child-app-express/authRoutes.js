// examples/child-app-express/authRoutes.js
//
// Reference implementation of the child-app side of the Authorization
// Code + PKCE flow, written for Paripraśna but identical for any of the
// four child apps -- only IDP_CLIENT_ID / IDP_CLIENT_SECRET / the
// registered redirect_uri differ between them.
//
// This is intentionally a SEPARATE, minimal Express app/router -- it does
// not depend on anything in ../../src. A real child app already has its
// own server; this file shows the handful of routes it needs to add.
//
// Flow implemented:
//   GET  /login            -> generates PKCE verifier/challenge + state,
//                              stores verifier in the child app's own
//                              session, redirects to the IdP's /oauth/authorize
//   GET  /callback          -> exchanges the returned code (+ verifier) for
//                              tokens at the IdP's /oauth/token
//   POST /refresh           -> rotates the refresh token
//   POST /logout            -> revokes the refresh token at the IdP and
//                              clears the local session (does NOT by
//                              itself end the IdP's SSO session -- see the
//                              Single Logout note in the guide)
//
// Where tokens are stored here (req.session) is a reference choice, not a
// requirement -- an API-only child app might instead hand the access/
// refresh tokens straight to its own frontend and skip server sessions
// entirely. Whatever you choose, refresh tokens are bearer secrets: never
// put them anywhere JS on the page can read them (no localStorage), the
// same reasoning the IdP itself applies to its own session cookie
// (httpOnly, see src/app.js).

const express = require('express');
const crypto = require('crypto');

const router = express.Router();

// --- Configuration (env vars in a real app) --------------------------
const IDP_ISSUER = process.env.IDP_ISSUER || 'https://auth.sastranidhi.org';
const IDP_CLIENT_ID = process.env.IDP_CLIENT_ID || 'PARIPRASHNA';
const IDP_CLIENT_SECRET = process.env.IDP_CLIENT_SECRET; // required for /oauth/token, /oauth/revoke
const REDIRECT_URI = process.env.IDP_REDIRECT_URI || 'https://pariprashna.sastranidhi.org/callback';
const SCOPE = 'openid profile email';

// --- PKCE helpers ------------------------------------------------------
// Mirrors the verification the IdP performs in src/utils/crypto.js
// (verifyPkce): S256 only, base64url without padding.
function base64url(buffer) {
  return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function generatePkcePair() {
  const verifier = base64url(crypto.randomBytes(32));
  const challenge = base64url(crypto.createHash('sha256').update(verifier).digest());
  return { verifier, challenge };
}

// ------------------------------------------------------------------
// GET /login
// ------------------------------------------------------------------
router.get('/login', (req, res) => {
  const { verifier, challenge } = generatePkcePair();
  const state = base64url(crypto.randomBytes(16));
  const nonce = base64url(crypto.randomBytes(16));

  // Stored in THIS app's own session -- not the IdP's -- so it survives
  // the round trip to /oauth/authorize and back to /callback.
  req.session.pkceVerifier = verifier;
  req.session.oauthState = state;
  req.session.oauthNonce = nonce;

  const authorizeUrl = new URL('/oauth/authorize', IDP_ISSUER);
  authorizeUrl.searchParams.set('response_type', 'code');
  authorizeUrl.searchParams.set('client_id', IDP_CLIENT_ID);
  authorizeUrl.searchParams.set('redirect_uri', REDIRECT_URI);
  authorizeUrl.searchParams.set('scope', SCOPE);
  authorizeUrl.searchParams.set('state', state);
  authorizeUrl.searchParams.set('nonce', nonce);
  authorizeUrl.searchParams.set('code_challenge', challenge);
  authorizeUrl.searchParams.set('code_challenge_method', 'S256');

  res.redirect(authorizeUrl.toString());
});

// ------------------------------------------------------------------
// GET /callback
// ------------------------------------------------------------------
router.get('/callback', async (req, res) => {
  const { code, state, error, error_description: errorDescription } = req.query;

  if (error) {
    return res.status(400).send(`Login failed: ${error_description || error}`);
  }
  if (!code || !state) {
    return res.status(400).send('Missing code or state on callback');
  }
  // CSRF defense: the state we get back must match the one we generated
  // for this browser's session at /login.
  if (state !== req.session.oauthState) {
    return res.status(400).send('Invalid state parameter');
  }

  const verifier = req.session.pkceVerifier;
  delete req.session.pkceVerifier;
  delete req.session.oauthState;

  const tokenRes = await fetch(new URL('/oauth/token', IDP_ISSUER), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      client_id: IDP_CLIENT_ID,
      client_secret: IDP_CLIENT_SECRET,
      code_verifier: verifier,
    }),
  });

  if (!tokenRes.ok) {
    const body = await tokenRes.json().catch(() => ({}));
    return res.status(400).send(`Token exchange failed: ${body.error_description || tokenRes.status}`);
  }

  const tokens = await tokenRes.json();
  // access_token / id_token / refresh_token / expires_in / scope

  // Reference choice: keep tokens server-side in this app's own session.
  req.session.accessToken = tokens.access_token;
  req.session.refreshToken = tokens.refresh_token;
  req.session.accessTokenExpiresAt = Date.now() + tokens.expires_in * 1000;

  res.redirect('/');
});

// ------------------------------------------------------------------
// POST /refresh
// ------------------------------------------------------------------
router.post('/refresh', async (req, res) => {
  if (!req.session.refreshToken) {
    return res.status(401).json({ error: 'no_session', error_description: 'Not logged in' });
  }

  const tokenRes = await fetch(new URL('/oauth/token', IDP_ISSUER), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'refresh_token',
      refresh_token: req.session.refreshToken,
      client_id: IDP_CLIENT_ID,
      client_secret: IDP_CLIENT_SECRET,
    }),
  });

  if (!tokenRes.ok) {
    // Refresh token was invalid/expired/revoked -- the user needs to log
    // in again, the same as any expired SSO session.
    req.session.accessToken = null;
    req.session.refreshToken = null;
    return res.status(401).json({ error: 'invalid_grant', error_description: 'Session expired, please log in again' });
  }

  const tokens = await tokenRes.json();
  // Rotation: the IdP has already revoked the old refresh token (see
  // src/routes/oauth.js handleRefreshTokenGrant), so this NEW one is the
  // only one that still works from here on.
  req.session.accessToken = tokens.access_token;
  req.session.refreshToken = tokens.refresh_token;
  req.session.accessTokenExpiresAt = Date.now() + tokens.expires_in * 1000;

  res.json({ ok: true });
});

// ------------------------------------------------------------------
// POST /logout
// ------------------------------------------------------------------
router.post('/logout', async (req, res) => {
  const { refreshToken } = req.session;

  if (refreshToken) {
    // Best-effort: revoke this app's refresh token at the IdP so it can't
    // be replayed even if it leaked. Per RFC 7009 the IdP always returns
    // 200 here regardless of whether the token was already invalid.
    await fetch(new URL('/oauth/revoke', IDP_ISSUER), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token: refreshToken,
        token_type_hint: 'refresh_token',
        client_id: IDP_CLIENT_ID,
        client_secret: IDP_CLIENT_SECRET,
      }),
    }).catch(() => {
      // Network hiccup talking to the IdP shouldn't block a local logout.
    });
  }

  req.session.destroy(() => {
    res.json({ ok: true });
  });

  // NOTE -- Single Logout scope: this only ends THIS app's local session
  // and revokes THIS app's refresh token. It does NOT end the shared
  // Redis-backed SSO session at auth.sastranidhi.org (so the user would
  // still be silently signed in if they visited another child app). True
  // cross-app SLO means redirecting the browser through
  // `${IDP_ISSUER}/auth/logout` as well -- see "Known gap" in the guide.
});

module.exports = router;
