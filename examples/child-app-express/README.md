# Child app integration example (Module 6)

Reference code for how a Sastranidhi child app (written for Paripraśna,
identical for the other three) integrates with `sastranidhi-oauth`. This
is **not a runnable standalone app** — it's two files meant to be copied
into an existing child app's own Express server:

- `authRoutes.js` — `/login`, `/callback`, `/refresh`, `/logout` — the
  Authorization Code + PKCE flow, from the child app's side.
- `verifyAccessToken.js` — middleware that verifies a Bearer access token
  locally against the IdP's JWKS, no shared secret required.

See `../../docs/child-app-integration.md` for the full walkthrough,
including the one-time client registration step and what's still
untested (real Google/Microsoft callback exchange — inherited from
Module 5, not specific to this integration).

## Wiring these into a real child app

```js
// child app's own server.js
const session = require('express-session');
const authRoutes = require('./authRoutes');           // copy of examples/child-app-express/authRoutes.js
const { createAccessTokenVerifier } = require('./verifyAccessToken');

app.use(session({ /* the child app's own session config */ }));
app.use('/', authRoutes);

const requireAccessToken = createAccessTokenVerifier({
  issuer: 'https://auth.sastranidhi.org',
  jwksUri: 'https://auth.sastranidhi.org/oidc/jwks',
  audience: 'PARIPRASHNA',
});

app.get('/api/questions', requireAccessToken, (req, res) => {
  const myRoles = req.token.apps?.PARIPRASHNA || [];
  // ...
});
```

Required environment variables on the child app's side:

```
IDP_ISSUER=https://auth.sastranidhi.org
IDP_CLIENT_ID=PARIPRASHNA
IDP_CLIENT_SECRET=<from scripts/create-client.js on the IdP>
IDP_REDIRECT_URI=https://pariprashna.sastranidhi.org/callback
```
