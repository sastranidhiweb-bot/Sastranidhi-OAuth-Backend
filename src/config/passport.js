// src/config/passport.js
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const OAuth2Strategy = require('passport-oauth2');
const bcrypt = require('bcrypt');

const env = require('./env');
const logger = require('./logger');
const userModel = require('../models/userModel');
const auditLogModel = require('../models/auditLogModel');
const socialAuthService = require('../services/socialAuthService');

const LOCK_THRESHOLD = 5; // failed attempts
const LOCK_DURATION_MS = 15 * 60 * 1000; // 15 minutes

passport.use(
  new LocalStrategy(
    { usernameField: 'email', passwordField: 'password', passReqToCallback: true },
    async (req, email, password, done) => {
      try {
        const user = await userModel.findByEmail(email);

        if (!user) {
          await auditLogModel.record({
            eventType: 'LOGIN_FAILED',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            metadata: { reason: 'no_such_user', email },
          });
          return done(null, false, { message: 'Invalid credentials' });
        }

        if (user.status === 'inactive') {
          await auditLogModel.record({
            userId: user.id,
            eventType: 'LOGIN_BLOCKED',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            metadata: { reason: 'account_inactive' },
          });
          return done(null, false, { message: 'This account has been deactivated.' });
        }

        if (user.status === 'locked' && user.locked_until && new Date(user.locked_until) > new Date()) {
          await auditLogModel.record({
            userId: user.id,
            eventType: 'LOGIN_BLOCKED',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            metadata: { reason: 'account_locked' },
          });
          return done(null, false, {
            message: 'Account temporarily locked due to repeated failed logins. Try again later.',
          });
        }

        if (!user.password_hash) {
          // Social-only account (Google/Microsoft — module 4)
          return done(null, false, { message: 'Invalid credentials' });
        }

        const passwordMatches = await bcrypt.compare(password, user.password_hash);

        if (!passwordMatches) {
          const nextAttempts = user.failed_login_attempts + 1;
          const shouldLock = nextAttempts >= LOCK_THRESHOLD;
          await userModel.recordFailedLogin(user.id, {
            lockUntil: shouldLock ? new Date(Date.now() + LOCK_DURATION_MS) : undefined,
          });
          await auditLogModel.record({
            userId: user.id,
            eventType: 'LOGIN_FAILED',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            metadata: { reason: 'bad_password', attempt: nextAttempts, locked: shouldLock },
          });
          return done(null, false, { message: 'Invalid credentials' });
        }

        await userModel.resetFailedLogins(user.id);
        await auditLogModel.record({
          userId: user.id,
          eventType: 'LOGIN_SUCCESS',
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'],
        });

        // Re-fetch rather than returning the stale `user` object captured
        // above — resetFailedLogins may have just changed status/locked
        // fields (e.g. locked -> active), and both the API response and
        // the session should reflect that, not a pre-update snapshot.
        const freshUser = await userModel.findById(user.id);
        return done(null, freshUser);
      } catch (err) {
        return done(err);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await userModel.findById(id);

    // This runs on EVERY request for a logged-in browser, not just at
    // login time. Without this check, a session created before an admin
    // deactivates the account would stay fully authenticated indefinitely
    // — req.isAuthenticated() would keep returning true, and /oauth/authorize
    // would keep silently issuing fresh authorization codes (and therefore
    // fresh tokens) through "silent SSO", with no password re-entry ever
    // required. Rejecting here is what actually makes deactivation take
    // effect on the user's very next request rather than only blocking
    // their *next login*.
    if (!user || user.status !== 'active') {
      return done(null, false);
    }

    done(null, user);
  } catch (err) {
    done(err);
  }
});

// ------------------------------------------------------------------
// Social login (module 5)
//
// Both strategies funnel into the same account-linking logic
// (socialAuthService.findOrCreateUser) so a user who registered locally
// and later signs in with Google — or the reverse order — ends up as one
// account, not two. Each strategy is only registered if its client
// credentials are actually configured, so the server boots fine with
// neither set up; routes/social.js checks the same env vars before
// exposing /auth/google and /auth/microsoft at all.
// ------------------------------------------------------------------

async function handleSocialProfile(provider, profile, done) {
  try {
    const email = profile.emails && profile.emails[0] && profile.emails[0].value;
    const user = await socialAuthService.findOrCreateUser({
      provider,
      providerUserId: profile.id,
      email,
      firstName: profile.name && profile.name.givenName,
      lastName: profile.name && profile.name.familyName,
    });
    done(null, user);
  } catch (err) {
    done(err);
  }
}

if (env.google.clientId && env.google.clientSecret && env.google.callbackUrl) {
  passport.use(
    'google',
    new GoogleStrategy(
      {
        clientID: env.google.clientId,
        clientSecret: env.google.clientSecret,
        callbackURL: env.google.callbackUrl,
      },
      (accessToken, refreshToken, profile, done) => handleSocialProfile('google', profile, done)
    )
  );
} else {
  logger.warn('Google login not configured (GOOGLE_CLIENT_ID/SECRET/CALLBACK_URL) — /auth/google disabled');
}

/**
 * passport-oauth2 is the generic strategy — it doesn't know how to fetch a
 * profile for any specific provider on its own (unlike
 * passport-google-oauth20, which hardcodes Google's userinfo endpoint).
 * Overriding userProfile() here is what teaches it to call Microsoft
 * Graph's /me endpoint and shape the result into the same
 * { id, name, emails } structure handleSocialProfile expects from either
 * provider.
 */
class MicrosoftStrategy extends OAuth2Strategy {
  constructor(options, verify) {
    super(options, verify);
    this.name = 'microsoft';
  }

  userProfile(accessToken, done) {
    fetch('https://graph.microsoft.com/v1.0/me', {
      headers: { Authorization: `Bearer ${accessToken}` },
    })
      .then((res) => {
        if (!res.ok) throw new Error(`Microsoft Graph /me returned ${res.status}`);
        return res.json();
      })
      .then((data) => {
        done(null, {
          provider: 'microsoft',
          id: data.id,
          name: { givenName: data.givenName, familyName: data.surname },
          emails: [{ value: data.mail || data.userPrincipalName }],
          _json: data,
        });
      })
      .catch((err) => done(err));
  }
}

if (env.microsoft.clientId && env.microsoft.clientSecret && env.microsoft.callbackUrl) {
  const tenant = env.microsoft.tenant;
  passport.use(
    new MicrosoftStrategy(
      {
        authorizationURL: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`,
        tokenURL: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
        clientID: env.microsoft.clientId,
        clientSecret: env.microsoft.clientSecret,
        callbackURL: env.microsoft.callbackUrl,
        scope: ['openid', 'profile', 'email', 'User.Read'],
      },
      (accessToken, refreshToken, profile, done) => handleSocialProfile('microsoft', profile, done)
    )
  );
} else {
  logger.warn(
    'Microsoft login not configured (MICROSOFT_CLIENT_ID/SECRET/CALLBACK_URL) — /auth/microsoft disabled'
  );
}


module.exports = passport;
