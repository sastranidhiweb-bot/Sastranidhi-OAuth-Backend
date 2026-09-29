// src/app.js
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const session = require('express-session');
// connect-redis v7 ships as an ESM default export; under CJS `require`
// that surfaces as `.default` rather than a named export.
const RedisStore = require('connect-redis').default;
const passport = require('./config/passport');

const env = require('./config/env');
const logger = require('./config/logger');
const { redisClient, SESSION_KEY_PREFIX } = require('./config/redis');

const requestLogger = require('./middleware/requestLogger');
const globalRateLimiter = require('./middleware/rateLimiter');
const { notFoundHandler, errorHandler } = require('./middleware/errorHandler');

const routes = require('./routes');

const app = express();

// Trust the NGINX reverse proxy in front of this service (per infra spec)
// so req.ip / secure cookies behave correctly behind SSL termination.
app.set('trust proxy', 1);

app.use(helmet());

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow same-origin/non-browser requests (no Origin header) and
      // anything explicitly listed in ALLOWED_ORIGINS.
      if (!origin || env.allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      logger.warn('Blocked CORS request', { origin });
      return callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(requestLogger);
app.use(globalRateLimiter);

// SSO session, backed by Redis. This is what makes "silent SSO" possible:
// once a user has an authenticated session here, subsequent /oauth/authorize
// requests from other child apps skip the login screen (module 2).
app.use(
  session({
    store: new RedisStore({ client: redisClient, prefix: SESSION_KEY_PREFIX }),
    name: env.session.cookieName,
    secret: env.session.secret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      domain: env.session.cookieDomain,
      secure: env.nodeEnv === 'production',
      httpOnly: true,
      sameSite: env.nodeEnv === 'production' ? 'none' : 'lax',
      maxAge: env.session.maxAgeMs,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

app.use('/', routes);

app.use(notFoundHandler);
app.use(errorHandler);

module.exports = app;
