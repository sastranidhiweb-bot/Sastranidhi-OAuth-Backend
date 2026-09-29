// src/config/redis.js
//
// One ioredis client shared across:
//   - express-session store (connect-redis)         -> SSO session
//   - authorization-code storage (module 2)          -> short-lived codes
//   - refresh/access token blacklist on logout       -> single logout
//   - rate limiting (module 2, optional)

const Redis = require('ioredis');
const env = require('./env');
const logger = require('./logger');

// Shared with app.js's connect-redis store config and with the admin
// force-logout endpoint (module 4), which deletes a specific session's key
// directly — both need the exact same prefix or they'd silently disagree
// about where sessions live.
const SESSION_KEY_PREFIX = 'sastranidhi:sess:';

const redisClient = new Redis({
  host: env.redis.host,
  port: env.redis.port,
  password: env.redis.password,
  db: env.redis.db,
  maxRetriesPerRequest: 3,
  retryStrategy(times) {
    return Math.min(times * 200, 2000);
  },
});

redisClient.on('error', (err) => {
  logger.error('Redis client error', { error: err.message });
});

redisClient.on('connect', () => {
  logger.info('Redis connected');
});

async function checkConnection() {
  const pong = await redisClient.ping();
  return pong === 'PONG';
}

module.exports = { redisClient, checkConnection, SESSION_KEY_PREFIX };
