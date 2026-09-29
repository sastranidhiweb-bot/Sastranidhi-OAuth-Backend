// src/server.js
const env = require('./config/env');
const logger = require('./config/logger');
const app = require('./app');
const db = require('./config/db');
const { redisClient, checkConnection: checkRedis } = require('./config/redis');

let server;

async function start() {
  try {
    await db.checkConnection();
    logger.info('MySQL connection verified');
  } catch (err) {
    logger.error('Failed to connect to MySQL on startup', { error: err.message });
    process.exit(1);
  }

  try {
    const redisOk = await checkRedis();
    if (!redisOk) throw new Error('Redis ping did not return PONG');
    logger.info('Redis connection verified');
  } catch (err) {
    logger.error('Failed to connect to Redis on startup', { error: err.message });
    process.exit(1);
  }

  server = app.listen(env.port, () => {
    logger.info(`sastranidhi-oauth listening on port ${env.port} [${env.nodeEnv}]`);
  });
}

async function shutdown(signal) {
  logger.info(`Received ${signal}, shutting down gracefully...`);

  if (server) {
    server.close(() => logger.info('HTTP server closed'));
  }

  try {
    await db.closePool();
    logger.info('MySQL pool closed');
  } catch (err) {
    logger.error('Error closing MySQL pool', { error: err.message });
  }

  try {
    redisClient.disconnect();
    logger.info('Redis client disconnected');
  } catch (err) {
    logger.error('Error disconnecting Redis client', { error: err.message });
  }

  process.exit(0);
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

start();
