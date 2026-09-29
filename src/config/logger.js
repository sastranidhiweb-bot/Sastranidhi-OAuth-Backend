// src/config/logger.js
const path = require('path');
const winston = require('winston');
const env = require('./env');

const logger = winston.createLogger({
  level: env.logLevel,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'sastranidhi-oauth' },
  transports: [
    new winston.transports.File({
      filename: path.join(__dirname, '..', '..', 'logs', 'error.log'),
      level: 'error',
    }),
    new winston.transports.File({
      filename: path.join(__dirname, '..', '..', 'logs', 'combined.log'),
    }),
  ],
});

if (env.nodeEnv !== 'production') {
  logger.add(
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    })
  );
}

module.exports = logger;
