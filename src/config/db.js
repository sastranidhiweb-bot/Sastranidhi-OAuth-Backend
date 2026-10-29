// src/config/db.js
//
// The single shared MongoDB connection (Mongoose). Every model in
// src/db/schemas.js uses this default connection, so connecting and
// shutting down are handled in one place.

const mongoose = require('mongoose');
const env = require('./env');
const logger = require('./logger');

mongoose.connection.on('error', (err) => {
  logger.error('MongoDB connection error', { error: err.message });
});

mongoose.connection.on('disconnected', () => {
  logger.warn('MongoDB disconnected');
});

async function connect() {
  await mongoose.connect(env.mongo.uri, {
    maxPoolSize: env.mongo.poolMax,
    serverSelectionTimeoutMS: 15000,
  });
}

/** Throws unless the database answers a ping right now — used by startup and GET /health/db. */
async function checkConnection() {
  if (mongoose.connection.readyState !== 1) {
    throw new Error('MongoDB is not connected');
  }
  await mongoose.connection.db.admin().ping();
  return true;
}

async function disconnect() {
  await mongoose.disconnect();
}

module.exports = { connect, checkConnection, disconnect };
