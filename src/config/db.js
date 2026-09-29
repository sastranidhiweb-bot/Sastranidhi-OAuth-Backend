// src/config/db.js
//
// A single shared MySQL connection pool (mysql2/promise). Every model file
// imports `query`/`getConnection` from here rather than opening its own
// connections, so pool sizing and shutdown are handled in one place.

const mysql = require('mysql2/promise');
const env = require('./env');
const logger = require('./logger');

const pool = mysql.createPool({
  host: env.db.host,
  port: env.db.port,
  user: env.db.user,
  password: env.db.password,
  database: env.db.database,
  connectionLimit: env.db.poolMax,
  waitForConnections: true,
  queueLimit: 0,
  dateStrings: false,
  namedPlaceholders: true,
});

/**
 * Run a query against the pool.
 * @param {string} sql
 * @param {object|Array} params
 */
async function query(sql, params) {
  const [rows] = await pool.execute(sql, params);
  return rows;
}

/**
 * Get a dedicated connection for multi-statement transactions.
 * Caller is responsible for connection.release().
 */
async function getConnection() {
  return pool.getConnection();
}

async function checkConnection() {
  const conn = await pool.getConnection();
  try {
    await conn.query('SELECT 1');
    return true;
  } finally {
    conn.release();
  }
}

async function closePool() {
  await pool.end();
}

pool.on('error', (err) => {
  logger.error('Unexpected MySQL pool error', { error: err.message });
});

module.exports = { pool, query, getConnection, checkConnection, closePool };
