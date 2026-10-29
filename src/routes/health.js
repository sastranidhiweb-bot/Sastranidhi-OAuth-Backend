// src/routes/health.js
const express = require('express');
const asyncHandler = require('../utils/asyncHandler');
const db = require('../config/db');
const { checkConnection: checkRedis } = require('../config/redis');

const router = express.Router();

// Liveness — process is up
router.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'sastranidhi-oauth', time: new Date().toISOString() });
});

// Readiness — MongoDB is reachable
router.get(
  '/db',
  asyncHandler(async (req, res) => {
    await db.checkConnection();
    res.json({ status: 'ok', db: 'connected' });
  })
);

// Readiness — Redis is reachable
router.get(
  '/redis',
  asyncHandler(async (req, res) => {
    const ok = await checkRedis();
    res.json({ status: ok ? 'ok' : 'error', redis: ok ? 'connected' : 'unreachable' });
  })
);

module.exports = router;
