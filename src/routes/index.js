// src/routes/index.js
//
// Mounts every route module under its base path.

const express = require('express');
const healthRoutes = require('./health');
const authRoutes = require('./auth');
const socialRoutes = require('./social');
const mfaRoutes = require('./mfa');
const oauthRoutes = require('./oauth');
const oidcRoutes = require('./oidc');
const adminRoutes = require('./admin');
const edmingleSsoRoutes = require('./edmingleSso');

const router = express.Router();

router.use('/health', healthRoutes);
router.use('/auth', authRoutes);
router.use('/auth', socialRoutes);
router.use('/auth', edmingleSsoRoutes);
router.use('/auth/mfa', mfaRoutes);
router.use('/oauth', oauthRoutes);
// oidcRoutes defines its own full paths (including the fixed
// /.well-known/openid-configuration path), so it's mounted at root.
router.use('/', oidcRoutes);
router.use('/admin', adminRoutes);

module.exports = router;
