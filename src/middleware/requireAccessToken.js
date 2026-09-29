// src/middleware/requireAccessToken.js
//
// Guards API routes with a JWT access token, the way a child application's
// backend will guard its own routes once it trusts tokens issued by this
// IdP (see the QA-app conversion guide in a later module).

const asyncHandler = require('../utils/asyncHandler');
const ApiError = require('../utils/ApiError');
const tokenService = require('../services/tokenService');

const requireAccessToken = asyncHandler(async (req, res, next) => {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');

  if (scheme !== 'Bearer' || !token) {
    throw new ApiError(401, 'invalid_token', 'Missing or malformed Authorization header');
  }

  try {
    req.token = await tokenService.verifyAccessToken(token);
  } catch (err) {
    throw new ApiError(401, 'invalid_token', err.message);
  }

  next();
});

module.exports = requireAccessToken;
