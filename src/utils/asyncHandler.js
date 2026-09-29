// src/utils/asyncHandler.js
//
// Wrap async route handlers so a rejected promise is passed to next(err)
// instead of crashing the process or hanging the request.

const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

module.exports = asyncHandler;
