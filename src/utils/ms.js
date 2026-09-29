// src/utils/ms.js
//
// Minimal parser for the small set of duration strings used in this project
// ("15m", "30d", "1h", "45s"). Deliberately not the npm 'ms' package —
// this is the entire feature surface we need, so one dependency less.

const UNIT_MS = {
  s: 1000,
  m: 60 * 1000,
  h: 60 * 60 * 1000,
  d: 24 * 60 * 60 * 1000,
};

function ms(durationString) {
  const match = /^(\d+)(s|m|h|d)$/.exec(durationString.trim());
  if (!match) {
    throw new Error(`Unsupported duration string: "${durationString}" (expected e.g. "15m", "30d")`);
  }
  const [, amount, unit] = match;
  return parseInt(amount, 10) * UNIT_MS[unit];
}

module.exports = ms;
