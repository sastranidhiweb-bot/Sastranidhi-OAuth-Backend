// src/utils/pagination.js
const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;

function parsePagination(query) {
  let limit = parseInt(query.limit, 10);
  let offset = parseInt(query.offset, 10);

  if (!Number.isFinite(limit) || limit <= 0) limit = DEFAULT_LIMIT;
  if (limit > MAX_LIMIT) limit = MAX_LIMIT;
  if (!Number.isFinite(offset) || offset < 0) offset = 0;

  return { limit, offset };
}

module.exports = { parsePagination };
