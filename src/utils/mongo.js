// src/utils/mongo.js
//
// Small helpers shared by every model file, so the rest of the codebase
// keeps seeing the same plain objects it got from MySQL: an `id` field
// (now a string) instead of Mongo's `_id`, and referenced ids such as
// `user_id` as strings rather than ObjectId instances.

const mongoose = require('mongoose');

/** Converts an id string to an ObjectId, or returns null if it isn't a valid one (so a bad id in a URL is "not found", not a crash). */
function toObjectId(value) {
  if (value instanceof mongoose.Types.ObjectId) return value;
  if (typeof value === 'string' && mongoose.isObjectIdOrHexString(value)) {
    return new mongoose.Types.ObjectId(value);
  }
  return null;
}

/** Turns a lean() document into the plain shape the routes expect: `_id` -> `id` (string), ObjectId fields -> strings, no `__v`. */
function toPlain(doc) {
  if (!doc) return null;
  const { _id, __v, ...fields } = doc;
  const plain = { id: String(_id) };
  for (const [key, value] of Object.entries(fields)) {
    plain[key] = value instanceof mongoose.Types.ObjectId ? String(value) : value;
  }
  return plain;
}

/** Escapes user input before it's used inside a $regex search. */
function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

module.exports = { toObjectId, toPlain, escapeRegex };
