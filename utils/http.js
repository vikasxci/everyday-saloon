const mongoose = require('mongoose');

// Maps known failure types to a client status. Anything unexpected is logged
// and answered with a generic 500 so internals never reach the client.
function sendError(res, err) {
  if (err?.name === 'ValidationError') {
    const first = Object.values(err.errors || {})[0];
    return res.status(400).json({ message: first?.message || 'Invalid input.' });
  }
  if (err?.name === 'CastError' || err?.name === 'BSONError')
    return res.status(400).json({ message: `Invalid ${err.path || 'id'}.` });
  if (err?.code === 11000)
    return res.status(409).json({ message: 'That phone number or email is already in use.' });
  console.error('❌', err);
  res.status(500).json({ message: 'Something went wrong. Please try again.' });
}

const isId = v => typeof v === 'string' && /^[a-f0-9]{24}$/i.test(v) && mongoose.Types.ObjectId.isValid(v);

const escapeRegex = s => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function pageParams(query, defLimit = 30, maxLimit = 100) {
  const page  = Math.max(1, parseInt(query.page) || 1);
  const limit = Math.min(maxLimit, Math.max(1, parseInt(query.limit) || defLimit));
  return { page, limit, skip: (page - 1) * limit };
}

// '' / null / undefined → undefined; anything else → Number (may be NaN)
const toNum = v => (v === '' || v === null || v === undefined) ? undefined : Number(v);

const isEmail = v => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(v || '').trim());

const MIN_PASSWORD = 6;
const weakPassword = p => !p || String(p).length < MIN_PASSWORD;

module.exports = { sendError, isId, escapeRegex, pageParams, toNum, isEmail, MIN_PASSWORD, weakPassword };
