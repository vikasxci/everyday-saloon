// Fixed-window in-memory rate limiter. Enough for a single instance; move the
// counters to Redis if the API is ever scaled out to several instances.
//   failuresOnly — only responses with status >= 400 count (successful logins are free)
//   successOnly  — only 2xx responses count (e.g. accounts actually created)
function rateLimit({ windowMs, max, key = req => req.ip, failuresOnly = false, successOnly = false, message = 'Too many attempts. Please wait a few minutes and try again.' }) {
  const hits = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.reset <= now) hits.delete(k);
  }, windowMs).unref();

  return (req, res, next) => {
    const k = key(req);
    if (!k) return next();
    const now = Date.now();
    let entry = hits.get(k);
    if (!entry || entry.reset <= now) { entry = { count: 0, reset: now + windowMs }; hits.set(k, entry); }

    if (entry.count >= max) {
      res.set('Retry-After', String(Math.ceil((entry.reset - now) / 1000)));
      return res.status(429).json({ code: 'RATE_LIMITED', message });
    }
    if (failuresOnly)     res.on('finish', () => { if (res.statusCode >= 400) entry.count++; });
    else if (successOnly) res.on('finish', () => { if (res.statusCode < 300) entry.count++; });
    else entry.count++;
    next();
  };
}

// Per-identifier key for auth forms (mobile/email/username), lower-cased and trimmed
const byIdentifier = (...fields) => req => {
  const v = fields.map(f => req.body?.[f]).find(x => typeof x === 'string' && x.trim());
  return v ? `${req.path}|${v.trim().toLowerCase().replace(/[\s-]/g, '')}` : null;
};

module.exports = { rateLimit, byIdentifier };
