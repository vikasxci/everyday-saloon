// JWT signing secrets. A missing JWT_SECRET used to fall back to a value that is
// public in this source code, which would let anyone forge tokens — so outside
// local development the server now refuses to start without one.
const DEV_FALLBACK = 'local-dev-only-secret';

const secret = process.env.JWT_SECRET;
if (!secret && process.env.NODE_ENV !== 'development' && process.env.NODE_ENV !== 'test') {
  console.error('❌ JWT_SECRET is not set. Set it in the environment (e.g. Render → Environment) and restart.');
  process.exit(1);
}

const JWT_SECRET   = secret || DEV_FALLBACK;
const ADMIN_SECRET = JWT_SECRET + '_admin';

module.exports = { JWT_SECRET, ADMIN_SECRET };
