require('dotenv').config();
require('./config/secrets');           // exits early if JWT_SECRET is missing outside development
const express  = require('express');
const mongoose = require('mongoose');
const cors     = require('cors');
const cloudinary = require('cloudinary').v2;
const { sendError } = require('./utils/http');

const PORT      = process.env.PORT || 5001;
const MONGO_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/saloon-app';
// Test mode only when explicitly asked for AND the database is local — the test
// suites refuse to run unless /api/health says so, so they can never hit production.
const QA_MODE = process.env.QA_TEST_DB === '1' && /^mongodb:\/\/(localhost|127\.0\.0\.1)[:/]/.test(MONGO_URI);

const app = express();
app.disable('x-powered-by');
// Render sits behind one proxy hop; this makes req.ip the real client IP for rate limiting
app.set('trust proxy', 1);

// Cloudinary config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// CORS — FRONTEND_URL may list several origins, comma separated
const allowed = (process.env.FRONTEND_URL || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: allowed.length ? allowed : '*',
  optionsSuccessStatus: 200
}));

// Basic security headers (API only serves JSON)
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Cross-Origin-Resource-Policy': 'cross-origin'
  });
  next();
});

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// ── Request logging ───────────────────────────────────────────
// Method, path, status and timing only — never bodies, which carry passwords and OTPs.
app.use((req, res, next) => {
  const t0 = Date.now();
  res.on('finish', () => {
    console.log(`📨 ${req.method} ${req.path} ${res.statusCode} ${Date.now() - t0}ms`);
  });
  next();
});

// ── Routes ────────────────────────────────────────────────────
app.use('/api/saloon', require('./routes/saloon'));
app.use('/api/admin',  require('./routes/admin'));

// ── Health check ──────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    message: 'Saloon App API is running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    ...(QA_MODE ? { qa: true } : {})
  });
});

app.get('/', (req, res) => {
  res.json({ message: 'Saloon App API', version: '1.0.0', health: '/api/health' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ message: 'Route not found.' });
});

// Error handler — malformed JSON, oversized bodies, upload errors, anything thrown
// outside a route's own try/catch. Always JSON, never a stack trace.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') return res.status(400).json({ message: 'Malformed JSON body.' });
  if (err.type === 'entity.too.large')    return res.status(413).json({ message: 'Request is too large.' });
  if (err.name === 'MulterError') {
    const msg = err.code === 'LIMIT_FILE_SIZE' ? 'Photo is too large (max 5 MB).' : 'Photo upload failed.';
    return res.status(400).json({ message: msg });
  }
  if (err.http_code || /cloudinary|format/i.test(err.message || '')) {
    console.error('❌ upload', err.message);
    return res.status(400).json({ message: 'Photo upload failed. Use a JPG, PNG or WebP image under 5 MB.' });
  }
  sendError(res, err);
});

// ── MongoDB + Server start ────────────────────────────────────
mongoose
  .connect(MONGO_URI)
  .then(() => {
    console.log('✅ MongoDB connected');
    app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Server running on http://localhost:${PORT}`));
  })
  .catch(err => {
    console.error('❌ MongoDB connection failed:', err.message);
    process.exit(1);
  });
