const jwt            = require('jsonwebtoken');
const SaloonStaff    = require('../models/SaloonStaff');
const SaloonBusiness = require('../models/SaloonBusiness');
const AppConfig      = require('../models/AppConfig');
const { JWT_SECRET } = require('../config/secrets');

const SECRET_FIELDS = ['password', 'pin', 'token', 'tokens', 'resetOtp', 'resetOtpExpiresAt', 'resetOtpAttempts'];

const hasSession = (staff, token) => staff.token === token || (staff.tokens || []).includes(token);

// Verifies the bearer token and loads staff + saloon. Returns false after
// replying when the session is not usable.
async function loadSession(req, res) {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) { res.status(401).json({ message: 'Authentication required.' }); return false; }

  let payload;
  try { payload = jwt.verify(token, JWT_SECRET); }
  catch { res.status(401).json({ message: 'Invalid or expired token.' }); return false; }

  const [staff, saloon] = await Promise.all([
    SaloonStaff.findById(payload.staffId).lean(),
    SaloonBusiness.findById(payload.saloonId).select('-password -token').lean()
  ]);

  if (!staff || !hasSession(staff, token)) {
    res.status(401).json({ message: 'Session expired. Please login again.' }); return false;
  }
  SECRET_FIELDS.forEach(f => delete staff[f]);
  req.staff  = staff;
  req.saloon = saloon;
  req.token  = token;
  return true;
}

// ── Main auth middleware ──────────────────────────────────────────────────────
const saloonAuth = async (req, res, next) => {
  try {
    if (!await loadSession(req, res)) return;
    const { staff, saloon } = req;

    if (!staff.isActive)
      return res.status(403).json({ message: 'Your account has been deactivated.' });
    if (!saloon || !saloon.isActive)
      return res.status(403).json({ message: 'Saloon account is inactive.' });

    // ── Subscription / service-mode check ──────────────────
    const cfg = await AppConfig.findOne({ key: 'global' }).lean();
    if (cfg?.globalServiceMode) {
      return res.status(503).json({
        code: 'SERVICE_MODE',
        message: cfg.serviceModeMessage || 'Service is under maintenance. Please try again shortly.'
      });
    }

    if (saloon.serviceMode) {
      return res.status(503).json({
        code: 'SERVICE_MODE',
        message: 'This account is temporarily suspended for maintenance.'
      });
    }

    const sub = saloon.subscription || {};
    const now = new Date();

    if (sub.status === 'trial') {
      if (sub.trialEndsAt && new Date(sub.trialEndsAt) < now) {
        await SaloonBusiness.findByIdAndUpdate(saloon._id, { 'subscription.status': 'expired' });
        return res.status(402).json({
          code: 'TRIAL_EXPIRED',
          message: 'Your free trial has ended. Please subscribe to continue.',
          trialEnded: true
        });
      }
    } else if (sub.status === 'active') {
      if (sub.currentPeriodEnd && new Date(sub.currentPeriodEnd) < now) {
        await SaloonBusiness.findByIdAndUpdate(saloon._id, { 'subscription.status': 'expired' });
        return res.status(402).json({
          code: 'SUBSCRIPTION_EXPIRED',
          message: 'Your subscription has expired. Please renew to continue.'
        });
      }
    } else if (sub.status === 'expired') {
      return res.status(402).json({
        code: 'SUBSCRIPTION_EXPIRED',
        message: 'Your subscription has expired. Please contact the admin to renew.'
      });
    } else if (sub.status === 'suspended') {
      return res.status(402).json({
        code: 'ACCOUNT_SUSPENDED',
        message: 'Your account has been suspended. Please contact support.'
      });
    }

    next();
  } catch (err) {
    console.error('❌ saloonAuth', err);
    res.status(500).json({ message: 'Something went wrong. Please try again.' });
  }
};

// Session only — no subscription/service-mode gate, so people can always log out
// (and the owner can still delete their account) while the app is locked.
saloonAuth.sessionOnly = async (req, res, next) => {
  try { if (await loadSession(req, res)) next(); }
  catch (err) {
    console.error('❌ saloonAuth.sessionOnly', err);
    res.status(500).json({ message: 'Something went wrong. Please try again.' });
  }
};

// ── Role guard factory ────────────────────────────────────────────────────────
saloonAuth.requireRole = (...roles) => (req, res, next) => {
  if (!roles.includes(req.staff.role))
    return res.status(403).json({ message: `Access denied. Requires role: ${roles.join(' or ')}.` });
  next();
};

module.exports = saloonAuth;
