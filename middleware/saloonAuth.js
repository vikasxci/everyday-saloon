const jwt            = require('jsonwebtoken');
const SaloonStaff    = require('../models/SaloonStaff');
const SaloonBusiness = require('../models/SaloonBusiness');
const AppConfig      = require('../models/AppConfig');

const JWT_SECRET = process.env.JWT_SECRET || 'hadlay-kalan-secret-key';

// ── Main auth middleware ──────────────────────────────────────────────────────
const saloonAuth = async (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'Authentication required.' });

  try {
    const { staffId, saloonId } = jwt.verify(token, JWT_SECRET);

    const [staff, saloon] = await Promise.all([
      SaloonStaff.findById(staffId).select('-password -pin').lean(),
      SaloonBusiness.findById(saloonId).select('-password -token').lean()
    ]);

    if (!staff || staff.token !== token)
      return res.status(401).json({ message: 'Session expired. Please login again.' });
    if (!staff.isActive)
      return res.status(403).json({ message: 'Your account has been deactivated.' });
    if (!saloon || !saloon.isActive)
      return res.status(403).json({ message: 'Saloon account is inactive.' });

    req.staff  = staff;
    req.saloon = saloon;

    // ── Subscription / service-mode check ──────────────────
    // Check global service mode
    const cfg = await AppConfig.findOne({ key: 'global' }).lean();
    if (cfg?.globalServiceMode) {
      return res.status(503).json({
        code: 'SERVICE_MODE',
        message: cfg.serviceModeMessage || 'Service is under maintenance. Please try again shortly.'
      });
    }

    // Per-saloon service mode
    if (saloon.serviceMode) {
      return res.status(503).json({
        code: 'SERVICE_MODE',
        message: 'This account is temporarily suspended for maintenance.'
      });
    }

    // Subscription check
    const sub = saloon.subscription || {};
    const now = new Date();

    if (sub.status === 'trial') {
      if (sub.trialEndsAt && new Date(sub.trialEndsAt) < now) {
        await SaloonBusiness.findByIdAndUpdate(saloonId, { 'subscription.status': 'expired' });
        return res.status(402).json({
          code: 'TRIAL_EXPIRED',
          message: 'Your free trial has ended. Please subscribe to continue.',
          trialEnded: true
        });
      }
    } else if (sub.status === 'active') {
      if (sub.currentPeriodEnd && new Date(sub.currentPeriodEnd) < now) {
        await SaloonBusiness.findByIdAndUpdate(saloonId, { 'subscription.status': 'expired' });
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
  } catch {
    res.status(401).json({ message: 'Invalid or expired token.' });
  }
};

// ── Role guard factory ────────────────────────────────────────────────────────
saloonAuth.requireRole = (...roles) => (req, res, next) => {
  if (!roles.includes(req.staff.role))
    return res.status(403).json({ message: `Access denied. Requires role: ${roles.join(' or ')}.` });
  next();
};

module.exports = saloonAuth;
