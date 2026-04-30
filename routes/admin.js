const express   = require('express');
const jwt       = require('jsonwebtoken');
const mongoose  = require('mongoose');
const router    = express.Router();

const AdminUser         = require('../models/AdminUser');
const SubscriptionPlan  = require('../models/SubscriptionPlan');
const AppConfig         = require('../models/AppConfig');
const SaloonBusiness    = require('../models/SaloonBusiness');
const SaloonStaff       = require('../models/SaloonStaff');
const SaloonWorkEntry   = require('../models/SaloonWorkEntry');
const adminAuth         = require('../middleware/adminAuth');

const ADMIN_SECRET = (process.env.JWT_SECRET || 'hadlay-kalan-secret-key') + '_admin';

// ── Helper ───────────────────────────────────────────────────
function makeAdminToken(id) {
  return jwt.sign({ id }, ADMIN_SECRET, { expiresIn: '7d' });
}

// ═══════════════════════════════════════════════════════════════
// SETUP — create first admin (only if none exists)
// ═══════════════════════════════════════════════════════════════
router.post('/setup', async (req, res) => {
  try {
    const count = await AdminUser.countDocuments();
    if (count > 0)
      return res.status(403).json({ message: 'Admin already exists. Use login.' });

    const { name, username, password } = req.body;
    if (!name || !username || !password)
      return res.status(400).json({ message: 'name, username and password are required.' });

    const admin = await AdminUser.create({ name, username, password, role: 'superadmin' });

    // Seed default AppConfig
    await AppConfig.findOneAndUpdate(
      { key: 'global' },
      { $setOnInsert: { key: 'global', defaultTrialDays: 30, defaultMonthlyRate: 999 } },
      { upsert: true }
    );

    res.status(201).json({ message: 'Admin created.', username: admin.username });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ═══════════════════════════════════════════════════════════════
// AUTH
// ═══════════════════════════════════════════════════════════════
router.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ message: 'username and password required.' });

    const admin = await AdminUser.findOne({ username: username.toLowerCase() });
    if (!admin || !admin.isActive)
      return res.status(401).json({ message: 'Invalid credentials.' });

    const match = await admin.comparePassword(password);
    if (!match) return res.status(401).json({ message: 'Invalid credentials.' });

    admin.lastLogin = new Date();
    await admin.save({ validateBeforeSave: false });

    const token = makeAdminToken(admin._id);
    res.json({ token, admin: { id: admin._id, name: admin.name, username: admin.username, role: admin.role } });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

router.get('/auth/me', adminAuth, (req, res) => {
  res.json(req.admin);
});

// ═══════════════════════════════════════════════════════════════
// DASHBOARD
// ═══════════════════════════════════════════════════════════════
router.get('/dashboard', adminAuth, async (req, res) => {
  try {
    const now = new Date();

    const [total, trialCount, activeCount, expiredCount, suspendedCount,
           recentSaloons, expiringSoon] = await Promise.all([
      SaloonBusiness.countDocuments(),
      SaloonBusiness.countDocuments({ 'subscription.status': 'trial' }),
      SaloonBusiness.countDocuments({ 'subscription.status': 'active' }),
      SaloonBusiness.countDocuments({ 'subscription.status': 'expired' }),
      SaloonBusiness.countDocuments({ 'subscription.status': 'suspended' }),
      SaloonBusiness.find()
        .sort({ createdAt: -1 })
        .limit(8)
        .select('businessName ownerName phone subscription.status subscription.trialEndsAt createdAt address.city')
        .lean(),
      SaloonBusiness.find({
        'subscription.status': 'trial',
        'subscription.trialEndsAt': { $gte: now, $lte: new Date(now.getTime() + 7 * 86400000) }
      })
        .select('businessName ownerName phone subscription.trialEndsAt')
        .lean()
    ]);

    res.json({ total, trialCount, activeCount, expiredCount, suspendedCount, recentSaloons, expiringSoon });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ═══════════════════════════════════════════════════════════════
// SALOONS
// ═══════════════════════════════════════════════════════════════
router.get('/saloons', adminAuth, async (req, res) => {
  try {
    const { search = '', status = '', page = 1, limit = 20 } = req.query;
    const q = {};
    if (status) q['subscription.status'] = status;
    if (search) {
      q.$or = [
        { businessName: { $regex: search, $options: 'i' } },
        { ownerName:    { $regex: search, $options: 'i' } },
        { phone:        { $regex: search, $options: 'i' } },
        { email:        { $regex: search, $options: 'i' } }
      ];
    }

    const [saloons, total] = await Promise.all([
      SaloonBusiness.find(q)
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(Number(limit))
        .select('-password -token')
        .lean(),
      SaloonBusiness.countDocuments(q)
    ]);

    res.json({ saloons, total, page: Number(page), pages: Math.ceil(total / limit) });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

router.get('/saloons/:id', adminAuth, async (req, res) => {
  try {
    const saloon = await SaloonBusiness.findById(req.params.id)
      .select('-password -token').lean();
    if (!saloon) return res.status(404).json({ message: 'Saloon not found.' });

    const [staffCount, billCount] = await Promise.all([
      SaloonStaff.countDocuments({ saloon: saloon._id }),
      SaloonWorkEntry.countDocuments({ saloon: saloon._id })
    ]);

    res.json({ ...saloon, staffCount, billCount });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// Update subscription details
router.patch('/saloons/:id/subscription', adminAuth, async (req, res) => {
  try {
    const { status, trialEndsAt, monthlyRate, planId, planName,
            currentPeriodStart, currentPeriodEnd, adminNotes } = req.body;

    const update = {};
    if (status)             update['subscription.status']             = status;
    if (trialEndsAt)        update['subscription.trialEndsAt']        = new Date(trialEndsAt);
    if (monthlyRate !== undefined) update['subscription.monthlyRate'] = Number(monthlyRate);
    if (planId)             update['subscription.planId']             = planId;
    if (planName)           update['subscription.planName']           = planName;
    if (currentPeriodStart) update['subscription.currentPeriodStart'] = new Date(currentPeriodStart);
    if (currentPeriodEnd)   update['subscription.currentPeriodEnd']   = new Date(currentPeriodEnd);
    if (adminNotes !== undefined) update['subscription.adminNotes']   = adminNotes;

    if (status === 'active' && currentPeriodEnd)
      update['subscription.lastPaidAt'] = new Date();

    const saloon = await SaloonBusiness.findByIdAndUpdate(
      req.params.id, { $set: update }, { new: true }
    ).select('-password -token').lean();

    if (!saloon) return res.status(404).json({ message: 'Saloon not found.' });
    res.json(saloon);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// Toggle per-saloon service mode
router.patch('/saloons/:id/service-mode', adminAuth, async (req, res) => {
  try {
    const { serviceMode } = req.body;
    const saloon = await SaloonBusiness.findByIdAndUpdate(
      req.params.id,
      { $set: { serviceMode: !!serviceMode } },
      { new: true }
    ).select('businessName serviceMode').lean();
    if (!saloon) return res.status(404).json({ message: 'Saloon not found.' });
    res.json(saloon);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ═══════════════════════════════════════════════════════════════
// SUBSCRIPTION PLANS
// ═══════════════════════════════════════════════════════════════
router.get('/plans', adminAuth, async (req, res) => {
  try {
    const plans = await SubscriptionPlan.find().sort({ period: 1, sortOrder: 1 }).lean();
    res.json(plans);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

router.post('/plans', adminAuth, async (req, res) => {
  try {
    const { name, description, period, price, originalPrice, discountLabel, features, isDefault, sortOrder } = req.body;
    if (!name || !period || price === undefined)
      return res.status(400).json({ message: 'name, period and price are required.' });

    // Clear other defaults for this period if isDefault
    if (isDefault) {
      await SubscriptionPlan.updateMany({ period, isDefault: true }, { $set: { isDefault: false } });
    }

    const plan = await SubscriptionPlan.create({
      name, description, period, price, originalPrice,
      discountLabel, features: features || [], isDefault: !!isDefault,
      sortOrder: sortOrder || 0
    });
    res.status(201).json(plan);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

router.put('/plans/:id', adminAuth, async (req, res) => {
  try {
    const { isDefault, period } = req.body;

    if (isDefault) {
      const current = await SubscriptionPlan.findById(req.params.id).lean();
      const p = period || current?.period;
      await SubscriptionPlan.updateMany({ period: p, isDefault: true }, { $set: { isDefault: false } });
    }

    const plan = await SubscriptionPlan.findByIdAndUpdate(
      req.params.id, { $set: req.body }, { new: true, runValidators: true }
    );
    if (!plan) return res.status(404).json({ message: 'Plan not found.' });
    res.json(plan);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

router.delete('/plans/:id', adminAuth, async (req, res) => {
  try {
    await SubscriptionPlan.findByIdAndDelete(req.params.id);
    res.json({ message: 'Plan deleted.' });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ═══════════════════════════════════════════════════════════════
// APP CONFIG (global service mode, defaults)
// ═══════════════════════════════════════════════════════════════
router.get('/config', adminAuth, async (req, res) => {
  try {
    const cfg = await AppConfig.findOneAndUpdate(
      { key: 'global' },
      { $setOnInsert: { key: 'global' } },
      { upsert: true, new: true }
    ).lean();
    res.json(cfg);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

router.patch('/config', adminAuth, async (req, res) => {
  try {
    const allowed = ['globalServiceMode', 'serviceModeMessage', 'defaultTrialDays', 'defaultMonthlyRate'];
    const update  = {};
    for (const k of allowed) {
      if (req.body[k] !== undefined) update[k] = req.body[k];
    }
    const cfg = await AppConfig.findOneAndUpdate(
      { key: 'global' }, { $set: update }, { upsert: true, new: true }
    ).lean();
    res.json(cfg);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

module.exports = router;
