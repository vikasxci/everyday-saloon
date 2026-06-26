const express   = require('express');
const jwt       = require('jsonwebtoken');
const mongoose  = require('mongoose');
const router    = express.Router();

const AdminUser              = require('../models/AdminUser');
const SubscriptionPlan       = require('../models/SubscriptionPlan');
const AppConfig              = require('../models/AppConfig');
const SaloonBusiness         = require('../models/SaloonBusiness');
const SaloonStaff            = require('../models/SaloonStaff');
const SaloonWorkEntry        = require('../models/SaloonWorkEntry');
const SaloonSalarySettlement = require('../models/SaloonSalarySettlement');
const adminAuth              = require('../middleware/adminAuth');

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
    const now          = new Date();
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
    const endOfMonth   = new Date(now.getFullYear(), now.getMonth() + 1, 0, 23, 59, 59, 999);

    const [
      total, trialCount, activeCount, expiredCount, suspendedCount,
      recentSaloons, expiringSoon,
      revenueAgg, salaryPaidAgg, mrrAgg, activeStaffCount
    ] = await Promise.all([
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
        .lean(),
      // Revenue & commissions this month across ALL saloons
      SaloonWorkEntry.aggregate([
        { $match: { serviceDate: { $gte: startOfMonth, $lte: endOfMonth } } },
        { $group: {
          _id: null,
          revenue:       { $sum: '$grandTotal' },
          staffEarnings: { $sum: '$staffEarning' },
          bills:         { $sum: 1 }
        }}
      ]),
      // Salary already settled this month
      SaloonSalarySettlement.aggregate([
        { $match: { settledAt: { $gte: startOfMonth, $lte: endOfMonth } } },
        { $group: { _id: null, totalPaid: { $sum: '$amountPaid' } } }
      ]),
      // Platform MRR: sum of active saloon monthly rates
      SaloonBusiness.aggregate([
        { $match: { 'subscription.status': 'active' } },
        { $group: { _id: null, mrr: { $sum: '$subscription.monthlyRate' } } }
      ]),
      SaloonStaff.countDocuments({ isActive: true })
    ]);

    const monthlyRevenue  = revenueAgg[0]?.revenue       || 0;
    const staffEarnings   = revenueAgg[0]?.staffEarnings  || 0;
    const billsThisMonth  = revenueAgg[0]?.bills          || 0;
    const salaryPaid      = salaryPaidAgg[0]?.totalPaid   || 0;
    const platformMRR     = mrrAgg[0]?.mrr                || 0;
    const pendingSalary   = Math.max(0, staffEarnings - salaryPaid);
    const grossProfit     = monthlyRevenue - staffEarnings;

    res.json({
      total, trialCount, activeCount, expiredCount, suspendedCount,
      recentSaloons, expiringSoon,
      // Revenue stats
      monthlyRevenue, staffEarnings, salaryPaid, pendingSalary,
      grossProfit, billsThisMonth, platformMRR, activeStaffCount,
      month: now.toLocaleString('en-IN', { month: 'long', year: 'numeric' })
    });
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

// ═══════════════════════════════════════════════════════════════
// SALARY REPORT
// ═══════════════════════════════════════════════════════════════

// GET /admin/salary-report — all saloons with salary summary for a period
router.get('/salary-report', adminAuth, async (req, res) => {
  try {
    const { from, to } = req.query;
    const fromDate = from ? new Date(from) : new Date(new Date().getFullYear(), new Date().getMonth(), 1);
    const toDate   = to   ? new Date(to)   : new Date();
    toDate.setHours(23, 59, 59, 999);

    const [saloons, earningsAgg, settledAgg] = await Promise.all([
      SaloonBusiness.find({ isActive: true })
        .select('businessName ownerName phone address.city subscription.status')
        .sort({ businessName: 1 })
        .lean(),
      SaloonWorkEntry.aggregate([
        { $match: { serviceDate: { $gte: fromDate, $lte: toDate } } },
        { $group: {
          _id: '$saloon',
          totalRevenue:   { $sum: '$grandTotal' },
          staffEarnings:  { $sum: '$staffEarning' },
          totalBills:     { $sum: 1 }
        }}
      ]),
      SaloonSalarySettlement.aggregate([
        { $match: { settledAt: { $gte: fromDate, $lte: toDate } } },
        { $group: { _id: '$saloon', totalPaid: { $sum: '$amountPaid' } } }
      ])
    ]);

    const earningsMap = {};
    earningsAgg.forEach(e => { earningsMap[e._id.toString()] = e; });
    const settledMap = {};
    settledAgg.forEach(s => { settledMap[s._id.toString()] = s.totalPaid; });

    const result = saloons.map(s => {
      const sid  = s._id.toString();
      const e    = earningsMap[sid] || { totalRevenue: 0, staffEarnings: 0, totalBills: 0 };
      const paid = settledMap[sid] || 0;
      return {
        ...s,
        totalRevenue:  e.totalRevenue,
        staffEarnings: e.staffEarnings,
        totalBills:    e.totalBills,
        salaryPaid:    paid,
        pending:       Math.max(0, e.staffEarnings - paid)
      };
    });

    res.json({ saloons: result, fromDate, toDate });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// GET /admin/salary-report/:saloonId — staff-level salary breakdown for a saloon
router.get('/salary-report/:saloonId', adminAuth, async (req, res) => {
  try {
    const { from, to } = req.query;
    const saloonId = req.params.saloonId;
    if (!mongoose.Types.ObjectId.isValid(saloonId))
      return res.status(400).json({ message: 'Invalid saloon ID.' });

    const fromDate = from ? new Date(from) : new Date(new Date().getFullYear(), new Date().getMonth(), 1);
    const toDate   = to   ? new Date(to)   : new Date();
    toDate.setHours(23, 59, 59, 999);

    const sid = new mongoose.Types.ObjectId(saloonId);

    const [saloon, staff, earningsAgg, settledAgg] = await Promise.all([
      SaloonBusiness.findById(saloonId).select('businessName ownerName phone address.city').lean(),
      SaloonStaff.find({ saloon: saloonId })
        .select('name phone role salary commissionType commissionValue joiningDate isActive avatar')
        .sort({ name: 1 })
        .lean(),
      SaloonWorkEntry.aggregate([
        { $match: { saloon: sid, serviceDate: { $gte: fromDate, $lte: toDate } } },
        { $group: {
          _id: '$staff',
          totalRevenue:  { $sum: '$grandTotal' },
          staffEarnings: { $sum: '$staffEarning' },
          totalBills:    { $sum: 1 }
        }}
      ]),
      SaloonSalarySettlement.aggregate([
        { $match: { saloon: sid, settledAt: { $gte: fromDate, $lte: toDate } } },
        { $group: { _id: '$staff', totalPaid: { $sum: '$amountPaid' }, count: { $sum: 1 } } }
      ])
    ]);

    if (!saloon) return res.status(404).json({ message: 'Saloon not found.' });

    const earningsMap = {};
    earningsAgg.forEach(e => { earningsMap[e._id.toString()] = e; });
    const settledMap = {};
    settledAgg.forEach(s => { settledMap[s._id.toString()] = s; });

    const staffData = staff.map(s => {
      const stid  = s._id.toString();
      const e     = earningsMap[stid] || { totalRevenue: 0, staffEarnings: 0, totalBills: 0 };
      const pData = settledMap[stid]  || { totalPaid: 0, count: 0 };
      const pending = Math.max(0, e.staffEarnings - pData.totalPaid);
      return {
        ...s,
        totalRevenue:    e.totalRevenue,
        staffEarnings:   e.staffEarnings,
        totalBills:      e.totalBills,
        salaryPaid:      pData.totalPaid,
        settlementsCount: pData.count,
        pending
      };
    });

    res.json({ saloon, staff: staffData, fromDate, toDate });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// GET /admin/salary-report/:saloonId/staff/:staffId/history
router.get('/salary-report/:saloonId/staff/:staffId/history', adminAuth, async (req, res) => {
  try {
    const settlements = await SaloonSalarySettlement.find({
      saloon: req.params.saloonId,
      staff:  req.params.staffId
    }).sort({ settledAt: -1 }).limit(30).lean();
    res.json(settlements);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// POST /admin/salary-report/:saloonId/settle — record a salary payment
router.post('/salary-report/:saloonId/settle', adminAuth, async (req, res) => {
  try {
    const { staffId, staffName, staffPhone, periodFrom, periodTo,
            totalBills, totalRevenue, grossEarning, amountPaid, paymentMode, notes } = req.body;

    if (!staffId || !periodFrom || !periodTo || amountPaid === undefined)
      return res.status(400).json({ message: 'staffId, periodFrom, periodTo and amountPaid are required.' });

    if (Number(amountPaid) < 0)
      return res.status(400).json({ message: 'amountPaid cannot be negative.' });

    const settlement = await SaloonSalarySettlement.create({
      saloon:       req.params.saloonId,
      staff:        staffId,
      staffName:    staffName || '',
      staffPhone:   staffPhone || '',
      periodFrom:   new Date(periodFrom),
      periodTo:     new Date(periodTo),
      totalBills:   totalBills   || 0,
      totalRevenue: totalRevenue || 0,
      grossEarning: grossEarning || 0,
      amountPaid:   Number(amountPaid),
      paymentMode:  paymentMode || 'cash',
      notes:        notes || '',
      paidBy:       req.admin?.name || 'Admin',
      settledAt:    new Date()
    });

    res.status(201).json(settlement);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

module.exports = router;
