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
const SaloonService          = require('../models/SaloonService');
const SaloonCustomer         = require('../models/SaloonCustomer');
const SaloonAttendance       = require('../models/SaloonAttendance');
const SaloonCollectionRequest = require('../models/SaloonCollectionRequest');
const BusinessActivityLog    = require('../models/BusinessActivityLog');
const adminAuth              = require('../middleware/adminAuth');
const { ADMIN_SECRET }       = require('../config/secrets');
const { rateLimit, byIdentifier } = require('../middleware/rateLimit');
const { sendError, isId, escapeRegex, pageParams, toNum, isEmail } = require('../utils/http');
const { normPhone, isPhone, phoneVariants } = require('../utils/phone');
const { DEFAULT_TZ, todayRange, monthRange, parseDay } = require('../utils/time');
const { deleteSaloonData }   = require('../utils/saloonData');

// Platform-wide reports are cut on Indian calendar days
const TZ = DEFAULT_TZ;
const SUB_STATUSES = ['trial', 'active', 'expired', 'suspended'];

const loginLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 8, failuresOnly: true,
  key: byIdentifier('username'), message: 'Too many failed sign-ins. Please wait 15 minutes.' });
const ipLimit    = rateLimit({ windowMs: 15 * 60 * 1000, max: 50, failuresOnly: true });

// Rejects malformed :id params with 404 before they reach Mongo
router.param('id', (req, res, next, id) => isId(id) ? next() : res.status(404).json({ message: 'Not found.' }));
router.param('saloonId', (req, res, next, id) => isId(id) ? next() : res.status(400).json({ message: 'Invalid saloon ID.' }));
router.param('staffId', (req, res, next, id) => isId(id) ? next() : res.status(400).json({ message: 'Invalid staff ID.' }));

// ── Helpers ──────────────────────────────────────────────────
function makeAdminToken(admin) {
  return jwt.sign({ id: admin._id, tv: admin.tokenVersion || 0 }, ADMIN_SECRET, { expiresIn: '7d' });
}

// Anything that changes an account, deletes data, or touches other admins
// is superadmin-only. 'support' keeps read access plus subscription edits.
function requireSuper(req, res, next) {
  if (req.admin?.role !== 'superadmin')
    return res.status(403).json({ message: 'Superadmin access required for this action.' });
  next();
}

// Record an admin action against the saloon's own activity trail
async function logAdmin(req, saloon, action, extras = {}) {
  try {
    await BusinessActivityLog.create({
      bizType: 'saloon',
      business: saloon._id,
      businessName: saloon.businessName,
      ownerEmail: saloon.email,
      actor: `${req.admin.name} (admin)`,
      actorRole: req.admin.role,
      action,
      entity: extras.entity || 'saloon',
      entityId: extras.entityId || saloon._id,
      entityName: extras.entityName || saloon.businessName,
      details: extras.details || null,
      ip: req.ip || '',
      userAgent: req.headers['user-agent'] || ''
    });
  } catch (err) {
    console.warn(`⚠️  admin activity log skipped (${action}):`, err.message);
  }
}

// ═══════════════════════════════════════════════════════════════
// SETUP — create first admin (only if none exists)
// ═══════════════════════════════════════════════════════════════
// Public: lets the panel show a first-run setup form instead of a dead login box
router.get('/setup-status', async (req, res) => {
  try {
    const count = await AdminUser.countDocuments();
    res.json({ needsSetup: count === 0 });
  } catch (err) { sendError(res, err); }
});

router.post('/setup', ipLimit, async (req, res) => {
  try {
    const count = await AdminUser.countDocuments();
    if (count > 0)
      return res.status(403).json({ message: 'Admin already exists. Use login.' });

    const { name, username, password } = req.body;
    if (!name || !username || !password)
      return res.status(400).json({ message: 'name, username and password are required.' });
    if (String(password).length < 8)
      return res.status(400).json({ message: 'Choose a password of at least 8 characters.' });
    if (!/^[a-z0-9._-]{3,32}$/i.test(String(username).trim()))
      return res.status(400).json({ message: 'Username: 3–32 letters, numbers, dots, dashes or underscores.' });

    const admin = await AdminUser.create({ name: String(name).trim(), username: String(username).trim(), password, role: 'superadmin' });

    // Seed default AppConfig
    await AppConfig.findOneAndUpdate(
      { key: 'global' },
      { $setOnInsert: { key: 'global', defaultTrialDays: 30, defaultMonthlyRate: 999 } },
      { upsert: true }
    );

    res.status(201).json({ message: 'Admin created.', username: admin.username });
  } catch (err) { sendError(res, err); }
});

// ═══════════════════════════════════════════════════════════════
// AUTH
// ═══════════════════════════════════════════════════════════════
router.post('/auth/login', ipLimit, loginLimit, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password || typeof username !== 'string' || typeof password !== 'string')
      return res.status(400).json({ message: 'username and password required.' });

    const admin = await AdminUser.findOne({ username: username.toLowerCase().trim() });
    if (!admin || !admin.isActive)
      return res.status(401).json({ message: 'Invalid credentials.' });

    const match = await admin.comparePassword(password);
    if (!match) return res.status(401).json({ message: 'Invalid credentials.' });

    admin.lastLogin = new Date();
    await admin.save({ validateBeforeSave: false });

    const token = makeAdminToken(admin);
    res.json({ token, admin: { id: admin._id, name: admin.name, username: admin.username, role: admin.role } });
  } catch (err) { sendError(res, err); }
});

router.get('/auth/me', adminAuth, (req, res) => {
  res.json(req.admin);
});

// Change your own password
router.post('/auth/change-password', adminAuth, ipLimit, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword)
      return res.status(400).json({ message: 'Current and new password are required.' });
    if (String(newPassword).length < 6)
      return res.status(400).json({ message: 'Password must be at least 6 characters.' });

    const admin = await AdminUser.findById(req.admin._id);
    if (!admin) return res.status(404).json({ message: 'Admin not found.' });
    // 400, not 401 — the panel treats 401 as "signed out"
    if (!await admin.comparePassword(String(oldPassword)))
      return res.status(400).json({ message: 'Current password is incorrect.' });

    admin.password = newPassword;
    await admin.save();               // bumps tokenVersion → older tokens stop working
    res.json({ message: 'Password changed.', token: makeAdminToken(admin) });
  } catch (err) { sendError(res, err); }
});

// ═══════════════════════════════════════════════════════════════
// ADMIN USERS  (superadmin only)
// ═══════════════════════════════════════════════════════════════
router.get('/admins', adminAuth, requireSuper, async (req, res) => {
  try {
    const list = await AdminUser.find().select('-password').sort({ createdAt: 1 }).lean();
    res.json(list.map(a => ({ ...a, isSelf: String(a._id) === String(req.admin._id) })));
  } catch (err) { sendError(res, err); }
});

router.post('/admins', adminAuth, requireSuper, async (req, res) => {
  try {
    const { name, username, password, role } = req.body;
    if (!name || !username || !password)
      return res.status(400).json({ message: 'Name, username and password are required.' });
    if (String(password).length < 6)
      return res.status(400).json({ message: 'Password must be at least 6 characters.' });
    if (role && !['superadmin', 'support'].includes(role))
      return res.status(400).json({ message: 'Role must be superadmin or support.' });

    const exists = await AdminUser.findOne({ username: String(username).toLowerCase().trim() });
    if (exists) return res.status(409).json({ message: 'That username is already taken.' });

    const admin = await AdminUser.create({
      name: name.trim(), username: String(username).toLowerCase().trim(),
      password, role: role || 'support'
    });
    const { password: _, ...safe } = admin.toObject();
    res.status(201).json(safe);
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ message: 'That username is already taken.' });
    sendError(res, err);
  }
});

router.patch('/admins/:id', adminAuth, requireSuper, async (req, res) => {
  try {
    const { name, role, isActive } = req.body;
    if (role !== undefined && !['superadmin', 'support'].includes(role))
      return res.status(400).json({ message: 'Role must be superadmin or support.' });
    if (name !== undefined && !String(name).trim())
      return res.status(400).json({ message: 'Name cannot be empty.' });
    const admin = await AdminUser.findById(req.params.id);
    if (!admin) return res.status(404).json({ message: 'Admin not found.' });

    const isSelf = String(admin._id) === String(req.admin._id);
    if (isSelf && (isActive === false || (role && role !== 'superadmin')))
      return res.status(400).json({ message: 'You cannot demote or deactivate your own account.' });

    // Never leave the platform without a way in
    const losingSuper = admin.role === 'superadmin' &&
      ((role && role !== 'superadmin') || isActive === false);
    if (losingSuper) {
      const others = await AdminUser.countDocuments({
        _id: { $ne: admin._id }, role: 'superadmin', isActive: true
      });
      if (others === 0)
        return res.status(400).json({ message: 'This is the last active superadmin — promote another one first.' });
    }

    if (name !== undefined)     admin.name = String(name).trim();
    if (role !== undefined)     admin.role = role;
    if (isActive !== undefined) admin.isActive = !!isActive;
    await admin.save();

    const { password: _, ...safe } = admin.toObject();
    res.json(safe);
  } catch (err) { sendError(res, err); }
});

// Reset another admin's password
router.post('/admins/:id/password', adminAuth, requireSuper, async (req, res) => {
  try {
    const { password } = req.body;
    if (!password || String(password).length < 6)
      return res.status(400).json({ message: 'Password must be at least 6 characters.' });

    const admin = await AdminUser.findById(req.params.id);
    if (!admin) return res.status(404).json({ message: 'Admin not found.' });

    admin.password = password;
    await admin.save();               // revokes that admin's existing tokens
    const self = String(admin._id) === String(req.admin._id);
    res.json({ message: `Password reset for ${admin.username}. They have been signed out.`,
               ...(self ? { token: makeAdminToken(admin) } : {}) });
  } catch (err) { sendError(res, err); }
});

router.delete('/admins/:id', adminAuth, requireSuper, async (req, res) => {
  try {
    const admin = await AdminUser.findById(req.params.id);
    if (!admin) return res.status(404).json({ message: 'Admin not found.' });
    if (String(admin._id) === String(req.admin._id))
      return res.status(400).json({ message: 'You cannot delete your own account.' });

    if (admin.role === 'superadmin') {
      const others = await AdminUser.countDocuments({
        _id: { $ne: admin._id }, role: 'superadmin', isActive: true
      });
      if (others === 0)
        return res.status(400).json({ message: 'This is the last active superadmin — promote another one first.' });
    }

    await AdminUser.findByIdAndDelete(admin._id);
    res.json({ message: `Removed ${admin.username}.` });
  } catch (err) { sendError(res, err); }
});

// ═══════════════════════════════════════════════════════════════
// DASHBOARD
// ═══════════════════════════════════════════════════════════════
router.get('/dashboard', adminAuth, async (req, res) => {
  try {
    const now = new Date();
    const { start: startOfMonth, end: endOfMonth } = monthRange(TZ, now);

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
      month: now.toLocaleString('en-IN', { month: 'long', year: 'numeric', timeZone: TZ })
    });
  } catch (err) { sendError(res, err); }
});

// ═══════════════════════════════════════════════════════════════
// SALOONS
// ═══════════════════════════════════════════════════════════════
router.get('/saloons', adminAuth, async (req, res) => {
  try {
    const { search = '', status = '' } = req.query;
    const { page, limit, skip } = pageParams(req.query, 20);
    const q = {};
    if (status) q['subscription.status'] = String(status);
    if (search) {
      const rx = { $regex: escapeRegex(String(search).trim()), $options: 'i' };
      q.$or = [
        { businessName: rx }, { ownerName: rx }, { phone: rx }, { email: rx }, { saloonCode: rx }
      ];
      const digits = normPhone(search);
      if (digits && digits !== String(search).trim()) q.$or.push({ phone: { $regex: escapeRegex(digits) } });
    }

    const [saloons, total] = await Promise.all([
      SaloonBusiness.find(q)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .select('-password -token')
        .lean(),
      SaloonBusiness.countDocuments(q)
    ]);

    res.json({ saloons, total, page, pages: Math.ceil(total / limit) });
  } catch (err) { sendError(res, err); }
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
  } catch (err) { sendError(res, err); }
});

// Update subscription details. null / '' clears a field.
router.patch('/saloons/:id/subscription', adminAuth, async (req, res) => {
  try {
    const b = req.body || {};
    const $set = {}, $unset = {};
    const cleared = v => v === null || v === '';

    if (b.status !== undefined) {
      if (!SUB_STATUSES.includes(b.status))
        return res.status(400).json({ message: `Status must be one of: ${SUB_STATUSES.join(', ')}.` });
      $set['subscription.status'] = b.status;
    }
    // Dates arrive as YYYY-MM-DD; end dates run to the end of that day (IST)
    for (const [k, end] of [['trialEndsAt', true], ['currentPeriodStart', false], ['currentPeriodEnd', true]]) {
      if (b[k] === undefined) continue;
      if (cleared(b[k])) { $unset[`subscription.${k}`] = 1; continue; }
      const d = parseDay(b[k], TZ, end);
      if (!d) return res.status(400).json({ message: `Invalid date for ${k}.` });
      $set[`subscription.${k}`] = d;
    }
    if (b.monthlyRate !== undefined) {
      const rate = toNum(b.monthlyRate);
      if (rate === undefined) $set['subscription.monthlyRate'] = 0;
      else if (!Number.isFinite(rate) || rate < 0) return res.status(400).json({ message: 'Monthly rate must be a number of 0 or more.' });
      else $set['subscription.monthlyRate'] = rate;
    }
    if (b.planId !== undefined) {
      if (cleared(b.planId)) { $unset['subscription.planId'] = 1; }
      else if (!isId(String(b.planId)) || !await SubscriptionPlan.exists({ _id: b.planId }))
        return res.status(400).json({ message: 'Plan not found.' });
      else $set['subscription.planId'] = b.planId;
    }
    for (const k of ['planName', 'adminNotes']) {
      if (b[k] === undefined) continue;
      if (cleared(b[k])) $unset[`subscription.${k}`] = 1;
      else $set[`subscription.${k}`] = String(b[k]).slice(0, 2000);
    }

    if (b.status === 'active' && $set['subscription.currentPeriodEnd'])
      $set['subscription.lastPaidAt'] = new Date();

    const update = {};
    if (Object.keys($set).length)   update.$set = $set;
    if (Object.keys($unset).length) update.$unset = $unset;

    const saloon = await SaloonBusiness.findByIdAndUpdate(req.params.id, update, { new: true, runValidators: true })
      .select('-password -token').lean();

    if (!saloon) return res.status(404).json({ message: 'Saloon not found.' });
    logAdmin(req, saloon, 'admin_subscription_update', { details: { set: $set, cleared: Object.keys($unset) } });
    res.json(saloon);
  } catch (err) { sendError(res, err); }
});

// Toggle per-saloon service mode
router.patch('/saloons/:id/service-mode', adminAuth, async (req, res) => {
  try {
    const { serviceMode } = req.body;
    const saloon = await SaloonBusiness.findByIdAndUpdate(
      req.params.id,
      { $set: { serviceMode: !!serviceMode } },
      { new: true }
    ).select('businessName email serviceMode').lean();
    if (!saloon) return res.status(404).json({ message: 'Saloon not found.' });
    logAdmin(req, saloon, 'admin_service_mode', { details: { serviceMode: !!serviceMode } });
    res.json(saloon);
  } catch (err) { sendError(res, err); }
});

// ── Saloon detail tabs ───────────────────────────────────────

// Staff roster with per-staff earnings
router.get('/saloons/:id/staff', adminAuth, async (req, res) => {
  try {
    const saloonId = new mongoose.Types.ObjectId(String(req.params.id));
    const [staff, earnings, paid] = await Promise.all([
      SaloonStaff.find({ saloon: saloonId })
        .select('name phone email role designation salary commissionType commissionValue joiningDate isActive avatar lastLoginAt loginCount')
        .sort({ createdAt: 1 }).lean(),
      SaloonWorkEntry.aggregate([
        { $match: { saloon: saloonId } },
        { $group: { _id: '$staff', bills: { $sum: 1 }, revenue: { $sum: '$grandTotal' }, earned: { $sum: '$staffEarning' } } }
      ]),
      SaloonSalarySettlement.aggregate([
        { $match: { saloon: saloonId } },
        { $group: { _id: '$staff', paid: { $sum: '$amountPaid' } } }
      ])
    ]);

    const eMap = Object.fromEntries(earnings.map(e => [String(e._id), e]));
    const pMap = Object.fromEntries(paid.map(p => [String(p._id), p.paid]));

    res.json(staff.map(st => {
      const e = eMap[String(st._id)] || { bills: 0, revenue: 0, earned: 0 };
      const totalPaid = pMap[String(st._id)] || 0;
      return { ...st, bills: e.bills, revenue: e.revenue, earned: e.earned,
               paid: totalPaid, pending: Math.max(0, e.earned - totalPaid) };
    }));
  } catch (err) { sendError(res, err); }
});

// Recent bills
router.get('/saloons/:id/bills', adminAuth, async (req, res) => {
  try {
    const { page, limit, skip } = pageParams(req.query, 20);
    const q = { saloon: req.params.id };
    const [bills, total] = await Promise.all([
      SaloonWorkEntry.find(q).sort({ serviceDate: -1, createdAt: -1 })
        .skip(skip).limit(limit)
        .select('billNumber customerName staffName grandTotal amountPaid amountDue paymentStatus paymentMode serviceDate staffEarning')
        .lean(),
      SaloonWorkEntry.countDocuments(q)
    ]);
    res.json({ bills, total, page, pages: Math.ceil(total / limit) });
  } catch (err) { sendError(res, err); }
});

// Activity for one saloon
router.get('/saloons/:id/activity', adminAuth, async (req, res) => {
  try {
    const { action = '' } = req.query;
    const { page, limit, skip } = pageParams(req.query, 30);
    const q = { business: req.params.id };
    if (action) q.action = String(action);
    const [logs, total] = await Promise.all([
      BusinessActivityLog.find(q).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
      BusinessActivityLog.countDocuments(q)
    ]);
    res.json({ logs, total, page, pages: Math.ceil(total / limit) });
  } catch (err) { sendError(res, err); }
});

// ── Saloon account commands (superadmin) ─────────────────────

// Edit business details. The owner logs in through their SaloonStaff record,
// so email/phone/name changes are mirrored there.
router.patch('/saloons/:id', adminAuth, requireSuper, async (req, res) => {
  try {
    const { businessName, ownerName, email, phone, city, businessType, gstin } = req.body;
    const saloon = await SaloonBusiness.findById(req.params.id);
    if (!saloon) return res.status(404).json({ message: 'Saloon not found.' });
    const ownerSet = {};

    if (email && email.toLowerCase().trim() !== saloon.email) {
      const em = email.toLowerCase().trim();
      if (!isEmail(em)) return res.status(400).json({ message: 'Please enter a valid email address.' });
      const clash = await SaloonBusiness.findOne({ email: em, _id: { $ne: saloon._id } });
      if (clash) return res.status(409).json({ message: 'Another saloon already uses that email.' });
      saloon.email = em;
      ownerSet.email = em;
    }
    if (phone && normPhone(phone) !== saloon.phone) {
      const ph = normPhone(phone);
      if (!isPhone(ph)) return res.status(400).json({ message: 'Please enter a valid mobile number.' });
      const clash = await SaloonBusiness.findOne({ phone: { $in: phoneVariants(ph) }, _id: { $ne: saloon._id } });
      if (clash) return res.status(409).json({ message: 'Another saloon already uses that phone.' });
      if (await SaloonStaff.exists({ saloon: saloon._id, role: { $ne: 'owner' }, phone: { $in: phoneVariants(ph) } }))
        return res.status(409).json({ message: 'A staff member of this saloon already uses that phone.' });
      saloon.phone = ph;
      ownerSet.phone = ph;
    }
    if (businessName) saloon.businessName = String(businessName).trim();
    if (ownerName)    { saloon.ownerName = String(ownerName).trim(); ownerSet.name = saloon.ownerName; }
    if (businessType) saloon.businessType = businessType;
    if (gstin !== undefined) saloon.gstin = gstin;
    if (city !== undefined)  saloon.set('address.city', String(city).trim());

    await saloon.save();
    if (Object.keys(ownerSet).length)
      await SaloonStaff.updateOne({ saloon: saloon._id, role: 'owner' }, { $set: ownerSet });
    logAdmin(req, saloon, 'admin_saloon_update', { details: { by: req.admin.username } });

    const { password: _, token: __, ...safe } = saloon.toObject();
    res.json(safe);
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ message: 'Email or phone already in use.' });
    sendError(res, err);
  }
});

// Activate / deactivate the whole account
router.patch('/saloons/:id/status', adminAuth, requireSuper, async (req, res) => {
  try {
    const { isActive } = req.body;
    const saloon = await SaloonBusiness.findByIdAndUpdate(
      req.params.id, { $set: { isActive: !!isActive } }, { new: true }
    ).select('-password -token');
    if (!saloon) return res.status(404).json({ message: 'Saloon not found.' });

    // Deactivating logs everyone out
    if (!isActive) await SaloonStaff.updateMany({ saloon: saloon._id }, { $unset: { token: 1 }, $set: { tokens: [] } });

    logAdmin(req, saloon, 'admin_saloon_status', { details: { isActive: !!isActive } });
    res.json({ _id: saloon._id, businessName: saloon.businessName, isActive: saloon.isActive });
  } catch (err) { sendError(res, err); }
});

// Reset the owner's login password (support requests)
router.post('/saloons/:id/owner-password', adminAuth, requireSuper, async (req, res) => {
  try {
    const { password } = req.body;
    if (!password || String(password).length < 6)
      return res.status(400).json({ message: 'Password must be at least 6 characters.' });

    const saloon = await SaloonBusiness.findById(req.params.id);
    if (!saloon) return res.status(404).json({ message: 'Saloon not found.' });

    // The owner logs in through their SaloonStaff record; keep the business
    // record in step so both credentials stay consistent.
    const owner = await SaloonStaff.findOne({ saloon: saloon._id, role: 'owner' });
    if (!owner) return res.status(404).json({ message: 'Owner account not found for this saloon.' });

    owner.password = password;
    owner.token = undefined;
    owner.tokens = [];                 // signs the owner out of every device
    await owner.save();

    saloon.password = password;
    await saloon.save();

    logAdmin(req, saloon, 'admin_owner_password_reset', {
      entity: 'staff', entityId: owner._id, entityName: owner.name
    });
    res.json({ message: `Owner password reset for ${saloon.businessName}.`, ownerName: owner.name, loginWith: owner.phone || owner.email });
  } catch (err) { sendError(res, err); }
});

// Delete a saloon and everything under it
router.delete('/saloons/:id', adminAuth, requireSuper, async (req, res) => {
  try {
    const saloon = await SaloonBusiness.findById(req.params.id);
    if (!saloon) return res.status(404).json({ message: 'Saloon not found.' });

    // Typing the exact business name is the confirmation
    if (String(req.body?.confirmName || '').trim() !== saloon.businessName.trim())
      return res.status(400).json({ message: `Type the exact business name "${saloon.businessName}" to confirm deletion.` });

    const removed = await deleteSaloonData(saloon);
    // The saloon's own trail goes with it; this one record keeps the deletion auditable
    await logAdmin(req, saloon, 'admin_saloon_delete', { details: { by: req.admin.username, removed } });

    console.warn(`🗑️  Admin ${req.admin.username} deleted saloon "${saloon.businessName}" (${saloon._id})`);
    res.json({ message: `Deleted "${saloon.businessName}" and all of its data.`, removed });
  } catch (err) { sendError(res, err); }
});

// ═══════════════════════════════════════════════════════════════
// ACTIVITY LOG  (platform-wide)
// ═══════════════════════════════════════════════════════════════
router.get('/activity', adminAuth, async (req, res) => {
  try {
    const { action = '', search = '', from = '', to = '' } = req.query;
    const { page, limit, skip } = pageParams(req.query, 40);
    const q = { bizType: 'saloon' };
    if (action) q.action = String(action);
    if (search) {
      const rx = { $regex: escapeRegex(String(search).trim()), $options: 'i' };
      q.$or = [{ businessName: rx }, { actor: rx }, { entityName: rx }];
    }
    if (from || to) {
      const f = parseDay(from, TZ), t = parseDay(to, TZ, true);
      if ((from && !f) || (to && !t)) return res.status(400).json({ message: 'Invalid date range.' });
      q.createdAt = {};
      if (f) q.createdAt.$gte = f;
      if (t) q.createdAt.$lte = t;
    }

    const [logs, total, actions] = await Promise.all([
      BusinessActivityLog.find(q).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
      BusinessActivityLog.countDocuments(q),
      BusinessActivityLog.distinct('action', { bizType: 'saloon' })
    ]);

    res.json({ logs, total, page, pages: Math.ceil(total / limit), actions: actions.sort() });
  } catch (err) { sendError(res, err); }
});

// ═══════════════════════════════════════════════════════════════
// SUBSCRIPTION PLANS
// ═══════════════════════════════════════════════════════════════
router.get('/plans', adminAuth, async (req, res) => {
  try {
    const plans = await SubscriptionPlan.find().sort({ period: 1, sortOrder: 1 }).lean();
    res.json(plans);
  } catch (err) { sendError(res, err); }
});

router.post('/plans', adminAuth, requireSuper, async (req, res) => {
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
  } catch (err) { sendError(res, err); }
});

router.put('/plans/:id', adminAuth, requireSuper, async (req, res) => {
  try {
    const { isDefault, period } = req.body;

    if (isDefault) {
      const current = await SubscriptionPlan.findById(req.params.id).lean();
      const p = period || current?.period;
      await SubscriptionPlan.updateMany({ period: p, isDefault: true }, { $set: { isDefault: false } });
    }

    const fields = ['name', 'description', 'period', 'price', 'originalPrice', 'discountLabel', 'features', 'isActive', 'isDefault', 'sortOrder'];
    const $set = {}, $unset = {};
    for (const f of fields) {
      if (req.body[f] === undefined) continue;
      if (['originalPrice', 'discountLabel', 'description'].includes(f) && (req.body[f] === null || req.body[f] === '')) $unset[f] = 1;
      else $set[f] = req.body[f];
    }
    const plan = await SubscriptionPlan.findByIdAndUpdate(
      req.params.id, { $set, ...(Object.keys($unset).length ? { $unset } : {}) }, { new: true, runValidators: true }
    );
    if (!plan) return res.status(404).json({ message: 'Plan not found.' });
    res.json(plan);
  } catch (err) { sendError(res, err); }
});

router.delete('/plans/:id', adminAuth, requireSuper, async (req, res) => {
  try {
    const plan = await SubscriptionPlan.findByIdAndDelete(req.params.id);
    if (!plan) return res.status(404).json({ message: 'Plan not found.' });
    res.json({ message: 'Plan deleted.' });
  } catch (err) { sendError(res, err); }
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
  } catch (err) { sendError(res, err); }
});

router.patch('/config', adminAuth, requireSuper, async (req, res) => {
  try {
    const allowed = ['globalServiceMode', 'serviceModeMessage', 'defaultTrialDays', 'defaultMonthlyRate', 'appDownloadUrl', 'appDownloadEnabled'];
    const update  = {};
    for (const k of allowed) {
      if (req.body[k] !== undefined) update[k] = req.body[k];
    }
    if (update.globalServiceMode !== undefined) update.globalServiceMode = update.globalServiceMode === true || update.globalServiceMode === 'true';
    if (update.serviceModeMessage !== undefined) update.serviceModeMessage = String(update.serviceModeMessage).slice(0, 500);
    if (update.defaultTrialDays !== undefined) {
      const d = Number(update.defaultTrialDays);
      if (!Number.isInteger(d) || d < 1 || d > 365) return res.status(400).json({ message: 'Trial days must be a whole number from 1 to 365.' });
      update.defaultTrialDays = d;
    }
    if (update.appDownloadUrl !== undefined) {
      const url = String(update.appDownloadUrl || '').trim();
      // https only — this link is handed to every visitor of the web app
      let ok = url === '';
      try { ok = ok || (url.length <= 500 && new URL(url).protocol === 'https:'); } catch { ok = false; }
      if (!ok) return res.status(400).json({ message: 'Download link must be a full https:// address (or empty to use the default).' });
      update.appDownloadUrl = url;
    }
    if (update.appDownloadEnabled !== undefined) update.appDownloadEnabled = update.appDownloadEnabled === true || update.appDownloadEnabled === 'true';
    if (update.defaultMonthlyRate !== undefined) {
      const r = Number(update.defaultMonthlyRate);
      if (!Number.isFinite(r) || r < 0) return res.status(400).json({ message: 'Monthly rate must be a number of 0 or more.' });
      update.defaultMonthlyRate = r;
    }
    const cfg = await AppConfig.findOneAndUpdate(
      { key: 'global' }, { $set: update }, { upsert: true, new: true }
    ).lean();
    res.json(cfg);
  } catch (err) { sendError(res, err); }
});

// ═══════════════════════════════════════════════════════════════
// SALARY REPORT
// ═══════════════════════════════════════════════════════════════

// GET /admin/salary-report — all saloons with salary summary for a period
router.get('/salary-report', adminAuth, async (req, res) => {
  try {
    const { from, to } = req.query;
    const fromDate = parseDay(from, TZ) || monthRange(TZ).start;
    const toDate   = parseDay(to, TZ, true) || todayRange(TZ).end;

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
  } catch (err) { sendError(res, err); }
});

// GET /admin/salary-report/:saloonId — staff-level salary breakdown for a saloon
router.get('/salary-report/:saloonId', adminAuth, async (req, res) => {
  try {
    const { from, to } = req.query;
    const saloonId = req.params.saloonId;
    const fromDate = parseDay(from, TZ) || monthRange(TZ).start;
    const toDate   = parseDay(to, TZ, true) || todayRange(TZ).end;

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
  } catch (err) { sendError(res, err); }
});

// GET /admin/salary-report/:saloonId/staff/:staffId/history
router.get('/salary-report/:saloonId/staff/:staffId/history', adminAuth, async (req, res) => {
  try {
    const settlements = await SaloonSalarySettlement.find({
      saloon: req.params.saloonId,
      staff:  req.params.staffId
    }).sort({ settledAt: -1 }).limit(30).lean();
    res.json(settlements);
  } catch (err) { sendError(res, err); }
});

// POST /admin/salary-report/:saloonId/settle — record a salary payment (superadmin).
// Bills, revenue and commission for the period are computed here, not trusted from the client.
router.post('/salary-report/:saloonId/settle', adminAuth, requireSuper, async (req, res) => {
  try {
    const { staffId, periodFrom, periodTo, paymentMode, notes } = req.body;
    const amountPaid = toNum(req.body.amountPaid);

    if (!staffId || !periodFrom || !periodTo || amountPaid === undefined)
      return res.status(400).json({ message: 'staffId, periodFrom, periodTo and amountPaid are required.' });
    if (!Number.isFinite(amountPaid) || amountPaid < 0)
      return res.status(400).json({ message: 'amountPaid must be a number of 0 or more.' });

    const mode = String(paymentMode || '').trim().toLowerCase();
    if (!['cash', 'upi'].includes(mode)) return res.status(400).json({ message: 'Select a payment mode: Cash or UPI.' });

    const from = parseDay(periodFrom, TZ), to = parseDay(periodTo, TZ, true);
    if (!from || !to || from > to) return res.status(400).json({ message: 'Invalid pay period.' });

    const staff = isId(String(staffId)) && await SaloonStaff.findOne({ _id: staffId, saloon: req.params.saloonId }).lean();
    if (!staff) return res.status(404).json({ message: 'Staff not found in this saloon.' });

    const [agg] = await SaloonWorkEntry.aggregate([
      { $match: { saloon: staff.saloon, staff: staff._id, serviceDate: { $gte: from, $lte: to } } },
      { $group: { _id: null, bills: { $sum: 1 }, revenue: { $sum: '$grandTotal' }, earning: { $sum: '$staffEarning' } } }
    ]);

    const settlement = await SaloonSalarySettlement.create({
      saloon:       staff.saloon,
      staff:        staff._id,
      staffName:    staff.name,
      staffPhone:   staff.phone || '',
      periodFrom:   from,
      periodTo:     to,
      totalBills:   agg?.bills   || 0,
      totalRevenue: agg?.revenue || 0,
      grossEarning: agg?.earning || 0,
      amountPaid,
      paymentMode:  mode,
      notes:        notes ? String(notes).slice(0, 500) : '',
      paidBy:       `${req.admin?.name || 'Admin'} (admin)`,
      settledAt:    new Date()
    });

    res.status(201).json(settlement);
  } catch (err) { sendError(res, err); }
});

module.exports = router;
