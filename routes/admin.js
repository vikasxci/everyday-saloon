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

const ADMIN_SECRET = (process.env.JWT_SECRET || 'hadlay-kalan-secret-key') + '_admin';

// ── Helpers ──────────────────────────────────────────────────
function makeAdminToken(id) {
  return jwt.sign({ id }, ADMIN_SECRET, { expiresIn: '7d' });
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
      ip: req.headers['x-forwarded-for']?.split(',')[0] || req.socket?.remoteAddress || '',
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
  } catch (err) { res.status(500).json({ message: err.message }); }
});

router.post('/setup', async (req, res) => {
  try {
    const count = await AdminUser.countDocuments();
    if (count > 0)
      return res.status(403).json({ message: 'Admin already exists. Use login.' });

    const { name, username, password } = req.body;
    if (!name || !username || !password)
      return res.status(400).json({ message: 'name, username and password are required.' });
    if (String(password).length < 8)
      return res.status(400).json({ message: 'Choose a password of at least 8 characters.' });

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

// Change your own password
router.post('/auth/change-password', adminAuth, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword)
      return res.status(400).json({ message: 'Current and new password are required.' });
    if (String(newPassword).length < 6)
      return res.status(400).json({ message: 'Password must be at least 6 characters.' });

    const admin = await AdminUser.findById(req.admin._id);
    if (!admin) return res.status(404).json({ message: 'Admin not found.' });
    if (!await admin.comparePassword(oldPassword))
      return res.status(401).json({ message: 'Current password is incorrect.' });

    admin.password = newPassword;
    await admin.save();
    res.json({ message: 'Password changed.' });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ═══════════════════════════════════════════════════════════════
// ADMIN USERS  (superadmin only)
// ═══════════════════════════════════════════════════════════════
router.get('/admins', adminAuth, requireSuper, async (req, res) => {
  try {
    const list = await AdminUser.find().select('-password').sort({ createdAt: 1 }).lean();
    res.json(list.map(a => ({ ...a, isSelf: String(a._id) === String(req.admin._id) })));
  } catch (err) { res.status(500).json({ message: err.message }); }
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
    res.status(500).json({ message: err.message });
  }
});

router.patch('/admins/:id', adminAuth, requireSuper, async (req, res) => {
  try {
    const { name, role, isActive } = req.body;
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

    if (name !== undefined)     admin.name = name.trim();
    if (role !== undefined)     admin.role = role;
    if (isActive !== undefined) admin.isActive = !!isActive;
    await admin.save();

    const { password: _, ...safe } = admin.toObject();
    res.json(safe);
  } catch (err) { res.status(500).json({ message: err.message }); }
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
    await admin.save();
    res.json({ message: `Password reset for ${admin.username}.` });
  } catch (err) { res.status(500).json({ message: err.message }); }
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
  } catch (err) { res.status(500).json({ message: err.message }); }
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
        { email:        { $regex: search, $options: 'i' } },
        { saloonCode:   { $regex: search, $options: 'i' } }
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
    logAdmin(req, saloon, 'admin_subscription_update', { details: update });
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
    ).select('businessName email serviceMode').lean();
    if (!saloon) return res.status(404).json({ message: 'Saloon not found.' });
    logAdmin(req, saloon, 'admin_service_mode', { details: { serviceMode: !!serviceMode } });
    res.json(saloon);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── Saloon detail tabs ───────────────────────────────────────

// Staff roster with per-staff earnings
router.get('/saloons/:id/staff', adminAuth, async (req, res) => {
  try {
    const saloonId = new mongoose.Types.ObjectId(req.params.id);
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
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// Recent bills
router.get('/saloons/:id/bills', adminAuth, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const q = { saloon: req.params.id };
    const [bills, total] = await Promise.all([
      SaloonWorkEntry.find(q).sort({ serviceDate: -1, createdAt: -1 })
        .skip((page - 1) * limit).limit(Number(limit))
        .select('billNumber customerName staffName grandTotal amountPaid amountDue paymentStatus paymentMode serviceDate staffEarning')
        .lean(),
      SaloonWorkEntry.countDocuments(q)
    ]);
    res.json({ bills, total, page: Number(page), pages: Math.ceil(total / limit) });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// Activity for one saloon
router.get('/saloons/:id/activity', adminAuth, async (req, res) => {
  try {
    const { page = 1, limit = 30, action = '' } = req.query;
    const q = { business: req.params.id };
    if (action) q.action = action;
    const [logs, total] = await Promise.all([
      BusinessActivityLog.find(q).sort({ createdAt: -1 })
        .skip((page - 1) * limit).limit(Number(limit)).lean(),
      BusinessActivityLog.countDocuments(q)
    ]);
    res.json({ logs, total, page: Number(page), pages: Math.ceil(total / limit) });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── Saloon account commands (superadmin) ─────────────────────

// Edit business details
router.patch('/saloons/:id', adminAuth, requireSuper, async (req, res) => {
  try {
    const { businessName, ownerName, email, phone, city, businessType, gstin } = req.body;
    const saloon = await SaloonBusiness.findById(req.params.id);
    if (!saloon) return res.status(404).json({ message: 'Saloon not found.' });

    if (email && email.toLowerCase().trim() !== saloon.email) {
      const clash = await SaloonBusiness.findOne({ email: email.toLowerCase().trim(), _id: { $ne: saloon._id } });
      if (clash) return res.status(409).json({ message: 'Another saloon already uses that email.' });
      saloon.email = email.toLowerCase().trim();
    }
    if (phone && phone.trim() !== saloon.phone) {
      const clash = await SaloonBusiness.findOne({ phone: phone.trim(), _id: { $ne: saloon._id } });
      if (clash) return res.status(409).json({ message: 'Another saloon already uses that phone.' });
      saloon.phone = phone.trim();
    }
    if (businessName) saloon.businessName = businessName.trim();
    if (ownerName)    saloon.ownerName    = ownerName.trim();
    if (businessType) saloon.businessType = businessType;
    if (gstin !== undefined) saloon.gstin = gstin;
    if (city !== undefined)  saloon.address = { ...(saloon.address || {}), city };

    await saloon.save();
    logAdmin(req, saloon, 'admin_saloon_update', { details: { by: req.admin.username } });

    const { password: _, token: __, ...safe } = saloon.toObject();
    res.json(safe);
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ message: 'Email or phone already in use.' });
    res.status(500).json({ message: err.message });
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
    if (!isActive) await SaloonStaff.updateMany({ saloon: saloon._id }, { $unset: { token: 1 } });

    logAdmin(req, saloon, 'admin_saloon_status', { details: { isActive: !!isActive } });
    res.json({ _id: saloon._id, businessName: saloon.businessName, isActive: saloon.isActive });
  } catch (err) { res.status(500).json({ message: err.message }); }
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
    await owner.save();

    saloon.password = password;
    await saloon.save();

    logAdmin(req, saloon, 'admin_owner_password_reset', {
      entity: 'staff', entityId: owner._id, entityName: owner.name
    });
    res.json({ message: `Owner password reset for ${saloon.businessName}.`, ownerName: owner.name, loginWith: owner.phone || owner.email });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// Delete a saloon and everything under it
router.delete('/saloons/:id', adminAuth, requireSuper, async (req, res) => {
  try {
    const saloon = await SaloonBusiness.findById(req.params.id);
    if (!saloon) return res.status(404).json({ message: 'Saloon not found.' });

    // Typing the exact business name is the confirmation
    if (String(req.body?.confirmName || '').trim() !== saloon.businessName)
      return res.status(400).json({ message: `Type the exact business name "${saloon.businessName}" to confirm deletion.` });

    const id = saloon._id;
    const [staff, services, entries, customers, attendance, settlements, requests] = await Promise.all([
      SaloonStaff.deleteMany({ saloon: id }),
      SaloonService.deleteMany({ saloon: id }),
      SaloonWorkEntry.deleteMany({ saloon: id }),
      SaloonCustomer.deleteMany({ saloon: id }),
      SaloonAttendance.deleteMany({ saloon: id }),
      SaloonSalarySettlement.deleteMany({ saloon: id }),
      SaloonCollectionRequest.deleteMany({ saloon: id })
    ]);
    await BusinessActivityLog.deleteMany({ business: id });
    await SaloonBusiness.findByIdAndDelete(id);

    console.warn(`🗑️  Admin ${req.admin.username} deleted saloon "${saloon.businessName}" (${id})`);
    res.json({
      message: `Deleted "${saloon.businessName}" and all of its data.`,
      removed: {
        staff: staff.deletedCount, services: services.deletedCount,
        bills: entries.deletedCount, customers: customers.deletedCount,
        attendance: attendance.deletedCount, settlements: settlements.deletedCount,
        collectionRequests: requests.deletedCount
      }
    });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ═══════════════════════════════════════════════════════════════
// ACTIVITY LOG  (platform-wide)
// ═══════════════════════════════════════════════════════════════
router.get('/activity', adminAuth, async (req, res) => {
  try {
    const { page = 1, limit = 40, action = '', search = '', from = '', to = '' } = req.query;
    const q = { bizType: 'saloon' };
    if (action) q.action = action;
    if (search) q.$or = [
      { businessName: { $regex: search, $options: 'i' } },
      { actor:        { $regex: search, $options: 'i' } },
      { entityName:   { $regex: search, $options: 'i' } }
    ];
    if (from || to) {
      q.createdAt = {};
      if (from) q.createdAt.$gte = new Date(from);
      if (to)   q.createdAt.$lte = new Date(new Date(to).setHours(23, 59, 59, 999));
    }

    const [logs, total, actions] = await Promise.all([
      BusinessActivityLog.find(q).sort({ createdAt: -1 })
        .skip((page - 1) * limit).limit(Number(limit)).lean(),
      BusinessActivityLog.countDocuments(q),
      BusinessActivityLog.distinct('action', { bizType: 'saloon' })
    ]);

    res.json({ logs, total, page: Number(page), pages: Math.ceil(total / limit), actions: actions.sort() });
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
  } catch (err) { res.status(500).json({ message: err.message }); }
});

router.put('/plans/:id', adminAuth, requireSuper, async (req, res) => {
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

router.delete('/plans/:id', adminAuth, requireSuper, async (req, res) => {
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

router.patch('/config', adminAuth, requireSuper, async (req, res) => {
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
