const express = require('express');
const router  = express.Router();
const jwt     = require('jsonwebtoken');
const mongoose = require('mongoose');
const multer  = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const cloudinary = require('cloudinary').v2;

const saloonAuth = require('../middleware/saloonAuth');
const { requireRole } = saloonAuth;

const SaloonBusiness   = require('../models/SaloonBusiness');
const SaloonStaff      = require('../models/SaloonStaff');
const SaloonService    = require('../models/SaloonService');
const SaloonWorkEntry  = require('../models/SaloonWorkEntry');
const SaloonCustomer   = require('../models/SaloonCustomer');
const SaloonAttendance = require('../models/SaloonAttendance');
const SaloonSalarySettlement = require('../models/SaloonSalarySettlement');
const BusinessActivityLog = require('../models/BusinessActivityLog');
const SaloonCollectionRequest = require('../models/SaloonCollectionRequest');

const JWT_SECRET = process.env.JWT_SECRET || 'hadlay-kalan-secret-key';

// ── Activity Logger ───────────────────────────────────────────────────────────
async function logActivity(req, saloon, action, extras = {}) {
  try {
    await BusinessActivityLog.create({
      bizType:      'saloon',
      business:     saloon._id,
      businessName: saloon.businessName,
      ownerEmail:   saloon.email,
      actor:        req.staff?.name  || extras.actor || null,
      actorRole:    req.staff?.role  || extras.actorRole || null,
      action,
      entity:     extras.entity     || null,
      entityId:   extras.entityId   || null,
      entityName: extras.entityName || null,
      details:    extras.details    || null,
      ip:         req.headers['x-forwarded-for']?.split(',')[0] || req.socket?.remoteAddress || '',
      userAgent:  req.headers['user-agent'] || '',
    });
  } catch (_) { /* non-critical */ }
}

// ── Cloudinary upload for customer photos ─────────────────────────────────────
const photoStorage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: 'hadlay-kalan/saloon',
    allowed_formats: ['jpg', 'jpeg', 'png', 'webp'],
    transformation: [{ width: 800, height: 800, crop: 'limit', quality: 'auto' }]
  }
});
const uploadPhoto = multer({ storage: photoStorage, limits: { fileSize: 5 * 1024 * 1024 } });

// ── Helpers ───────────────────────────────────────────────────────────────────
function makeToken(staffId, saloonId, role) {
  return jwt.sign({ staffId, saloonId, role }, JWT_SECRET, { expiresIn: '30d' });
}
function slugify(t) {
  return t.toLowerCase().replace(/[^a-z0-9\s-]/g, '').trim().replace(/\s+/g, '-').substring(0, 50);
}
async function nextBillNumber(saloonId) {
  const n = await SaloonWorkEntry.countDocuments({ saloon: saloonId });
  return `SAL-${String(n + 1).padStart(5, '0')}`;
}
async function nextCustomerName(saloonId) {
  const n = await SaloonCustomer.countDocuments({ saloon: saloonId });
  return `Customer-${n + 1}`;
}

// ════════════════════════════════════════════════════════════════════════════
// AUTH
// ════════════════════════════════════════════════════════════════════════════

// POST /api/saloon/auth/register
router.post('/auth/register', async (req, res) => {
  try {
    const { ownerName, businessName, email, phone, password, businessType, city, gstin } = req.body;
    if (!ownerName || !businessName || !email || !phone || !password)
      return res.status(400).json({ message: 'ownerName, businessName, email, phone and password are required.' });

    const existing = await SaloonBusiness.findOne({ $or: [{ email: email.toLowerCase() }, { phone: phone.trim() }] });
    if (existing) return res.status(409).json({ message: 'Email or phone already registered.' });

    let base = slugify(businessName), slug = base, n = 1;
    while (await SaloonBusiness.findOne({ slug })) slug = `${base}-${n++}`;

    // Determine trial duration from AppConfig
    const AppConfig = require('../models/AppConfig');
    const cfg = await AppConfig.findOne({ key: 'global' }).lean();
    const trialDays = cfg?.defaultTrialDays ?? 30;
    const trialEndsAt = new Date(Date.now() + trialDays * 24 * 60 * 60 * 1000);

    const saloon = await SaloonBusiness.create({
      businessName: businessName.trim(),
      ownerName: ownerName.trim(),
      email: email.toLowerCase().trim(),
      phone: phone.trim(),
      password,
      slug,
      businessType: businessType || 'salon',
      gstin,
      'address.city': city || '',
      subscription: {
        status: 'trial',
        trialEndsAt,
        monthlyRate: cfg?.defaultMonthlyRate || 999
      }
    });

    const owner = await SaloonStaff.create({
      saloon: saloon._id,
      name: ownerName.trim(),
      email: email.toLowerCase().trim(),
      phone: phone.trim(),
      password,
      role: 'owner'
    });

    const token = makeToken(owner._id, saloon._id, 'owner');
    owner.token = token;
    await owner.save({ validateBeforeSave: false });
    saloon.token = token;
    await saloon.save({ validateBeforeSave: false });

    logActivity(req, saloon, 'register', { actor: ownerName, actorRole: 'owner', details: { businessType: saloon.businessType, city } });
    res.status(201).json({
      message: 'Saloon registered.',
      token,
      staff: owner.toSafeObject(),
      saloon: saloon.toSafeObject(),
      trial: { endsAt: trialEndsAt, days: trialDays }
    });
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ message: 'Email or phone already registered.' });
    res.status(500).json({ message: err.message });
  }
});

// POST /api/saloon/auth/login  (owner / manager full login)
router.post('/auth/login', async (req, res) => {
  try {
    const { emailOrPhone, password, saloonId } = req.body;
    if (!emailOrPhone || !password) return res.status(400).json({ message: 'Email/phone and password required.' });

    const q = saloonId
      ? { saloon: saloonId, $or: [{ email: emailOrPhone.toLowerCase() }, { phone: emailOrPhone }] }
      : { $or: [{ email: emailOrPhone.toLowerCase() }, { phone: emailOrPhone }] };

    const staff = await SaloonStaff.findOne(q);
    if (!staff || !staff.password) return res.status(401).json({ message: 'Invalid credentials.' });
    if (!await staff.comparePassword(password)) return res.status(401).json({ message: 'Invalid credentials.' });
    if (!staff.isActive) return res.status(403).json({ message: 'Account deactivated.' });

    const saloon = await SaloonBusiness.findById(staff.saloon);
    if (!saloon || !saloon.isActive) return res.status(403).json({ message: 'Saloon account inactive.' });

    const token = makeToken(staff._id, saloon._id, staff.role);
    staff.token = token;
    staff.lastLoginAt = new Date();
    staff.loginCount = (staff.loginCount || 0) + 1;
    await staff.save({ validateBeforeSave: false });

    logActivity(req, saloon, 'login', { actor: staff.name, actorRole: staff.role });
    res.json({ token, staff: staff.toSafeObject(), saloon: saloon.toSafeObject() });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// POST /api/saloon/auth/pin-login  (staff PIN login)
router.post('/auth/pin-login', async (req, res) => {
  try {
    const { saloonId, pin } = req.body;
    if (!saloonId || !pin) return res.status(400).json({ message: 'saloonId and pin required.' });

    const staffList = await SaloonStaff.find({ saloon: saloonId, isActive: true, pin: { $exists: true, $ne: null } });
    let matched = null;
    for (const s of staffList) {
      if (s.pin && await s.comparePin(pin)) { matched = s; break; }
    }
    if (!matched) return res.status(401).json({ message: 'Invalid PIN.' });

    const saloon = await SaloonBusiness.findById(saloonId);
    if (!saloon || !saloon.isActive) return res.status(403).json({ message: 'Saloon account inactive.' });

    const token = makeToken(matched._id, saloon._id, matched.role);
    matched.token = token;
    matched.lastLoginAt = new Date();
    matched.loginCount = (matched.loginCount || 0) + 1;
    await matched.save({ validateBeforeSave: false });

    logActivity(req, saloon, 'pin_login', { actor: matched.name, actorRole: matched.role });
    res.json({ token, staff: matched.toSafeObject(), saloon: saloon.toSafeObject() });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// POST /api/saloon/auth/staff-login  (staff login with phone + password)
router.post('/auth/staff-login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password) return res.status(400).json({ message: 'phone and password required.' });

    // Find staff by phone across all saloons
    const staff = await SaloonStaff.findOne({ phone: phone.trim(), isActive: true });
    if (!staff) return res.status(401).json({ message: 'Staff not found or inactive.' });

    // Verify password
    if (!await staff.comparePassword(password)) return res.status(401).json({ message: 'Invalid password.' });

    const saloon = await SaloonBusiness.findById(staff.saloon);
    if (!saloon || !saloon.isActive) return res.status(403).json({ message: 'Saloon account inactive.' });

    const token = makeToken(staff._id, saloon._id, staff.role);
    staff.token = token;
    staff.lastLoginAt = new Date();
    staff.loginCount = (staff.loginCount || 0) + 1;
    await staff.save({ validateBeforeSave: false });

    logActivity(req, saloon, 'staff_login', { actor: staff.name, actorRole: staff.role });
    res.json({ token, staff: staff.toSafeObject(), saloon: saloon.toSafeObject() });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// POST /api/saloon/auth/staff/set-password  (first-time or forgot password setup)
router.post('/auth/staff/set-password', async (req, res) => {
  try {
    const { phone, pin, password } = req.body;
    if (!phone || !password) return res.status(400).json({ message: 'phone and password required.' });

    // Find staff by phone
    const staff = await SaloonStaff.findOne({ phone: phone.trim() });
    if (!staff) return res.status(401).json({ message: 'Staff not found.' });

    // If PIN is provided, verify it
    if (pin) {
      if (!staff.pin || !await staff.comparePin(pin)) {
        return res.status(401).json({ message: 'Invalid PIN.' });
      }
    }

    // Set the new password
    staff.password = password;
    await staff.save();

    logActivity(req, staff.saloon, 'staff_set_password', { entity: 'staff', entityId: staff._id, entityName: staff.name });
    res.json({ message: 'Password set successfully.' });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// POST /api/saloon/auth/logout
router.post('/auth/logout', saloonAuth, async (req, res) => {
  try {
    await SaloonStaff.findByIdAndUpdate(req.staff._id, { $unset: { token: 1 } });
    res.json({ message: 'Logged out.' });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// GET /api/saloon/auth/me
router.get('/auth/me', saloonAuth, async (req, res) => {
  res.json({ staff: req.staff, saloon: req.saloon });
});

// POST /api/saloon/auth/change-password  (staff change their own password)
router.post('/auth/change-password', saloonAuth, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) return res.status(400).json({ message: 'oldPassword and newPassword required.' });

    const staff = await SaloonStaff.findById(req.staff._id);
    if (!staff) return res.status(404).json({ message: 'Staff not found.' });

    // Verify old password
    if (!await staff.comparePassword(oldPassword)) return res.status(401).json({ message: 'Current password is incorrect.' });

    // Set new password
    staff.password = newPassword;
    await staff.save();

    logActivity(req, req.saloon, 'staff_change_password', { entity: 'staff', entityId: staff._id, entityName: staff.name });
    res.json({ message: 'Password changed successfully.' });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ════════════════════════════════════════════════════════════════════════════
// STAFF MANAGEMENT  (owner / manager only)
// ════════════════════════════════════════════════════════════════════════════

// GET /api/saloon/staff
router.get('/staff', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const list = await SaloonStaff.find({ saloon: req.saloon._id })
      .select('-password -pin -token').sort({ createdAt: 1 }).lean();
    res.json(list);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// POST /api/saloon/staff
router.post('/staff', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const { name, email, phone, role, pin, password, specializations, salary, commissionType, commissionValue, designation, joiningDate } = req.body;
    if (!name || !role) return res.status(400).json({ message: 'name and role are required.' });

    const staff = await SaloonStaff.create({
      saloon: req.saloon._id,
      name: name.trim(), email, phone,
      role, pin, password,
      specializations: specializations || [],
      salary: salary || 0,
      commissionType: commissionType || 'percent',
      commissionValue: commissionValue ?? 40,
      designation, joiningDate
    });
    logActivity(req, req.saloon, 'staff_create', { entity: 'staff', entityId: staff._id, entityName: staff.name, details: { role } });
    res.status(201).json(staff.toSafeObject());
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ message: 'Phone or email already used.' });
    res.status(500).json({ message: err.message });
  }
});

// PUT /api/saloon/staff/:id
router.put('/staff/:id', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const staff = await SaloonStaff.findOne({ _id: req.params.id, saloon: req.saloon._id });
    if (!staff) return res.status(404).json({ message: 'Staff not found.' });

    const fields = ['name', 'email', 'phone', 'role', 'specializations', 'salary', 'commissionType', 'commissionValue', 'designation', 'joiningDate', 'isActive'];
    fields.forEach(f => { if (req.body[f] !== undefined) staff[f] = req.body[f]; });

    if (req.body.password) staff.password = req.body.password;
    if (req.body.pin)      staff.pin      = req.body.pin;

    await staff.save();
    logActivity(req, req.saloon, 'staff_update', { entity: 'staff', entityId: staff._id, entityName: staff.name });
    res.json(staff.toSafeObject());
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// DELETE /api/saloon/staff/:id
router.delete('/staff/:id', saloonAuth, requireRole('owner'), async (req, res) => {
  try {
    const staff = await SaloonStaff.findOne({ _id: req.params.id, saloon: req.saloon._id });
    if (!staff) return res.status(404).json({ message: 'Staff not found.' });
    if (staff.role === 'owner') return res.status(400).json({ message: 'Cannot delete owner.' });
    logActivity(req, req.saloon, 'staff_delete', { entity: 'staff', entityId: staff._id, entityName: staff.name });
    await SaloonStaff.findByIdAndDelete(staff._id);
    res.json({ message: 'Staff deleted.' });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// POST /api/saloon/staff/:id/avatar
router.post('/staff/:id/avatar', saloonAuth, requireRole('owner', 'manager'), uploadPhoto.single('photo'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded.' });
    const staff = await SaloonStaff.findOneAndUpdate(
      { _id: req.params.id, saloon: req.saloon._id },
      { avatar: req.file.path },
      { new: true }
    );
    if (!staff) return res.status(404).json({ message: 'Staff not found.' });
    res.json({ avatar: staff.avatar });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// GET /api/saloon/staff/:id/pending-customers — customers with pending amount billed by this staff
// Staff can view their own; owner/manager can view any
router.get('/staff/:id/pending-customers', saloonAuth, async (req, res) => {
  try {
    const staffId = req.params.id;
    // Staff can only view their own pending customers
    if (req.staff.role === 'staff' && req.staff._id.toString() !== staffId) {
      return res.status(403).json({ message: 'Access denied.' });
    }

    // Aggregate pending due per customer from work entries billed by this staff
    const agg = await SaloonWorkEntry.aggregate([
      {
        $match: {
          saloon: req.saloon._id,
          staff:  new mongoose.Types.ObjectId(staffId),
          paymentStatus: { $in: ['pending', 'partial'] },
          amountDue: { $gt: 0 },
          customer: { $exists: true, $ne: null }
        }
      },
      {
        $group: {
          _id: '$customer',
          totalDue: { $sum: '$amountDue' },
          lastBill: { $max: '$serviceDate' }
        }
      }
    ]);

    if (!agg.length) return res.json([]);

    const custMap = {};
    agg.forEach(a => { custMap[String(a._id)] = { totalDue: a.totalDue, lastBill: a.lastBill }; });

    const customers = await SaloonCustomer.find({
      _id: { $in: agg.map(a => a._id) },
      saloon: req.saloon._id,
      isActive: true
    }).lean();

    // Attach live totalDue from aggregation (more accurate than denormalized pendingAmount)
    const result = customers.map(c => ({
      ...c,
      pendingAmount: custMap[String(c._id)]?.totalDue ?? c.pendingAmount
    })).sort((a, b) => b.pendingAmount - a.pendingAmount);

    res.json(result);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ════════════════════════════════════════════════════════════════════════════
// COLLECTION REQUESTS (staff submits → owner/manager approves)
// ════════════════════════════════════════════════════════════════════════════

// POST /api/saloon/collection-requests  — staff submits a collection request
router.post('/collection-requests', saloonAuth, async (req, res) => {
  try {
    const { customerId, amount, paymentMode, notes } = req.body;
    if (!customerId || !amount || parseFloat(amount) <= 0)
      return res.status(400).json({ message: 'customerId and amount required.' });

    const customer = await SaloonCustomer.findOne({ _id: customerId, saloon: req.saloon._id });
    if (!customer) return res.status(404).json({ message: 'Customer not found.' });

    // Verify this customer actually has pending amount from this staff's bills
    const pendingSum = await SaloonWorkEntry.aggregate([
      { $match: {
        saloon: req.saloon._id,
        staff: req.staff._id,
        customer: customer._id,
        paymentStatus: { $in: ['pending', 'partial'] },
        amountDue: { $gt: 0 }
      }},
      { $group: { _id: null, total: { $sum: '$amountDue' } } }
    ]);
    const totalDue = pendingSum[0]?.total || 0;
    // If owner/manager, allow collecting for any customer in saloon
    const isManager = ['owner', 'manager'].includes(req.staff.role);
    if (!isManager && totalDue <= 0)
      return res.status(400).json({ message: 'No pending amount for this customer from your bills.' });

    const collectAmt = Math.min(parseFloat(amount), isManager ? customer.pendingAmount : totalDue);
    if (collectAmt <= 0) return res.status(400).json({ message: 'Nothing to collect.' });

    const creq = await SaloonCollectionRequest.create({
      saloon:          req.saloon._id,
      customer:        customer._id,
      customerName:    customer.name,
      customerPhone:   customer.phone,
      amount:          collectAmt,
      paymentMode:     paymentMode || 'cash',
      notes:           notes || '',
      requestedBy:     req.staff._id,
      requestedByName: req.staff.name,
      status:          isManager ? 'approved' : 'pending'  // managers auto-approve
    });

    // If manager/owner — process immediately
    if (isManager) {
      await processCollectionApproval(creq, req.saloon, req.staff);
    }

    logActivity(req, req.saloon, 'collection_request_submit', {
      entity: 'customer', entityId: customer._id, entityName: customer.name,
      details: { amount: collectAmt, paymentMode, status: creq.status }
    });

    res.status(201).json(creq);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// Shared helper — apply an approved collection to bills and customer
async function processCollectionApproval(creq, saloon, reviewer) {
  const customer = await SaloonCustomer.findById(creq.customer);
  if (!customer) return;

  // Use live work-entry sum — customer.pendingAmount can be stale
  const liveAgg = await SaloonWorkEntry.aggregate([
    { $match: { saloon: customer.saloon, customer: customer._id, paymentStatus: { $in: ['pending', 'partial'] }, amountDue: { $gt: 0 } } },
    { $group: { _id: null, total: { $sum: '$amountDue' } } }
  ]);
  const livePending = liveAgg[0]?.total || 0;
  const toCollect = Math.min(creq.amount, livePending > 0 ? livePending : creq.amount);

  // Sync and reduce customer pendingAmount
  customer.pendingAmount = Math.max(0, livePending - toCollect);
  await customer.save();

  // Mark bills as paid (oldest first)
  const pendingBills = await SaloonWorkEntry.find({
    saloon: customer.saloon,
    customer: customer._id,
    paymentStatus: { $in: ['pending', 'partial'] },
    amountDue: { $gt: 0 }
  }).sort({ serviceDate: 1 });

  let remaining = toCollect;
  for (const bill of pendingBills) {
    if (remaining <= 0) break;
    const toPay = Math.min(remaining, bill.amountDue);
    bill.amountPaid = (bill.amountPaid || 0) + toPay;
    bill.amountDue  = Math.max(0, bill.amountDue - toPay);
    bill.paymentStatus = bill.amountDue === 0 ? 'paid' : 'partial';
    if (bill.amountDue === 0) {
      bill.staffEarning = bill.staffEarning || Math.round(bill.grandTotal * 0.4);
    }
    await bill.save();
    remaining -= toPay;
  }

  // Mark request as approved with reviewer
  if (reviewer) {
    creq.status = 'approved';
    creq.reviewedBy = reviewer._id;
    creq.reviewedByName = reviewer.name;
    creq.reviewedAt = new Date();
    await creq.save();
  }
}

// GET /api/saloon/collection-requests  — owner/manager sees all pending, staff sees their own
router.get('/collection-requests', saloonAuth, async (req, res) => {
  try {
    const { status, page = 1, limit = 30 } = req.query;
    const q = { saloon: req.saloon._id };
    if (status) q.status = status;
    // Staff see only their own requests
    if (!['owner', 'manager'].includes(req.staff.role)) {
      q.requestedBy = req.staff._id;
    }
    const requests = await SaloonCollectionRequest.find(q)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(Number(limit))
      .lean();
    const total = await SaloonCollectionRequest.countDocuments(q);
    res.json({ requests, total });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// PATCH /api/saloon/collection-requests/:id/approve  — owner/manager approves
router.patch('/collection-requests/:id/approve', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const creq = await SaloonCollectionRequest.findOne({ _id: req.params.id, saloon: req.saloon._id });
    if (!creq) return res.status(404).json({ message: 'Request not found.' });
    if (creq.status !== 'pending') return res.status(400).json({ message: `Request is already ${creq.status}.` });

    await processCollectionApproval(creq, req.saloon, req.staff);

    logActivity(req, req.saloon, 'collection_request_approved', {
      entity: 'customer', entityId: creq.customer, entityName: creq.customerName,
      details: { amount: creq.amount, requestedBy: creq.requestedByName }
    });

    res.json({ message: `Approved ₹${creq.amount} collection from ${creq.customerName}.`, request: creq });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// PATCH /api/saloon/collection-requests/:id/reject  — owner/manager rejects
router.patch('/collection-requests/:id/reject', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const creq = await SaloonCollectionRequest.findOne({ _id: req.params.id, saloon: req.saloon._id });
    if (!creq) return res.status(404).json({ message: 'Request not found.' });
    if (creq.status !== 'pending') return res.status(400).json({ message: `Request is already ${creq.status}.` });

    creq.status = 'rejected';
    creq.reviewedBy = req.staff._id;
    creq.reviewedByName = req.staff.name;
    creq.reviewedAt = new Date();
    creq.rejectReason = req.body.reason || '';
    await creq.save();

    logActivity(req, req.saloon, 'collection_request_rejected', {
      entity: 'customer', entityId: creq.customer, entityName: creq.customerName,
      details: { amount: creq.amount, reason: creq.rejectReason }
    });

    res.json({ message: 'Request rejected.', request: creq });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ════════════════════════════════════════════════════════════════════════════
// SERVICES
// ════════════════════════════════════════════════════════════════════════════

// GET /api/saloon/services
router.get('/services', saloonAuth, async (req, res) => {
  try {
    const services = await SaloonService.find({ saloon: req.saloon._id, isActive: true })
      .sort({ category: 1, sortOrder: 1, name: 1 }).lean();
    res.json(services);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// POST /api/saloon/services
router.post('/services', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const { name, category, price, duration, gender, description } = req.body;
    if (!name || price === undefined) return res.status(400).json({ message: 'name and price are required.' });
    const service = await SaloonService.create({ saloon: req.saloon._id, name, category, price, duration, gender, description });
    logActivity(req, req.saloon, 'service_create', { entity: 'service', entityId: service._id, entityName: name, details: { category, price } });
    res.status(201).json(service);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// PUT /api/saloon/services/:id
router.put('/services/:id', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const service = await SaloonService.findOneAndUpdate(
      { _id: req.params.id, saloon: req.saloon._id },
      req.body,
      { new: true, runValidators: true }
    );
    if (!service) return res.status(404).json({ message: 'Service not found.' });
    logActivity(req, req.saloon, 'service_update', { entity: 'service', entityId: service._id, entityName: service.name });
    res.json(service);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// DELETE /api/saloon/services/:id
router.delete('/services/:id', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const svc = await SaloonService.findOne({ _id: req.params.id, saloon: req.saloon._id });
    await SaloonService.findOneAndUpdate(
      { _id: req.params.id, saloon: req.saloon._id },
      { isActive: false }
    );
    logActivity(req, req.saloon, 'service_delete', { entity: 'service', entityId: req.params.id, entityName: svc?.name });
    res.json({ message: 'Service removed.' });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ════════════════════════════════════════════════════════════════════════════
// WORK ENTRIES (BILLS)
// ════════════════════════════════════════════════════════════════════════════

// POST /api/saloon/entries  — staff creates a new work entry / bill
router.post('/entries', saloonAuth, uploadPhoto.single('customerPhoto'), async (req, res) => {
  try {
    let body = req.body;
    if (typeof body.services === 'string') {
      try { body.services = JSON.parse(body.services); } catch { body.services = []; }
    }

    const { customerPhone, customerId, customerName: custNameOverride, services, paymentMode, paymentStatus, amountPaid, notes, serviceDate, waived } = body;

    if (!services || !Array.isArray(services) || services.length === 0)
      return res.status(400).json({ message: 'At least one service is required.' });

    const billNumber = await nextBillNumber(req.saloon._id);

    // Compute totals
    let subtotal = 0, discountTotal = 0, staffEarningTotal = 0;
    const commType = req.staff.commissionType || req.saloon.settings?.commissionType || 'percent';
    const commVal  = req.staff.commissionValue ?? req.saloon.settings?.commissionValue ?? 40;

    const serviceLines = services.map(s => {
      const lineTotal = (s.price || 0) * (s.qty || 1);
      const disc      = s.discount || 0;
      const net       = lineTotal - disc;
      const earning   = commType === 'percent' ? (net * commVal / 100) : commVal;
      subtotal     += net;
      discountTotal += disc;
      staffEarningTotal += earning;
      return { ...s, staffEarning: Math.round(earning) };
    });

    const taxPct     = req.saloon.settings?.taxPercent || 0;
    const taxAmount  = Math.round(subtotal * taxPct / 100);
    const grandTotal = subtotal + taxAmount;

    // Determine payment status
    const pStatus = paymentStatus || 'paid';
    const paid    = pStatus === 'pending' ? 0 : parseFloat(amountPaid ?? grandTotal);
    const due     = Math.max(0, Math.round(grandTotal - paid));

    // Auto-create or look up customer by phone
    let resolvedCustomerId = customerId || null;
    let resolvedCustomerName = 'Walk-in';

    if (customerPhone && customerPhone.trim()) {
      let cust = await SaloonCustomer.findOne({ saloon: req.saloon._id, phone: customerPhone.trim() });
      if (!cust) {
        const autoName = custNameOverride && custNameOverride.trim()
          ? custNameOverride.trim()
          : await nextCustomerName(req.saloon._id);
        cust = await SaloonCustomer.create({
          saloon: req.saloon._id,
          name: autoName,
          phone: customerPhone.trim(),
          firstVisitAt: new Date()
        });
      }
      resolvedCustomerId = cust._id;
      resolvedCustomerName = cust.name;
    }

    const entry = await SaloonWorkEntry.create({
      saloon:        req.saloon._id,
      staff:         req.staff._id,
      staffName:     req.staff.name,
      billNumber,
      customer:      resolvedCustomerId || undefined,
      customerName:  resolvedCustomerName,
      customerPhone: customerPhone || '',
      customerPhoto: req.file ? req.file.path : undefined,
      services:      serviceLines,
      subtotal:      Math.round(subtotal),
      discountTotal,
      taxAmount,
      grandTotal:    Math.round(grandTotal),
      staffEarning:  pStatus === 'pending' ? 0 : Math.round(staffEarningTotal),
      paymentMode:   pStatus === 'pending' ? 'credit' : (paymentMode || 'cash'),
      paymentStatus: pStatus,
      amountPaid:    Math.round(paid),
      amountDue:     due,
      notes,
      serviceDate:   serviceDate ? new Date(serviceDate) : new Date()
    });

    // Update customer stats
    if (resolvedCustomerId) {
      const custUpdate = {
        $inc: { totalVisits: 1, totalSpent: grandTotal },
        $set: { lastVisitAt: new Date() }
      };
      // If pending, add to pendingAmount
      if (due > 0) custUpdate.$inc.pendingAmount = due;
      await SaloonCustomer.findByIdAndUpdate(resolvedCustomerId, custUpdate);
    }

    // Add photo to customer gallery
    if (req.file && resolvedCustomerId) {
      await SaloonCustomer.findByIdAndUpdate(resolvedCustomerId, {
        $push: { photos: { url: req.file.path, workEntry: entry._id, takenAt: new Date() } }
      });
    }

    logActivity(req, req.saloon, 'bill_create', {
      entity: 'bill', entityId: entry._id, entityName: entry.billNumber,
      details: { grandTotal: entry.grandTotal, customerName: entry.customerName, paymentMode: entry.paymentMode, paymentStatus: pStatus }
    });
    res.status(201).json(entry);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// GET /api/saloon/entries  — filtered list
router.get('/entries', saloonAuth, async (req, res) => {
  try {
    const { from, to, staffId, page = 1, limit = 50 } = req.query;
    const q = { saloon: req.saloon._id };

    // Non-owner staff can only see their own entries
    if (!['owner', 'manager'].includes(req.staff.role)) {
      q.staff = req.staff._id;
    } else if (staffId) {
      q.staff = staffId;
    }

    if (from || to) {
      q.serviceDate = {};
      if (from) q.serviceDate.$gte = new Date(from);
      if (to)   { const d = new Date(to); d.setHours(23, 59, 59); q.serviceDate.$lte = d; }
    }

    // Today range
    const todayStart = new Date(); todayStart.setHours(0, 0, 0, 0);
    const todayEnd   = new Date(); todayEnd.setHours(23, 59, 59, 999);
    const todayQ = { ...q, serviceDate: { $gte: todayStart, $lte: todayEnd } };

    const [entries, total, summaryAgg, todayCount] = await Promise.all([
      SaloonWorkEntry.find(q)
        .sort({ serviceDate: -1 })
        .skip((page - 1) * limit)
        .limit(Number(limit))
        .lean(),
      SaloonWorkEntry.countDocuments(q),
      SaloonWorkEntry.aggregate([
        { $match: q },
        { $group: {
          _id: null,
          totalRevenue:  { $sum: '$grandTotal' },
          totalEarning:  { $sum: '$staffEarning' }
        }}
      ]),
      SaloonWorkEntry.countDocuments(todayQ)
    ]);

    // settledEarning = total salary actually paid to this staff (from SaloonSalarySettlement)
    let settledEarning = 0;
    if (q.staff) {
      const staffOid = new mongoose.Types.ObjectId(q.staff.toString());
      const [settledAgg] = await SaloonSalarySettlement.aggregate([
        { $match: { saloon: req.saloon._id, staff: staffOid } },
        { $group: { _id: null, total: { $sum: '$amountPaid' } } }
      ]);
      settledEarning = settledAgg?.total || 0;
    }

    const summary = summaryAgg[0] || { totalRevenue: 0, totalEarning: 0 };
    res.json({ entries, total, page: Number(page), pages: Math.ceil(total / limit),
      summary: { ...summary, settledEarning, todayCount } });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// GET /api/saloon/entries/:id
router.get('/entries/:id', saloonAuth, async (req, res) => {
  try {
    const entry = await SaloonWorkEntry.findOne({ _id: req.params.id, saloon: req.saloon._id })
      .populate('staff', 'name role avatar')
      .lean();
    if (!entry) return res.status(404).json({ message: 'Entry not found.' });
    res.json(entry);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// PUT /api/saloon/entries/:id  (owner / manager can edit)
router.put('/entries/:id', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const entry = await SaloonWorkEntry.findOneAndUpdate(
      { _id: req.params.id, saloon: req.saloon._id },
      req.body,
      { new: true, runValidators: true }
    );
    if (!entry) return res.status(404).json({ message: 'Entry not found.' });
    res.json(entry);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ════════════════════════════════════════════════════════════════════════════
// CUSTOMERS
// ════════════════════════════════════════════════════════════════════════════

// GET /api/saloon/customers?pending=true  — list, optionally filter pending only
router.get('/customers', saloonAuth, async (req, res) => {
  try {
    const { q, page = 1, limit = 30, pending } = req.query;
    const filter = { saloon: req.saloon._id, isActive: true };
    if (q) filter.$or = [
      { name: { $regex: q, $options: 'i' } },
      { phone: { $regex: q, $options: 'i' } }
    ];
    if (pending === 'true') filter.pendingAmount = { $gt: 0 };
    const [customers, total] = await Promise.all([
      SaloonCustomer.find(filter).sort({ pendingAmount: -1, totalVisits: -1 }).skip((page - 1) * limit).limit(Number(limit)).lean(),
      SaloonCustomer.countDocuments(filter)
    ]);
    res.json({ customers, total });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// POST /api/saloon/customers  — create with auto-name if name not provided
router.post('/customers', saloonAuth, async (req, res) => {
  try {
    const { phone, email, gender, birthdate, notes, preferredStaff } = req.body;
    if (!phone) return res.status(400).json({ message: 'phone is required.' });
    const existing = await SaloonCustomer.findOne({ saloon: req.saloon._id, phone: phone.trim() });
    if (existing) return res.status(409).json(existing);
    const autoName = await nextCustomerName(req.saloon._id);
    const customer = await SaloonCustomer.create({
      saloon: req.saloon._id,
      name: autoName, phone: phone.trim(), email, gender, birthdate, notes, preferredStaff,
      firstVisitAt: new Date()
    });
    logActivity(req, req.saloon, 'customer_create', { entity: 'customer', entityId: customer._id, entityName: customer.name });
    res.status(201).json(customer);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// GET /api/saloon/customers/search?q=  — search by phone or name for bill creation
router.get('/customers/search', saloonAuth, async (req, res) => {
  try {
    const { phone, q } = req.query;
    const filter = { saloon: req.saloon._id, isActive: true };
    const term = q || phone;
    if (term) {
      filter.$or = [
        { name:  { $regex: term.trim(), $options: 'i' } },
        { phone: { $regex: term.trim(), $options: 'i' } }
      ];
    } else return res.json([]);
    const customers = await SaloonCustomer.find(filter).limit(10).lean();
    res.json(customers);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// POST /api/saloon/customers/:id/collect  — collect pending payment from customer
router.post('/customers/:id/collect', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const { amount, paymentMode, staffId, notes } = req.body;
    const collectAmount = parseFloat(amount);
    if (!collectAmount || collectAmount <= 0)
      return res.status(400).json({ message: 'amount is required and must be > 0.' });

    const customer = await SaloonCustomer.findOne({ _id: req.params.id, saloon: req.saloon._id });
    if (!customer) return res.status(404).json({ message: 'Customer not found.' });

    // Use live work-entry sum as source of truth (customer.pendingAmount can be stale)
    const liveAgg = await SaloonWorkEntry.aggregate([
      { $match: { saloon: req.saloon._id, customer: customer._id, paymentStatus: { $in: ['pending', 'partial'] }, amountDue: { $gt: 0 } } },
      { $group: { _id: null, total: { $sum: '$amountDue' } } }
    ]);
    const livePending = liveAgg[0]?.total || 0;
    if (livePending <= 0) return res.status(400).json({ message: 'No pending amount for this customer.' });

    const toCollect = Math.min(collectAmount, livePending);

    // Sync customer.pendingAmount with live value then deduct
    customer.pendingAmount = Math.max(0, livePending - toCollect);
    await customer.save();

    // Update matching pending/partial bills — mark as paid (oldest first)
    const pendingBills = await SaloonWorkEntry.find({
      saloon: req.saloon._id, customer: customer._id, paymentStatus: { $in: ['pending', 'partial'] }, amountDue: { $gt: 0 }
    }).sort({ serviceDate: 1 });

    let remaining = toCollect;
    for (const bill of pendingBills) {
      if (remaining <= 0) break;
      const toPay = Math.min(remaining, bill.amountDue);
      bill.amountPaid = (bill.amountPaid || 0) + toPay;
      bill.amountDue  = Math.max(0, bill.amountDue - toPay);
      bill.paymentStatus = bill.amountDue === 0 ? 'paid' : 'partial';
      if (bill.paymentStatus === 'paid' || bill.paymentStatus === 'partial') {
        // Now credit staff earning for this bill
        bill.staffEarning = bill.staffEarning || Math.round(bill.grandTotal * 0.4);
      }
      await bill.save();

      // Add to staff earning if specified
      if (staffId) {
        await SaloonWorkEntry.updateOne({ _id: bill._id }, { staff: staffId });
      }
      remaining -= toPay;
    }

    logActivity(req, req.saloon, 'pending_collected', {
      entity: 'customer', entityId: customer._id, entityName: customer.name,
      details: { collected: toCollect, paymentMode, remainingPending: customer.pendingAmount }
    });

    res.json({ message: `Collected ₹${toCollect}`, customer, remainingPending: customer.pendingAmount });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// GET /api/saloon/customers/:id  (with visit history)
router.get('/customers/:id', saloonAuth, async (req, res) => {
  try {
    const customer = await SaloonCustomer.findOne({ _id: req.params.id, saloon: req.saloon._id }).lean();
    if (!customer) return res.status(404).json({ message: 'Customer not found.' });
    const history = await SaloonWorkEntry.find({ saloon: req.saloon._id, customer: customer._id })
      .sort({ serviceDate: -1 }).limit(20).lean();
    res.json({ customer, history });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ════════════════════════════════════════════════════════════════════════════
// ATTENDANCE
// ════════════════════════════════════════════════════════════════════════════

// Haversine distance in meters
function haversineDistance(lat1, lng1, lat2, lng2) {
  const R = 6371000;
  const toRad = deg => deg * Math.PI / 180;
  const dLat = toRad(lat2 - lat1);
  const dLng = toRad(lng2 - lng1);
  const a = Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

// POST /api/saloon/attendance/self-checkin  — any staff member (self check-in/out)
router.post('/attendance/self-checkin', saloonAuth, async (req, res) => {
  try {
    const { lat, lng, type = 'in' } = req.body; // type: 'in' | 'out'
    const saloon = req.saloon;

    // Geofence check — only if shop location is configured
    if (lat != null && lng != null && saloon.location?.lat && saloon.location?.lng) {
      const dist = haversineDistance(Number(lat), Number(lng), saloon.location.lat, saloon.location.lng);
      const radius = saloon.location.radius || 50;
      if (dist > radius) {
        return res.status(400).json({
          message: `You are ${Math.round(dist)}m away from the shop. You must be within ${radius}m to check ${type === 'out' ? 'out' : 'in'}.`,
          distance: Math.round(dist),
          required: radius
        });
      }
    }

    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const now = new Date();
    const timeStr = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;

    let update;
    if (type === 'out') {
      update = { $set: { checkOut: timeStr, checkoutAt: now, checkoutLat: lat, checkoutLng: lng } };
    } else {
      update = { $set: { status: 'present', selfCheckedIn: true, checkinAt: now, checkIn: timeStr, checkinLat: lat, checkinLng: lng } };
    }

    const record = await SaloonAttendance.findOneAndUpdate(
      { saloon: req.saloon._id, staff: req.staff._id, date: today },
      update,
      { upsert: true, new: true, runValidators: true }
    );
    res.json({ record, type, time: timeStr });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// GET /api/saloon/attendance/my-today  — get my attendance for today
router.get('/attendance/my-today', saloonAuth, async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const record = await SaloonAttendance.findOne({
      saloon: req.saloon._id, staff: req.staff._id, date: today
    }).lean();
    res.json(record || null);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// PATCH /api/saloon/settings/location  — save shop GPS location (owner/manager)
router.patch('/settings/location', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const { lat, lng, radius } = req.body;
    if (lat == null || lng == null) return res.status(400).json({ message: 'lat and lng required.' });
    const updated = await SaloonBusiness.findByIdAndUpdate(
      req.saloon._id,
      { $set: { 'location.lat': Number(lat), 'location.lng': Number(lng), 'location.radius': Number(radius) || 50 } },
      { new: true }
    );
    res.json({ location: updated.location });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// GET /api/saloon/attendance?month=YYYY-MM&staffId=...
// Staff can view their own attendance; managers/owners can view any
router.get('/attendance', saloonAuth, async (req, res) => {
  try {
    const { month, staffId } = req.query;
    const q = { saloon: req.saloon._id };
    
    // Determine which staff to query
    let queryStaffId = staffId || req.staff._id.toString();
    
    // Staff can only view their own; managers/owners can view any
    if (req.staff.role === 'staff' && queryStaffId !== req.staff._id.toString()) {
      return res.status(403).json({ message: 'Access denied. Can only view your own attendance.' });
    }
    
    if (queryStaffId) q.staff = queryStaffId;
    if (month) {
      const [y, m] = month.split('-').map(Number);
      q.date = { $gte: new Date(y, m - 1, 1), $lte: new Date(y, m, 0, 23, 59, 59) };
    }
    const records = await SaloonAttendance.find(q).populate('staff', 'name role avatar').sort({ date: -1 }).lean();
    res.json(records);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// POST /api/saloon/attendance
router.post('/attendance', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const { staffId, date, status, checkIn, checkOut, note } = req.body;
    if (!staffId || !date) return res.status(400).json({ message: 'staffId and date required.' });
    const record = await SaloonAttendance.findOneAndUpdate(
      { saloon: req.saloon._id, staff: staffId, date: new Date(date) },
      { status: status || 'present', checkIn, checkOut, note },
      { upsert: true, new: true, runValidators: true }
    );
    logActivity(req, req.saloon, 'attendance_mark', { entity: 'attendance', entityId: staffId, details: { date, status: status || 'present' } });
    res.json(record);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ════════════════════════════════════════════════════════════════════════════
// DASHBOARD & REPORTS
// ════════════════════════════════════════════════════════════════════════════

// GET /api/saloon/dashboard
router.get('/dashboard', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const saloonId = req.saloon._id;
    const today = new Date(); today.setHours(0, 0, 0, 0);
    const todayEnd = new Date(); todayEnd.setHours(23, 59, 59, 999);

    // This month
    const monthStart = new Date(today.getFullYear(), today.getMonth(), 1);
    const monthEnd   = new Date(today.getFullYear(), today.getMonth() + 1, 0, 23, 59, 59);

    const [
      todayEntries,
      monthEntries,
      totalCustomers,
      totalStaff,
      recentEntries,
      pendingAgg
    ] = await Promise.all([
      SaloonWorkEntry.aggregate([
        { $match: { saloon: saloonId, serviceDate: { $gte: today, $lte: todayEnd } } },
        { $group: { _id: null, revenue: { $sum: '$grandTotal' }, count: { $sum: 1 }, staffEarning: { $sum: '$staffEarning' } } }
      ]),
      SaloonWorkEntry.aggregate([
        { $match: { saloon: saloonId, serviceDate: { $gte: monthStart, $lte: monthEnd } } },
        { $group: { _id: null, revenue: { $sum: '$grandTotal' }, count: { $sum: 1 }, staffEarning: { $sum: '$staffEarning' } } }
      ]),
      SaloonCustomer.countDocuments({ saloon: saloonId, isActive: true }),
      SaloonStaff.countDocuments({ saloon: saloonId, isActive: true }),
      SaloonWorkEntry.find({ saloon: saloonId })
        .sort({ createdAt: -1 }).limit(10)
        .populate('staff', 'name avatar').lean(),
      SaloonWorkEntry.aggregate([
        { $match: { saloon: saloonId, paymentStatus: { $in: ['pending', 'partial'] }, amountDue: { $gt: 0 } } },
        { $group: { _id: null, total: { $sum: '$amountDue' }, count: { $sum: 1 } } }
      ])
    ]);

    // Staff performance this month
    const staffPerf = await SaloonWorkEntry.aggregate([
      { $match: { saloon: saloonId, serviceDate: { $gte: monthStart, $lte: monthEnd } } },
      { $group: { _id: '$staff', name: { $first: '$staffName' }, bills: { $sum: 1 }, revenue: { $sum: '$grandTotal' }, earning: { $sum: '$staffEarning' } } },
      { $sort: { revenue: -1 } }
    ]);

    // Owner's own earning (bills where owner themselves is the staff)
    const ownerEarnAgg = await SaloonWorkEntry.aggregate([
      { $match: { saloon: saloonId, staff: req.staff._id, serviceDate: { $gte: monthStart, $lte: monthEnd } } },
      { $group: { _id: null, earning: { $sum: '$staffEarning' }, bills: { $sum: 1 }, revenue: { $sum: '$grandTotal' } } }
    ]);
    const ownerEarn = ownerEarnAgg[0] || { earning: 0, bills: 0, revenue: 0 };

    res.json({
      today: todayEntries[0] || { revenue: 0, count: 0, staffEarning: 0 },
      month: monthEntries[0] || { revenue: 0, count: 0, staffEarning: 0 },
      totalCustomers,
      totalStaff,
      recentEntries,
      staffPerformance: staffPerf,
      pendingPayments: pendingAgg[0] || { total: 0, count: 0 },
      ownerEarn
    });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// GET /api/saloon/reports/staff  — per-staff earnings report
router.get('/reports/staff', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const { from, to } = req.query;
    const match = { saloon: req.saloon._id };
    if (from || to) {
      match.serviceDate = {};
      if (from) match.serviceDate.$gte = new Date(from);
      if (to) { const d = new Date(to); d.setHours(23, 59, 59); match.serviceDate.$lte = d; }
    }
    const data = await SaloonWorkEntry.aggregate([
      { $match: match },
      { $group: { _id: '$staff', name: { $first: '$staffName' }, bills: { $sum: 1 }, revenue: { $sum: '$grandTotal' }, earning: { $sum: '$staffEarning' } } },
      { $sort: { revenue: -1 } }
    ]);
    res.json(data);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ════════════════════════════════════════════════════════════════════════════
// SALOON SETTINGS
// ════════════════════════════════════════════════════════════════════════════

// GET /api/saloon/settings
router.get('/settings', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const saloon = await SaloonBusiness.findById(req.saloon._id).select('-password -token').lean();
    res.json(saloon);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// PUT /api/saloon/settings
router.put('/settings', saloonAuth, requireRole('owner'), async (req, res) => {
  try {
    const allowed = ['businessName', 'ownerName', 'phone', 'businessType', 'address', 'gstin', 'hours', 'settings'];
    const update = {};
    allowed.forEach(k => { if (req.body[k] !== undefined) update[k] = req.body[k]; });
    const saloon = await SaloonBusiness.findByIdAndUpdate(req.saloon._id, update, { new: true }).select('-password -token');
    logActivity(req, saloon, 'settings_update', { entity: 'business', entityId: saloon._id });
    res.json(saloon.toSafeObject ? saloon.toSafeObject() : saloon);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// POST /api/saloon/settings/logo
router.post('/settings/logo', saloonAuth, requireRole('owner'), uploadPhoto.single('logo'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded.' });
    const saloon = await SaloonBusiness.findByIdAndUpdate(req.saloon._id, { logo: req.file.path }, { new: true });
    res.json({ logo: saloon.logo });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// SALARY SETTLEMENT
// ════════════════════════════════════════════════════════════════════════════

// GET /api/saloon/salary/settlements?staffId=  — pending earning + settlement history
router.get('/salary/settlements', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const { staffId } = req.query;
    if (!staffId) return res.status(400).json({ message: 'staffId required.' });
    const saloonId = req.saloon._id;

    // All past settlements (most recent first)
    const settlements = await SaloonSalarySettlement
      .find({ saloon: saloonId, staff: staffId })
      .sort({ settledAt: -1 })
      .limit(30)
      .lean();

    // Period start = last settlement date (or joining date)
    const lastSettlement = settlements[0];
    let periodFrom;
    if (lastSettlement) {
      periodFrom = new Date(lastSettlement.settledAt);
    } else {
      const staffDoc = await SaloonStaff.findById(staffId).select('joiningDate').lean();
      periodFrom = staffDoc?.joiningDate || new Date(0);
    }

    const periodTo = new Date();
    periodTo.setHours(23, 59, 59, 999);

    const matchPending = {
      saloon: saloonId,
      staff:  new mongoose.Types.ObjectId(staffId),
      serviceDate: { $gte: periodFrom, $lte: periodTo }
    };

    const [pending] = await SaloonWorkEntry.aggregate([
      { $match: matchPending },
      { $group: { _id: null, bills: { $sum: 1 }, revenue: { $sum: '$grandTotal' }, earning: { $sum: '$staffEarning' } } }
    ]);

    res.json({
      settlements,
      pending: pending || { bills: 0, revenue: 0, earning: 0 },
      periodFrom,
      periodTo
    });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// POST /api/saloon/salary/settle  — create a settlement record
router.post('/salary/settle', saloonAuth, requireRole('owner'), async (req, res) => {
  try {
    const { staffId, amountPaid, paymentMode, notes } = req.body;
    if (!staffId || amountPaid === undefined)
      return res.status(400).json({ message: 'staffId and amountPaid are required.' });
    if (Number(amountPaid) < 0)
      return res.status(400).json({ message: 'amountPaid cannot be negative.' });

    const saloonId = req.saloon._id;

    // Determine period start
    const lastSettlement = await SaloonSalarySettlement
      .findOne({ saloon: saloonId, staff: staffId })
      .sort({ settledAt: -1 })
      .lean();

    let periodFrom;
    if (lastSettlement) {
      periodFrom = new Date(lastSettlement.settledAt);
    } else {
      const staffDoc = await SaloonStaff.findById(staffId).select('joiningDate').lean();
      periodFrom = staffDoc?.joiningDate || new Date(0);
    }

    const periodTo = new Date();
    periodTo.setHours(23, 59, 59, 999);

    // Aggregate earnings for this period
    const [agg] = await SaloonWorkEntry.aggregate([
      { $match: {
          saloon: saloonId,
          staff:  new mongoose.Types.ObjectId(staffId),
          serviceDate: { $gte: periodFrom, $lte: periodTo }
      }},
      { $group: { _id: null, bills: { $sum: 1 }, revenue: { $sum: '$grandTotal' }, earning: { $sum: '$staffEarning' } } }
    ]);

    const staffDoc = await SaloonStaff.findById(staffId).select('name phone').lean();

    const settlement = await SaloonSalarySettlement.create({
      saloon:       saloonId,
      staff:        staffId,
      staffName:    staffDoc?.name || 'Unknown',
      periodFrom,
      periodTo,
      totalBills:   agg?.bills   || 0,
      totalRevenue: agg?.revenue || 0,
      grossEarning: agg?.earning || 0,
      amountPaid:   Number(amountPaid),
      paymentMode:  paymentMode || 'cash',
      notes:        notes || '',
      paidBy:       req.staff?.name || req.saloon?.ownerName || '',
      staffPhone:   staffDoc?.phone || ''
    });

    logActivity(req, req.saloon, 'salary_settled', {
      entity: 'staff', entityId: staffId, entityName: staffDoc?.name,
      details: { amountPaid, paymentMode }
    });

    res.json({ settlement, staffPhone: staffDoc?.phone || '' });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// GET /api/saloon/salary/my-settlements  — staff views own settlement history + unsettled earning
router.get('/salary/my-settlements', saloonAuth, async (req, res) => {
  try {
    const staffId  = req.staff._id;
    const saloonId = req.saloon._id;

    const settlements = await SaloonSalarySettlement
      .find({ saloon: saloonId, staff: staffId })
      .sort({ settledAt: -1 }).limit(50).lean();

    // Period since last settlement
    const lastSettlement = settlements[0];
    const periodFrom = lastSettlement
      ? new Date(lastSettlement.settledAt)
      : ((await SaloonStaff.findById(staffId).select('joiningDate').lean())?.joiningDate || new Date(0));
    const periodTo = new Date(); periodTo.setHours(23, 59, 59, 999);

    const [unsettled] = await SaloonWorkEntry.aggregate([
      { $match: { saloon: saloonId, staff: staffId, serviceDate: { $gte: periodFrom, $lte: periodTo } } },
      { $group: { _id: null, bills: { $sum: 1 }, revenue: { $sum: '$grandTotal' }, earning: { $sum: '$staffEarning' } } }
    ]);

    // Total paid since ever
    const [totalPaid] = await SaloonSalarySettlement.aggregate([
      { $match: { saloon: saloonId, staff: staffId } },
      { $group: { _id: null, total: { $sum: '$amountPaid' } } }
    ]);

    res.json({
      settlements,
      unsettled: unsettled || { bills: 0, revenue: 0, earning: 0 },
      totalPaidEver: totalPaid?.total || 0,
      periodFrom,
      periodTo
    });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

module.exports = router;
