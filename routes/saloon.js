const express = require('express');
const router  = express.Router();
const jwt     = require('jsonwebtoken');
const crypto  = require('crypto');
const mongoose = require('mongoose');
const multer  = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const cloudinary = require('cloudinary').v2;

const saloonAuth = require('../middleware/saloonAuth');
const { requireRole } = saloonAuth;
const { rateLimit, byIdentifier } = require('../middleware/rateLimit');
const { JWT_SECRET } = require('../config/secrets');
const { sendError, isId, escapeRegex, pageParams, toNum, isEmail, MIN_PASSWORD, weakPassword } = require('../utils/http');
const { normPhone, isPhone, phoneVariants } = require('../utils/phone');
const { safeTz, todayRange, monthRange, parseDay, dateKey, hhmm } = require('../utils/time');
const { deleteSaloonData } = require('../utils/saloonData');

const SaloonBusiness   = require('../models/SaloonBusiness');
const SaloonStaff      = require('../models/SaloonStaff');
const SaloonService    = require('../models/SaloonService');
const SaloonWorkEntry  = require('../models/SaloonWorkEntry');
const SaloonCustomer   = require('../models/SaloonCustomer');
const SaloonAttendance = require('../models/SaloonAttendance');
const SaloonSalarySettlement = require('../models/SaloonSalarySettlement');
const BusinessActivityLog = require('../models/BusinessActivityLog');
const SaloonCollectionRequest = require('../models/SaloonCollectionRequest');
const AppConfig        = require('../models/AppConfig');
const Counter          = require('../models/Counter');

const oid = v => new mongoose.Types.ObjectId(String(v));
const MANAGERS = ['owner', 'manager'];
const isManager = staff => MANAGERS.includes(staff?.role);
const tzOf = saloon => safeTz(saloon?.settings?.timezone);
const pwMsg = `Password must be at least ${MIN_PASSWORD} characters.`;

// Money taken in (bills, collections, salary) is Cash or UPI only, always chosen explicitly.
// Older records may still hold card/wallet/bank/other; the schemas keep those values valid.
const PAY_MODES = ['cash', 'upi'];
const payModeOf = v => { const m = String(v || '').trim().toLowerCase(); return PAY_MODES.includes(m) ? m : null; };
const PAY_MODE_MSG = 'Select a payment mode: Cash or UPI.';

// ── Rate limits ───────────────────────────────────────────────────────────────
const MIN15 = 15 * 60 * 1000;
const authIpLimit    = rateLimit({ windowMs: MIN15, max: 300 });
const loginLimit     = rateLimit({ windowMs: MIN15, max: 10, failuresOnly: true,
  key: byIdentifier('identifier', 'emailOrPhone', 'phone'),
  message: 'Too many failed attempts for this account. Please wait 15 minutes or use "Forgot password".' });
const pinLimit       = rateLimit({ windowMs: MIN15, max: 10, failuresOnly: true });
const forgotLimit    = rateLimit({ windowMs: MIN15, max: 5, key: byIdentifier('identifier', 'phone'),
  message: 'Too many reset requests. Please wait 15 minutes.' });
const otpLimit       = rateLimit({ windowMs: MIN15, max: 20, failuresOnly: true });
const registerLimit  = rateLimit({ windowMs: 60 * 60 * 1000, max: 10, successOnly: true,
  message: 'Too many registrations from this network. Please try again later.' });
const passwordLimit  = rateLimit({ windowMs: MIN15, max: 10, failuresOnly: true });

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
      ip:         req.ip || '',
      userAgent:  req.headers['user-agent'] || '',
    });
  } catch (err) {
    // Non-critical, but a dropped entry means a hole in the audit trail —
    // most often a new action name missing from the model's enum.
    console.warn(`⚠️  activity log skipped (${action}):`, err.message);
  }
}

// ── Cloudinary upload for customer photos ─────────────────────────────────────
const photoStorage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: 'everyday-saloon/saloon',
    allowed_formats: ['jpg', 'jpeg', 'png', 'webp'],
    transformation: [{ width: 800, height: 800, crop: 'limit', quality: 'auto' }]
  }
});
const uploadPhoto = multer({ storage: photoStorage, limits: { fileSize: 5 * 1024 * 1024 } });

// ── Sessions ──────────────────────────────────────────────────────────────────
// 10 years — staff/owner stay logged in until they explicitly log out.
// Each device gets its own token; the newest MAX_SESSIONS are kept.
const MAX_SESSIONS = 5;
function issueToken(staff) {
  // jwtid makes every token unique — two logins in the same second would otherwise be identical
  const token = jwt.sign({ staffId: staff._id, saloonId: staff.saloon, role: staff.role }, JWT_SECRET,
    { expiresIn: '3650d', jwtid: crypto.randomBytes(9).toString('base64url') });
  staff.tokens = [...(staff.tokens || []), token].slice(-MAX_SESSIONS);
  return token;
}
// Signs a staff member out everywhere (password reset, deactivation …), optionally keeping one token
function revokeSessions(staffId, keepToken) {
  return SaloonStaff.updateOne({ _id: staffId }, {
    $unset: { token: 1 }, $set: { tokens: keepToken ? [keepToken] : [] }
  });
}

function slugify(t) {
  return t.toLowerCase().replace(/[^a-z0-9\s-]/g, '').trim().replace(/\s+/g, '-').substring(0, 50) || 'saloon';
}

// ── Saloon code (short, human friendly ID) ────────────────────────────────────
// Avoids look-alike characters (0/O, 1/I/L) so it can be read out over a phone.
const CODE_ALPHABET = 'ACDEFGHJKMNPQRTUVWXY2346789';
function randomCode(len = 6) {
  let out = '';
  for (let i = 0; i < len; i++) out += CODE_ALPHABET[Math.floor(Math.random() * CODE_ALPHABET.length)];
  return out;
}
async function generateSaloonCode() {
  for (let i = 0; i < 20; i++) {
    const code = randomCode(6);
    if (!await SaloonBusiness.exists({ saloonCode: code })) return code;
  }
  // Extremely unlikely — fall back to a longer code
  return randomCode(9);
}
// Makes sure an existing saloon (created before saloonCode existed) has one.
async function ensureSaloonCode(saloonId) {
  const biz = await SaloonBusiness.findById(saloonId).select('saloonCode').lean();
  if (!biz) return null;
  if (biz.saloonCode) return biz.saloonCode;
  const code = await generateSaloonCode();
  await SaloonBusiness.updateOne({ _id: saloonId }, { $set: { saloonCode: code } });
  return code;
}
// Accepts a saloon code, a slug, or a raw Mongo _id — all three keep working.
async function resolveSaloon(idOrCode) {
  const key = String(idOrCode || '').trim();
  if (!key) return null;
  let biz = await SaloonBusiness.findOne({ saloonCode: key.toUpperCase() });
  if (!biz && isId(key)) biz = await SaloonBusiness.findById(key);
  if (!biz) biz = await SaloonBusiness.findOne({ slug: key.toLowerCase() });
  return biz;
}
function makeOtp() {
  return String(crypto.randomInt(100000, 1000000));
}
const OTP_TTL_MS = 15 * 60 * 1000; // 15 minutes
const OTP_MAX_ATTEMPTS = 5;

// Bill numbers come from an atomic per-saloon counter (countDocuments()+1 handed
// out duplicates under concurrent saves). Seeded from existing bills the first time.
async function nextBillNumber(saloonId) {
  const key = `bill:${saloonId}`;
  if (!await Counter.exists({ key })) {
    const [count, last] = await Promise.all([
      SaloonWorkEntry.countDocuments({ saloon: saloonId }),
      SaloonWorkEntry.findOne({ saloon: saloonId }).sort({ createdAt: -1 }).select('billNumber').lean()
    ]);
    const lastN = parseInt(String(last?.billNumber || '').replace(/\D/g, ''), 10) || 0;
    try {
      await Counter.updateOne({ key }, { $max: { seq: Math.max(count, lastN) } }, { upsert: true });
    } catch (err) { if (err.code !== 11000) throw err; }
  }
  const c = await Counter.findOneAndUpdate({ key }, { $inc: { seq: 1 } }, { new: true });
  return `SAL-${String(c.seq).padStart(5, '0')}`;
}
async function nextCustomerName(saloonId) {
  const n = await SaloonCustomer.countDocuments({ saloon: saloonId });
  return `Customer-${n + 1}`;
}

// The live outstanding balance — customer.pendingAmount is a cache of this.
async function livePending(saloonId, customerId, staffId) {
  const match = { saloon: saloonId, customer: customerId, paymentStatus: { $in: ['pending', 'partial'] }, amountDue: { $gt: 0 } };
  if (staffId) match.staff = staffId;
  const [agg] = await SaloonWorkEntry.aggregate([{ $match: match }, { $group: { _id: null, total: { $sum: '$amountDue' } } }]);
  return agg?.total || 0;
}
async function syncCustomerPending(saloonId, customerId) {
  const total = await livePending(saloonId, customerId);
  await SaloonCustomer.updateOne({ _id: customerId }, { $set: { pendingAmount: total } });
  return total;
}

// Applies a payment to a customer's open bills, oldest first. A bill that becomes
// fully paid credits the staff commission that was computed (at their own rate)
// when the bill was created. Returns the amount actually applied.
async function applyPayment({ saloonId, customerId, amount, staffScope, creditStaffId }) {
  const q = { saloon: saloonId, customer: customerId, paymentStatus: { $in: ['pending', 'partial'] }, amountDue: { $gt: 0 } };
  if (staffScope) q.staff = staffScope;
  const bills = await SaloonWorkEntry.find(q).sort({ serviceDate: 1, createdAt: 1 });

  let remaining = amount, applied = 0;
  for (const bill of bills) {
    if (remaining <= 0) break;
    const toPay = Math.min(remaining, bill.amountDue);
    bill.amountPaid = (bill.amountPaid || 0) + toPay;
    bill.amountDue  = Math.max(0, bill.amountDue - toPay);
    bill.paymentStatus = bill.amountDue === 0 ? 'paid' : 'partial';
    if (bill.amountDue === 0 && !bill.staffEarning)
      bill.staffEarning = (bill.services || []).reduce((s, l) => s + (l.staffEarning || 0), 0);
    if (creditStaffId) bill.staff = creditStaffId;
    await bill.save();
    remaining -= toPay;
    applied += toPay;
  }
  await syncCustomerPending(saloonId, customerId);
  return applied;
}

// Staff record inside the caller's saloon, or null (also for malformed ids)
function findSaloonStaff(saloonId, id) {
  if (!isId(String(id || ''))) return Promise.resolve(null);
  return SaloonStaff.findOne({ _id: id, saloon: saloonId });
}

function phoneTaken(saloonId, phone, exceptId) {
  const q = { saloon: saloonId, phone: { $in: phoneVariants(phone) } };
  if (exceptId) q._id = { $ne: exceptId };
  return SaloonStaff.exists(q);
}

// Who may change whom. Owner manages everyone (but stays owner and active);
// a manager manages only staff below manager, plus limited edits of themselves.
function staffChangeError(actor, target, body = {}) {
  const self = String(actor._id) === String(target._id);
  if (actor.role === 'manager' && !self && MANAGERS.includes(target.role))
    return 'Managers can only manage staff below manager.';
  if (actor.role === 'manager' && self &&
      ['role', 'isActive', 'salary', 'commissionType', 'commissionValue'].some(f => body[f] !== undefined && String(body[f]) !== String(target[f])))
    return 'Managers cannot change their own role, pay or status.';
  if (body.role !== undefined && body.role !== target.role) {
    if (target.role === 'owner') return 'The owner role cannot be changed.';
    if (body.role === 'owner')   return 'A saloon has exactly one owner.';
    if (body.role === 'manager' && actor.role !== 'owner') return 'Only the owner can make someone a manager.';
  }
  if (target.role === 'owner' && body.isActive === false) return 'The owner account cannot be deactivated.';
  return null;
}

// GET /api/saloon/app-info — public: the "Download App" link, set by the admin panel.
// downloadUrl '' means "use the link built into the web app".
router.get('/app-info', async (req, res) => {
  try {
    const cfg = await AppConfig.findOne({ key: 'global' }).select('appDownloadUrl appDownloadEnabled').lean();
    res.set('Cache-Control', 'public, max-age=60');
    res.json({ downloadUrl: cfg?.appDownloadUrl || '', downloadEnabled: cfg?.appDownloadEnabled !== false });
  } catch (err) { sendError(res, err); }
});

// ════════════════════════════════════════════════════════════════════════════
// AUTH
// ════════════════════════════════════════════════════════════════════════════
router.use('/auth', authIpLimit);

// POST /api/saloon/auth/register
router.post('/auth/register', registerLimit, async (req, res) => {
  try {
    const { ownerName, businessName, email, phone: rawPhone, password, businessType, city, gstin } = req.body;
    if (!ownerName || !businessName || !email || !rawPhone || !password)
      return res.status(400).json({ message: 'ownerName, businessName, email, phone and password are required.' });
    if (!isEmail(email)) return res.status(400).json({ message: 'Please enter a valid email address.' });
    const phone = normPhone(rawPhone);
    if (!isPhone(phone)) return res.status(400).json({ message: 'Please enter a valid mobile number.' });
    if (weakPassword(password)) return res.status(400).json({ message: pwMsg });

    const em = String(email).toLowerCase().trim();
    const existing = await SaloonBusiness.findOne({ $or: [{ email: em }, { phone: { $in: phoneVariants(phone) } }] });
    if (existing) return res.status(409).json({ message: 'Email or phone already registered.' });

    let base = slugify(String(businessName)), slug = base, n = 1;
    while (await SaloonBusiness.findOne({ slug })) slug = `${base}-${n++}`;

    // Determine trial duration from AppConfig
    const cfg = await AppConfig.findOne({ key: 'global' }).lean();
    const trialDays = cfg?.defaultTrialDays ?? 30;
    const trialEndsAt = new Date(Date.now() + trialDays * 24 * 60 * 60 * 1000);

    const saloonCode = await generateSaloonCode();

    const saloon = await SaloonBusiness.create({
      businessName: String(businessName).trim(),
      ownerName: String(ownerName).trim(),
      email: em,
      phone,
      password,
      slug,
      saloonCode,
      businessType: businessType || 'salon',
      gstin,
      'address.city': city || '',
      subscription: {
        status: 'trial',
        trialEndsAt,
        monthlyRate: cfg?.defaultMonthlyRate ?? 999
      }
    });

    let owner, token;
    try {
      owner = new SaloonStaff({
        saloon: saloon._id,
        name: String(ownerName).trim(),
        email: em,
        phone,
        password,
        role: 'owner'
      });
      token = issueToken(owner);
      await owner.save();
    } catch (err) {
      await SaloonBusiness.deleteOne({ _id: saloon._id }); // don't leave a saloon nobody can log into
      throw err;
    }

    logActivity(req, saloon, 'register', { actor: owner.name, actorRole: 'owner', details: { businessType: saloon.businessType, city } });
    res.status(201).json({
      message: 'Saloon registered.',
      token,
      staff: owner.toSafeObject(),
      saloon: saloon.toSafeObject(),
      trial: { endsAt: trialEndsAt, days: trialDays }
    });
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ message: 'Email or phone already registered.' });
    sendError(res, err);
  }
});

// Mongo filter for "this mobile number or email"
function identifierFilter(ident) {
  return ident.includes('@')
    ? { email: ident.toLowerCase() }
    : { $or: [{ phone: { $in: phoneVariants(ident) } }, { email: ident.toLowerCase() }] };
}

// ── Unified login ────────────────────────────────────────────────────────────
// Owner, manager and staff all live in SaloonStaff, so one login serves everyone.
// An owner's email/phone is unique platform-wide; a staff mobile is only unique
// inside its own saloon. So we match on the identifier, verify the password
// against every candidate, and only ask which saloon when more than one matches.
async function handleLogin(req, res) {
  try {
    const { identifier, emailOrPhone, phone, password, saloonCode, saloonId } = req.body;
    const ident = String(identifier || emailOrPhone || phone || '').trim();
    const code  = saloonCode || saloonId;

    if (!ident || !password || typeof password !== 'string')
      return res.status(400).json({ message: 'Mobile number / email and password are required.' });

    let query = identifierFilter(ident);

    // A saloon code (optional) narrows the search up front
    if (code) {
      const saloon = await resolveSaloon(code);
      if (!saloon) return res.status(404).json({ message: 'Saloon ID not found. Please check with your owner.' });
      query = { saloon: saloon._id, ...query };
    }

    const candidates = await SaloonStaff.find(query).limit(10);
    if (!candidates.length)
      return res.status(401).json({ message: 'No account found with this mobile number or email.' });

    // The password decides which account is meant
    let matches = [];
    for (const c of candidates) {
      if (c.password && await c.comparePassword(password)) matches.push(c);
    }

    if (!matches.length) {
      const noPassword = candidates.some(c => !c.password);
      return res.status(401).json({
        message: noPassword && candidates.length === 1
          ? 'Password not set yet. Use "Forgot password" to get a code from your owner.'
          : 'Incorrect password.'
      });
    }

    // Duplicates inside one saloon can't be told apart by choosing a saloon —
    // keep the active, most recently used one.
    const bySaloon = new Map();
    matches
      .sort((a, b) => (b.isActive - a.isActive) || ((b.lastLoginAt || 0) - (a.lastLoginAt || 0)))
      .forEach(m => { if (!bySaloon.has(String(m.saloon))) bySaloon.set(String(m.saloon), m); });
    matches = [...bySaloon.values()];

    // Same number and password at more than one saloon — let them pick
    if (matches.length > 1) {
      const saloons = await SaloonBusiness.find({ _id: { $in: matches.map(m => m.saloon) } })
        .select('businessName saloonCode isActive').lean();
      return res.status(409).json({
        code: 'CHOOSE_SALOON',
        message: 'This login works at more than one saloon. Please choose which one.',
        saloons: saloons.filter(x => x.isActive !== false).map(x => ({
          saloonCode: x.saloonCode,
          businessName: x.businessName,
          role: matches.find(m => String(m.saloon) === String(x._id))?.role
        }))
      });
    }

    const staff = matches[0];
    if (!staff.isActive)
      return res.status(403).json({ message: 'Your account has been deactivated. Contact your owner.' });

    const saloon = await SaloonBusiness.findById(staff.saloon);
    if (!saloon || !saloon.isActive)
      return res.status(403).json({ message: 'Saloon account inactive.' });

    // Backfill the short saloon code for accounts created before it existed
    if (!saloon.saloonCode) {
      saloon.saloonCode = await generateSaloonCode();
      await saloon.save({ validateBeforeSave: false });
    }

    const token = issueToken(staff);
    staff.lastLoginAt = new Date();
    staff.loginCount = (staff.loginCount || 0) + 1;
    // A successful login voids any outstanding reset request
    staff.resetOtp = undefined;
    staff.resetOtpExpiresAt = undefined;
    staff.resetRequestedAt = undefined;
    staff.resetOtpAttempts = 0;
    await staff.save({ validateBeforeSave: false });

    logActivity(req, saloon, isManager(staff) ? 'login' : 'staff_login',
                { actor: staff.name, actorRole: staff.role });
    res.json({ token, staff: staff.toSafeObject(), saloon: saloon.toSafeObject() });
  } catch (err) { sendError(res, err); }
}

// POST /api/saloon/auth/login — everyone signs in here
router.post('/auth/login', loginLimit, handleLogin);
// Kept so older app builds keep working; same handler.
router.post('/auth/staff-login', loginLimit, handleLogin);

// GET /api/saloon/auth/saloon-lookup/:code — confirm a saloon code before login
router.get('/auth/saloon-lookup/:code', async (req, res) => {
  try {
    const saloon = await resolveSaloon(req.params.code);
    if (!saloon || !saloon.isActive) return res.status(404).json({ message: 'Saloon ID not found.' });
    res.json({ saloonCode: saloon.saloonCode || '', businessName: saloon.businessName });
  } catch (err) { sendError(res, err); }
});

// POST /api/saloon/auth/pin-login  (staff PIN login, legacy)
router.post('/auth/pin-login', pinLimit, async (req, res) => {
  try {
    const { saloonId, pin } = req.body;
    if (!saloonId || !pin) return res.status(400).json({ message: 'saloonId and pin required.' });

    const saloon = await resolveSaloon(saloonId);
    if (!saloon) return res.status(401).json({ message: 'Invalid PIN.' });
    if (!saloon.isActive) return res.status(403).json({ message: 'Saloon account inactive.' });

    const staffList = await SaloonStaff.find({ saloon: saloon._id, isActive: true, pin: { $exists: true, $ne: null } });
    let matched = null;
    for (const s of staffList) {
      if (s.pin && await s.comparePin(String(pin))) { matched = s; break; }
    }
    if (!matched) return res.status(401).json({ message: 'Invalid PIN.' });

    const token = issueToken(matched);
    matched.lastLoginAt = new Date();
    matched.loginCount = (matched.loginCount || 0) + 1;
    await matched.save({ validateBeforeSave: false });

    logActivity(req, saloon, 'pin_login', { actor: matched.name, actorRole: matched.role });
    res.json({ token, staff: matched.toSafeObject(), saloon: saloon.toSafeObject() });
  } catch (err) { sendError(res, err); }
});

// Resolve the staff record an identifier could mean, optionally scoped to a saloon.
// Returns { error } | { staff } | { choose: [...] }
async function resolveStaffByIdentifier(ident, code) {
  const id = String(ident || '').trim();
  if (!id) return { error: { status: 400, message: 'Mobile number or email is required.' } };

  let query = identifierFilter(id);

  if (code) {
    const saloon = await resolveSaloon(code);
    if (!saloon) return { error: { status: 404, message: 'Saloon ID not found. Please check with your owner.' } };
    query = { saloon: saloon._id, ...query };
  }

  const candidates = await SaloonStaff.find(query).sort({ isActive: -1, lastLoginAt: -1 }).limit(10);
  if (!candidates.length)
    return { error: { status: 404, message: 'No account found with this mobile number or email.' } };

  const saloonIds = [...new Set(candidates.map(c => String(c.saloon)))];
  if (saloonIds.length === 1) return { staff: candidates[0] };

  const saloons = await SaloonBusiness.find({ _id: { $in: saloonIds } })
    .select('businessName saloonCode isActive').lean();
  return {
    choose: saloons.filter(x => x.isActive !== false).map(x => ({
      saloonCode: x.saloonCode, businessName: x.businessName
    }))
  };
}
const chooseReply = (res, saloons) => res.status(409).json({
  code: 'CHOOSE_SALOON',
  message: 'This mobile number is used at more than one saloon. Please choose which one.',
  saloons
});
const OWNER_RESET = {
  code: 'OWNER_RESET',
  message: 'Owner passwords cannot be reset from the app. Please contact support to reset it.'
};

// POST /api/saloon/auth/staff/forgot-password
// Staff ask for a reset (or a first password); the OTP is shown to the owner
// inside the app, who reads it out. Nothing about the account is revealed here.
router.post('/auth/staff/forgot-password', forgotLimit, async (req, res) => {
  try {
    const { identifier, phone, saloonCode, saloonId } = req.body;
    const found = await resolveStaffByIdentifier(identifier || phone, saloonCode || saloonId);
    if (found.error)  return res.status(found.error.status).json({ message: found.error.message });
    if (found.choose) return chooseReply(res, found.choose);

    const staff = found.staff;
    if (staff.role === 'owner') return res.status(400).json(OWNER_RESET);
    if (!staff.isActive)
      return res.status(403).json({ message: 'Your account has been deactivated. Contact your owner.' });

    const saloon = await SaloonBusiness.findById(staff.saloon);
    if (!saloon || !saloon.isActive) return res.status(403).json({ message: 'Saloon account inactive.' });

    staff.resetOtp = makeOtp();
    staff.resetOtpExpiresAt = new Date(Date.now() + OTP_TTL_MS);
    staff.resetRequestedAt = new Date();
    staff.resetOtpAttempts = 0;
    await staff.save({ validateBeforeSave: false });

    logActivity(req, saloon, 'staff_forgot_password', {
      entity: 'staff', entityId: staff._id, entityName: staff.name,
      actor: staff.name, actorRole: staff.role
    });

    res.json({
      message: 'A 6-digit code has been sent to your saloon owner\'s app. Ask them for it.',
      expiresInMinutes: Math.round(OTP_TTL_MS / 60000)
    });
  } catch (err) { sendError(res, err); }
});

// POST /api/saloon/auth/staff/reset-password  (verify OTP → set a new password)
router.post('/auth/staff/reset-password', otpLimit, async (req, res) => {
  try {
    const { identifier, phone, otp, password, saloonCode, saloonId } = req.body;
    if (!otp || !password)
      return res.status(400).json({ message: 'OTP and new password are required.' });
    if (weakPassword(password)) return res.status(400).json({ message: pwMsg });

    const found = await resolveStaffByIdentifier(identifier || phone, saloonCode || saloonId);
    if (found.error)  return res.status(found.error.status).json({ message: found.error.message });
    if (found.choose) return chooseReply(res, found.choose);

    const staff = found.staff;
    if (staff.role === 'owner') return res.status(400).json(OWNER_RESET);
    if (!staff.resetOtp || !staff.resetOtpExpiresAt)
      return res.status(400).json({ message: 'No OTP requested. Please tap "Forgot password" first.' });
    if (new Date(staff.resetOtpExpiresAt) < new Date())
      return res.status(400).json({ message: 'OTP expired. Please request a new one.' });

    if (String(staff.resetOtp) !== String(otp).trim()) {
      staff.resetOtpAttempts = (staff.resetOtpAttempts || 0) + 1;
      // Too many guesses burns the code, so a 6-digit OTP can't be brute-forced
      if (staff.resetOtpAttempts >= OTP_MAX_ATTEMPTS) {
        staff.resetOtp = undefined;
        staff.resetOtpExpiresAt = undefined;
        staff.resetRequestedAt = undefined;
        staff.resetOtpAttempts = 0;
        await staff.save({ validateBeforeSave: false });
        return res.status(400).json({ code: 'OTP_LOCKED', message: 'Too many wrong codes. Please request a new one.' });
      }
      await staff.save({ validateBeforeSave: false });
      return res.status(400).json({
        message: `Incorrect OTP. Please check with your owner. (${OTP_MAX_ATTEMPTS - staff.resetOtpAttempts} attempts left)`
      });
    }

    staff.password = password;
    staff.resetOtp = undefined;
    staff.resetOtpExpiresAt = undefined;
    staff.resetRequestedAt = undefined;
    staff.resetOtpAttempts = 0;
    staff.token = undefined;
    staff.tokens = [];        // a reset signs out every device
    await staff.save();

    const saloon = await SaloonBusiness.findById(staff.saloon).lean();
    if (saloon) logActivity(req, saloon, 'staff_reset_password', {
      entity: 'staff', entityId: staff._id, entityName: staff.name,
      actor: staff.name, actorRole: staff.role
    });
    res.json({ message: 'Password changed. You can now log in.' });
  } catch (err) { sendError(res, err); }
});

// POST /api/saloon/auth/staff/set-password  (first-time setup with the staff PIN)
// Without a PIN, first-time staff use the forgot-password flow instead, so an
// account can never be claimed by someone who only knows the mobile number.
router.post('/auth/staff/set-password', passwordLimit, async (req, res) => {
  try {
    const { identifier, phone, pin, password, saloonCode, saloonId } = req.body;
    if (!password) return res.status(400).json({ message: 'Password is required.' });
    if (weakPassword(password)) return res.status(400).json({ message: pwMsg });
    if (!pin) return res.status(400).json({
      code: 'PIN_REQUIRED',
      message: 'Enter the PIN your owner gave you, or tap "No PIN?" to get a code from your owner.'
    });

    const found = await resolveStaffByIdentifier(identifier || phone, saloonCode || saloonId);
    if (found.error)  return res.status(found.error.status).json({ message: found.error.message });
    if (found.choose) return chooseReply(res, found.choose);

    const staff = found.staff;
    if (!staff.pin || !await staff.comparePin(String(pin)))
      return res.status(401).json({ message: 'Invalid PIN.' });

    staff.password = password;
    staff.token = undefined;
    staff.tokens = [];
    await staff.save();

    const saloonForLog = await SaloonBusiness.findById(staff.saloon).lean();
    if (saloonForLog) {
      logActivity(req, saloonForLog, 'staff_set_password', { entity: 'staff', entityId: staff._id, entityName: staff.name });
    }
    res.json({ message: 'Password set successfully.' });
  } catch (err) { sendError(res, err); }
});

// POST /api/saloon/auth/logout — signs out this device only. Session check only,
// so it works even while the subscription is expired or the app is in service mode.
router.post('/auth/logout', saloonAuth.sessionOnly, async (req, res) => {
  try {
    const staff = await SaloonStaff.findById(req.staff._id).select('token tokens');
    if (staff) {
      if (staff.token === req.token) staff.token = undefined;
      staff.tokens = (staff.tokens || []).filter(t => t !== req.token);
      await staff.save({ validateBeforeSave: false });
    }
    res.json({ message: 'Logged out.' });
  } catch (err) { sendError(res, err); }
});

// GET /api/saloon/auth/me
router.get('/auth/me', saloonAuth, async (req, res) => {
  // Legacy saloons have no short code until someone asks for it
  if (!req.saloon.saloonCode) {
    try { req.saloon.saloonCode = await ensureSaloonCode(req.saloon._id); } catch { /* non-critical */ }
  }
  res.json({ staff: req.staff, saloon: req.saloon });
});

// POST /api/saloon/auth/change-password  (staff change their own password)
// Keeps this device signed in and signs out every other one.
router.post('/auth/change-password', saloonAuth, passwordLimit, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) return res.status(400).json({ message: 'oldPassword and newPassword required.' });
    if (weakPassword(newPassword)) return res.status(400).json({ message: pwMsg });

    const staff = await SaloonStaff.findById(req.staff._id);
    if (!staff) return res.status(404).json({ message: 'Staff not found.' });

    // 400, not 401 — a 401 means "session gone" to the app and would log the user out
    if (!staff.password || !await staff.comparePassword(String(oldPassword)))
      return res.status(400).json({ message: 'Current password is incorrect.' });

    staff.password = newPassword;
    staff.token = undefined;
    staff.tokens = [req.token];
    await staff.save();

    logActivity(req, req.saloon, 'staff_change_password', { entity: 'staff', entityId: staff._id, entityName: staff.name });
    res.json({ message: 'Password changed successfully.' });
  } catch (err) { sendError(res, err); }
});

// DELETE /api/saloon/account — owner permanently deletes the saloon and all its data
// (Play Store account-deletion requirement). Works even when the subscription has lapsed.
router.delete('/account', saloonAuth.sessionOnly, requireRole('owner'), passwordLimit, async (req, res) => {
  try {
    const { password, confirmName } = req.body || {};
    const saloon = await SaloonBusiness.findById(req.staff.saloon);
    if (!saloon) return res.status(404).json({ message: 'Saloon not found.' });

    if (String(confirmName || '').trim() !== saloon.businessName.trim())
      return res.status(400).json({ message: `Type the exact business name "${saloon.businessName}" to confirm.` });
    const owner = await SaloonStaff.findById(req.staff._id);
    if (!password || !owner?.password || !await owner.comparePassword(String(password)))
      return res.status(400).json({ message: 'Password is incorrect.' });

    const removed = await deleteSaloonData(saloon);
    // One record survives so the deletion itself is auditable (no personal data)
    await BusinessActivityLog.create({
      bizType: 'saloon', business: saloon._id, businessName: saloon.businessName,
      actor: 'owner', actorRole: 'owner', action: 'account_delete', entity: 'saloon',
      entityId: saloon._id, details: { removed }, ip: req.ip || ''
    }).catch(() => {});

    console.warn(`🗑️  Owner deleted saloon "${saloon.businessName}" (${saloon._id})`);
    res.json({ message: 'Your saloon account and all of its data have been deleted.' });
  } catch (err) { sendError(res, err); }
});

// ════════════════════════════════════════════════════════════════════════════
// STAFF MANAGEMENT  (owner / manager only)
// ════════════════════════════════════════════════════════════════════════════

const STAFF_HIDDEN = '-password -pin -token -tokens -resetOtp -resetOtpExpiresAt -resetOtpAttempts';

// GET /api/saloon/staff
router.get('/staff', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const list = await SaloonStaff.find({ saloon: req.saloon._id })
      .select(STAFF_HIDDEN).sort({ createdAt: 1 }).lean();
    res.json(list);
  } catch (err) { sendError(res, err); }
});

// GET /api/saloon/staff/password-requests — pending staff password-reset OTPs.
// Managers only see requests from staff below them.
router.get('/staff/password-requests', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const q = {
      saloon: req.saloon._id,
      role: req.staff.role === 'owner' ? { $ne: 'owner' } : { $nin: MANAGERS },
      resetOtp: { $ne: null },
      resetOtpExpiresAt: { $gt: new Date() }
    };
    const list = await SaloonStaff.find(q)
      .select('name phone role avatar resetOtp resetOtpExpiresAt resetRequestedAt')
      .sort({ resetRequestedAt: -1 }).lean();

    res.json(list.map(s => ({
      _id: s._id,
      name: s.name,
      phone: s.phone,
      role: s.role,
      avatar: s.avatar,
      otp: s.resetOtp,
      requestedAt: s.resetRequestedAt,
      expiresAt: s.resetOtpExpiresAt
    })));
  } catch (err) { sendError(res, err); }
});

// Loads a staff member the caller is allowed to manage, or replies with the reason
async function manageableStaff(req, res, body) {
  const staff = await findSaloonStaff(req.saloon._id, req.params.id);
  if (!staff) { res.status(404).json({ message: 'Staff not found.' }); return null; }
  const why = staffChangeError(req.staff, staff, body);
  if (why) { res.status(403).json({ message: why }); return null; }
  return staff;
}

// POST /api/saloon/staff/:id/password-otp — owner/manager generates an OTP for a staff member
router.post('/staff/:id/password-otp', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const staff = await manageableStaff(req, res);
    if (!staff) return;
    if (staff.role === 'owner') return res.status(400).json(OWNER_RESET);

    staff.resetOtp = makeOtp();
    staff.resetOtpExpiresAt = new Date(Date.now() + OTP_TTL_MS);
    staff.resetRequestedAt = new Date();
    staff.resetOtpAttempts = 0;
    await staff.save({ validateBeforeSave: false });

    logActivity(req, req.saloon, 'staff_otp_issued', { entity: 'staff', entityId: staff._id, entityName: staff.name });
    res.json({ otp: staff.resetOtp, expiresAt: staff.resetOtpExpiresAt, name: staff.name, phone: staff.phone });
  } catch (err) { sendError(res, err); }
});

// DELETE /api/saloon/staff/:id/password-otp — owner/manager dismisses a reset request
router.delete('/staff/:id/password-otp', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const staff = await manageableStaff(req, res);
    if (!staff) return;
    await SaloonStaff.updateOne({ _id: staff._id },
      { $unset: { resetOtp: 1, resetOtpExpiresAt: 1, resetRequestedAt: 1 }, $set: { resetOtpAttempts: 0 } });
    res.json({ message: 'Request dismissed.' });
  } catch (err) { sendError(res, err); }
});

// POST /api/saloon/staff
router.post('/staff', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const { name, email, phone: rawPhone, role, pin, password, specializations, salary, commissionType, commissionValue, designation, joiningDate } = req.body;
    if (!name || !role) return res.status(400).json({ message: 'name and role are required.' });
    if (role === 'owner') return res.status(400).json({ message: 'A saloon has exactly one owner.' });
    if (role === 'manager' && req.staff.role !== 'owner')
      return res.status(403).json({ message: 'Only the owner can add a manager.' });
    if (password && weakPassword(password)) return res.status(400).json({ message: pwMsg });
    if (email && !isEmail(email)) return res.status(400).json({ message: 'Please enter a valid email address.' });

    const phone = rawPhone ? normPhone(rawPhone) : undefined;
    if (phone && !isPhone(phone)) return res.status(400).json({ message: 'Please enter a valid mobile number.' });
    if (phone && await phoneTaken(req.saloon._id, phone))
      return res.status(409).json({ message: 'Another staff member in this saloon already uses this mobile number.' });

    const staff = await SaloonStaff.create({
      saloon: req.saloon._id,
      name: String(name).trim(), email: email || undefined, phone,
      role, pin: pin ? String(pin) : undefined, password: password || undefined,
      specializations: Array.isArray(specializations) ? specializations : [],
      salary: toNum(salary) ?? 0,
      commissionType: commissionType || 'percent',
      commissionValue: toNum(commissionValue) ?? req.saloon.settings?.commissionValue ?? 50,
      designation, joiningDate: joiningDate || undefined
    });
    logActivity(req, req.saloon, 'staff_create', { entity: 'staff', entityId: staff._id, entityName: staff.name, details: { role } });
    res.status(201).json(staff.toSafeObject());
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ message: 'Phone or email already used.' });
    sendError(res, err);
  }
});

// PUT /api/saloon/staff/:id
router.put('/staff/:id', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const body = { ...req.body };
    if (body.role === '' || body.role === null) delete body.role;   // the owner row has no role option in the form
    const staff = await manageableStaff(req, res, body);
    if (!staff) return;

    if (body.password && weakPassword(body.password)) return res.status(400).json({ message: pwMsg });
    if (body.email && !isEmail(body.email)) return res.status(400).json({ message: 'Please enter a valid email address.' });
    if (body.phone !== undefined) {
      body.phone = body.phone ? normPhone(body.phone) : undefined;
      if (body.phone && !isPhone(body.phone)) return res.status(400).json({ message: 'Please enter a valid mobile number.' });
      if (body.phone && await phoneTaken(req.saloon._id, body.phone, staff._id))
        return res.status(409).json({ message: 'Another staff member in this saloon already uses this mobile number.' });
    }

    // The owner's email/phone are also the saloon's platform-wide identity
    if (staff.role === 'owner') {
      const biz = {};
      if (body.phone && body.phone !== staff.phone) {
        if (await SaloonBusiness.exists({ _id: { $ne: req.saloon._id }, phone: { $in: phoneVariants(body.phone) } }))
          return res.status(409).json({ message: 'Another saloon already uses this mobile number.' });
        biz.phone = body.phone;
      }
      if (body.email && body.email.toLowerCase().trim() !== staff.email) {
        const em = body.email.toLowerCase().trim();
        if (await SaloonBusiness.exists({ _id: { $ne: req.saloon._id }, email: em }))
          return res.status(409).json({ message: 'Another saloon already uses this email.' });
        biz.email = em;
      }
      if (body.name) biz.ownerName = String(body.name).trim();
      if (Object.keys(biz).length) await SaloonBusiness.updateOne({ _id: req.saloon._id }, { $set: biz });
    }

    const fields = ['name', 'email', 'phone', 'role', 'specializations', 'salary', 'commissionType', 'commissionValue', 'designation', 'joiningDate', 'isActive'];
    fields.forEach(f => { if (body[f] !== undefined) staff[f] = body[f]; });

    const credsChanged = !!(body.password || body.pin);
    if (body.password) staff.password = body.password;
    if (body.pin)      staff.pin      = String(body.pin);

    await staff.save();

    // New credentials or deactivation sign the person out (keeping the caller's own device)
    if (credsChanged || body.isActive === false) {
      const self = String(staff._id) === String(req.staff._id);
      await revokeSessions(staff._id, self ? req.token : undefined);
    }

    logActivity(req, req.saloon, 'staff_update', { entity: 'staff', entityId: staff._id, entityName: staff.name });
    res.json(staff.toSafeObject());
  } catch (err) { sendError(res, err); }
});

// DELETE /api/saloon/staff/:id
router.delete('/staff/:id', saloonAuth, requireRole('owner'), async (req, res) => {
  try {
    const staff = await findSaloonStaff(req.saloon._id, req.params.id);
    if (!staff) return res.status(404).json({ message: 'Staff not found.' });
    if (staff.role === 'owner') return res.status(400).json({ message: 'Cannot delete owner.' });
    logActivity(req, req.saloon, 'staff_delete', { entity: 'staff', entityId: staff._id, entityName: staff.name });
    await SaloonStaff.findByIdAndDelete(staff._id);
    res.json({ message: 'Staff deleted.' });
  } catch (err) { sendError(res, err); }
});

// POST /api/saloon/staff/:id/avatar
router.post('/staff/:id/avatar', saloonAuth, requireRole('owner', 'manager'), async (req, res, next) => {
  try {
    const staff = await manageableStaff(req, res);
    if (!staff) return;
    req.targetStaff = staff;
    next();
  } catch (err) { sendError(res, err); }
}, uploadPhoto.single('photo'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded.' });
    req.targetStaff.avatar = req.file.path;
    await req.targetStaff.save({ validateBeforeSave: false });
    res.json({ avatar: req.targetStaff.avatar });
  } catch (err) { sendError(res, err); }
});

// GET /api/saloon/staff/:id/pending-customers — customers with pending amount billed by this staff
// Staff can view their own; owner/manager can view any
router.get('/staff/:id/pending-customers', saloonAuth, async (req, res) => {
  try {
    const staffId = req.params.id;
    if (!isId(staffId)) return res.status(400).json({ message: 'Invalid staff id.' });
    // Staff can only view their own pending customers
    if (!isManager(req.staff) && req.staff._id.toString() !== staffId) {
      return res.status(403).json({ message: 'Access denied.' });
    }

    // Aggregate pending due per customer from work entries billed by this staff
    const agg = await SaloonWorkEntry.aggregate([
      {
        $match: {
          saloon: req.saloon._id,
          staff:  oid(staffId),
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
  } catch (err) { sendError(res, err); }
});

// ════════════════════════════════════════════════════════════════════════════
// COLLECTION REQUESTS (staff submits → owner/manager approves)
// ════════════════════════════════════════════════════════════════════════════

// POST /api/saloon/collection-requests  — staff submits a collection request
router.post('/collection-requests', saloonAuth, async (req, res) => {
  try {
    const { customerId, amount, paymentMode, notes } = req.body;
    const requested = toNum(amount);
    if (!customerId || !Number.isFinite(requested) || requested <= 0)
      return res.status(400).json({ message: 'customerId and amount required.' });
    if (!isId(String(customerId))) return res.status(400).json({ message: 'Invalid customer id.' });
    if (!payModeOf(paymentMode)) return res.status(400).json({ message: PAY_MODE_MSG });

    const customer = await SaloonCustomer.findOne({ _id: customerId, saloon: req.saloon._id });
    if (!customer) return res.status(404).json({ message: 'Customer not found.' });

    // Staff collect only against their own bills; owner/manager against any bill
    const manager = isManager(req.staff);
    const due = await livePending(req.saloon._id, customer._id, manager ? undefined : req.staff._id);
    if (due <= 0)
      return res.status(400).json({ message: manager ? 'No pending amount for this customer.' : 'No pending amount for this customer from your bills.' });

    const collectAmt = Math.min(requested, due);

    const creq = await SaloonCollectionRequest.create({
      saloon:          req.saloon._id,
      customer:        customer._id,
      customerName:    customer.name,
      customerPhone:   customer.phone,
      amount:          collectAmt,
      requestedAmount: requested,
      paymentMode:     payModeOf(paymentMode),
      notes:           notes || '',
      requestedBy:     req.staff._id,
      requestedByName: req.staff.name,
      status:          manager ? 'approved' : 'pending'  // managers auto-approve
    });

    // If manager/owner — process immediately
    if (manager) {
      const applied = await applyPayment({ saloonId: req.saloon._id, customerId: customer._id, amount: collectAmt });
      creq.amount = applied;
      creq.reviewedBy = req.staff._id;
      creq.reviewedByName = req.staff.name;
      creq.reviewedAt = new Date();
      await creq.save();
    }

    logActivity(req, req.saloon, 'collection_request_submit', {
      entity: 'customer', entityId: customer._id, entityName: customer.name,
      details: { amount: creq.amount, paymentMode: creq.paymentMode, status: creq.status }
    });

    res.status(201).json(creq);
  } catch (err) { sendError(res, err); }
});

// GET /api/saloon/collection-requests  — owner/manager sees all, staff sees their own
router.get('/collection-requests', saloonAuth, async (req, res) => {
  try {
    const { status } = req.query;
    const { page, limit, skip } = pageParams(req.query, 30);
    const q = { saloon: req.saloon._id };
    if (status) q.status = String(status);
    if (!isManager(req.staff)) q.requestedBy = req.staff._id;
    const [requests, total] = await Promise.all([
      SaloonCollectionRequest.find(q).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
      SaloonCollectionRequest.countDocuments(q)
    ]);
    res.json({ requests, total, page });
  } catch (err) { sendError(res, err); }
});

// PATCH /api/saloon/collection-requests/:id/approve  — owner/manager approves
router.patch('/collection-requests/:id/approve', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const creq = await SaloonCollectionRequest.findOne({ _id: req.params.id, saloon: req.saloon._id });
    if (!creq) return res.status(404).json({ message: 'Request not found.' });
    if (creq.status !== 'pending') return res.status(400).json({ message: `Request is already ${creq.status}.` });

    // A staff member's request settles only the bills they made
    const requester = await SaloonStaff.findById(creq.requestedBy).select('role').lean();
    const staffScope = requester && !isManager(requester) ? creq.requestedBy : undefined;

    const due = await livePending(req.saloon._id, creq.customer, staffScope);
    if (due <= 0)
      return res.status(400).json({ message: 'Nothing is pending for this customer any more. Reject this request instead.' });

    const applied = await applyPayment({
      saloonId: req.saloon._id, customerId: creq.customer,
      amount: Math.min(creq.amount, due), staffScope
    });

    if (!creq.requestedAmount) creq.requestedAmount = creq.amount;
    creq.amount = applied;          // record what was actually collected
    creq.status = 'approved';
    creq.reviewedBy = req.staff._id;
    creq.reviewedByName = req.staff.name;
    creq.reviewedAt = new Date();
    await creq.save();

    logActivity(req, req.saloon, 'collection_request_approved', {
      entity: 'customer', entityId: creq.customer, entityName: creq.customerName,
      details: { amount: creq.amount, requestedBy: creq.requestedByName }
    });

    res.json({ message: `Approved ₹${creq.amount} collection from ${creq.customerName}.`, request: creq });
  } catch (err) { sendError(res, err); }
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
    creq.rejectReason = String(req.body.reason || '').slice(0, 500);
    await creq.save();

    logActivity(req, req.saloon, 'collection_request_rejected', {
      entity: 'customer', entityId: creq.customer, entityName: creq.customerName,
      details: { amount: creq.amount, reason: creq.rejectReason }
    });

    res.json({ message: 'Request rejected.', request: creq });
  } catch (err) { sendError(res, err); }
});

// ════════════════════════════════════════════════════════════════════════════
// SERVICES
// ════════════════════════════════════════════════════════════════════════════

const SERVICE_FIELDS = ['name', 'category', 'price', 'duration', 'gender', 'description', 'sortOrder'];
const pick = (obj, fields) => Object.fromEntries(fields.filter(f => obj[f] !== undefined).map(f => [f, obj[f]]));

// GET /api/saloon/services
router.get('/services', saloonAuth, async (req, res) => {
  try {
    const services = await SaloonService.find({ saloon: req.saloon._id, isActive: true })
      .sort({ category: 1, sortOrder: 1, name: 1 }).lean();
    res.json(services);
  } catch (err) { sendError(res, err); }
});

// POST /api/saloon/services
router.post('/services', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const data = pick(req.body, SERVICE_FIELDS);
    if (!data.name || data.price === undefined || data.price === '')
      return res.status(400).json({ message: 'name and price are required.' });
    const service = await SaloonService.create({ ...data, saloon: req.saloon._id });
    logActivity(req, req.saloon, 'service_create', { entity: 'service', entityId: service._id, entityName: service.name, details: { category: service.category, price: service.price } });
    res.status(201).json(service);
  } catch (err) { sendError(res, err); }
});

// PUT /api/saloon/services/:id  — only service fields; the saloon can never be changed
router.put('/services/:id', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const service = await SaloonService.findOneAndUpdate(
      { _id: req.params.id, saloon: req.saloon._id },
      { $set: pick(req.body, [...SERVICE_FIELDS, 'isActive']) },
      { new: true, runValidators: true }
    );
    if (!service) return res.status(404).json({ message: 'Service not found.' });
    logActivity(req, req.saloon, 'service_update', { entity: 'service', entityId: service._id, entityName: service.name });
    res.json(service);
  } catch (err) { sendError(res, err); }
});

// DELETE /api/saloon/services/:id
router.delete('/services/:id', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const svc = await SaloonService.findOneAndUpdate({ _id: req.params.id, saloon: req.saloon._id }, { isActive: false });
    if (!svc) return res.status(404).json({ message: 'Service not found.' });
    logActivity(req, req.saloon, 'service_delete', { entity: 'service', entityId: svc._id, entityName: svc.name });
    res.json({ message: 'Service removed.' });
  } catch (err) { sendError(res, err); }
});

// ════════════════════════════════════════════════════════════════════════════
// WORK ENTRIES (BILLS)
// ════════════════════════════════════════════════════════════════════════════

// Commission for one bill line at the staff member's rate.
//   percent → % of the line's net, fixed → ₹ per unit, none → nothing
function lineEarning(net, qty, type, value) {
  if (type === 'none') return 0;
  if (type === 'fixed') return value * qty;
  return net * value / 100;
}

// Validates and normalises the services array of a bill. Returns { lines } or { error }.
function parseServiceLines(raw) {
  let services = raw;
  if (typeof services === 'string') {
    try { services = JSON.parse(services); } catch { return { error: 'Invalid services.' }; }
  }
  if (!Array.isArray(services) || services.length === 0) return { error: 'At least one service is required.' };
  if (services.length > 50) return { error: 'Too many services on one bill.' };

  const lines = [];
  for (const s of services) {
    const price = Number(s?.price), qty = s?.qty === undefined || s?.qty === '' ? 1 : Number(s.qty);
    const discount = s?.discount === undefined || s?.discount === '' ? 0 : Number(s.discount);
    const name = String(s?.serviceName || '').trim();
    if (!name) return { error: 'Every service needs a name.' };
    if (!Number.isFinite(price) || price < 0) return { error: `Invalid price for ${name}.` };
    if (!Number.isInteger(qty) || qty < 1 || qty > 100) return { error: `Invalid quantity for ${name}.` };
    if (!Number.isFinite(discount) || discount < 0 || discount > price * qty)
      return { error: `Discount for ${name} must be between 0 and the line total.` };
    lines.push({
      service: s.service && isId(String(s.service)) ? s.service : undefined,
      serviceName: name, category: s.category ? String(s.category) : undefined,
      price, qty, discount
    });
  }
  return { lines };
}

// POST /api/saloon/entries  — staff creates a new work entry / bill
router.post('/entries', saloonAuth, uploadPhoto.single('customerPhoto'), async (req, res) => {
  try {
    const body = req.body;
    const { customerId, customerName: custNameOverride, paymentMode, paymentStatus, amountPaid, notes, serviceDate, waived } = body;
    const customerPhone = body.customerPhone ? normPhone(body.customerPhone) : '';

    const parsed = parseServiceLines(body.services);
    if (parsed.error) return res.status(400).json({ message: parsed.error });

    let when = new Date();
    if (serviceDate) {
      when = new Date(serviceDate);
      if (isNaN(when)) return res.status(400).json({ message: 'Invalid service date.' });
    }
    if (customerPhone && !isPhone(customerPhone))
      return res.status(400).json({ message: 'Please enter a valid customer mobile number.' });

    // Totals and commission
    const commType = req.staff.commissionType || req.saloon.settings?.commissionType || 'percent';
    const commVal  = req.staff.commissionValue ?? req.saloon.settings?.commissionValue ?? 50;
    let subtotal = 0, discountTotal = 0;
    const serviceLines = parsed.lines.map(s => {
      const net = s.price * s.qty - s.discount;
      subtotal += net;
      discountTotal += s.discount;
      return { ...s, staffEarning: lineEarning(net, s.qty, commType, commVal) };
    });

    const taxPct    = req.saloon.settings?.taxPercent || 0;
    const taxAmount = Math.round(subtotal * taxPct / 100);
    const grossTotal = Math.round(subtotal + taxAmount);

    // Payment. 'pending' = Pay Later (an upfront part-payment is honoured);
    // 'paid' with less money = a partial bill, unless the balance is waived,
    // in which case the waived part is a discount and revenue = cash received.
    const wanted = ['paid', 'pending', 'partial'].includes(paymentStatus) ? paymentStatus : 'paid';
    const paidIn = toNum(amountPaid);
    if (paidIn !== undefined && (!Number.isFinite(paidIn) || paidIn < 0))
      return res.status(400).json({ message: 'Amount paid must be a positive number.' });

    let paid = wanted === 'pending' ? (paidIn || 0) : (paidIn ?? grossTotal);
    paid = Math.round(Math.min(paid, grossTotal));
    const isWaived = (waived === true || waived === 'true') && wanted !== 'pending';
    const waivedAmount = isWaived ? grossTotal - paid : 0;
    const grandTotal = grossTotal - waivedAmount;
    const due = Math.max(0, grandTotal - paid);
    const status = due === 0 ? 'paid' : (paid > 0 ? 'partial' : 'pending');

    // Any money received now needs its mode; a fully unpaid Pay Later bill is 'credit'
    const mode = payModeOf(paymentMode);
    if (paid > 0 && !mode) return res.status(400).json({ message: PAY_MODE_MSG });

    // A waiver shrinks the bill, so commission shrinks with it
    const scale = grossTotal > 0 ? grandTotal / grossTotal : 1;
    serviceLines.forEach(l => { l.staffEarning = Math.round(l.staffEarning * scale); });
    const staffEarningTotal = serviceLines.reduce((s, l) => s + l.staffEarning, 0);

    // Resolve the customer: by phone (auto-created), or an existing id in this saloon
    let resolvedCustomerId = null;
    let resolvedCustomerName = 'Walk-in';
    let resolvedPhone = customerPhone;

    if (customerPhone) {
      let cust = await SaloonCustomer.findOne({ saloon: req.saloon._id, phone: { $in: phoneVariants(customerPhone) } });
      if (!cust) {
        const autoName = custNameOverride && String(custNameOverride).trim()
          ? String(custNameOverride).trim().slice(0, 80)
          : await nextCustomerName(req.saloon._id);
        cust = await SaloonCustomer.create({
          saloon: req.saloon._id,
          name: autoName,
          phone: customerPhone,
          firstVisitAt: new Date()
        });
      }
      resolvedCustomerId = cust._id;
      resolvedCustomerName = cust.name;
    } else if (customerId) {
      const cust = isId(String(customerId)) && await SaloonCustomer.findOne({ _id: customerId, saloon: req.saloon._id });
      if (!cust) return res.status(404).json({ message: 'Customer not found.' });
      resolvedCustomerId = cust._id;
      resolvedCustomerName = cust.name;
      resolvedPhone = cust.phone;
    }

    if (due > 0 && !resolvedCustomerId)
      return res.status(400).json({ message: 'Customer phone is required when part of the bill is unpaid.' });

    const billNumber = await nextBillNumber(req.saloon._id);

    const entry = await SaloonWorkEntry.create({
      saloon:        req.saloon._id,
      staff:         req.staff._id,
      staffName:     req.staff.name,
      billNumber,
      customer:      resolvedCustomerId || undefined,
      customerName:  resolvedCustomerName,
      customerPhone: resolvedPhone || '',
      customerPhoto: req.file ? req.file.path : undefined,
      services:      serviceLines,
      subtotal:      Math.round(subtotal),
      discountTotal: discountTotal + waivedAmount,
      waivedAmount,
      taxAmount,
      grandTotal,
      // Pay Later commission is credited when the customer pays (see applyPayment)
      staffEarning:  status === 'pending' ? 0 : staffEarningTotal,
      paymentMode:   paid > 0 ? mode : 'credit',
      paymentStatus: status,
      amountPaid:    paid,
      amountDue:     due,
      notes:         notes ? String(notes).slice(0, 1000) : undefined,
      serviceDate:   when
    });

    // Update customer stats
    if (resolvedCustomerId) {
      const custUpdate = {
        $inc: { totalVisits: 1, totalSpent: grandTotal },
        $set: { lastVisitAt: new Date() }
      };
      if (req.file) custUpdate.$push = { photos: { url: req.file.path, workEntry: entry._id, takenAt: new Date() } };
      await SaloonCustomer.findByIdAndUpdate(resolvedCustomerId, custUpdate);
      if (due > 0) await syncCustomerPending(req.saloon._id, resolvedCustomerId);
    }

    logActivity(req, req.saloon, 'bill_create', {
      entity: 'bill', entityId: entry._id, entityName: entry.billNumber,
      details: { grandTotal: entry.grandTotal, customerName: entry.customerName, paymentMode: entry.paymentMode, paymentStatus: status, waivedAmount }
    });
    res.status(201).json(entry);
  } catch (err) { sendError(res, err); }
});

// GET /api/saloon/entries  — filtered list
router.get('/entries', saloonAuth, async (req, res) => {
  try {
    const { from, to, staffId } = req.query;
    const { page, limit, skip } = pageParams(req.query, 50, 200);
    const tz = tzOf(req.saloon);
    const q = { saloon: req.saloon._id };

    // Non-owner staff can only see their own entries
    if (!isManager(req.staff)) {
      q.staff = req.staff._id;
    } else if (staffId) {
      if (!isId(staffId)) return res.status(400).json({ message: 'Invalid staff id.' });
      q.staff = oid(staffId);   // ObjectId — aggregate $match does not cast strings
    }

    if (from || to) {
      const f = parseDay(from, tz), t = parseDay(to, tz, true);
      if ((from && !f) || (to && !t)) return res.status(400).json({ message: 'Invalid date range.' });
      q.serviceDate = {};
      if (f) q.serviceDate.$gte = f;
      if (t) q.serviceDate.$lte = t;
    }

    const today = todayRange(tz);
    const todayQ = { ...q, serviceDate: { $gte: today.start, $lte: today.end } };

    // All-time query for this staff (no date filter) — for lifetime earning stat
    const allTimeQ = q.staff
      ? { saloon: req.saloon._id, staff: q.staff }
      : { saloon: req.saloon._id };

    const [entries, total, summaryAgg, todayCount, allTimeAgg] = await Promise.all([
      SaloonWorkEntry.find(q).sort({ serviceDate: -1 }).skip(skip).limit(limit).lean(),
      SaloonWorkEntry.countDocuments(q),
      SaloonWorkEntry.aggregate([
        { $match: q },
        { $group: {
          _id: null,
          totalRevenue:  { $sum: '$grandTotal' },
          totalEarning:  { $sum: '$staffEarning' }
        }}
      ]),
      SaloonWorkEntry.countDocuments(todayQ),
      SaloonWorkEntry.aggregate([
        { $match: allTimeQ },
        { $group: { _id: null, totalEarning: { $sum: '$staffEarning' } } }
      ])
    ]);

    // settledEarning = total salary actually paid to this staff (from SaloonSalarySettlement)
    let settledEarning = 0;
    if (q.staff) {
      const [settledAgg] = await SaloonSalarySettlement.aggregate([
        { $match: { saloon: req.saloon._id, staff: oid(q.staff) } },
        { $group: { _id: null, total: { $sum: '$amountPaid' } } }
      ]);
      settledEarning = settledAgg?.total || 0;
    }

    const summary = summaryAgg[0] || { totalRevenue: 0, totalEarning: 0 };
    delete summary._id;
    const allTimeEarning = allTimeAgg[0]?.totalEarning || 0;
    res.json({ entries, total, page, pages: Math.ceil(total / limit),
      summary: { ...summary, settledEarning, allTimeEarning, pendingEarning: Math.max(0, allTimeEarning - settledEarning), todayCount } });
  } catch (err) { sendError(res, err); }
});

// GET /api/saloon/entries/:id
router.get('/entries/:id', saloonAuth, async (req, res) => {
  try {
    const q = { _id: req.params.id, saloon: req.saloon._id };
    if (!isManager(req.staff)) q.staff = req.staff._id;
    const entry = await SaloonWorkEntry.findOne(q).populate('staff', 'name role avatar').lean();
    if (!entry) return res.status(404).json({ message: 'Entry not found.' });
    res.json(entry);
  } catch (err) { sendError(res, err); }
});

// PUT /api/saloon/entries/:id  (owner / manager) — descriptive fields only. Money
// fields stay consistent with customer balances and commission, so they change
// only through billing and collection, never by direct edit.
router.put('/entries/:id', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const update = pick(req.body, ['customerName', 'notes', 'paymentMode', 'serviceDate']);
    if (update.serviceDate !== undefined && isNaN(new Date(update.serviceDate)))
      return res.status(400).json({ message: 'Invalid service date.' });
    const entry = await SaloonWorkEntry.findOneAndUpdate(
      { _id: req.params.id, saloon: req.saloon._id },
      { $set: update },
      { new: true, runValidators: true }
    );
    if (!entry) return res.status(404).json({ message: 'Entry not found.' });
    logActivity(req, req.saloon, 'bill_update', { entity: 'bill', entityId: entry._id, entityName: entry.billNumber, details: update });
    res.json(entry);
  } catch (err) { sendError(res, err); }
});

// ════════════════════════════════════════════════════════════════════════════
// CUSTOMERS
// ════════════════════════════════════════════════════════════════════════════

// Name / phone search filter; a typed mobile also matches its normalised digits
function customerSearch(term) {
  const t = String(term || '').trim();
  const or = [
    { name:  { $regex: escapeRegex(t), $options: 'i' } },
    { phone: { $regex: escapeRegex(t), $options: 'i' } }
  ];
  const digits = normPhone(t);
  if (digits && digits !== t) or.push({ phone: { $regex: escapeRegex(digits) } });
  return or;
}

// GET /api/saloon/customers?pending=true  — list, optionally filter pending only
router.get('/customers', saloonAuth, async (req, res) => {
  try {
    const { q, pending } = req.query;
    const { page, limit, skip } = pageParams(req.query, 30);
    const filter = { saloon: req.saloon._id, isActive: true };
    if (q) filter.$or = customerSearch(q);
    if (pending === 'true') filter.pendingAmount = { $gt: 0 };
    const [customers, total] = await Promise.all([
      SaloonCustomer.find(filter).sort({ pendingAmount: -1, totalVisits: -1 }).skip(skip).limit(limit).lean(),
      SaloonCustomer.countDocuments(filter)
    ]);
    res.json({ customers, total, page });
  } catch (err) { sendError(res, err); }
});

// POST /api/saloon/customers  — create with auto-name
router.post('/customers', saloonAuth, async (req, res) => {
  try {
    const { email, gender, birthdate, notes, preferredStaff } = req.body;
    const phone = normPhone(req.body.phone);
    if (!phone) return res.status(400).json({ message: 'phone is required.' });
    if (!isPhone(phone)) return res.status(400).json({ message: 'Please enter a valid mobile number.' });
    if (email && !isEmail(email)) return res.status(400).json({ message: 'Please enter a valid email address.' });
    const existing = await SaloonCustomer.findOne({ saloon: req.saloon._id, phone: { $in: phoneVariants(phone) } });
    if (existing) return res.status(409).json(existing);
    const autoName = await nextCustomerName(req.saloon._id);
    const customer = await SaloonCustomer.create({
      saloon: req.saloon._id,
      name: autoName, phone, email, gender, birthdate, notes,
      preferredStaff: preferredStaff && isId(String(preferredStaff)) ? preferredStaff : undefined,
      firstVisitAt: new Date()
    });
    logActivity(req, req.saloon, 'customer_create', { entity: 'customer', entityId: customer._id, entityName: customer.name });
    res.status(201).json(customer);
  } catch (err) { sendError(res, err); }
});

// GET /api/saloon/customers/search?q=  — search by phone or name for bill creation
router.get('/customers/search', saloonAuth, async (req, res) => {
  try {
    const term = req.query.q || req.query.phone;
    if (!term || !String(term).trim()) return res.json([]);
    const customers = await SaloonCustomer.find({ saloon: req.saloon._id, isActive: true, $or: customerSearch(term) })
      .limit(10).lean();
    res.json(customers);
  } catch (err) { sendError(res, err); }
});

// POST /api/saloon/customers/:id/collect  — collect pending payment from customer
router.post('/customers/:id/collect', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const { paymentMode, staffId } = req.body;
    const collectAmount = toNum(req.body.amount);
    if (!Number.isFinite(collectAmount) || collectAmount <= 0)
      return res.status(400).json({ message: 'amount is required and must be > 0.' });
    if (!payModeOf(paymentMode)) return res.status(400).json({ message: PAY_MODE_MSG });

    const customer = await SaloonCustomer.findOne({ _id: req.params.id, saloon: req.saloon._id });
    if (!customer) return res.status(404).json({ message: 'Customer not found.' });

    // Optionally credit the collected bills to a specific staff member of this saloon
    let creditStaffId;
    if (staffId) {
      const st = await findSaloonStaff(req.saloon._id, staffId);
      if (!st) return res.status(400).json({ message: 'Selected staff member not found in this saloon.' });
      creditStaffId = st._id;
    }

    const due = await livePending(req.saloon._id, customer._id);
    if (due <= 0) {
      await syncCustomerPending(req.saloon._id, customer._id);
      return res.status(400).json({ message: 'No pending amount for this customer.' });
    }

    const collected = await applyPayment({
      saloonId: req.saloon._id, customerId: customer._id,
      amount: Math.min(collectAmount, due), creditStaffId
    });
    const fresh = await SaloonCustomer.findById(customer._id).lean();

    logActivity(req, req.saloon, 'pending_collected', {
      entity: 'customer', entityId: customer._id, entityName: customer.name,
      details: { collected, paymentMode: payModeOf(paymentMode), remainingPending: fresh.pendingAmount }
    });

    res.json({ message: `Collected ₹${collected}`, customer: fresh, remainingPending: fresh.pendingAmount });
  } catch (err) { sendError(res, err); }
});

// GET /api/saloon/customers/:id  (with visit history)
router.get('/customers/:id', saloonAuth, async (req, res) => {
  try {
    const customer = await SaloonCustomer.findOne({ _id: req.params.id, saloon: req.saloon._id }).lean();
    if (!customer) return res.status(404).json({ message: 'Customer not found.' });
    const history = await SaloonWorkEntry.find({ saloon: req.saloon._id, customer: customer._id })
      .sort({ serviceDate: -1 }).limit(20).lean();
    res.json({ customer, history });
  } catch (err) { sendError(res, err); }
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
const validLat = v => Number.isFinite(v) && v >= -90 && v <= 90;
const validLng = v => Number.isFinite(v) && v >= -180 && v <= 180;

// POST /api/saloon/attendance/self-checkin  — any staff member (self check-in/out)
router.post('/attendance/self-checkin', saloonAuth, async (req, res) => {
  try {
    const type = req.body.type === 'out' ? 'out' : 'in';
    const lat = toNum(req.body.lat), lng = toNum(req.body.lng);
    const hasCoords = validLat(lat) && validLng(lng);
    const saloon = req.saloon;
    const tz = tzOf(saloon);

    // Geofence — once the shop location is set, a location is mandatory
    if (saloon.location?.lat != null && saloon.location?.lng != null) {
      if (!hasCoords) {
        return res.status(400).json({
          code: 'LOCATION_REQUIRED',
          message: `Turn on location to check ${type}. You must be at the shop.`
        });
      }
      const dist = haversineDistance(lat, lng, saloon.location.lat, saloon.location.lng);
      const radius = saloon.location.radius || 50;
      if (dist > radius) {
        return res.status(400).json({
          message: `You are ${Math.round(dist)}m away from the shop. You must be within ${radius}m to check ${type}.`,
          distance: Math.round(dist),
          required: radius
        });
      }
    }

    const today = dateKey(tz);
    const now = new Date();
    const timeStr = hhmm(tz, now);
    const filter = { saloon: saloon._id, staff: req.staff._id, date: today };

    let record;
    if (type === 'out') {
      const existing = await SaloonAttendance.findOne(filter);
      if (!existing?.checkIn) return res.status(400).json({ message: 'Please check in first.' });
      existing.set({ checkOut: timeStr, checkoutAt: now, checkoutLat: hasCoords ? lat : undefined, checkoutLng: hasCoords ? lng : undefined });
      record = await existing.save();
    } else {
      record = await SaloonAttendance.findOneAndUpdate(filter,
        { $set: { status: 'present', selfCheckedIn: true, checkinAt: now, checkIn: timeStr,
                  checkinLat: hasCoords ? lat : undefined, checkinLng: hasCoords ? lng : undefined } },
        { upsert: true, new: true, runValidators: true });
    }
    res.json({ record, type, time: timeStr });
  } catch (err) { sendError(res, err); }
});

// GET /api/saloon/attendance/my-today  — get my attendance for today
router.get('/attendance/my-today', saloonAuth, async (req, res) => {
  try {
    const record = await SaloonAttendance.findOne({
      saloon: req.saloon._id, staff: req.staff._id, date: dateKey(tzOf(req.saloon))
    }).lean();
    res.json(record || null);
  } catch (err) { sendError(res, err); }
});

// PATCH /api/saloon/settings/location  — save shop GPS location (owner/manager)
router.patch('/settings/location', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const lat = toNum(req.body.lat), lng = toNum(req.body.lng);
    const radius = toNum(req.body.radius) ?? 50;
    if (!validLat(lat) || !validLng(lng)) return res.status(400).json({ message: 'Valid lat and lng required.' });
    if (!Number.isFinite(radius) || radius < 10 || radius > 5000)
      return res.status(400).json({ message: 'Radius must be between 10 and 5000 metres.' });
    const updated = await SaloonBusiness.findByIdAndUpdate(
      req.saloon._id,
      { $set: { 'location.lat': lat, 'location.lng': lng, 'location.radius': radius } },
      { new: true }
    );
    logActivity(req, req.saloon, 'settings_update', { entity: 'business', entityId: req.saloon._id, details: { location: true } });
    res.json({ location: updated.location });
  } catch (err) { sendError(res, err); }
});

// Attendance dates are UTC-midnight keys, so ranges are plain UTC calendar ranges
function monthKeyRange(month) {
  const m = /^(\d{4})-(\d{2})$/.exec(String(month || ''));
  if (!m) return null;
  const y = +m[1], mo = +m[2];
  if (mo < 1 || mo > 12) return null;
  return { $gte: new Date(Date.UTC(y, mo - 1, 1)), $lt: new Date(Date.UTC(y, mo, 1)) };
}

// GET /api/saloon/attendance?month=YYYY-MM&staffId=...
// Staff can view their own attendance; managers/owners can view any
router.get('/attendance', saloonAuth, async (req, res) => {
  try {
    const { month, staffId } = req.query;
    const q = { saloon: req.saloon._id };

    const queryStaffId = staffId || req.staff._id.toString();
    if (!isId(queryStaffId)) return res.status(400).json({ message: 'Invalid staff id.' });
    if (!isManager(req.staff) && queryStaffId !== req.staff._id.toString()) {
      return res.status(403).json({ message: 'Access denied. Can only view your own attendance.' });
    }
    q.staff = queryStaffId;

    if (month) {
      const range = monthKeyRange(month);
      if (!range) return res.status(400).json({ message: 'month must be YYYY-MM.' });
      q.date = range;
    }
    const records = await SaloonAttendance.find(q).populate('staff', 'name role avatar').sort({ date: -1 }).lean();
    res.json(records);
  } catch (err) { sendError(res, err); }
});

// POST /api/saloon/attendance
router.post('/attendance', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const { staffId, date, status, checkIn, checkOut, note } = req.body;
    if (!staffId || !date) return res.status(400).json({ message: 'staffId and date required.' });
    const staff = await findSaloonStaff(req.saloon._id, staffId);
    if (!staff) return res.status(404).json({ message: 'Staff not found.' });

    // 'YYYY-MM-DD' is already the key; anything else is converted in the saloon's timezone
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(date));
    const day = m ? new Date(Date.UTC(+m[1], +m[2] - 1, +m[3])) : (isNaN(new Date(date)) ? null : dateKey(tzOf(req.saloon), new Date(date)));
    if (!day || isNaN(day)) return res.status(400).json({ message: 'Invalid date.' });

    const set = { status: status || 'present' };
    if (checkIn !== undefined)  set.checkIn = checkIn;
    if (checkOut !== undefined) set.checkOut = checkOut;
    if (note !== undefined)     set.note = String(note).slice(0, 500);

    const record = await SaloonAttendance.findOneAndUpdate(
      { saloon: req.saloon._id, staff: staff._id, date: day },
      { $set: set },
      { upsert: true, new: true, runValidators: true }
    );
    logActivity(req, req.saloon, 'attendance_mark', { entity: 'attendance', entityId: staff._id, entityName: staff.name, details: { date, status: set.status } });
    res.json(record);
  } catch (err) { sendError(res, err); }
});

// ════════════════════════════════════════════════════════════════════════════
// DASHBOARD & REPORTS
// ════════════════════════════════════════════════════════════════════════════

// GET /api/saloon/dashboard
router.get('/dashboard', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const saloonId = req.saloon._id;
    const tz = tzOf(req.saloon);
    const billsPage  = Math.max(1, parseInt(req.query.billsPage)  || 1);
    const billsLimit = Math.min(50, Math.max(1, parseInt(req.query.billsLimit) || 10));
    const today = todayRange(tz);
    const month = monthRange(tz);

    const [
      todayEntries,
      monthEntries,
      totalCustomers,
      totalStaff,
      recentEntries,
      totalBillsCount,
      pendingAgg
    ] = await Promise.all([
      SaloonWorkEntry.aggregate([
        { $match: { saloon: saloonId, serviceDate: { $gte: today.start, $lte: today.end } } },
        { $group: { _id: null, revenue: { $sum: '$grandTotal' }, count: { $sum: 1 }, staffEarning: { $sum: '$staffEarning' } } }
      ]),
      SaloonWorkEntry.aggregate([
        { $match: { saloon: saloonId, serviceDate: { $gte: month.start, $lte: month.end } } },
        { $group: { _id: null, revenue: { $sum: '$grandTotal' }, count: { $sum: 1 }, staffEarning: { $sum: '$staffEarning' } } }
      ]),
      SaloonCustomer.countDocuments({ saloon: saloonId, isActive: true }),
      SaloonStaff.countDocuments({ saloon: saloonId, isActive: true }),
      SaloonWorkEntry.find({ saloon: saloonId })
        .sort({ createdAt: -1 })
        .skip((billsPage - 1) * billsLimit)
        .limit(billsLimit)
        .populate('staff', 'name avatar').lean(),
      SaloonWorkEntry.countDocuments({ saloon: saloonId }),
      SaloonWorkEntry.aggregate([
        { $match: { saloon: saloonId, paymentStatus: { $in: ['pending', 'partial'] }, amountDue: { $gt: 0 } } },
        { $group: { _id: null, total: { $sum: '$amountDue' }, count: { $sum: 1 } } }
      ])
    ]);

    // Staff performance this month
    const staffPerf = await SaloonWorkEntry.aggregate([
      { $match: { saloon: saloonId, serviceDate: { $gte: month.start, $lte: month.end } } },
      { $group: { _id: '$staff', name: { $first: '$staffName' }, bills: { $sum: 1 }, revenue: { $sum: '$grandTotal' }, earning: { $sum: '$staffEarning' } } },
      { $sort: { revenue: -1 } }
    ]);

    // Owner's own earning (bills where owner themselves is the staff)
    const ownerEarnAgg = await SaloonWorkEntry.aggregate([
      { $match: { saloon: saloonId, staff: req.staff._id, serviceDate: { $gte: month.start, $lte: month.end } } },
      { $group: { _id: null, earning: { $sum: '$staffEarning' }, bills: { $sum: 1 }, revenue: { $sum: '$grandTotal' } } }
    ]);
    const ownerEarn = ownerEarnAgg[0] || { earning: 0, bills: 0, revenue: 0 };

    res.json({
      today: todayEntries[0] || { revenue: 0, count: 0, staffEarning: 0 },
      month: monthEntries[0] || { revenue: 0, count: 0, staffEarning: 0 },
      totalCustomers,
      totalStaff,
      recentEntries,
      billsPagination: {
        page: billsPage,
        limit: billsLimit,
        total: totalBillsCount,
        pages: Math.ceil(totalBillsCount / billsLimit)
      },
      staffPerformance: staffPerf,
      pendingPayments: pendingAgg[0] || { total: 0, count: 0 },
      ownerEarn
    });
  } catch (err) { sendError(res, err); }
});

// GET /api/saloon/reports/staff  — per-staff earnings report
router.get('/reports/staff', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const { from, to } = req.query;
    const tz = tzOf(req.saloon);
    const match = { saloon: req.saloon._id };
    if (from || to) {
      const f = parseDay(from, tz), t = parseDay(to, tz, true);
      if ((from && !f) || (to && !t)) return res.status(400).json({ message: 'Invalid date range.' });
      match.serviceDate = {};
      if (f) match.serviceDate.$gte = f;
      if (t) match.serviceDate.$lte = t;
    }
    const data = await SaloonWorkEntry.aggregate([
      { $match: match },
      { $group: { _id: '$staff', name: { $first: '$staffName' }, bills: { $sum: 1 }, revenue: { $sum: '$grandTotal' }, earning: { $sum: '$staffEarning' } } },
      { $sort: { revenue: -1 } }
    ]);
    res.json(data);
  } catch (err) { sendError(res, err); }
});

// GET /api/saloon/salary/staff-summary — all staff with period earnings + pending amount
router.get('/salary/staff-summary', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const { from, to } = req.query;
    const saloonId = req.saloon._id;
    const tz = tzOf(req.saloon);

    const fromDate = parseDay(from, tz) || monthRange(tz).start;
    const toDate   = parseDay(to, tz, true) || todayRange(tz).end;

    const [staffList, earningsAgg, settledAgg, allTimeEarnAgg] = await Promise.all([
      SaloonStaff.find({ saloon: saloonId })
        .select('name phone role salary commissionType commissionValue joiningDate isActive avatar designation')
        .sort({ name: 1 })
        .lean(),
      // earnings in the selected period
      SaloonWorkEntry.aggregate([
        { $match: { saloon: saloonId, serviceDate: { $gte: fromDate, $lte: toDate } } },
        { $group: { _id: '$staff', bills: { $sum: 1 }, revenue: { $sum: '$grandTotal' }, earned: { $sum: '$staffEarning' } } }
      ]),
      // total salary settled EVER (to compute cumulative pending)
      SaloonSalarySettlement.aggregate([
        { $match: { saloon: saloonId } },
        { $group: { _id: '$staff', totalPaid: { $sum: '$amountPaid' }, lastSettledAt: { $max: '$settledAt' }, settlementsCount: { $sum: 1 } } }
      ]),
      SaloonWorkEntry.aggregate([
        { $match: { saloon: saloonId } },
        { $group: { _id: '$staff', totalEarned: { $sum: '$staffEarning' } } }
      ])
    ]);

    const earnMap = {};
    earningsAgg.forEach(e => { earnMap[e._id.toString()] = e; });
    const settledMap = {};
    settledAgg.forEach(s => { settledMap[s._id.toString()] = s; });
    const allTimeMap = {};
    allTimeEarnAgg.forEach(e => { allTimeMap[e._id.toString()] = e.totalEarned; });

    const result = staffList.map(s => {
      const sid  = s._id.toString();
      const e    = earnMap[sid]   || { bills: 0, revenue: 0, earned: 0 };
      const paid = settledMap[sid] || { totalPaid: 0, lastSettledAt: null, settlementsCount: 0 };
      const allTimeEarned = allTimeMap[sid] || 0;
      const allTimePending = Math.max(0, allTimeEarned - paid.totalPaid);
      return {
        ...s,
        periodBills:   e.bills,
        periodRevenue: e.revenue,
        periodEarned:  e.earned,
        totalPaidEver: paid.totalPaid,
        lastSettledAt: paid.lastSettledAt,
        settlementsCount: paid.settlementsCount,
        allTimeEarned,
        pendingAmount: allTimePending  // total unsettled (all time)
      };
    });

    res.json({ staff: result, fromDate, toDate });
  } catch (err) { sendError(res, err); }
});

// ════════════════════════════════════════════════════════════════════════════
// ANALYTICS  (owner) — everything for one period in a single response
// ════════════════════════════════════════════════════════════════════════════

// Headline numbers for a bill filter (used for the period and the one before it)
async function analyticsSummary(match) {
  const [s] = await SaloonWorkEntry.aggregate([
    { $match: match },
    { $group: {
      _id: null,
      revenue: { $sum: '$grandTotal' }, bills: { $sum: 1 },
      commission: { $sum: '$staffEarning' }, discounts: { $sum: '$discountTotal' },
      collected: { $sum: '$amountPaid' }, due: { $sum: '$amountDue' },
      customers: { $addToSet: '$customer' }
    } }
  ]);
  if (!s) return { revenue: 0, bills: 0, avgBill: 0, commission: 0, net: 0, discounts: 0, collected: 0, due: 0, customers: 0 };
  return {
    revenue: s.revenue, bills: s.bills, avgBill: Math.round(s.revenue / s.bills),
    commission: s.commission, net: s.revenue - s.commission, discounts: s.discounts,
    collected: s.collected, due: s.due, customers: s.customers.filter(Boolean).length
  };
}

// Revenue trend buckets: hourly for one day, daily up to ~2 months, monthly beyond
function trendBuckets(from, to, tz) {
  const DAY = 86400000;
  const span = to - from;
  const fmtParts = d => new Intl.DateTimeFormat('en-CA', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit' }).format(d);
  if (span <= DAY) return { unit: 'hour', format: '%H', keys: Array.from({ length: 24 }, (_, h) => String(h).padStart(2, '0')) };
  if (span <= 62 * DAY) {
    const keys = [];
    for (let t = from.getTime(); t <= to.getTime(); t += DAY) keys.push(fmtParts(new Date(t)));
    return { unit: 'day', format: '%Y-%m-%d', keys: [...new Set(keys)] };
  }
  const keys = [];
  const [y0, m0] = fmtParts(from).split('-').map(Number), [y1, m1] = fmtParts(to).split('-').map(Number);
  for (let y = y0, m = m0; y < y1 || (y === y1 && m <= m1); m === 12 ? (y++, m = 1) : m++) keys.push(`${y}-${String(m).padStart(2, '0')}`);
  return { unit: 'month', format: '%Y-%m', keys };
}

// GET /api/saloon/analytics?from=YYYY-MM-DD&to=YYYY-MM-DD   (both optional; no from = all time)
router.get('/analytics', saloonAuth, requireRole('owner'), async (req, res) => {
  try {
    const saloonId = req.saloon._id;
    const tz = tzOf(req.saloon);
    const { from: qFrom, to: qTo } = req.query;

    let from = parseDay(qFrom, tz), to = parseDay(qTo, tz, true);
    if ((qFrom && !from) || (qTo && !to)) return res.status(400).json({ message: 'Invalid date range.' });
    if (!to) to = todayRange(tz).end;
    if (!from) {   // all time: start at the first bill
      const first = await SaloonWorkEntry.findOne({ saloon: saloonId }).sort({ serviceDate: 1 }).select('serviceDate').lean();
      from = first ? parseDay(new Intl.DateTimeFormat('en-CA', { timeZone: tz }).format(first.serviceDate), tz) : todayRange(tz).start;
    }
    if (from > to) return res.status(400).json({ message: 'Start date is after end date.' });

    const match = { saloon: saloonId, serviceDate: { $gte: from, $lte: to } };
    // The same length of time immediately before, for ▲/▼ comparisons (not for all time)
    const prevMatch = qFrom
      ? { saloon: saloonId, serviceDate: { $gte: new Date(from - (to - from) - 1), $lt: from } }
      : null;
    const bucket = trendBuckets(from, to, tz);

    const [summary, previous, [f], newCustomers, outstanding] = await Promise.all([
      analyticsSummary(match),
      prevMatch ? analyticsSummary(prevMatch) : null,
      SaloonWorkEntry.aggregate([
        { $match: match },
        { $facet: {
          trend: [
            { $group: { _id: { $dateToString: { format: bucket.format, date: '$serviceDate', timezone: tz } }, revenue: { $sum: '$grandTotal' }, bills: { $sum: 1 } } }
          ],
          heat: [
            { $group: { _id: { dow: { $dayOfWeek: { date: '$serviceDate', timezone: tz } }, hour: { $hour: { date: '$serviceDate', timezone: tz } } }, bills: { $sum: 1 }, revenue: { $sum: '$grandTotal' } } }
          ],
          services: [
            { $unwind: '$services' },
            { $group: { _id: '$services.serviceName', qty: { $sum: { $ifNull: ['$services.qty', 1] } },
              revenue: { $sum: { $subtract: [{ $multiply: ['$services.price', { $ifNull: ['$services.qty', 1] }] }, { $ifNull: ['$services.discount', 0] }] } } } },
            { $sort: { revenue: -1 } }, { $limit: 8 }
          ],
          categories: [
            { $unwind: '$services' },
            { $group: { _id: { $ifNull: ['$services.category', 'other'] },
              revenue: { $sum: { $subtract: [{ $multiply: ['$services.price', { $ifNull: ['$services.qty', 1] }] }, { $ifNull: ['$services.discount', 0] }] } } } },
            { $sort: { revenue: -1 } }
          ],
          staff: [
            { $group: { _id: '$staff', name: { $first: '$staffName' }, bills: { $sum: 1 }, revenue: { $sum: '$grandTotal' }, commission: { $sum: '$staffEarning' } } },
            { $sort: { revenue: -1 } }
          ],
          payment: [
            { $group: { _id: '$paymentMode', collected: { $sum: '$amountPaid' }, bills: { $sum: 1 } } }
          ],
          topCustomers: [
            { $match: { customer: { $ne: null } } },
            { $group: { _id: '$customer', spent: { $sum: '$grandTotal' }, visits: { $sum: 1 }, last: { $max: '$serviceDate' } } },
            { $sort: { spent: -1 } }, { $limit: 5 },
            { $lookup: { from: 'salooncustomers', localField: '_id', foreignField: '_id', as: 'c' } },
            { $project: { spent: 1, visits: 1, last: 1, name: { $first: '$c.name' }, phone: { $first: '$c.phone' } } }
          ],
          walkIns: [{ $match: { customer: null } }, { $count: 'n' }]
        } }
      ]),
      // New = their first bill ever falls in this period (works for backdated bills too)
      SaloonWorkEntry.aggregate([
        { $match: { saloon: saloonId, customer: { $ne: null }, serviceDate: { $lte: to } } },
        { $group: { _id: '$customer', first: { $min: '$serviceDate' } } },
        { $match: { first: { $gte: from } } },
        { $count: 'n' }
      ]).then(r => r[0]?.n || 0),
      SaloonWorkEntry.aggregate([
        { $match: { saloon: saloonId, paymentStatus: { $in: ['pending', 'partial'] }, amountDue: { $gt: 0 } } },
        { $group: { _id: null, total: { $sum: '$amountDue' }, customers: { $addToSet: '$customer' } } }
      ])
    ]);

    const byKey = Object.fromEntries(f.trend.map(t => [t._id, t]));
    const newC = Math.min(newCustomers, summary.customers);

    res.json({
      period: { from, to, unit: bucket.unit, timezone: tz },
      summary, previous,
      trend: bucket.keys.map(k => ({ key: k, revenue: byKey[k]?.revenue || 0, bills: byKey[k]?.bills || 0 })),
      heat: f.heat.map(h => ({ dow: h._id.dow, hour: h._id.hour, bills: h.bills, revenue: h.revenue })),   // dow: 1 = Sunday
      services: f.services.map(s => ({ name: s._id, qty: s.qty, revenue: s.revenue })),
      categories: f.categories.map(c => ({ category: c._id, revenue: c.revenue })),
      staff: f.staff.map(s => ({ name: s.name, bills: s.bills, revenue: s.revenue, commission: s.commission })),
      payment: { modes: f.payment.map(p => ({ mode: p._id, collected: p.collected, bills: p.bills })), unpaid: summary.due },
      customers: {
        served: summary.customers, new: newC, returning: Math.max(0, summary.customers - newC),
        walkIns: f.walkIns[0]?.n || 0, top: f.topCustomers
      },
      outstanding: { total: outstanding[0]?.total || 0, customers: (outstanding[0]?.customers || []).filter(Boolean).length }
    });
  } catch (err) { sendError(res, err); }
});

// ════════════════════════════════════════════════════════════════════════════
// SALOON SETTINGS
// ════════════════════════════════════════════════════════════════════════════

// GET /api/saloon/settings
router.get('/settings', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    await ensureSaloonCode(req.saloon._id);
    const saloon = await SaloonBusiness.findById(req.saloon._id).select('-password -token').lean();
    res.json(saloon);
  } catch (err) { sendError(res, err); }
});

const SETTINGS_KEYS = ['currency', 'currencySymbol', 'timezone', 'commissionType', 'commissionValue', 'taxPercent', 'appointmentSlotMinutes'];
const ADDRESS_KEYS  = ['street', 'city', 'state', 'pincode'];

// PUT /api/saloon/settings — nested settings/address are merged key by key,
// so sending { settings: { taxPercent } } no longer wipes the other settings.
router.put('/settings', saloonAuth, requireRole('owner'), async (req, res) => {
  try {
    const b = req.body || {};
    const $set = {};
    ['businessName', 'ownerName', 'businessType', 'gstin', 'hours'].forEach(k => {
      if (b[k] !== undefined) $set[k] = typeof b[k] === 'string' ? b[k].trim() : b[k];
    });
    if ($set.businessName === '' || $set.ownerName === '')
      return res.status(400).json({ message: 'Business name and owner name cannot be empty.' });

    if (b.settings && typeof b.settings === 'object') {
      const s = b.settings;
      for (const k of SETTINGS_KEYS) if (s[k] !== undefined) $set[`settings.${k}`] = s[k];
      const tax = toNum(s.taxPercent), comm = toNum(s.commissionValue);
      if (tax !== undefined && !(Number.isFinite(tax) && tax >= 0 && tax <= 100))
        return res.status(400).json({ message: 'Tax must be between 0 and 100%.' });
      if (comm !== undefined && !(Number.isFinite(comm) && comm >= 0 && (s.commissionType !== 'percent' || comm <= 100)))
        return res.status(400).json({ message: 'Commission must be 0–100% (or a positive fixed amount).' });
      if (s.timezone !== undefined && safeTz(s.timezone) !== s.timezone)
        return res.status(400).json({ message: 'Unknown timezone.' });
    }
    if (b.address && typeof b.address === 'object') {
      for (const k of ADDRESS_KEYS) if (b.address[k] !== undefined) $set[`address.${k}`] = String(b.address[k]).trim();
    }

    // The phone is the saloon's platform-wide identity and the owner's login
    let newPhone;
    if (b.phone !== undefined) {
      newPhone = normPhone(b.phone);
      if (!isPhone(newPhone)) return res.status(400).json({ message: 'Please enter a valid mobile number.' });
      if (await SaloonBusiness.exists({ _id: { $ne: req.saloon._id }, phone: { $in: phoneVariants(newPhone) } }))
        return res.status(409).json({ message: 'Another saloon already uses this mobile number.' });
      if (await SaloonStaff.exists({ saloon: req.saloon._id, role: { $ne: 'owner' }, phone: { $in: phoneVariants(newPhone) } }))
        return res.status(409).json({ message: 'A staff member in this saloon already uses this mobile number.' });
      $set.phone = newPhone;
    }

    const saloon = await SaloonBusiness.findByIdAndUpdate(req.saloon._id, { $set }, { new: true, runValidators: true });

    // Keep the owner's login record in step with the business record
    const ownerSet = {};
    if (newPhone) ownerSet.phone = newPhone;
    if ($set.ownerName) ownerSet.name = $set.ownerName;
    if (Object.keys(ownerSet).length)
      await SaloonStaff.updateOne({ saloon: req.saloon._id, role: 'owner' }, { $set: ownerSet });

    logActivity(req, saloon, 'settings_update', { entity: 'business', entityId: saloon._id });
    res.json(saloon.toSafeObject());
  } catch (err) { sendError(res, err); }
});

// POST /api/saloon/settings/logo
router.post('/settings/logo', saloonAuth, requireRole('owner'), uploadPhoto.single('logo'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded.' });
    const saloon = await SaloonBusiness.findByIdAndUpdate(req.saloon._id, { logo: req.file.path }, { new: true });
    res.json({ logo: saloon.logo });
  } catch (err) { sendError(res, err); }
});

// ════════════════════════════════════════════════════════════════════════════
// SALARY SETTLEMENT
// ════════════════════════════════════════════════════════════════════════════

// Earnings since the last settlement (or joining date) for one staff member
async function unsettledPeriod(saloonId, staff) {
  const last = await SaloonSalarySettlement.findOne({ saloon: saloonId, staff: staff._id }).sort({ settledAt: -1 }).lean();
  const periodFrom = last ? new Date(last.settledAt) : (staff.joiningDate || new Date(0));
  const periodTo = new Date();
  const [agg] = await SaloonWorkEntry.aggregate([
    { $match: { saloon: saloonId, staff: staff._id, serviceDate: { $gte: periodFrom, $lte: periodTo } } },
    { $group: { _id: null, bills: { $sum: 1 }, revenue: { $sum: '$grandTotal' }, earning: { $sum: '$staffEarning' } } }
  ]);
  return { periodFrom, periodTo, pending: agg ? { bills: agg.bills, revenue: agg.revenue, earning: agg.earning } : { bills: 0, revenue: 0, earning: 0 } };
}

// GET /api/saloon/salary/settlements?staffId=  — pending earning + settlement history
router.get('/salary/settlements', saloonAuth, requireRole('owner', 'manager'), async (req, res) => {
  try {
    const { staffId } = req.query;
    if (!staffId) return res.status(400).json({ message: 'staffId required.' });
    const staff = await findSaloonStaff(req.saloon._id, staffId);
    if (!staff) return res.status(404).json({ message: 'Staff not found.' });

    const settlements = await SaloonSalarySettlement
      .find({ saloon: req.saloon._id, staff: staff._id })
      .sort({ settledAt: -1 })
      .limit(30)
      .lean();
    const { periodFrom, periodTo, pending } = await unsettledPeriod(req.saloon._id, staff);

    res.json({ settlements, pending, periodFrom, periodTo });
  } catch (err) { sendError(res, err); }
});

// POST /api/saloon/salary/settle  — create a settlement record
router.post('/salary/settle', saloonAuth, requireRole('owner'), async (req, res) => {
  try {
    const { staffId, paymentMode, notes } = req.body;
    const amountPaid = toNum(req.body.amountPaid);
    if (!staffId || amountPaid === undefined)
      return res.status(400).json({ message: 'staffId and amountPaid are required.' });
    if (!Number.isFinite(amountPaid) || amountPaid < 0)
      return res.status(400).json({ message: 'amountPaid must be a number of 0 or more.' });
    if (!payModeOf(paymentMode)) return res.status(400).json({ message: PAY_MODE_MSG });

    const staff = await findSaloonStaff(req.saloon._id, staffId);
    if (!staff) return res.status(404).json({ message: 'Staff not found.' });

    const { periodFrom, periodTo, pending } = await unsettledPeriod(req.saloon._id, staff);

    const settlement = await SaloonSalarySettlement.create({
      saloon:       req.saloon._id,
      staff:        staff._id,
      staffName:    staff.name,
      periodFrom,
      periodTo,
      totalBills:   pending.bills,
      totalRevenue: pending.revenue,
      grossEarning: pending.earning,
      amountPaid,
      paymentMode:  payModeOf(paymentMode),
      notes:        notes ? String(notes).slice(0, 500) : '',
      paidBy:       req.staff?.name || req.saloon?.ownerName || '',
      staffPhone:   staff.phone || ''
    });

    logActivity(req, req.saloon, 'salary_settled', {
      entity: 'staff', entityId: staff._id, entityName: staff.name,
      details: { amountPaid, paymentMode: settlement.paymentMode }
    });

    res.json({ settlement, staffPhone: staff.phone || '' });
  } catch (err) { sendError(res, err); }
});

// GET /api/saloon/salary/my-settlements  — staff views own settlement history + unsettled earning
router.get('/salary/my-settlements', saloonAuth, async (req, res) => {
  try {
    const staffId  = req.staff._id;
    const saloonId = req.saloon._id;

    const [settlements, period, totalPaid] = await Promise.all([
      SaloonSalarySettlement.find({ saloon: saloonId, staff: staffId }).sort({ settledAt: -1 }).limit(50).lean(),
      unsettledPeriod(saloonId, req.staff),
      SaloonSalarySettlement.aggregate([
        { $match: { saloon: saloonId, staff: staffId } },
        { $group: { _id: null, total: { $sum: '$amountPaid' } } }
      ])
    ]);

    res.json({
      settlements,
      unsettled: period.pending,
      totalPaidEver: totalPaid[0]?.total || 0,
      periodFrom: period.periodFrom,
      periodTo: period.periodTo
    });
  } catch (err) { sendError(res, err); }
});

module.exports = router;
