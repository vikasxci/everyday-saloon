const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { Schema } = mongoose;

const saloonBusinessSchema = new Schema({
  // Identity
  businessName: { type: String, required: true, trim: true },
  slug:         { type: String, unique: true, sparse: true },
  ownerName:    { type: String, required: true, trim: true },
  email:        { type: String, required: true, lowercase: true, trim: true, unique: true },
  phone:        { type: String, required: true, trim: true, unique: true },
  password:     { type: String, required: true },
  logo:         { type: String },   // Cloudinary URL
  coverImage:   { type: String },

  // Business details
  businessType: {
    type: String,
    enum: ['salon', 'barber', 'spa', 'beauty_parlour', 'unisex_salon'],
    default: 'salon'
  },
  address: {
    street:  { type: String, trim: true },
    city:    { type: String, trim: true },
    state:   { type: String, trim: true },
    pincode: { type: String, trim: true }
  },
  gstin:  { type: String, trim: true },

  // Business hours
  hours: {
    type: Map,
    of: new Schema({
      open:   { type: String, default: '09:00' },
      close:  { type: String, default: '21:00' },
      closed: { type: Boolean, default: false }
    }, { _id: false }),
    default: {}
  },

  // Settings
  settings: {
    currency:       { type: String, default: 'INR' },
    currencySymbol: { type: String, default: '₹' },
    timezone:       { type: String, default: 'Asia/Kolkata' },
    commissionType: {
      type: String,
      enum: ['fixed', 'percent', 'none'],
      default: 'percent'
    },
    commissionValue: { type: Number, default: 40 }, // e.g. 40%
    taxPercent:      { type: Number, default: 0 },
    appointmentSlotMinutes: { type: Number, default: 30 }
  },

  // Token for persistent login
  token: { type: String },

  // Shop GPS location (for staff attendance geofencing)
  location: {
    lat: { type: Number },
    lng: { type: Number },
    radius: { type: Number, default: 50 } // meters
  },

  isActive: { type: Boolean, default: true },

  // ── Subscription ───────────────────────────────────────────
  subscription: {
    status: {
      type: String,
      enum: ['trial', 'active', 'expired', 'suspended'],
      default: 'trial'
    },
    trialEndsAt:        { type: Date },
    planId:             { type: mongoose.Schema.Types.ObjectId, ref: 'SubscriptionPlan' },
    planName:           { type: String },
    monthlyRate:        { type: Number, default: 0 },     // custom per-saloon rate
    currentPeriodStart: { type: Date },
    currentPeriodEnd:   { type: Date },
    lastPaidAt:         { type: Date },
    adminNotes:         { type: String }
  },

  // Per-saloon maintenance/service mode
  serviceMode: { type: Boolean, default: false }

}, { timestamps: true });

// Hash password
saloonBusinessSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

saloonBusinessSchema.methods.comparePassword = function (plain) {
  return bcrypt.compare(plain, this.password);
};

saloonBusinessSchema.methods.toSafeObject = function () {
  const obj = this.toObject();
  delete obj.password;
  return obj;
};

module.exports = mongoose.models.SaloonBusiness ||
  mongoose.model('SaloonBusiness', saloonBusinessSchema);
