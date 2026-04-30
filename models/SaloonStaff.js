const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { Schema } = mongoose;

const saloonStaffSchema = new Schema({
  saloon: { type: Schema.Types.ObjectId, ref: 'SaloonBusiness', required: true },

  // Identity
  name:   { type: String, required: true, trim: true },
  email:  { type: String, lowercase: true, trim: true },
  phone:  { type: String, trim: true },
  avatar: { type: String }, // Cloudinary URL

  // Auth
  password: { type: String },  // for full login
  pin:      { type: String },  // 4-digit PIN for quick login

  role: {
    type: String,
    enum: ['owner', 'manager', 'stylist', 'barber', 'beautician', 'trainee'],
    default: 'stylist',
    required: true
  },

  // Specializations
  specializations: [{ type: String, trim: true }], // e.g. ['haircut', 'beard', 'facial']

  // Work & pay
  designation:    { type: String, trim: true },
  salary:         { type: Number, default: 0 },        // base salary
  commissionType: { type: String, enum: ['percent', 'fixed', 'none'], default: 'percent' },
  commissionValue: { type: Number, default: 40 },      // 40% or fixed ₹ per service

  joiningDate: { type: Date },

  // Session
  token:       { type: String },
  lastLoginAt: { type: Date },
  loginCount:  { type: Number, default: 0 },
  isActive:    { type: Boolean, default: true }

}, { timestamps: true });

saloonStaffSchema.index({ saloon: 1, role: 1 });
saloonStaffSchema.index({ saloon: 1, phone: 1 }, { sparse: true });

// Hooks
saloonStaffSchema.pre('save', async function (next) {
  if (this.isModified('password') && this.password)
    this.password = await bcrypt.hash(this.password, 12);
  if (this.isModified('pin') && this.pin)
    this.pin = await bcrypt.hash(this.pin, 10);
  next();
});

saloonStaffSchema.methods.comparePassword = function (plain) {
  return bcrypt.compare(plain, this.password);
};
saloonStaffSchema.methods.comparePin = function (plain) {
  return bcrypt.compare(plain, this.pin);
};
saloonStaffSchema.methods.toSafeObject = function () {
  const obj = this.toObject();
  delete obj.password;
  delete obj.pin;
  return obj;
};

module.exports = mongoose.models.SaloonStaff ||
  mongoose.model('SaloonStaff', saloonStaffSchema);
