const mongoose = require('mongoose');
const { Schema } = mongoose;

const saloonCustomerSchema = new Schema({
  saloon:  { type: Schema.Types.ObjectId, ref: 'SaloonBusiness', required: true },

  // Identity — name is auto-assigned as "Customer-1", "Customer-2" etc.
  name:      { type: String, required: true, trim: true },
  phone:     { type: String, required: true, trim: true },
  email:     { type: String, trim: true, lowercase: true },
  gender:    { type: String, enum: ['male', 'female', 'other'], default: 'male' },
  birthdate: { type: Date },
  avatar:    { type: String },

  // Preferences
  preferredStaff: { type: Schema.Types.ObjectId, ref: 'SaloonStaff' },
  notes:          { type: String, trim: true },

  // Stats (updated on each visit)
  totalVisits:    { type: Number, default: 0 },
  totalSpent:     { type: Number, default: 0 },
  lastVisitAt:    { type: Date },
  firstVisitAt:   { type: Date },

  // Pending / Credit amount owed by this customer
  pendingAmount:  { type: Number, default: 0 },

  // Loyalty points
  loyaltyPoints: { type: Number, default: 0 },

  // Photo gallery (before/after)
  photos: [{
    url:       { type: String },
    caption:   { type: String },
    workEntry: { type: Schema.Types.ObjectId, ref: 'SaloonWorkEntry' },
    takenAt:   { type: Date, default: Date.now }
  }],

  isActive: { type: Boolean, default: true }

}, { timestamps: true });

saloonCustomerSchema.index({ saloon: 1, phone: 1 }, { unique: true });
saloonCustomerSchema.index({ saloon: 1, name: 'text' });

module.exports = mongoose.models.SaloonCustomer ||
  mongoose.model('SaloonCustomer', saloonCustomerSchema);
