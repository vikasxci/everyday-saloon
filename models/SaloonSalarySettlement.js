const mongoose = require('mongoose');
const { Schema } = mongoose;

const saloonSalarySettlementSchema = new Schema({
  saloon:      { type: Schema.Types.ObjectId, ref: 'SaloonBusiness', required: true },
  staff:       { type: Schema.Types.ObjectId, ref: 'SaloonStaff', required: true },
  staffName:   { type: String, required: true },

  periodFrom:  { type: Date, required: true },
  periodTo:    { type: Date, required: true },

  totalBills:   { type: Number, default: 0 },
  totalRevenue: { type: Number, default: 0 },
  grossEarning: { type: Number, default: 0 },   // commission computed for the period
  amountPaid:   { type: Number, required: true },
  paymentMode:  { type: String, enum: ['cash', 'upi', 'bank', 'other'], default: 'cash' },
  notes:        { type: String, trim: true },
  paidBy:       { type: String },
  staffPhone:   { type: String },               // for WhatsApp share
  settledAt:    { type: Date, default: Date.now }

}, { timestamps: true });

saloonSalarySettlementSchema.index({ saloon: 1, staff: 1, settledAt: -1 });

module.exports = mongoose.models.SaloonSalarySettlement ||
  mongoose.model('SaloonSalarySettlement', saloonSalarySettlementSchema);
