const mongoose = require('mongoose');
const { Schema } = mongoose;

const serviceLineSchema = new Schema({
  service:      { type: Schema.Types.ObjectId, ref: 'SaloonService' },
  serviceName:  { type: String, required: true },
  category:     { type: String },
  price:        { type: Number, required: true, min: 0 },
  qty:          { type: Number, default: 1, min: 1 },
  discount:     { type: Number, default: 0 },      // flat discount on this line
  staffEarning: { type: Number, default: 0 }        // commission earned by staff for this line
}, { _id: true });

const saloonWorkEntrySchema = new Schema({
  saloon:  { type: Schema.Types.ObjectId, ref: 'SaloonBusiness', required: true },
  staff:   { type: Schema.Types.ObjectId, ref: 'SaloonStaff',    required: true },
  staffName: { type: String },

  // Bill number
  billNumber: { type: String, required: true },

  // Customer info (may or may not be a registered customer)
  customer:      { type: Schema.Types.ObjectId, ref: 'SaloonCustomer' },
  customerName:  { type: String, trim: true, default: 'Walk-in' },
  customerPhone: { type: String, trim: true },
  customerPhoto: { type: String },  // Cloudinary URL — customer photo for this bill

  // Services rendered
  services: [serviceLineSchema],

  // Totals
  subtotal:      { type: Number, default: 0 },
  discountTotal: { type: Number, default: 0 },
  taxAmount:     { type: Number, default: 0 },
  grandTotal:    { type: Number, default: 0 },
  staffEarning:  { type: Number, default: 0 },  // total commission for this bill

  // Payment
  paymentMode: {
    type: String,
    enum: ['cash', 'upi', 'card', 'wallet', 'credit'],
    default: 'cash'
  },
  paymentStatus: {
    type: String,
    enum: ['paid', 'pending', 'partial'],
    default: 'paid'
  },
  amountPaid:   { type: Number, default: 0 },
  amountDue:    { type: Number, default: 0 },

  // Notes
  notes: { type: String, trim: true },

  // Date
  serviceDate: { type: Date, default: Date.now }

}, { timestamps: true });

saloonWorkEntrySchema.index({ saloon: 1, serviceDate: -1 });
saloonWorkEntrySchema.index({ saloon: 1, staff: 1, serviceDate: -1 });

module.exports = mongoose.models.SaloonWorkEntry ||
  mongoose.model('SaloonWorkEntry', saloonWorkEntrySchema);
