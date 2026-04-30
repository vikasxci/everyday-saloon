const mongoose = require('mongoose');

const collectionRequestSchema = new mongoose.Schema({
  saloon:       { type: mongoose.Schema.Types.ObjectId, ref: 'SaloonBusiness', required: true },
  customer:     { type: mongoose.Schema.Types.ObjectId, ref: 'SaloonCustomer', required: true },
  customerName: { type: String, default: '' },
  customerPhone:{ type: String, default: '' },
  amount:       { type: Number, required: true },
  paymentMode:  { type: String, enum: ['cash','upi','card','wallet'], default: 'cash' },
  notes:        { type: String, default: '' },

  // Staff who collected
  requestedBy:      { type: mongoose.Schema.Types.ObjectId, ref: 'SaloonStaff', required: true },
  requestedByName:  { type: String, default: '' },

  // Approval
  status:       { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  reviewedBy:   { type: mongoose.Schema.Types.ObjectId, ref: 'SaloonStaff' },
  reviewedByName: { type: String, default: '' },
  reviewedAt:   { type: Date },
  rejectReason: { type: String, default: '' },
}, { timestamps: true });

collectionRequestSchema.index({ saloon: 1, status: 1 });
collectionRequestSchema.index({ saloon: 1, requestedBy: 1 });

module.exports = mongoose.model('SaloonCollectionRequest', collectionRequestSchema);
