const mongoose = require('mongoose');

const subscriptionPlanSchema = new mongoose.Schema({
  name:          { type: String, required: true, trim: true },
  description:   { type: String, trim: true },
  period:        { type: String, enum: ['monthly', 'yearly'], required: true },
  price:         { type: Number, required: true },
  originalPrice: { type: Number },          // show strikethrough for discounts
  discountLabel: { type: String },          // e.g. "Save 20%"
  features:      [{ type: String }],
  isActive:      { type: Boolean, default: true },
  isDefault:     { type: Boolean, default: false },
  sortOrder:     { type: Number, default: 0 }
}, { timestamps: true });

module.exports = mongoose.models.SubscriptionPlan ||
  mongoose.model('SubscriptionPlan', subscriptionPlanSchema);
