const mongoose = require('mongoose');
const { Schema } = mongoose;

const saloonServiceSchema = new Schema({
  saloon:    { type: Schema.Types.ObjectId, ref: 'SaloonBusiness', required: true },

  name:      { type: String, required: true, trim: true },
  category: {
    type: String,
    enum: ['hair', 'beard', 'skin', 'nail', 'massage', 'makeup', 'waxing', 'threading', 'other'],
    default: 'hair'
  },
  description: { type: String, trim: true },
  price:       { type: Number, required: true, min: 0 },
  duration:    { type: Number, default: 30 }, // minutes
  gender:      { type: String, enum: ['male', 'female', 'unisex'], default: 'unisex' },
  isActive:    { type: Boolean, default: true },
  sortOrder:   { type: Number, default: 0 }

}, { timestamps: true });

saloonServiceSchema.index({ saloon: 1, category: 1 });

module.exports = mongoose.models.SaloonService ||
  mongoose.model('SaloonService', saloonServiceSchema);
