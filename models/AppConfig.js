const mongoose = require('mongoose');

// Singleton document — always upsert with key='global'
const appConfigSchema = new mongoose.Schema({
  key:                  { type: String, default: 'global', unique: true },
  globalServiceMode:    { type: Boolean, default: false },
  serviceModeMessage:   { type: String, default: 'Service is under maintenance. Please try again shortly.' },
  defaultTrialDays:     { type: Number, default: 30 },
  defaultMonthlyRate:   { type: Number, default: 999 }
}, { timestamps: true });

module.exports = mongoose.models.AppConfig || mongoose.model('AppConfig', appConfigSchema);
