const mongoose = require('mongoose');

// Atomic sequences (e.g. per-saloon bill numbers) — countDocuments()+1 races.
const counterSchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true },
  seq: { type: Number, default: 0 }
});

module.exports = mongoose.models.Counter || mongoose.model('Counter', counterSchema);
