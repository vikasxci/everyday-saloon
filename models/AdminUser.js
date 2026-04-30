const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');

const adminUserSchema = new mongoose.Schema({
  name:     { type: String, required: true, trim: true },
  username: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  role:     { type: String, enum: ['superadmin', 'support'], default: 'superadmin' },
  isActive: { type: Boolean, default: true },
  lastLogin:{ type: Date }
}, { timestamps: true });

adminUserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

adminUserSchema.methods.comparePassword = function (plain) {
  return bcrypt.compare(plain, this.password);
};

module.exports = mongoose.models.AdminUser || mongoose.model('AdminUser', adminUserSchema);
