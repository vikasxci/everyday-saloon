const jwt       = require('jsonwebtoken');
const AdminUser = require('../models/AdminUser');
const { ADMIN_SECRET } = require('../config/secrets');

module.exports = async (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer '))
    return res.status(401).json({ message: 'Admin authentication required.' });

  const token = auth.slice(7);
  try {
    const { id, tv = 0 } = jwt.verify(token, ADMIN_SECRET);
    const admin  = await AdminUser.findById(id).select('-password').lean();
    if (!admin || !admin.isActive)
      return res.status(401).json({ message: 'Admin not found or deactivated.' });
    // A password change (own or reset by a superadmin) signs out older tokens
    if ((admin.tokenVersion || 0) !== tv)
      return res.status(401).json({ message: 'Password was changed. Please sign in again.' });
    req.admin = admin;
    next();
  } catch {
    res.status(401).json({ message: 'Invalid or expired admin token.' });
  }
};
