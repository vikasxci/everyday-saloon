const jwt       = require('jsonwebtoken');
const AdminUser = require('../models/AdminUser');

const ADMIN_SECRET = (process.env.JWT_SECRET || 'hadlay-kalan-secret-key') + '_admin';

module.exports = async (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer '))
    return res.status(401).json({ message: 'Admin authentication required.' });

  const token = auth.slice(7);
  try {
    const { id } = jwt.verify(token, ADMIN_SECRET);
    const admin  = await AdminUser.findById(id).select('-password').lean();
    if (!admin || !admin.isActive)
      return res.status(401).json({ message: 'Admin not found or deactivated.' });
    req.admin = admin;
    next();
  } catch {
    res.status(401).json({ message: 'Invalid or expired admin token.' });
  }
};
