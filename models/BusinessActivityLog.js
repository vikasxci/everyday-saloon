const mongoose = require('mongoose');
const { Schema } = mongoose;

const businessActivityLogSchema = new Schema({
  bizType:      { type: String, enum: ['saloon', 'restaurant'], required: true, index: true },
  business:     { type: Schema.Types.ObjectId, required: true, index: true },
  businessName: { type: String },
  ownerEmail:   { type: String },

  actor:     { type: String },  // staff name or 'owner'
  actorRole: { type: String },  // role of the staff who triggered action

  action: {
    type: String,
    required: true,
    enum: [
      // Auth
      'register', 'login', 'pin_login', 'logout',
      // Bills / Orders
      'bill_create', 'bill_update',
      'order_create', 'order_update', 'order_status',
      'kot_create',
      // Staff
      'staff_create', 'staff_update', 'staff_delete',
      // Staff auth (added — these were being dropped by this enum)
      'staff_login', 'staff_set_password', 'staff_change_password',
      'staff_forgot_password', 'staff_reset_password', 'staff_otp_issued',
      // Services / Menu
      'service_create', 'service_update', 'service_delete',
      'menu_item_create', 'menu_item_update', 'menu_item_delete',
      // Customers & Reservations
      'customer_create',
      'reservation_create',
      // Money
      'collection_request_submit', 'collection_request_approved',
      'collection_request_rejected', 'pending_collected', 'salary_settled',
      // Admin actions
      'admin_saloon_update', 'admin_saloon_status', 'admin_owner_password_reset',
      'admin_subscription_update', 'admin_service_mode', 'admin_saloon_delete',
      // Operations
      'table_status',
      'attendance_mark',
      'settings_update',
    ]
  },

  entity:     { type: String },   // 'bill', 'order', 'staff', 'service', etc.
  entityId:   { type: Schema.Types.ObjectId },
  entityName: { type: String },

  details:   { type: Schema.Types.Mixed },
  ip:        { type: String },
  userAgent: { type: String },
}, { timestamps: true });

businessActivityLogSchema.index({ bizType: 1, createdAt: -1 });
businessActivityLogSchema.index({ business: 1, createdAt: -1 });
businessActivityLogSchema.index({ action: 1,   createdAt: -1 });
businessActivityLogSchema.index({ createdAt: -1 });

module.exports = mongoose.models.BusinessActivityLog ||
  mongoose.model('BusinessActivityLog', businessActivityLogSchema);
