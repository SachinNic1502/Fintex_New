const mongoose = require('mongoose');
const { User, ROLES } = require('../models/user.model');
const logger = require('../config/logger');
const config = require('../config/config');

// Admin user configuration
const ADMIN_CONFIG = {
  firstName: 'Admin',
  email: 'admin@fintex.com',
  password: 'Admin@123', // In production, use environment variable
  role: ROLES.ADMIN,
  isEmailVerified: true,
  isActive: true,
  isApproved: true,
  permissions: [
    'users:read', 'users:create', 'users:update', 'users:delete',
    'products:read', 'products:create', 'products:update', 'products:delete',
    'orders:read', 'orders:update', 'orders:delete',
    'categories:manage', 'settings:manage'
  ]
};

/**
 * Initialize admin user if not exists
 */
async function initAdmin() {
  try {
    // Connect to MongoDB
    await mongoose.connect(config.mongodb.uri, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    logger.info('Connected to MongoDB for admin initialization');

    // Check if admin already exists
    const existingAdmin = await User.findOne({ email: ADMIN_CONFIG.email });
    
    if (existingAdmin) {
      logger.info('Admin user already exists');
      process.exit(0);
    }

    // Create admin user
    const admin = new User(ADMIN_CONFIG);
    await admin.save();

    logger.info('Admin user created successfully');
    logger.info(`Email: ${ADMIN_CONFIG.email}`);
    logger.info('Please change the default password after first login');
    
    process.exit(0);
  } catch (error) {
    logger.error('Error initializing admin user:', error);
    process.exit(1);
  }
}

// Run the initialization
initAdmin();
