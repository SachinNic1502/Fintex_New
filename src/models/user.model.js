const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const config = require('../config/config');
const logger = require('../config/logger');

// Define user roles and their permissions
const ROLES = {
  CUSTOMER: 'customer',
  SELLER: 'seller',
  DISTRIBUTOR: 'distributor',
  ADMIN: 'admin',
};

const GENDER = {
  MALE: 'male',
  FEMALE: 'female',
  OTHER: 'other',
  PREFER_NOT_TO_SAY: 'prefer not to say',
};

// Default login attempts before lockout
const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_TIME = 15 * 60 * 1000; // 15 minutes in milliseconds

const userSchema = new mongoose.Schema(
  {
    // Basic Information
    firstName: {
      type: String,
      required: true,
      trim: true,
    },
    lastName: {
      type: String,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
      match: [/^\S+@\S+\.\S+$/, 'Please use a valid email address.'],
    },
    phoneNumber: {
      type: String,
      trim: true,
      match: [/^[0-9]{10,15}$/, 'Please use a valid phone number.'],
    },
    // Authentication
    password: {
      type: String,
      required: true,
      minlength: 8,
      private: true, // Don't include in JSON responses
      select: false, // Don't include in query results by default
    },
    resetPasswordToken: {
      type: String,
      select: false,
    },
    resetPasswordExpires: {
      type: Date,
      select: false,
    },
    dateOfBirth: {
      type: Date,
    },
    gender: {
      type: String,
      enum: Object.values(GENDER),
    },
    
    // Role and Permissions
    role: {
      type: String,
      enum: Object.values(ROLES),
      default: ROLES.CUSTOMER,
    },
    permissions: [{
      type: String,
    }],
    
    // Account Status
    isEmailVerified: {
      type: Boolean,
      default: false,
    },
    isPhoneVerified: {
      type: Boolean,
      default: false,
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    isApproved: {
      type: Boolean,
      default: function() {
        return this.role === ROLES.CUSTOMER; // Auto-approve customers
      },
    },
    
    // Seller/Distributor Specific Fields
    companyName: {
      type: String,
      required: function() {
        return [ROLES.SELLER, ROLES.DISTRIBUTOR].includes(this.role);
      },
      trim: true,
    },
    gstNumber: {
      type: String,
      trim: true,
      match: [/^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$/, 'Please enter a valid GST number'],
    },
    panNumber: {
      type: String,
      trim: true,
      uppercase: true,
      match: [/^[A-Z]{5}[0-9]{4}[A-Z]{1}$/, 'Please enter a valid PAN number'],
    },
    businessAddress: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Address',
    },
    
    // Customer Specific Fields
    defaultShippingAddress: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Address',
    },
    defaultBillingAddress: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Address',
    },
    
    // Additional Information
    profileImage: {
      type: String,
      trim: true,
    },
    lastLogin: {
      type: Date,
    },
    lastPasswordChange: {
      type: Date,
    },
    loginAttempts: {
      type: Number,
      default: 0,
    },
    lockUntil: {
      type: Date,
    },
  },
  {
    timestamps: true,
    toJSON: {
      transform(doc, ret) {
        delete ret.password;
        delete ret.__v;
        return ret;
      },
      virtuals: true,
    },
  }
);

// Virtual for full name
userSchema.virtual('fullName').get(function() {
  return `${this.firstName} ${this.lastName || ''}`.trim();
});

// Indexes for better query performance
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ phoneNumber: 1 });
userSchema.index({ role: 1 });
userSchema.index({ isActive: 1 });
userSchema.index({ isApproved: 1 });

/**
 * Check if email is taken
 * @param {string} email - The user's email
 * @param {ObjectId} [excludeUserId] - The id of the user to be excluded
 * @returns {Promise<boolean>}
 */
userSchema.statics.isEmailTaken = async function(email, excludeUserId) {
  const user = await this.findOne({ email, _id: { $ne: excludeUserId } });
  return !!user;
};

/**
 * Check if phone number is taken
 * @param {string} phoneNumber - The user's phone number
 * @param {ObjectId} [excludeUserId] - The id of the user to be excluded
 * @returns {Promise<boolean>}
 */
userSchema.statics.isPhoneTaken = async function(phoneNumber, excludeUserId) {
  if (!phoneNumber) return false;
  const user = await this.findOne({ phoneNumber, _id: { $ne: excludeUserId } });
  return !!user;
};

/**
 * Check if password matches the user's password
 * @param {string} password - The password to check
 * @returns {Promise<boolean>}
 */
userSchema.methods.isPasswordMatch = async function(password) {
  return bcrypt.compare(password, this.password);
};

/**
 * Check if password was changed after a certain timestamp
 * @param {number} JWTTimestamp - Timestamp from JWT
 * @returns {boolean}
 */
userSchema.methods.changedPasswordAfter = function(JWTTimestamp) {
  if (this.lastPasswordChange) {
    const changedTimestamp = parseInt(this.lastPasswordChange.getTime() / 1000, 10);
    return JWTTimestamp < changedTimestamp;
  }
  // False means NOT changed
  return false;
};

/**
 * Hash password before saving
 */
userSchema.pre('save', async function(next) {
  const user = this;
  
  // Only hash the password if it has been modified (or is new)
  if (!user.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(user.password, salt);
    user.lastPasswordChange = Date.now();
    next();
  } catch (error) {
    logger.error('Error hashing password', error);
    next(error);
  }
});

/**
 * Check if account is locked due to too many failed login attempts
 * @returns {boolean}
 */
userSchema.methods.isLocked = function() {
  return this.lockUntil && this.lockUntil > Date.now();
};

/**
 * Get the remaining lockout time in minutes
 * @returns {number} Remaining lockout time in minutes
 */
userSchema.methods.getRemainingLockTime = function() {
  if (!this.isLocked()) return 0;
  return Math.ceil((this.lockUntil - Date.now()) / 60000); // Convert to minutes
};

/**
 * Increment login attempts and lock account if too many failed attempts
 */
userSchema.methods.incrementLoginAttempts = async function() {
  // If lock has expired, reset attempts
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return await this.updateOne({
      $set: { loginAttempts: 1 },
      $unset: { lockUntil: 1 },
    });
  }
  
  const updates = { $inc: { loginAttempts: 1 } };
  
  // Lock the account if max attempts reached
  if (this.loginAttempts + 1 >= MAX_LOGIN_ATTEMPTS && !this.lockUntil) {
    updates.$set = { 
      lockUntil: Date.now() + LOCK_TIME,
      loginAttempts: this.loginAttempts + 1
    };
  }
  
  return await this.updateOne(updates);
};

/**
 * Reset login attempts after successful login
 */
userSchema.methods.resetLoginAttempts = async function() {
  return await this.updateOne({
    $set: { loginAttempts: 0 },
    $unset: { lockUntil: 1 },
  });
};

// Create and export the model
const User = mongoose.model('User', userSchema);

// Export constants
module.exports = {
  User,
  ROLES,
  GENDER,
};
