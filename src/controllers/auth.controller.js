const httpStatus = require('http-status');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { omit, pick } = require('lodash');
const { User, ROLES } = require('../models/user.model');
const ApiError = require('../utils/ApiError');
const logger = require('../config/logger');
const emailService = require('../services/email.service');
const config = require('../config/config');

// Validate JWT configuration
if (!config.jwt.secret || !config.jwt.refreshSecret) {
  throw new Error('JWT secrets are not properly configured');
}

// Log JWT configuration (remove in production)
if (process.env.NODE_ENV === 'development') {
  console.log('JWT Config:', {
    secret: config.jwt.secret ? '***' : 'MISSING',
    refreshSecret: config.jwt.refreshSecret ? '***' : 'MISSING',
    expiresIn: config.jwt.expiresIn,
    refreshExpiresIn: config.jwt.refreshExpiresIn
  });
}

// Fields that can be updated by users
const userPublicFields = [
  'firstName', 'lastName', 'email', 'phoneNumber', 'dateOfBirth', 'gender',
  'companyName', 'gstNumber', 'panNumber', 'profileImage'
];

// Fields that can be updated by admin
const adminUserFields = [
  ...userPublicFields,
  'role', 'permissions', 'isActive', 'isApproved', 'isEmailVerified', 'isPhoneVerified'
];

/**
 * Generate JWT token for authentication
 * @param {Object} user - User object
 * @returns {string} JWT token
 */
const generateAuthToken = (user) => {
  const payload = {
    id: user._id,
    email: user.email,
    role: user.role,
    permissions: user.permissions || [],
  };

  return jwt.sign(payload, config.jwt.secret, {
    expiresIn: config.jwt.expiresIn,
  });
};

/**
 * Generate refresh token
 * @param {Object} user - User object
 * @returns {string} Refresh token
 */
const generateRefreshToken = (user) => {
  const payload = {
    id: user._id,
    version: user.tokenVersion || 0,
  };

  return jwt.sign(payload, config.jwt.refreshSecret, {
    expiresIn: config.jwt.refreshExpiresIn,
  });
};

/**
 * Get user data without sensitive information
 * @param {Object} user - User object
 * @returns {Object} User data without sensitive information
 */
const getUserData = (user) => {
  return omit(user.toJSON(), [
    'password',
    'loginAttempts',
    'lockUntil',
    'tokenVersion',
    '__v',
    'resetPasswordToken',
    'resetPasswordExpires',
  ]);
};

/**
 * Create a user account
 * @param {Object} userBody - User registration data
 * @param {boolean} [isAdminRequest=false] - Whether the request is from an admin
 * @returns {Promise<Object>} User object with tokens
 */
const register = async (userBody, isAdminRequest = false) => {
  // Check if email is already taken
  if (await User.isEmailTaken(userBody.email)) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'Email already taken');
  }

  // Check if phone number is already taken
  if (userBody.phoneNumber && (await User.isPhoneTaken(userBody.phoneNumber))) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'Phone number already in use');
  }

  // Set default role to CUSTOMER if not provided
  if (!userBody.role) {
    userBody.role = ROLES.CUSTOMER;
  }

  // For non-customers, validate required fields and set defaults
  if (userBody.role !== ROLES.CUSTOMER) {
    // Require companyName for seller and distributor roles
    if (!userBody.companyName) {
      throw new ApiError(
        httpStatus.BAD_REQUEST,
        'Company name is required for seller and distributor accounts'
      );
    }
    
    // Auto-approve if request is from admin, otherwise require approval
    userBody.isApproved = isAdminRequest;
    
    // If admin is creating the account, set as active by default
    if (isAdminRequest) {
      userBody.isActive = true;
      userBody.isEmailVerified = true;
    }
  } else {
    // For customers, ensure companyName is not set
    delete userBody.companyName;
  }

  // Initialize token version for refresh token invalidation
  userBody.tokenVersion = 0;

  // Create user
  const user = await User.create(userBody);
  
  // Generate tokens
  const accessToken = generateAuthToken(user);
  const refreshToken = generateRefreshToken(user);
  
  // Update user with refresh token
  user.refreshToken = refreshToken;
  await user.save();
  
  // Send welcome email (in background, don't wait for it)
  emailService.sendWelcomeEmail(user).catch((error) => {
    logger.error('Failed to send welcome email:', error);
  });
  
  // Return user data with tokens
  return {
    user: getUserData(user),
    token: accessToken,
    refreshToken,
  };
};

/**
 * Login with email and password
 * @param {string} email - User's email
 * @param {string} password - User's password
 * @returns {Promise<Object>} User data with tokens
 */
const login = async (email, password) => {
  // Find user by email with password field included
  const user = await User.findOne({ email }).select('+password');
  
  // Check if user exists and password is correct
  if (!user || !(await user.isPasswordMatch(password))) {
    // Increment login attempts for existing user
    if (user) {
      await user.incrementLoginAttempts();
      
      // Check if account is now locked
      if (user.loginAttempts + 1 >= 5) {
        throw new ApiError(
          httpStatus.TOO_MANY_REQUESTS,
          'Account locked due to too many failed login attempts. Please try again later.'
        );
      }
    }
    
    throw new ApiError(
      httpStatus.UNAUTHORIZED,
      'Incorrect email or password'
    );
  }

  // Check if account is active
  if (!user.isActive) {
    throw new ApiError(
      httpStatus.FORBIDDEN,
      'Your account has been deactivated. Please contact support.'
    );
  }

  // Check if account is approved (for sellers/distributors)
  if (user.role !== ROLES.CUSTOMER && !user.isApproved) {
    throw new ApiError(
      httpStatus.FORBIDDEN,
      'Your account is pending approval. Please contact support for more information.'
    );
  }

  // Check if account is locked
  if (user.isLocked()) {
    const remainingTime = user.getRemainingLockTime();
    throw new ApiError(
      httpStatus.TOO_MANY_REQUESTS,
      `Account temporarily locked. Try again in ${remainingTime} minutes.`
    );
  }
  
  // Reset login attempts
  await user.resetLoginAttempts();
  
  // Update last login
  user.lastLogin = new Date();
  
  // Increment token version to invalidate previous refresh tokens
  user.tokenVersion = (user.tokenVersion || 0) + 1;
  
  // Generate new tokens
  const accessToken = generateAuthToken(user);
  const refreshToken = generateRefreshToken(user);
  
  // Update user with refresh token and save
  user.refreshToken = refreshToken;
  await user.save();
  
  // Return user data with tokens
  return {
    user: getUserData(user),
    token: accessToken,
    refreshToken,
  };
};

/**
 * Logout user
 * @param {string} refreshToken - The refresh token to invalidate
 * @returns {Promise<void>}
 */
const logout = async (refreshToken) => {
  if (!refreshToken) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'Refresh token is required');
  }

  try {
    // Verify the token to get the user ID
    const payload = jwt.verify(refreshToken, config.jwt.refreshSecret);
    const userId = payload.id;
    
    // Invalidate the refresh token by unsetting it
    await User.findByIdAndUpdate(userId, { $unset: { refreshToken: 1 } });
    
    logger.info(`User ${userId} logged out successfully`);
  } catch (error) {
    // Don't throw error if token is already invalid
    if (error.name !== 'JsonWebTokenError') {
      logger.error('Error during logout:', error);
      throw new ApiError(httpStatus.INTERNAL_SERVER_ERROR, 'Error during logout');
    }
  }
};

/**
 * Logout user from all devices
 * @param {string} userId - The ID of the user to log out
 * @returns {Promise<void>}
 */
const logoutAllDevices = async (userId) => {
  try {
    // Increment token version to invalidate all refresh tokens
    await User.findByIdAndUpdate(userId, { 
      $inc: { tokenVersion: 1 },
      $unset: { refreshToken: 1 }
    });
    
    logger.info(`User ${userId} logged out from all devices`);
  } catch (error) {
    logger.error('Error during logout from all devices:', error);
    throw new ApiError(httpStatus.INTERNAL_SERVER_ERROR, 'Failed to logout from all devices');
  }
};

/**
 * Refresh authentication token
 * @param {string} refreshToken - The refresh token
 * @returns {Promise<Object>} New token and user data
 */
const refreshAuth = async (refreshToken) => {
  try {
    const payload = jwt.verify(refreshToken, config.jwt.secret);
    const user = await User.findById(payload.id);
    
    if (!user) {
      throw new ApiError(httpStatus.UNAUTHORIZED, 'User not found');
    }
    
    // Check if user is active
    if (!user.isActive) {
      throw new ApiError(httpStatus.FORBIDDEN, 'User account is deactivated');
    }
    
    // Verify token version
    if (user.tokenVersion !== (payload.version || 0)) {
      throw new ApiError(httpStatus.UNAUTHORIZED, 'Invalid token version');
    }
    
    // Generate new tokens
    const newAccessToken = generateAuthToken(user);
    const newRefreshToken = generateRefreshToken(user);
    
    // Update user with new refresh token
    user.refreshToken = newRefreshToken;
    await user.save();
    
    return {
      user: getUserData(user),
      token: newAccessToken,
      refreshToken: newRefreshToken,
    };
  } catch (error) {
    logger.error('Error refreshing token:', error);
    
    if (error.name === 'TokenExpiredError') {
      throw new ApiError(httpStatus.UNAUTHORIZED, 'Refresh token expired');
    } else if (error.name === 'JsonWebTokenError') {
      throw new ApiError(httpStatus.UNAUTHORIZED, 'Invalid refresh token');
    }
    
    throw new ApiError(httpStatus.INTERNAL_SERVER_ERROR, 'Failed to refresh token');
  }
};

/**
 * Get user profile
 * @param {string} userId - User ID
 * @returns {Promise<Object>} User profile data
 */
const getProfile = async (userId) => {
  const user = await User.findById(userId);
  if (!user) {
    throw new ApiError(httpStatus.NOT_FOUND, 'User not found');
  }
  return omit(user.toJSON(), ['password', 'loginAttempts', 'lockUntil', '__v']);
};

/**
 * Update user profile
 * @param {string} userId - User ID
 * @param {Object} updateBody - Fields to update
 * @param {boolean} isAdmin - Whether the requester is an admin
 * @returns {Promise<Object>} Updated user data
 */
const updateProfile = async (userId, updateBody, isAdmin = false) => {
  const user = await User.findById(userId);
  if (!user) {
    throw new ApiError(httpStatus.NOT_FOUND, 'User not found');
  }
  
  // Check if email is being updated and if it's already taken
  if (updateBody.email && (await User.isEmailTaken(updateBody.email, userId))) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'Email already taken');
  }
  
  // Check if phone number is being updated and if it's already taken
  if (updateBody.phoneNumber && (await User.isPhoneTaken(updateBody.phoneNumber, userId))) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'Phone number already in use');
  }
  
  // Determine which fields can be updated
  const allowedFields = isAdmin ? adminUserFields : userPublicFields;
  const updateData = pick(updateBody, allowedFields);
  
  // Update user
  Object.assign(user, updateData);
  await user.save();
  
  return omit(user.toJSON(), ['password', 'loginAttempts', 'lockUntil', '__v']);
};

/**
 * Change user password
 * @param {string} userId - User ID
 * @param {string} currentPassword - Current password
 * @param {string} newPassword - New password
 * @returns {Promise<void>}
 */
const changePassword = async (userId, currentPassword, newPassword) => {
  const user = await User.findById(userId).select('+password');
  
  if (!user) {
    throw new ApiError(httpStatus.NOT_FOUND, 'User not found');
  }
  
  // Verify current password
  if (!(await user.isPasswordMatch(currentPassword))) {
    throw new ApiError(httpStatus.UNAUTHORIZED, 'Current password is incorrect');
  }
  
  // Update password
  user.password = newPassword;
  user.tokenVersion = (user.tokenVersion || 0) + 1; // Invalidate all tokens
  await user.save();
  
  // Send password change confirmation email
  emailService.sendPasswordChangeConfirmation(user.email, `${user.firstName} ${user.lastName}`.trim() || user.email)
    .catch(error => logger.error('Failed to send password change confirmation:', error));
};

/**
 * Request password reset
 * @param {string} email - User's email
 * @returns {Promise<void>}
 */
const forgotPassword = async (email) => {
  const user = await User.findOne({ email });
  
  if (!user) {
    // For security reasons, don't reveal if the email exists or not
    logger.info(`Password reset requested for non-existent email: ${email}`);
    return;
  }
  
  // Generate reset token (expires in 1 hour)
  const resetToken = crypto.randomBytes(32).toString('hex');
  const resetTokenExpiry = Date.now() + 3600000; // 1 hour from now
  
  user.resetPasswordToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
  user.resetPasswordExpires = resetTokenExpiry;
  
  await user.save({ validateBeforeSave: false });
  
  // Send email with reset link
  const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password/${resetToken}`;
  
  // Log the reset link in development
  if (process.env.NODE_ENV !== 'production') {
    logger.info(`Password reset link for ${user.email}: ${resetUrl}`);
    logger.info(`Reset token: ${resetToken}`);
  }
  
  try {
    await emailService.sendPasswordResetEmail(
      user.email,
      user.firstName || user.email,
      resetToken,
      resetUrl
    );
    logger.info(`Password reset email sent to ${user.email}`);
  } catch (error) {
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save({ validateBeforeSave: false });
    
    logger.error('Error sending password reset email:', error);
    throw new ApiError(
      httpStatus.INTERNAL_SERVER_ERROR,
      'There was an error sending the password reset email. Please try again later.'
    );
  }
};

/**
 * Reset password using token
 * @param {string} token - Password reset token
 * @param {string} password - New password
 * @returns {Promise<void>}
 */
const resetPassword = async (token, password) => {
  // Hash the token to match the one in database
  const hashedToken = crypto
    .createHash('sha256')
    .update(token)
    .digest('hex');
  
  const user = await User.findOne({
    resetPasswordToken: hashedToken,
    resetPasswordExpires: { $gt: Date.now() }
  });
  
  if (!user) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'Invalid or expired token');
  }
  
  // Update password and clear reset token
  user.password = password;
  user.resetPasswordToken = undefined;
  user.resetPasswordExpires = undefined;
  user.tokenVersion = (user.tokenVersion || 0) + 1; // Invalidate all sessions
  
  await user.save();
  
  // Send confirmation email
  try {
    await emailService.sendPasswordResetConfirmation(
      user.email,
      user.firstName || user.email
    );
    logger.info(`Password reset confirmation email sent to ${user.email}`);
  } catch (error) {
    logger.error('Failed to send password reset confirmation email:', error);
    // Don't throw the error to prevent the password reset from failing
    // just because the confirmation email couldn't be sent
  }
};

module.exports = {
  register,
  login,
  logout,
  forgotPassword,
  resetPassword,
  logoutAllDevices,
  refreshAuth,
  changePassword,
  getProfile,
  updateProfile,
  
  /**
   * Update user password
   * @param {Object} user - The user object from the request
   * @param {string} currentPassword - Current password
   * @param {string} newPassword - New password
   * @returns {Promise<void>}
   */
  async updatePassword(user, currentPassword, newPassword) {
    if (!(await user.isPasswordMatch(currentPassword))) {
      throw new ApiError(httpStatus.UNAUTHORIZED, 'Current password is incorrect');
    }

    if (currentPassword === newPassword) {
      throw new ApiError(httpStatus.BAD_REQUEST, 'New password must be different from current password');
    }

    user.password = newPassword;
    user.tokenVersion = (user.tokenVersion || 0) + 1; // Invalidate all sessions
    await user.save();

    try {
      // Send password change confirmation email
      await emailService.sendPasswordChangeConfirmation(
        user.email,
        user.firstName || user.email
      );
      logger.info(`Password change confirmation sent to ${user.email}`);
    } catch (error) {
      logger.error('Failed to send password change confirmation email:', error);
      // Don't fail the request if email sending fails
    }
  },
  
  ROLES,
};
