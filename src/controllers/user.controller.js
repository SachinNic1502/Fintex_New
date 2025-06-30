const httpStatus = require('http-status');
const { User, ROLES } = require('../models/user.model');
const ApiError = require('../utils/ApiError');

/**
 * Approve a user account (admin only)
 * @param {string} userId - The ID of the user to approve
 * @param {string} adminId - The ID of the admin approving the user
 * @returns {Promise<Object>} The updated user
 */
const approveUser = async (userId, adminId) => {
  // Check if user exists
  const user = await User.findById(userId);
  if (!user) {
    throw new ApiError(httpStatus.NOT_FOUND, 'User not found');
  }

  // Only sellers and distributors need approval
  if (user.role === ROLES.CUSTOMER) {
    throw new ApiError(
      httpStatus.BAD_REQUEST,
      'Customer accounts do not require approval'
    );
  }

  // Update user approval status
  user.isApproved = true;
  user.approvedBy = adminId;
  user.approvedAt = new Date();
  
  await user.save();
  
  // TODO: Send approval notification email
  
  return user;
};

/**
 * Get all pending approvals (admin only)
 * @returns {Promise<Array>} List of users pending approval
 */
const getPendingApprovals = async () => {
  return User.find({
    role: { $in: [ROLES.SELLER, ROLES.DISTRIBUTOR] },
    isApproved: false
  }).select('-password -refreshToken');
};

/**
 * Get user by ID (admin only)
 * @param {string} userId - The ID of the user to get
 * @returns {Promise<Object>} User object
 */
const getUserById = async (userId) => {
  const user = await User.findById(userId).select('-password -refreshToken');
  if (!user) {
    throw new ApiError(httpStatus.NOT_FOUND, 'User not found');
  }
  return user;
};

module.exports = {
  approveUser,
  getPendingApprovals,
  getUserById
};
