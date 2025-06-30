const httpStatus = require('http-status');
const jwt = require('jsonwebtoken');
const { User } = require('../models/user.model');
const ApiError = require('../utils/ApiError');
const config = require('../config/config');
const logger = require('../config/logger');

/**
 * Authentication middleware with role-based access control
 * @param {...string} requiredRoles - Roles that are allowed to access the route
 * @returns {Function} Express middleware function
 */
const auth = (...requiredRoles) => {
  return async (req, res, next) => {
    try {
      // Get token from header
      const authHeader = req.headers.authorization;
      
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        throw new ApiError(httpStatus.UNAUTHORIZED, 'Authentication required');
      }
      
      const token = authHeader.split(' ')[1];
      
      // Verify token
      let payload;
      try {
        payload = jwt.verify(token, config.jwt.secret);
      } catch (error) {
        if (error.name === 'TokenExpiredError') {
          throw new ApiError(httpStatus.UNAUTHORIZED, 'Token expired');
        }
        throw new ApiError(httpStatus.UNAUTHORIZED, 'Invalid token');
      }
      
      // Check if user still exists
      const user = await User.findById(payload.id);
      
      if (!user) {
        throw new ApiError(httpStatus.UNAUTHORIZED, 'User not found');
      }
      
      // Check if user role is authorized
      if (requiredRoles.length && !requiredRoles.includes(user.role)) {
        throw new ApiError(httpStatus.FORBIDDEN, 'Not enough permissions');
      }
      
      // Attach user to request object
      req.user = user;
      
      next();
    } catch (error) {
      next(error);
    }
  };
};

module.exports = auth;
