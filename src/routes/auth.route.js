const httpStatus = require('http-status');
const express = require('express');
const { body } = require('express-validator');
const validate = require('../middlewares/validate').validate;
const auth = require('../middlewares/auth');
const authController = require('../controllers').authController;
const { User, ROLES } = require('../models/user.model');
const logger = require('../config/logger');
const ApiError = require('../utils/ApiError');
const { 
  registerRateLimiter, 
  loginRateLimiter, 
  passwordResetLimiter,
  trackRequest 
} = require('../middlewares/rateLimiter');

const router = express.Router();

// Validation rules
const registerRules = [
  body('firstName').trim().notEmpty().withMessage('First name is required'),
  body('lastName').trim().notEmpty().withMessage('Last name is required'),
  body('email').isEmail().normalizeEmail().withMessage('Please provide a valid email'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/[a-z]/)
    .withMessage('Password must contain at least one lowercase letter')
    .matches(/[A-Z]/)
    .withMessage('Password must contain at least one uppercase letter')
    .matches(/[0-9]/)
    .withMessage('Password must contain at least one number'),
  body('phoneNumber')
    .optional({ checkFalsy: true })
    .matches(/^[0-9]{10,15}$/)
    .withMessage('Please provide a valid phone number'),
  body('role')
    .optional()
    .isIn(Object.values(ROLES))
    .withMessage('Invalid role'),
  body('companyName')
    .if((value, { req }) => [ROLES.SELLER, ROLES.DISTRIBUTOR].includes(req.body.role))
    .notEmpty()
    .withMessage('Company name is required for sellers and distributors')
    .trim()
];

const loginRules = [
  body('email').isEmail().normalizeEmail().withMessage('Please provide a valid email'),
  body('password').exists().withMessage('Password is required')
];

const refreshTokenRules = [
  body('refreshToken').notEmpty().withMessage('Refresh token is required')
];

const updateProfileRules = [
  body('email')
    .optional()
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('phoneNumber')
    .optional()
    .matches(/^[0-9]{10,15}$/)
    .withMessage('Please provide a valid phone number'),
  body('dateOfBirth')
    .optional()
    .isISO8601()
    .withMessage('Please provide a valid date of birth'),
  body('gender')
    .optional()
    .isIn(['male', 'female', 'other', 'prefer not to say'])
    .withMessage('Invalid gender')
];

const changePasswordRules = [
  body('currentPassword').notEmpty().withMessage('Current password is required'),
  body('newPassword')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/[a-z]/)
    .withMessage('Password must contain at least one lowercase letter')
    .matches(/[A-Z]/)
    .withMessage('Password must contain at least one uppercase letter')
    .matches(/[0-9]/)
    .withMessage('Password must contain at least one number')
    .not()
    .equals(body('currentPassword'))
    .withMessage('New password must be different from current password')
];

/**
 * @swagger
 * /api/v1/auth/register:
 *   post:
 *     summary: Register a new user (Admin only for customer/seller roles)
 *     description: |
 *       - Admins can register users with any role (customer, seller, distributor)
 *       - Public registration is only allowed for customer role
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - firstName
 *               - lastName
 *               - email
 *               - password
 *             properties:
 *               firstName:
 *                 type: string
 *               lastName:
 *                 type: string
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 format: password
 *               phoneNumber:
 *                 type: string
 *               role:
 *                 type: string
 *                 enum: [customer, seller, distributor]
 *                 default: customer
 *     responses:
 *       201:
 *         description: User registered successfully
 *       400:
 *         description: Validation error or email/phone already in use
 *       401:
 *         description: Unauthorized (admin required for non-customer roles)
 *       403:
 *         description: Forbidden (insufficient permissions)
 */
// Track all authentication requests
router.use(trackRequest);

/**
 * @swagger
 * /api/v1/auth/register:
 *   post:
 *     summary: Register a new user account
 *     description: |
 *       Register a new user account. 
 *       - For customer accounts, no authentication is required.
 *       - For seller/distributor accounts, admin authentication is required.
 *       - Rate limited to 5 attempts per IP every 15 minutes.
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - firstName
 *               - lastName
 *               - email
 *               - password
 *             properties:
 *               firstName:
 *                 type: string
 *               lastName:
 *                 type: string
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 format: password
 *                 minLength: 8
 *               phoneNumber:
 *                 type: string
 *               role:
 *                 type: string
 *                 enum: [customer, seller, distributor]
 *                 default: customer
 *               companyName:
 *                 type: string
 *                 description: Required for seller/distributor roles
 *     responses:
 *       201:
 *         description: User registered successfully
 *       400:
 *         description: Validation error or email/phone already in use
 *       401:
 *         description: Unauthorized (admin required for non-customer roles)
 *       403:
 *         description: Forbidden (insufficient permissions)
 *       429:
 *         description: Too many requests
 */
router.post('/register',
  // Apply rate limiting to registration
  registerRateLimiter,
  // If role is specified and not 'customer', require admin auth
  (req, res, next) => {
    if (req.body.role && req.body.role !== 'customer') {
      return auth()(req, res, (err) => {
        if (err) return next(err);
        // Check if user is admin
        if (req.user.role !== 'admin') {
          return next(new ApiError(httpStatus.FORBIDDEN, 'Only admins can register sellers and distributors'));
        }
        next();
      });
    }
    next();
  },
  validate(registerRules),
  async (req, res, next) => {
    try {
      // Default role to 'customer' if not specified
      if (!req.body.role) {
        req.body.role = 'customer';
      }
      
      // Check if this is an admin request (user is authenticated and has admin role)
      const isAdminRequest = req.user && req.user.role === 'admin';
      
      // Call register with isAdminRequest flag
      const result = await authController.register(req.body, isAdminRequest);
      
      // If this was an admin-created account, modify the response message
      if (isAdminRequest && [ROLES.SELLER, ROLES.DISTRIBUTOR].includes(req.body.role)) {
        result.message = `Successfully created and auto-approved ${req.body.role} account`;
      }
      
      res.status(httpStatus.CREATED).json(result);
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/v1/auth/login:
 *   post:
 *     summary: Login with email and password
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 format: password
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 user:
 *                   $ref: '#/components/schemas/User'
 *                 token:
 *                   type: string
 *       401:
 *         description: Invalid credentials
 *       403:
 *         description: Account not approved or deactivated
 *       429:
 *         description: Too many login attempts
 */
router.post('/login',
  loginRateLimiter,
  trackRequest,
  validate(loginRules),
  (req, res, next) => {
    const { email, password } = req.body;
    authController.login(email, password)
      .then(result => res.json(result))
      .catch(next);
});

/**
 * @swagger
 * /api/v1/auth/logout:
 *   post:
 *     summary: Logout
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logged out successfully
 *       401:
 *         description: Unauthorized
 */
router.post('/logout', auth(), authController.logout);

/**
 * @swagger
 * /api/v1/auth/forgot-password:
 *   post:
 *     summary: Request password reset
 *     description: Send a password reset email to the user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 description: User's email address
 *     responses:
 *       200:
 *         description: If the email exists, a password reset email has been sent
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: If your email is registered, you will receive a password reset link
 *       400:
 *         $ref: '#/components/responses/BadRequest'
 *       500:
 *         $ref: '#/components/responses/ServerError'
 */
router.post(
  '/forgot-password',
  [
    validate([
      body('email').isEmail().normalizeEmail().withMessage('Please provide a valid email')
    ])
  ],
  async (req, res, next) => {
    try {
      await authController.forgotPassword(req.body.email);
      res.status(httpStatus.OK).json({
        success: true,
        message: 'If your email is registered, you will receive a password reset link'
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/v1/auth/reset-password:
 *   post:
 *     summary: Reset password
 *     description: Reset user password using the token from email
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - token
 *               - password
 *               - confirmPassword
 *             properties:
 *               token:
 *                 type: string
 *                 description: Password reset token from email
 *               password:
 *                 type: string
 *                 format: password
 *                 minLength: 8
 *                 description: New password
 *               confirmPassword:
 *                 type: string
 *                 format: password
 *                 description: Must match the password field
 *     responses:
 *       200:
 *         description: Password has been reset successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: Password reset successful
 *       400:
 *         $ref: '#/components/responses/BadRequest'
 *       401:
 *         $ref: '#/components/responses/Unauthorized'
 *       500:
 *         $ref: '#/components/responses/ServerError'
 */
router.post(
  '/reset-password',
  [
    validate([
      body('token').notEmpty().withMessage('Token is required'),
      body('password')
        .isLength({ min: 8 })
        .withMessage('Password must be at least 8 characters long')
        .matches(/[a-z]/)
        .withMessage('Password must contain at least one lowercase letter')
        .matches(/[A-Z]/)
        .withMessage('Password must contain at least one uppercase letter')
        .matches(/[0-9]/)
        .withMessage('Password must contain at least one number'),
      body('confirmPassword').custom((value, { req }) => {
        if (value !== req.body.password) {
          throw new Error('Passwords do not match');
        }
        return true;
      })
    ])
  ],
  async (req, res, next) => {
    try {
      await authController.resetPassword(
        req.body.token,
        req.body.password
      );
      
      res.status(httpStatus.OK).json({
        success: true,
        message: 'Password reset successful'
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/v1/auth/update-password:
 *   post:
 *     summary: Update user password
 *     description: Update the password for the currently authenticated user
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - currentPassword
 *               - newPassword
 *               - confirmNewPassword
 *             properties:
 *               currentPassword:
 *                 type: string
 *                 format: password
 *                 description: Current password
 *               newPassword:
 *                 type: string
 *                 format: password
 *                 minLength: 8
 *                 description: New password
 *               confirmNewPassword:
 *                 type: string
 *                 format: password
 *                 description: Must match the new password field
 *     responses:
 *       200:
 *         description: Password has been updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: Password updated successfully
 *       400:
 *         $ref: '#/components/responses/BadRequest'
 *       401:
 *         $ref: '#/components/responses/Unauthorized'
 *       500:
 *         $ref: '#/components/responses/ServerError'
 */
router.post(
  '/update-password',
  auth(),
  [
    validate([
      body('currentPassword').notEmpty().withMessage('Current password is required'),
      body('newPassword')
        .isLength({ min: 8 })
        .withMessage('Password must be at least 8 characters long')
        .matches(/[a-z]/)
        .withMessage('Password must contain at least one lowercase letter')
        .matches(/[A-Z]/)
        .withMessage('Password must contain at least one uppercase letter')
        .matches(/[0-9]/)
        .withMessage('Password must contain at least one number'),
      body('confirmNewPassword').custom((value, { req }) => {
        if (value !== req.body.newPassword) {
          throw new Error('New passwords do not match');
        }
        return true;
      })
    ])
  ],
  async (req, res, next) => {
    try {
      // Fetch the full user document with password
      const user = await User.findById(req.user._id).select('+password');
      
      if (!user) {
        throw new ApiError(httpStatus.NOT_FOUND, 'User not found');
      }
      
      await authController.updatePassword(
        user,
        req.body.currentPassword,
        req.body.newPassword
      );
      
      res.status(httpStatus.OK).json({
        success: true,
        message: 'Password updated successfully'
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * components:
 *   responses:
 *     BadRequest:
 *       description: Bad request, validation failed or invalid input
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               success:
 *                 type: boolean
 *                 example: false
 *               message:
 *                 type: string
 *                 example: Validation failed
 *               errors:
 *                 type: array
 *                 items:
 *                   type: string
 *                 example: ["Email is required", "Password must be at least 8 characters"]
 *     Unauthorized:
 *       description: Unauthorized, invalid or missing token
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               success:
 *                 type: boolean
 *                 example: false
 *               message:
 *                 type: string
 *                 example: Please authenticate
 *     Forbidden:
 *       description: Forbidden, user doesn't have permission
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               success:
 *                 type: boolean
 *                 example: false
 *               message:
 *                 type: string
 *                 example: You do not have permission to perform this action
 *     NotFound:
 *       description: The requested resource was not found
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               success:
 *                 type: boolean
 *                 example: false
 *               message:
 *                 type: string
 *                 example: User not found
 *     ServerError:
 *       description: Internal server error
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               success:
 *                 type: boolean
 *                 example: false
 *               message:
 *                 type: string
 *                 example: Something went wrong
 */

module.exports = router;
