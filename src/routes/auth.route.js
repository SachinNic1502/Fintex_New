const httpStatus = require('http-status');
const express = require('express');
const { body } = require('express-validator');
const validate = require('../middlewares/validate').validate;
const auth = require('../middlewares/auth');
const authController = require('../controllers').authController;
const { ROLES } = require('../models/user.model');
const logger = require('../config/logger');

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
router.post('/register', 
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
  (req, res, next) => {
    // Default role to 'customer' if not specified
    if (!req.body.role) {
      req.body.role = 'customer';
    }
    authController.register(req.body)
      .then(user => res.status(httpStatus.CREATED).json(user))
      .catch(next);
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
router.post('/login', validate(loginRules), (req, res, next) => {
  const { email, password } = req.body;
  authController.login(email, password)
    .then(result => res.json(result))
    .catch(next);
});

/**
 * @swagger
 * /api/v1/auth/refresh-token:
 *   post:
 *     summary: Refresh authentication token
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - refreshToken
 *             properties:
 *               refreshToken:
 *                 type: string
 *     responses:
 *       200:
 *         description: Token refreshed successfully
 *       401:
 *         description: Invalid or expired refresh token
 */
router.post('/refresh-token', validate(refreshTokenRules), (req, res, next) => {
  authController.refreshAuth(req.body.refreshToken)
    .then(tokens => res.json(tokens))
    .catch(next);
});

/**
 * @swagger
 * /api/v1/auth/logout:
 *   post:
 *     summary: Logout user (invalidate current refresh token)
 *     description: Logs out the currently authenticated user by invalidating their refresh token
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
 *               - refreshToken
 *             properties:
 *               refreshToken:
 *                 type: string
 *                 description: Refresh token to invalidate
 *     responses:
 *       200:
 *         description: Successfully logged out
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Successfully logged out
 *       400:
 *         description: Bad request (missing refresh token)
 *       401:
 *         description: Unauthorized (invalid or expired token)
 *       500:
 *         description: Internal server error
 */
router.post('/logout', auth(), validate(refreshTokenRules), (req, res, next) => {
  authController.logout(req.body.refreshToken)
    .then(() => res.status(200).json({ message: 'Successfully logged out' }))
    .catch(next);
});

/**
 * @swagger
 * /api/v1/auth/logout-all:
 *   post:
 *     summary: Logout user from all devices
 *     description: Logs out the currently authenticated user from all devices by incrementing the token version
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Successfully logged out from all devices
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Successfully logged out from all devices
 *       401:
 *         description: Unauthorized (invalid or expired token)
 *       500:
 *         description: Internal server error
 */
router.post('/logout-all', auth(), (req, res, next) => {
  authController.logoutAllDevices(req.user.id)
    .then(() => res.status(200).json({ message: 'Successfully logged out from all devices' }))
    .catch(next);
});

/**
 * @swagger
 * /api/v1/auth/me:
 *   get:
 *     summary: Get current user profile
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 *       401:
 *         description: Unauthorized
 */
router.get('/me', auth(), (req, res, next) => {
  authController.getProfile(req.user.id)
    .then(profile => res.json(profile))
    .catch(next);
});

/**
 * @swagger
 * /api/v1/auth/me:
 *   patch:
 *     summary: Update current user profile
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               firstName:
 *                 type: string
 *               lastName:
 *                 type: string
 *               email:
 *                 type: string
 *                 format: email
 *               phoneNumber:
 *                 type: string
 *               dateOfBirth:
 *                 type: string
 *                 format: date
 *               gender:
 *                 type: string
 *                 enum: [male, female, other, prefer not to say]
 *               profileImage:
 *                 type: string
 *     responses:
 *       200:
 *         description: Profile updated successfully
 *       400:
 *         description: Validation error
 *       401:
 *         description: Unauthorized
 *       409:
 *         description: Email or phone number already in use
 */
router.patch(
  '/me',
  auth(),
  validate(updateProfileRules),
  (req, res, next) => {
    authController.updateProfile(req.user.id, req.body, req.user.role === ROLES.ADMIN)
      .then(updatedUser => res.json(updatedUser))
      .catch(next);
  }
);

/**
 * @swagger
 * /api/v1/auth/change-password:
 *   post:
 *     summary: Change password
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
 *               - currentPassword
 *               - newPassword
 *             properties:
 *               currentPassword:
 *                 type: string
 *                 format: password
 *               newPassword:
 *                 type: string
 *                 format: password
 *     responses:
 *       204:
 *         description: Password changed successfully
 *       400:
 *         description: Validation error or new password same as current
 *       401:
 *         description: Current password is incorrect
 */
router.post(
  '/change-password',
  auth(),
  validate(changePasswordRules),
  (req, res, next) => {
    const { currentPassword, newPassword } = req.body;
    authController.changePassword(req.user.id, currentPassword, newPassword)
      .then(() => res.status(httpStatus.NO_CONTENT).json({ message: 'Password changed successfully' }))
      .catch(next);
  }
);

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

module.exports = router;
