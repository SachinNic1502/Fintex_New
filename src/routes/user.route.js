const httpStatus = require('http-status');
const express = require('express');
const { body, param } = require('express-validator');
const auth = require('../middlewares/auth');
const validate = require('../middlewares/validate').validate;
const userController = require('../controllers/user.controller');
const { ROLES } = require('../models/user.model');
const ApiError = require('../utils/ApiError');

const router = express.Router();

// Middleware to ensure only admins can access these routes
const requireAdmin = (req, res, next) => {
  if (req.user.role !== ROLES.ADMIN) {
    return next(new ApiError(httpStatus.FORBIDDEN, 'Admin access required'));
  }
  next();
};

/**
 * @swagger
 * /api/v1/users/approve/{userId}:
 *   post:
 *     summary: Approve a user account (Admin only)
 *     description: Approve a seller or distributor account
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: string
 *         description: User ID to approve
 *     responses:
 *       200:
 *         description: User approved successfully
 *       400:
 *         description: Invalid user role or already approved
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden (admin access required)
 *       404:
 *         description: User not found
 */
router.post(
  '/approve/:userId',
  [
    auth(),
    requireAdmin,
    validate([
      param('userId').isMongoId().withMessage('Invalid user ID')
    ])
  ],
  async (req, res, next) => {
    try {
      const user = await userController.approveUser(req.params.userId, req.user.id);
      res.status(httpStatus.OK).json({
        success: true,
        message: 'User approved successfully',
        data: user
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/v1/users/pending-approvals:
 *   get:
 *     summary: Get all pending approvals (Admin only)
 *     description: Get a list of all users pending approval
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of users pending approval
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden (admin access required)
 */
router.get(
  '/pending-approvals',
  [auth(), requireAdmin],
  async (req, res, next) => {
    try {
      const pendingUsers = await userController.getPendingApprovals();
      res.status(httpStatus.OK).json({
        success: true,
        count: pendingUsers.length,
        data: pendingUsers
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/v1/users/{userId}:
 *   get:
 *     summary: Get user by ID (Admin only)
 *     description: Get user details by user ID
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: string
 *         description: User ID
 *     responses:
 *       200:
 *         description: User details
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden (admin access required)
 *       404:
 *         description: User not found
 */
router.get(
  '/:userId',
  [
    auth(),
    (req, res, next) => {
      if (req.user.role !== ROLES.ADMIN) {
        return next(new ApiError(httpStatus.FORBIDDEN, 'Admin access required'));
      }
      next();
    },
    validate([
      param('userId').isMongoId().withMessage('Invalid user ID')
    ])
  ],
  async (req, res, next) => {
    try {
      const user = await userController.getUserById(req.params.userId);
      res.status(httpStatus.OK).json({
        success: true,
        data: user
      });
    } catch (error) {
      next(error);
    }
  }
);

module.exports = router;
