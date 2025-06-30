const express = require('express');
const logger = require('../config/logger');

const router = express.Router();

/**
 * GET /api/health
 * Health check endpoint
 */
router.get('/health', (req, res) => {
  logger.info('Health check called');
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

// Import route files
const authRoutes = require('./auth.route');
const userRoutes = require('./user.route');

// API v1 routes
const v1Router = express.Router();

// Mount v1 routes
v1Router.use('/auth', authRoutes);
v1Router.use('/users', userRoutes);

// Mount v1 router under /v1
router.use('/v1', v1Router);

// Handle 404 for API routes
router.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'API endpoint not found',
  });
});

module.exports = router;
