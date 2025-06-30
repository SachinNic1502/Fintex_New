const rateLimit = require('express-rate-limit');
const logger = require('../config/logger');

// Rate limiting options for registration
const registerRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 register requests per windowMs
  message: 'Too many accounts created from this IP, please try again after 15 minutes',
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  handler: (req, res, next, options) => {
    logger.warn(`Rate limit exceeded for IP ${req.ip} on ${req.path}`);
    res.status(options.statusCode).json({
      success: false,
      message: options.message
    });
  }
});

// Rate limiting for login attempts
const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 login attempts per windowMs
  message: 'Too many login attempts from this IP, please try again after 15 minutes',
  skipSuccessfulRequests: true, // Only count failed login attempts
  handler: (req, res, next, options) => {
    logger.warn(`Login rate limit exceeded for IP ${req.ip}`);
    res.status(options.statusCode).json({
      success: false,
      message: options.message
    });
  }
});

// More aggressive rate limiter for password reset
const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Limit to 3 password reset requests per hour per IP
  message: 'Too many password reset attempts, please try again later',
  handler: (req, res, next, options) => {
    logger.warn(`Password reset rate limit exceeded for IP ${req.ip}`);
    res.status(options.statusCode).json({
      success: false,
      message: options.message
    });
  }
});

// Store IP and device info for security monitoring
const trackRequest = (req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  const userAgent = req.get('user-agent') || 'unknown';
  
  // Log or store this information for security monitoring
  logger.info(`Request from IP: ${ip}, User-Agent: ${userAgent}, Path: ${req.path}`);
  
  // Add to request object for use in other middlewares
  req.clientInfo = {
    ip,
    userAgent,
    timestamp: new Date()
  };
  
  next();
};

// Export the rate limiters and tracker
module.exports = {
  registerRateLimiter,
  loginRateLimiter,
  passwordResetLimiter,
  trackRequest,
  // Export rate limiter instance for potential reuse
  createRateLimiter: (options) => rateLimit({
    ...options,
    handler: (req, res, next, opts) => {
      logger.warn(`Rate limit exceeded for IP ${req.ip} on ${req.path}`);
      res.status(opts.statusCode).json({
        success: false,
        message: opts.message
      });
    }
  })
};
