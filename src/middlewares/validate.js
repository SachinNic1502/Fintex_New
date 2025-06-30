const httpStatus = require('http-status');
const { validationResult } = require('express-validator');
const ApiError = require('../utils/ApiError');

/**
 * Middleware factory that validates the request against validation rules
 * @param {Array} validations - Array of validation chains
 * @returns {Function} Express middleware function
 */
const validate = (validations) => {
  return async (req, res, next) => {
    // Run all validations
    await Promise.all(validations.map(validation => validation.run(req)));

    const errors = validationResult(req);
    if (errors.isEmpty()) {
      return next();
    }
    
    const extractedErrors = [];
    errors.array().forEach(err => {
      extractedErrors.push({ [err.param]: err.msg });
    });
    
    next(new ApiError(httpStatus.BAD_REQUEST, 'Validation failed', extractedErrors));
  };
};

module.exports = {
  validate,
};
