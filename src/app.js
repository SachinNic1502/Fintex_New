const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');
const httpStatus = require('http-status');
const logger = require('./config/logger');
const { errorConverter, errorHandler } = require('./middlewares/error');
const routes = require('./routes');

const app = express();

// Set security HTTP headers
app.use(helmet());

// Enable CORS
app.use(cors());
app.options('*', cors());

// Parse JSON request body
app.use(express.json());

// Parse URL-encoded request body
app.use(express.urlencoded({ extended: true }));

// Logging HTTP requests
if (process.env.NODE_ENV !== 'test') {
  app.use(morgan('combined', { stream: logger.stream }));
}
 
// API routes
app.use('/api', routes);

// Send 404 for any unknown API request
app.use((req, res, next) => {
  res.status(httpStatus.NOT_FOUND).json({
    success: false,
    message: 'Not found',
    error: {
      statusCode: 404,
      message: 'API not found',
    },
  });
});

// Convert error to ApiError, if needed
app.use(errorConverter);

// Handle error
app.use(errorHandler);

module.exports = app;
