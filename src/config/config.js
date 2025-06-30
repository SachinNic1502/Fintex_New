const dotenv = require('dotenv');

// Load environment variables from .env file
dotenv.config();

const env = process.env.NODE_ENV || 'development';

const baseConfig = {
  env,
  port: process.env.PORT || 3000,
  isProduction: env === 'production',
  isDevelopment: env === 'development',
  isTest: env === 'test',
  // JWT configuration
  jwt: {
    secret: process.env.JWT_SECRET || 'your_jwt_secret_key',
    refreshSecret: process.env.JWT_REFRESH_SECRET || 'your_refresh_secret_key',
    expiresIn: process.env.JWT_EXPIRES_IN || '30d',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '90d',
    cookieExpiresIn: process.env.JWT_COOKIE_EXPIRES_IN || 30,
  },
  // MongoDB configuration
  mongodb: {
    uri: process.env.MONGODB_URI || 'mongodb://localhost:27017/fintex',
    options: {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      useCreateIndex: true,
      useFindAndModify: false,
    },
  },
  // Email configuration
  email: {
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    username: process.env.EMAIL_USERNAME,
    password: process.env.EMAIL_PASSWORD,
    from: process.env.EMAIL_FROM || 'Fintex <noreply@fintex.com>',
  },
  // Frontend URL for email templates
  frontendUrl: process.env.FRONTEND_URL || 'http://localhost:3000',
  // Logging configuration
  logs: {
    level: process.env.LOG_LEVEL || 'info',
    directory: 'logs',
  },
};

// Environment specific configuration overrides
const envConfig = {
  development: {
    // Development specific configuration
  },
  test: {
    port: 3001,
    mongodb: {
      uri: process.env.MONGODB_URI_TEST || 'mongodb://localhost:27017/fintex-test',
    },
  },
  production: {
    // Production specific configuration
  },
};

// Merge base config with environment specific config
const config = {
  ...baseConfig,
  ...(envConfig[env] || {}),
};

module.exports = config;
