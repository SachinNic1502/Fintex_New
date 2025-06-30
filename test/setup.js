// Configure environment variables for testing
process.env.NODE_ENV = 'test';
process.env.PORT = 3000;
process.env.MONGODB_URI = 'mongodb://localhost:27017/fintex-test';
process.env.JWT_SECRET = 'test-secret-key';
process.env.JWT_EXPIRES_IN = '1h';
process.env.EMAIL_HOST = 'smtp.test.com';
process.env.EMAIL_PORT = 587;
process.env.EMAIL_USERNAME = 'test@example.com';
process.env.EMAIL_PASSWORD = 'test-password';
process.env.EMAIL_FROM = 'noreply@fintex.test';
process.env.FRONTEND_URL = 'http://localhost:3000';

// Set up global test timeout
jest.setTimeout(30000);

// Global test hooks
beforeEach(async () => {
  // Clear all mocks before each test
  jest.clearAllMocks();
});

afterAll(async () => {
  // Close any open connections or clean up resources
  const { mongoose } = require('mongoose');
  await mongoose.connection.close();
});

// Mock logger to avoid cluttering test output
jest.mock('../src/config/logger', () => ({
  error: jest.fn(),
  warn: jest.fn(),
  info: jest.fn(),
  http: jest.fn(),
  debug: jest.fn(),
}));
