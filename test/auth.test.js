const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const app = require('../src/app');
const { User } = require('../src/models');
const { ROLES } = require('../src/models/user.model');

let mongoServer;
let testUser = {
  firstName: 'Test',
  lastName: 'User',
  email: 'test@example.com',
  password: 'Test@1234',
  phoneNumber: '1234567890',
  role: ROLES.CUSTOMER,
};

// Set up test database before tests run
beforeAll(async () => {
  // Start an in-memory MongoDB server for testing
  mongoServer = await MongoMemoryServer.create();
  const mongoUri = mongoServer.getUri();
  
  // Connect to the in-memory database
  await mongoose.connect(mongoUri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });
  
  // Clear the test database
  await User.deleteMany({});
});

// Clean up after all tests are done
afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});

describe('Authentication API', () => {
  let authToken;
  let refreshToken;

  describe('POST /api/v1/auth/register', () => {
    it('should register a new user', async () => {
      const res = await request(app)
        .post('/api/v1/auth/register')
        .send(testUser)
        .expect(201);

      expect(res.body).toHaveProperty('user');
      expect(res.body.user).toHaveProperty('id');
      expect(res.body.user.email).toBe(testUser.email);
      expect(res.body.user.role).toBe(ROLES.CUSTOMER);
      expect(res.body.user).not.toHaveProperty('password');
    });

    it('should not register user with duplicate email', async () => {
      const res = await request(app)
        .post('/api/v1/auth/register')
        .send(testUser)
        .expect(400);

      expect(res.body.message).toContain('Email already taken');
    });
  });

  describe('POST /api/v1/auth/login', () => {
    it('should login with valid credentials', async () => {
      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: testUser.email,
          password: testUser.password,
        })
        .expect(200);

      expect(res.body).toHaveProperty('user');
      expect(res.body).toHaveProperty('token');
      expect(res.body.user.email).toBe(testUser.email);
      
      // Save the token for subsequent tests
      authToken = res.body.token;
      refreshToken = res.body.refreshToken;
    });

    it('should not login with invalid password', async () => {
      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: testUser.email,
          password: 'wrongpassword',
        })
        .expect(401);

      expect(res.body.message).toContain('Incorrect email or password');
    });
  });

  describe('GET /api/v1/auth/me', () => {
    it('should get current user profile with valid token', async () => {
      const res = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(res.body).toHaveProperty('id');
      expect(res.body.email).toBe(testUser.email);
    });

    it('should not get profile without token', async () => {
      const res = await request(app)
        .get('/api/v1/auth/me')
        .expect(401);

      expect(res.body.message).toContain('You are not logged in');
    });
  });

  describe('POST /api/v1/auth/refresh-token', () => {
    it('should refresh access token with valid refresh token', async () => {
      const res = await request(app)
        .post('/api/v1/auth/refresh-token')
        .send({ refreshToken })
        .expect(200);

      expect(res.body).toHaveProperty('token');
      expect(res.body).toHaveProperty('user');
      
      // Update the auth token
      authToken = res.body.token;
    });

    it('should not refresh token with invalid refresh token', async () => {
      const res = await request(app)
        .post('/api/v1/auth/refresh-token')
        .send({ refreshToken: 'invalid-token' })
        .expect(401);

      expect(res.body.message).toContain('Invalid or expired token');
    });
  });

  describe('POST /api/v1/auth/change-password', () => {
    it('should change password with valid current password', async () => {
      const newPassword = 'NewTest@1234';
      
      await request(app)
        .post('/api/v1/auth/change-password')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          currentPassword: testUser.password,
          newPassword,
        })
        .expect(204);
      
      // Update the test user's password for subsequent tests
      testUser.password = newPassword;
      
      // Verify login with new password works
      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: testUser.email,
          password: newPassword,
        })
        .expect(200);
      
      authToken = res.body.token;
    });
  });

  describe('POST /api/v1/auth/logout', () => {
    it('should logout user and invalidate token', async () => {
      await request(app)
        .post('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);
      
      // Attempt to use the invalidated token
      const res = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(401);
      
      expect(res.body.message).toContain('Invalid or expired token');
    });
  });

  describe('Account Lockout', () => {
    it('should lock account after multiple failed login attempts', async () => {
      const maxAttempts = 5;
      
      // Make multiple failed login attempts
      for (let i = 0; i < maxAttempts; i++) {
        await request(app)
          .post('/api/v1/auth/login')
          .send({
            email: testUser.email,
            password: 'wrongpassword',
          });
      }
      
      // Next attempt should be locked
      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: testUser.email,
          password: testUser.password,
        })
        .expect(429);
      
      expect(res.body.message).toContain('Too many login attempts');
      
      // Reset login attempts for other tests
      const user = await User.findOne({ email: testUser.email });
      await user.resetLoginAttempts();
    });
  });
});
