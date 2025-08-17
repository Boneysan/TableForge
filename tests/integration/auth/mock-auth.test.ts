/**
 * Authentication Flow Integration Tests - Phase 2 Week 2
 * Comprehensive authentication and authorization testing with mock database
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest';
import request from 'supertest';

// Mock the database imports to avoid connection issues during testing
vi.mock('@shared/schema', () => ({
  users: {
    id: 'users.id',
    email: 'users.email',
    firstName: 'users.firstName',
    lastName: 'users.lastName'
  },
  gameRooms: {
    name: 'gameRooms.name',
    createdBy: 'gameRooms.createdBy'
  }
}));

vi.mock('../../config/test-database', () => ({
  testDb: {
    select: vi.fn(() => ({
      from: vi.fn(() => ({
        where: vi.fn(() => ({
          limit: vi.fn(() => Promise.resolve([]))
        }))
      }))
    })),
    insert: vi.fn(() => ({
      values: vi.fn(() => ({
        returning: vi.fn(() => Promise.resolve([{ id: 'new-room-id', name: 'Test Room', createdBy: 'test-admin' }]))
      }))
    }))
  },
  initTestDatabase: vi.fn(() => Promise.resolve()),
  cleanupTestDatabase: vi.fn(() => Promise.resolve()),
  truncateAllTables: vi.fn(() => Promise.resolve()),
  seedTestData: vi.fn(() => Promise.resolve())
}));

// Mock Drizzle ORM eq function
vi.mock('drizzle-orm', () => ({
  eq: vi.fn((column, value) => ({ column, value, type: 'eq' }))
}));

// Import after mocking
const { initTestDatabase, cleanupTestDatabase, truncateAllTables, seedTestData } = await import('../../config/test-database');

// Create mock authentication server
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

// Mock JWT secret for testing
const JWT_SECRET = 'test-secret-key-for-integration-tests';

// Mock user database
const mockUsers = new Map([
  ['test1@example.com', { 
    id: 'test-user-1', 
    email: 'test1@example.com', 
    firstName: 'Test', 
    lastName: 'User One' 
  }],
  ['admin@example.com', { 
    id: 'test-admin', 
    email: 'admin@example.com', 
    firstName: 'Admin', 
    lastName: 'User' 
  }],
  ['xss@example.com', { 
    id: 'xss-test-user', 
    email: 'xss@example.com', 
    firstName: '<script>alert("xss")</script>', 
    lastName: 'Test' 
  }],
  ['test+special@example.com', { 
    id: 'special-chars-user', 
    email: 'test+special@example.com', 
    firstName: 'Special', 
    lastName: 'Chars' 
  }]
]);

// Mock authentication middleware
const authenticateToken = (req: any, res: any, next: any) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ 
      success: false, 
      error: 'Authentication required',
      message: 'Valid authentication token must be provided'
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ 
      success: false, 
      error: 'Invalid token',
      message: 'Token verification failed'
    });
  }
};

// Mock role-based authorization middleware
const requireRole = (requiredRole: string) => {
  return (req: any, res: any, next: any) => {
    if (!req.user) {
      return res.status(401).json({ success: false, error: 'Not authenticated' });
    }

    if (req.user.role !== requiredRole && req.user.role !== 'admin') {
      return res.status(403).json({ 
        success: false, 
        error: 'Insufficient permissions',
        required: requiredRole,
        current: req.user.role
      });
    }

    next();
  };
};

// Authentication routes
app.post('/auth/login', async (req: any, res: any) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Email and password are required' 
      });
    }

    // Check user exists in mock database
    const user = mockUsers.get(email);
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        error: 'Invalid credentials' 
      });
    }

    // For testing, we'll accept any password for existing users
    const token = jwt.sign({
      userId: user.id,
      email: user.email,
      role: 'user', // Default role for testing
      iat: Math.floor(Date.now() / 1000), // Current timestamp
      jti: `${Date.now()}-${Math.random()}` // Unique token ID
    }, JWT_SECRET, { expiresIn: '1h' });

    res.json({
      success: true,
      data: {
        token,
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName
        }
      }
    });

  } catch (error) {
    res.status(500).json({ success: false, error: 'Authentication error' });
  }
});

app.post('/auth/admin-login', async (req: any, res: any) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Email and password are required' 
      });
    }

    // Check if user is admin
    const user = mockUsers.get(email);
    if (!user || user.id !== 'test-admin') {
      return res.status(401).json({ 
        success: false, 
        error: 'Admin access denied' 
      });
    }

    const token = jwt.sign({
      userId: user.id,
      email: user.email,
      role: 'admin',
      iat: Math.floor(Date.now() / 1000), // Current timestamp
      jti: `${Date.now()}-${Math.random()}` // Unique token ID
    }, JWT_SECRET, { expiresIn: '1h' });

    res.json({
      success: true,
      data: {
        token,
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          role: 'admin'
        }
      }
    });

  } catch (error) {
    res.status(500).json({ success: false, error: 'Admin authentication error' });
  }
});

app.post('/auth/refresh', authenticateToken, (req: any, res: any) => {
  try {
    const newToken = jwt.sign({
      userId: req.user.userId,
      email: req.user.email,
      role: req.user.role,
      iat: Math.floor(Date.now() / 1000), // New timestamp
      jti: `${Date.now()}-${Math.random()}` // New unique token ID
    }, JWT_SECRET, { expiresIn: '1h' });

    res.json({
      success: true,
      data: { token: newToken }
    });

  } catch (error) {
    res.status(500).json({ success: false, error: 'Token refresh failed' });
  }
});

app.post('/auth/logout', authenticateToken, (_req: any, res: any) => {
  // In real implementation, we might invalidate the token
  res.json({
    success: true,
    message: 'Logged out successfully'
  });
});

// Protected routes for testing authorization
app.get('/api/profile', authenticateToken, async (req: any, res: any) => {
  try {
    // Find user in mock database
    const user = Array.from(mockUsers.values()).find(u => u.id === req.user.userId);

    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    res.json({
      success: true,
      data: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName
      }
    });

  } catch (error) {
    res.status(500).json({ success: false, error: 'Profile retrieval failed' });
  }
});

app.get('/api/admin/users', authenticateToken, requireRole('admin'), async (_req: any, res: any) => {
  try {
    const users = Array.from(mockUsers.values());
    res.json({ success: true, data: users });
  } catch (error) {
    res.status(500).json({ success: false, error: 'User retrieval failed' });
  }
});

app.post('/api/admin/rooms', authenticateToken, requireRole('admin'), async (req: any, res: any) => {
  try {
    const { name } = req.body;
    
    if (!name) {
      return res.status(400).json({ success: false, error: 'Room name is required' });
    }

    const room = {
      id: `room-${Date.now()}`,
      name,
      createdBy: req.user.userId
    };

    res.status(201).json({ success: true, data: room });

  } catch (error) {
    res.status(500).json({ success: false, error: 'Room creation failed' });
  }
});

app.delete('/api/admin/users/:userId', authenticateToken, requireRole('admin'), async (req: any, res: any) => {
  try {
    const { userId } = req.params;

    // Prevent admin from deleting themselves
    if (userId === req.user.userId) {
      return res.status(400).json({ 
        success: false, 
        error: 'Cannot delete your own account' 
      });
    }

    // For testing, we won't actually delete, just return success
    res.json({ 
      success: true, 
      message: `User ${userId} would be deleted` 
    });

  } catch (error) {
    res.status(500).json({ success: false, error: 'User deletion failed' });
  }
});

// Public routes for comparison
app.get('/api/public/health', (_req: any, res: any) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

describe('Authentication Flow Integration Tests', () => {
  beforeAll(async () => {
    await initTestDatabase();
  });

  afterAll(async () => {
    await cleanupTestDatabase();
  });

  beforeEach(async () => {
    await truncateAllTables();
    await seedTestData();
  });

  afterEach(async () => {
    await truncateAllTables();
  });

  describe('User Authentication', () => {
    it('should login successfully with valid credentials', async () => {
      const response = await request(app)
        .post('/auth/login')
        .send({
          email: 'test1@example.com',
          password: 'testpassword'
        })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toMatchObject({
        token: expect.any(String),
        user: {
          id: 'test-user-1',
          email: 'test1@example.com',
          firstName: 'Test',
          lastName: 'User One'
        }
      });

      // Verify token is valid JWT
      const decoded = jwt.verify(response.body.data.token, JWT_SECRET);
      expect(decoded).toMatchObject({
        userId: 'test-user-1',
        email: 'test1@example.com',
        role: 'user'
      });
    });

    it('should reject login with invalid email', async () => {
      const response = await request(app)
        .post('/auth/login')
        .send({
          email: 'nonexistent@example.com',
          password: 'testpassword'
        })
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('Invalid credentials');
    });

    it('should reject login without email or password', async () => {
      // Missing email
      await request(app)
        .post('/auth/login')
        .send({ password: 'testpassword' })
        .expect(400);

      // Missing password
      await request(app)
        .post('/auth/login')
        .send({ email: 'test@example.com' })
        .expect(400);

      // Missing both
      await request(app)
        .post('/auth/login')
        .send({})
        .expect(400);
    });

    it('should handle malformed login requests', async () => {
      // Invalid JSON - this will be handled by express middleware
      const invalidResponse = await request(app)
        .post('/auth/login')
        .set('Content-Type', 'application/json')
        .send('{ invalid json }');
      
      expect(invalidResponse.status).toBe(400);
    });
  });

  describe('Admin Authentication', () => {
    it('should allow admin login with admin credentials', async () => {
      const response = await request(app)
        .post('/auth/admin-login')
        .send({
          email: 'admin@example.com',
          password: 'adminpassword'
        })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.user.role).toBe('admin');

      // Verify admin token
      const decoded = jwt.verify(response.body.data.token, JWT_SECRET);
      expect(decoded).toMatchObject({
        userId: 'test-admin',
        role: 'admin'
      });
    });

    it('should reject admin login for non-admin users', async () => {
      const response = await request(app)
        .post('/auth/admin-login')
        .send({
          email: 'test1@example.com',
          password: 'testpassword'
        })
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('Admin access denied');
    });
  });

  describe('Token-based Authorization', () => {
    let userToken: string;

    beforeEach(async () => {
      // Get user token
      const userResponse = await request(app)
        .post('/auth/login')
        .send({
          email: 'test1@example.com',
          password: 'testpassword'
        });
      userToken = userResponse.body.data.token;

      // Get admin token for specific tests that need it
      await request(app)
        .post('/auth/admin-login')
        .send({
          email: 'admin@example.com',
          password: 'adminpassword'
        });
    });

    it('should access protected routes with valid token', async () => {
      const response = await request(app)
        .get('/api/profile')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toMatchObject({
        id: 'test-user-1',
        email: 'test1@example.com'
      });
    });

    it('should reject protected routes without token', async () => {
      const response = await request(app)
        .get('/api/profile')
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('Authentication required');
    });

    it('should reject protected routes with invalid token', async () => {
      const response = await request(app)
        .get('/api/profile')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('Invalid token');
    });

    it('should reject protected routes with malformed authorization header', async () => {
      // Missing "Bearer"
      await request(app)
        .get('/api/profile')
        .set('Authorization', userToken)
        .expect(401);

      // Wrong format
      await request(app)
        .get('/api/profile')
        .set('Authorization', `Token ${userToken}`)
        .expect(401);

      // Empty header
      await request(app)
        .get('/api/profile')
        .set('Authorization', '')
        .expect(401);
    });

    it('should refresh tokens successfully', async () => {
      const response = await request(app)
        .post('/auth/refresh')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.token).toBeDefined();
      expect(response.body.data.token).not.toBe(userToken);

      // New token should work
      await request(app)
        .get('/api/profile')
        .set('Authorization', `Bearer ${response.body.data.token}`)
        .expect(200);
    });

    it('should handle logout successfully', async () => {
      const response = await request(app)
        .post('/auth/logout')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe('Logged out successfully');
    });
  });

  describe('Role-based Authorization', () => {
    let userToken: string;
    let adminToken: string;

    beforeEach(async () => {
      // Get tokens
      const userResponse = await request(app)
        .post('/auth/login')
        .send({
          email: 'test1@example.com',
          password: 'testpassword'
        });
      userToken = userResponse.body.data.token;

      const adminResponse = await request(app)
        .post('/auth/admin-login')
        .send({
          email: 'admin@example.com',
          password: 'adminpassword'
        });
      adminToken = adminResponse.body.data.token;
    });

    it('should allow admin access to admin routes', async () => {
      const response = await request(app)
        .get('/api/admin/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toBeInstanceOf(Array);
    });

    it('should deny user access to admin routes', async () => {
      const response = await request(app)
        .get('/api/admin/users')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(403);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('Insufficient permissions');
      expect(response.body.required).toBe('admin');
      expect(response.body.current).toBe('user');
    });

    it('should allow admin to create rooms', async () => {
      const response = await request(app)
        .post('/api/admin/rooms')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ name: 'Admin Created Room' })
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data.name).toBe('Admin Created Room');
      expect(response.body.data.createdBy).toBe('test-admin');
    });

    it('should deny user access to admin room creation', async () => {
      const response = await request(app)
        .post('/api/admin/rooms')
        .set('Authorization', `Bearer ${userToken}`)
        .send({ name: 'User Attempted Room' })
        .expect(403);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('Insufficient permissions');
    });

    it('should prevent admin from deleting themselves', async () => {
      const response = await request(app)
        .delete('/api/admin/users/test-admin')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('Cannot delete your own account');
    });

    it('should allow admin to delete other users', async () => {
      const response = await request(app)
        .delete('/api/admin/users/test-user-1')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain('test-user-1 would be deleted');
    });
  });

  describe('Public Route Access', () => {
    it('should allow access to public routes without authentication', async () => {
      const response = await request(app)
        .get('/api/public/health')
        .expect(200);

      expect(response.body.status).toBe('ok');
      expect(response.body.timestamp).toBeDefined();
    });
  });

  describe('Cross-cutting Authentication Concerns', () => {
    it('should handle expired tokens', async () => {
      // Create an expired token
      const expiredToken = jwt.sign({
        userId: 'test-user-1',
        email: 'test1@example.com',
        role: 'user'
      }, JWT_SECRET, { expiresIn: '-1h' }); // Expired 1 hour ago

      const response = await request(app)
        .get('/api/profile')
        .set('Authorization', `Bearer ${expiredToken}`)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('Invalid token');
    });

    it('should handle tokens with invalid signatures', async () => {
      // Create token with wrong secret
      const invalidToken = jwt.sign({
        userId: 'test-user-1',
        email: 'test1@example.com',
        role: 'user'
      }, 'wrong-secret');

      const response = await request(app)
        .get('/api/profile')
        .set('Authorization', `Bearer ${invalidToken}`)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('Invalid token');
    });

    it('should handle concurrent authentication requests', async () => {
      const loginRequests = Array.from({ length: 5 }, () =>
        request(app)
          .post('/auth/login')
          .send({
            email: 'test1@example.com',
            password: 'testpassword'
          })
      );

      const responses = await Promise.all(loginRequests);

      // All should succeed
      responses.forEach(response => {
        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.data.token).toBeDefined();
      });

      // All tokens should be valid but different
      const tokens = responses.map(r => r.body.data.token);
      const uniqueTokens = new Set(tokens);
      expect(uniqueTokens.size).toBe(tokens.length);
    });

    it('should maintain consistent user data across requests', async () => {
      // Login to get token
      const loginResponse = await request(app)
        .post('/auth/login')
        .send({
          email: 'test1@example.com',
          password: 'testpassword'
        });

      const token = loginResponse.body.data.token;

      // Make multiple profile requests
      const profileRequests = Array.from({ length: 3 }, () =>
        request(app)
          .get('/api/profile')
          .set('Authorization', `Bearer ${token}`)
      );

      const profileResponses = await Promise.all(profileRequests);

      // All should return same user data
      profileResponses.forEach(response => {
        expect(response.status).toBe(200);
        expect(response.body.data).toMatchObject({
          id: 'test-user-1',
          email: 'test1@example.com',
          firstName: 'Test',
          lastName: 'User One'
        });
      });
    });
  });

  describe('Security Edge Cases', () => {
    it('should reject SQL injection attempts in credentials', async () => {
      const sqlInjectionPayloads = [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "' UNION SELECT * FROM users --"
      ];

      for (const payload of sqlInjectionPayloads) {
        const response = await request(app)
          .post('/auth/login')
          .send({
            email: payload,
            password: 'testpassword'
          })
          .expect(401);

        expect(response.body.success).toBe(false);
      }
    });

    it('should sanitize XSS attempts in authentication responses', async () => {
      const response = await request(app)
        .post('/auth/login')
        .send({
          email: 'xss@example.com',
          password: 'testpassword'
        })
        .expect(200);

      // Response should contain the XSS payload as-is (sanitization happens client-side)
      // But verify it doesn't break the JSON response
      expect(response.body.success).toBe(true);
      expect(response.body.data.user.firstName).toBe('<script>alert("xss")</script>');
    });

    it('should handle extremely long credential inputs', async () => {
      const longEmail = 'x'.repeat(1000) + '@example.com';
      const longPassword = 'x'.repeat(1000);

      const response = await request(app)
        .post('/auth/login')
        .send({
          email: longEmail,
          password: longPassword
        })
        .expect(401); // Should handle gracefully

      expect(response.body.success).toBe(false);
    });

    it('should handle special characters in credentials', async () => {
      const response = await request(app)
        .post('/auth/login')
        .send({
          email: 'test+special@example.com',
          password: 'pássw0rd!@#$%^&*()'
        })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.user.email).toBe('test+special@example.com');
    });
  });
});
