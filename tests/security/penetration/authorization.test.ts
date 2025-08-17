// tests/security/penetration/authorization.test.ts
import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { app } from '@server/index';

describe('Authorization Security Tests', () => {
  describe('Role-Based Access Control', () => {
    it('should enforce proper RBAC for room management', async () => {
      const testCases = [
        {
          role: 'player',
          token: 'player-token',
          allowedEndpoints: ['/api/rooms/test-room'],
          forbiddenEndpoints: ['/api/rooms/test-room/admin', '/api/admin/users']
        },
        {
          role: 'gm',
          token: 'gm-token',
          allowedEndpoints: ['/api/rooms/test-room', '/api/rooms/test-room/admin'],
          forbiddenEndpoints: ['/api/admin/global-settings']
        }
      ];

      for (const testCase of testCases) {
        // Test forbidden endpoints
        for (const endpoint of testCase.forbiddenEndpoints) {
          await request(app)
            .get(endpoint)
            .set('Authorization', `Bearer ${testCase.token}`)
            .expect(res => {
              expect(res.status).toBeGreaterThanOrEqual(403);
            });
        }
      }
    });

    it('should prevent privilege escalation attempts', async () => {
      const escalationAttempts = [
        { userId: 'admin-user-id', role: 'admin' },
        { headers: { 'X-User-Role': 'admin', 'X-Is-Admin': 'true' } },
        { body: { role: 'admin', permissions: ['all'] } }
      ];

      for (const attempt of escalationAttempts) {
        await request(app)
          .post('/api/users/role')
          .set('Authorization', 'Bearer player-token')
          .set(attempt.headers || {})
          .send(attempt.body || attempt)
          .expect(res => {
            expect(res.status).toBeGreaterThanOrEqual(403);
          });
      }
    });
  });

  describe('Cross-User Access Prevention', () => {
    it('should prevent accessing other users data', async () => {
      const userDataEndpoints = [
        '/api/users/other-user-id/profile',
        '/api/users/other-user-id/rooms',
        '/api/users/other-user-id/assets'
      ];

      for (const endpoint of userDataEndpoints) {
        await request(app)
          .get(endpoint)
          .set('Authorization', 'Bearer user-token')
          .expect(res => {
            expect(res.status).toBeGreaterThanOrEqual(403);
          });
      }
    });

    it('should prevent modifying other users rooms', async () => {
      const modificationAttempts = [
        { method: 'PUT', endpoint: '/api/rooms/other-user-room' },
        { method: 'DELETE', endpoint: '/api/rooms/other-user-room' },
        { method: 'POST', endpoint: '/api/rooms/other-user-room/assets' }
      ];

      for (const attempt of modificationAttempts) {
        const requestMethod = attempt.method.toLowerCase() as 'put' | 'delete' | 'post';
        
        await request(app)[requestMethod](attempt.endpoint)
          .set('Authorization', 'Bearer unauthorized-user-token')
          .send({ test: 'data' })
          .expect(res => {
            expect(res.status).toBeGreaterThanOrEqual(403);
          });
      }
    });
  });
});
