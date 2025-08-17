/**
 * XSS Prevention Security Tests - Phase 2 Week 4
 * Testing Cross-Site Scripting attack prevention
 */

import request from 'supertest';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';

describe('XSS Prevention Security Tests', () => {
  const baseUrl = process.env.TEST_BASE_URL || 'http://localhost:5000';
  
  describe('Input Sanitization', () => {
    const xssPayloads = [
      '<script>alert("xss")</script>',
      '"><script>alert("xss")</script>',
      "'><script>alert('xss')</script>",
      'javascript:alert("xss")',
      '<img src=x onerror=alert("xss")>',
      '<svg onload=alert("xss")>',
      '<iframe src="javascript:alert(\'xss\')"></iframe>',
      '<body onload=alert("xss")>',
      '<div onclick=alert("xss")>Click me</div>',
      '<input onfocus=alert("xss") autofocus>',
      '<details open ontoggle=alert("xss")>',
      '<marquee onstart=alert("xss")>',
      '<style>@import"javascript:alert(\\"xss\\")";</style>',
      '<link rel="stylesheet" href="javascript:alert(\\"xss\\")">',
      '<meta http-equiv="refresh" content="0;url=javascript:alert(\\"xss\\")">',
      '<object data="javascript:alert(\\"xss\\")"></object>',
      '<embed src="javascript:alert(\\"xss\\")">',
      '<form><button formaction="javascript:alert(\\"xss\\")">XSS</button></form>',
      '<video><source onerror="alert(\\"xss\\")">',
      '<audio src=x onerror=alert("xss")>',
      // Template injection attempts
      '{{7*7}}',
      '${7*7}',
      '#{7*7}',
      '<%= 7*7 %>',
      '{{constructor.constructor("alert(\\"xss\\")")()}}',
      // Unicode and encoding bypasses
      '\\u003cscript\\u003ealert(\\u0022xss\\u0022)\\u003c/script\\u003e',
      '%3Cscript%3Ealert%28%22xss%22%29%3C%2Fscript%3E',
      '&lt;script&gt;alert(&#34;xss&#34;)&lt;/script&gt;',
      // Data URI XSS
      'data:text/html,<script>alert("xss")</script>',
      'data:text/html;base64,PHNjcmlwdD5hbGVydCgieHNzIik8L3NjcmlwdD4=',
      // CSS XSS
      'expression(alert("xss"))',
      'behavior:url(javascript:alert("xss"))',
      // Double encoding
      '%253Cscript%253Ealert%2528%2522xss%2522%2529%253C%252Fscript%253E'
    ];

    it.each(xssPayloads)('should sanitize XSS payload in room name: %s', async (payload: string) => {
      const response = await request(baseUrl)
        .post('/api/rooms')
        .set('Authorization', 'Bearer test-token')
        .send({ name: payload })
        .timeout(5000);

      if (response.status === 201) {
        // If room creation succeeded, verify the content was sanitized
        expect(response.body.data.name).not.toContain('<script>');
        expect(response.body.data.name).not.toContain('javascript:');
        expect(response.body.data.name).not.toContain('onerror');
        expect(response.body.data.name).not.toContain('onload');
        expect(response.body.data.name).not.toContain('alert(');
        
        // Should not contain raw HTML tags
        expect(response.body.data.name).not.toMatch(/<[^>]*>/);
      } else {
        // If rejected, that's also acceptable for security
        expect([400, 422]).toContain(response.status);
      }
    });

    it.each(xssPayloads)('should sanitize XSS payload in chat messages: %s', async (payload: string) => {
      const response = await request(baseUrl)
        .post('/api/rooms/test-room/chat')
        .set('Authorization', 'Bearer test-token')
        .send({ message: payload })
        .timeout(5000);

      if (response.status === 201) {
        expect(response.body.data.message).not.toContain('<script>');
        expect(response.body.data.message).not.toContain('javascript:');
        expect(response.body.data.message).not.toContain('onerror');
        expect(response.body.data.message).not.toMatch(/<[^>]*>/);
      } else {
        expect([400, 422]).toContain(response.status);
      }
    });

    it.each(xssPayloads)('should sanitize XSS payload in user profile: %s', async (payload: string) => {
      const response = await request(baseUrl)
        .patch('/api/user/profile')
        .set('Authorization', 'Bearer test-token')
        .send({ displayName: payload })
        .timeout(5000);

      if (response.status === 200) {
        expect(response.body.data.displayName).not.toContain('<script>');
        expect(response.body.data.displayName).not.toContain('javascript:');
        expect(response.body.data.displayName).not.toMatch(/<[^>]*>/);
      } else {
        expect([400, 422]).toContain(response.status);
      }
    });
  });

  describe('Content Security Policy', () => {
    it('should include proper CSP headers', async () => {
      const response = await request(baseUrl)
        .get('/')
        .expect(200);

      expect(response.headers['content-security-policy']).toBeDefined();
      
      const csp = response.headers['content-security-policy'];
      expect(csp).toContain("default-src 'self'");
      expect(csp).toContain("script-src 'self'");
      expect(csp).toContain("style-src 'self'");
      expect(csp).toContain("img-src 'self'");
      expect(csp).toContain("object-src 'none'");
    });

    it('should prevent inline script execution', async () => {
      const response = await request(baseUrl)
        .get('/')
        .expect(200);

      const csp = response.headers['content-security-policy'];
      expect(csp).not.toContain("'unsafe-inline'");
      expect(csp).not.toContain("'unsafe-eval'");
    });
  });

  describe('HTTP Security Headers', () => {
    it('should include X-XSS-Protection header', async () => {
      const response = await request(baseUrl)
        .get('/api/health')
        .expect(200);

      expect(response.headers['x-xss-protection']).toBe('1; mode=block');
    });

    it('should include X-Content-Type-Options header', async () => {
      const response = await request(baseUrl)
        .get('/api/health')
        .expect(200);

      expect(response.headers['x-content-type-options']).toBe('nosniff');
    });

    it('should include X-Frame-Options header', async () => {
      const response = await request(baseUrl)
        .get('/api/health')
        .expect(200);

      expect(response.headers['x-frame-options']).toBe('DENY');
    });

    it('should include Referrer-Policy header', async () => {
      const response = await request(baseUrl)
        .get('/api/health')
        .expect(200);

      expect(response.headers['referrer-policy']).toBe('strict-origin-when-cross-origin');
    });
  });

  describe('URL Parameter XSS', () => {
    const urlXSSPayloads = [
      'javascript:alert("xss")',
      'data:text/html,<script>alert("xss")</script>',
      'vbscript:msgbox("xss")',
      'file:///etc/passwd',
      '../../../etc/passwd',
      '..\\..\\..\\windows\\system32\\config\\sam'
    ];

    it.each(urlXSSPayloads)('should prevent XSS in URL parameters: %s', async (payload: string) => {
      const response = await request(baseUrl)
        .get(`/api/rooms/search?name=${encodeURIComponent(payload)}`)
        .set('Authorization', 'Bearer test-token')
        .timeout(5000);

      expect(response.status).not.toBe(500);
      
      if (response.body.data) {
        expect(JSON.stringify(response.body)).not.toContain('<script>');
        expect(JSON.stringify(response.body)).not.toContain('javascript:');
      }
    });
  });

  describe('DOM-based XSS Prevention', () => {
    it('should properly escape JSON responses', async () => {
      const maliciousInput = '</script><script>alert("xss")</script>';
      
      const response = await request(baseUrl)
        .post('/api/rooms')
        .set('Authorization', 'Bearer test-token')
        .send({ name: maliciousInput })
        .timeout(5000);

      if (response.status === 201) {
        const responseString = JSON.stringify(response.body);
        expect(responseString).not.toContain('</script>');
        expect(responseString).not.toContain('<script>');
      }
    });

    it('should prevent template injection', async () => {
      const templatePayloads = [
        '{{constructor.constructor("alert(\\"xss\\")")()}}',
        '${alert("xss")}',
        '#{alert("xss")}',
        '<%= alert("xss") %>',
        '{{7*7}}',
        '${7*7}',
        '#{7*7}'
      ];

      for (const payload of templatePayloads) {
        const response = await request(baseUrl)
          .post('/api/rooms')
          .set('Authorization', 'Bearer test-token')
          .send({ description: payload })
          .timeout(5000);

        if (response.status === 201) {
          expect(response.body.data.description).not.toBe('49');
          expect(response.body.data.description).not.toContain('alert(');
        }
      }
    });
  });

  describe('File Upload XSS Prevention', () => {
    it('should prevent XSS in file names', async () => {
      const maliciousFileName = '<script>alert("xss")</script>.png';
      const fileContent = Buffer.from('fake image content');

      const response = await request(baseUrl)
        .post('/api/rooms/test-room/assets')
        .set('Authorization', 'Bearer test-token')
        .attach('file', fileContent, maliciousFileName)
        .timeout(10000);

      if (response.status === 201) {
        expect(response.body.data.name).not.toContain('<script>');
        expect(response.body.data.name).not.toContain('alert(');
      } else {
        expect([400, 422]).toContain(response.status);
      }
    });

    it('should sanitize file metadata', async () => {
      const maliciousMetadata = {
        alt: '<script>alert("xss")</script>',
        description: '<img src=x onerror=alert("xss")>',
        tags: ['<script>alert("xss")</script>', 'normal-tag']
      };

      const response = await request(baseUrl)
        .post('/api/rooms/test-room/assets')
        .set('Authorization', 'Bearer test-token')
        .field('metadata', JSON.stringify(maliciousMetadata))
        .attach('file', Buffer.from('fake content'), 'test.png')
        .timeout(10000);

      if (response.status === 201) {
        const metadata = response.body.data.metadata;
        expect(metadata.alt).not.toContain('<script>');
        expect(metadata.description).not.toContain('onerror');
        expect(metadata.tags.join('')).not.toContain('<script>');
      }
    });
  });

  describe('Advanced XSS Scenarios', () => {
    it('should prevent mutation XSS', async () => {
      // Test for mXSS vulnerabilities
      const mutationPayloads = [
        '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
        '<listing>&lt;img src=x onerror=alert(1)&gt;</listing>',
        '<style><![CDATA[</style ><script>alert(1)</script>]]></style>',
        '<math><mtext><option><FAKEFONT><option></option><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=x>"></FAKEFONT></option></mtext></math>'
      ];

      for (const payload of mutationPayloads) {
        const response = await request(baseUrl)
          .post('/api/rooms')
          .set('Authorization', 'Bearer test-token')
          .send({ name: payload })
          .timeout(5000);

        if (response.status === 201) {
          expect(response.body.data.name).not.toContain('onerror');
          expect(response.body.data.name).not.toContain('alert(');
          expect(response.body.data.name).not.toContain('<script>');
        }
      }
    });

    it('should prevent filter bypass attempts', async () => {
      const bypassPayloads = [
        'jaVaScRiPt:alert("xss")',
        'JaVaScRiPt:alert("xss")',
        '&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#34;&#120;&#115;&#115;&#34;&#41;',
        'javascript&#58;alert("xss")',
        'javascript&#x3A;alert("xss")',
        'j\\u0061vascript:alert("xss")',
        'javascript\\x3Aalert("xss")'
      ];

      for (const payload of bypassPayloads) {
        const response = await request(baseUrl)
          .post('/api/rooms')
          .set('Authorization', 'Bearer test-token')
          .send({ name: payload })
          .timeout(5000);

        if (response.status === 201) {
          expect(response.body.data.name.toLowerCase()).not.toContain('javascript:');
          expect(response.body.data.name).not.toContain('alert(');
        }
      }
    });
  });

  describe('Response Header Injection', () => {
    it('should prevent CRLF injection in custom headers', async () => {
      const crlfPayloads = [
        'test\r\nSet-Cookie: admin=true',
        'test\nLocation: http://evil.com',
        'test\r\n\r\n<script>alert("xss")</script>',
        'test%0D%0ASet-Cookie:%20admin=true',
        'test%0A%0D<script>alert("xss")</script>'
      ];

      for (const payload of crlfPayloads) {
        const response = await request(baseUrl)
          .get('/api/rooms')
          .set('Authorization', 'Bearer test-token')
          .set('X-Custom-Header', payload)
          .timeout(5000);

        expect(response.status).not.toBe(500);
        expect(response.headers['set-cookie']).not.toContain('admin=true');
        expect(response.headers['location']).not.toContain('evil.com');
      }
    });
  });
});
