// Test Utilities - Helper functions for testing
import { Request, Response } from 'express';
import { vi } from 'vitest';

// Express mock utilities
export function createMockRequest(overrides: Partial<Request> = {}): Partial<Request> {
  return {
    headers: {},
    body: {},
    params: {},
    query: {},
    user: undefined,
    method: 'GET',
    url: '/',
    ...overrides
  };
}

export function createMockResponse(): Partial<Response> {
  const res: Partial<Response> = {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
    send: vi.fn().mockReturnThis(),
    setHeader: vi.fn().mockReturnThis(),
    cookie: vi.fn().mockReturnThis(),
    clearCookie: vi.fn().mockReturnThis()
  };
  return res;
}

// Database test utilities
export async function cleanupDatabase(): Promise<void> {
  // Implementation would clean test database
  // For now, this is a placeholder
  console.log('Cleaning up test database...');
}

export async function createTestUser(userData: any = {}) {
  // Mock user creation for tests
  return {
    uid: 'test-user-' + Date.now(),
    email: 'test@example.com',
    displayName: 'Test User',
    ...userData
  };
}

export async function createAuthToken(userId: string): Promise<string> {
  // Mock token creation for tests
  return `test-token-${userId}-${Date.now()}`;
}

// WebSocket test utilities
export class MockWebSocket {
  public readyState = 1; // OPEN
  public url: string;
  private listeners: { [event: string]: Function[] } = {};

  constructor(url: string) {
    this.url = url;
    // Simulate connection after next tick
    setTimeout(() => this.emit('open'), 0);
  }

  send(data: string): void {
    // Mock send - could emit to paired mock sockets
    console.log('MockWebSocket send:', data);
  }

  close(): void {
    this.readyState = 3; // CLOSED
    this.emit('close');
  }

  addEventListener(event: string, listener: Function): void {
    if (!this.listeners[event]) {
      this.listeners[event] = [];
    }
    this.listeners[event].push(listener);
  }

  removeEventListener(event: string, listener: Function): void {
    if (this.listeners[event]) {
      this.listeners[event] = this.listeners[event].filter(l => l !== listener);
    }
  }

  emit(event: string, data?: any): void {
    if (this.listeners[event]) {
      this.listeners[event].forEach(listener => listener(data));
    }
  }

  // Simulate receiving a message
  simulateMessage(data: any): void {
    this.emit('message', { data: JSON.stringify(data) });
  }
}

// Test server utilities
export async function createTestServer() {
  // Mock test server creation
  return {
    port: 3001,
    close: async () => {
      console.log('Test server closed');
    }
  };
}

// Async testing utilities
export function waitFor(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export async function waitForElement(selector: string, timeout = 5000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    const element = document.querySelector(selector);
    if (element) return;
    await waitFor(50);
  }
  throw new Error(`Element ${selector} not found within ${timeout}ms`);
}

// Component testing utilities
export function renderWithProviders(component: React.ReactElement, options: any = {}) {
  // Mock implementation for rendering components with providers
  // In real implementation, this would set up QueryClient, theme providers, etc.
  return {
    ...component,
    rerender: vi.fn(),
    unmount: vi.fn()
  };
}

// File upload testing utilities
export function createMockFile(name: string, type: string, content: string = 'test-content'): File {
  const blob = new Blob([content], { type });
  return new File([blob], name, { type });
}

export function createMockFileList(files: File[]): FileList {
  const fileList = {
    length: files.length,
    item: (index: number) => files[index] || null,
    [Symbol.iterator]: function* () {
      for (let i = 0; i < files.length; i++) {
        yield files[i];
      }
    }
  };
  
  // Add files as indexed properties
  files.forEach((file, index) => {
    (fileList as any)[index] = file;
  });
  
  return fileList as FileList;
}

// Performance testing utilities
export function measureExecutionTime<T>(fn: () => T): { result: T; time: number } {
  const start = performance.now();
  const result = fn();
  const time = performance.now() - start;
  return { result, time };
}

export async function measureAsyncExecutionTime<T>(fn: () => Promise<T>): Promise<{ result: T; time: number }> {
  const start = performance.now();
  const result = await fn();
  const time = performance.now() - start;
  return { result, time };
}

// Security testing utilities
export const commonXSSPayloads = [
  '<script>alert("xss")</script>',
  '"><script>alert("xss")</script>',
  'javascript:alert("xss")',
  '<img src=x onerror=alert("xss")>',
  '<svg onload=alert("xss")>',
  '"><svg/onload=alert("xss")>',
  '<iframe src=javascript:alert("xss")>'
];

export const commonSQLInjectionPayloads = [
  "'; DROP TABLE users; --",
  "' OR '1'='1",
  "' UNION SELECT * FROM users --",
  "'; DELETE FROM users WHERE '1'='1",
  "1' AND 1=1 UNION SELECT @@version --"
];

export function sanitizeTestInput(input: string): boolean {
  // Check if input has been properly sanitized
  const dangerousPatterns = [
    /<script/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /DROP\s+TABLE/i,
    /UNION\s+SELECT/i
  ];
  
  return !dangerousPatterns.some(pattern => pattern.test(input));
}
