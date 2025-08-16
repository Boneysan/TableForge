// tests/utils/express-mocks.ts
import type { Request, Response } from 'express';
import { vi } from 'vitest';

/**
 * Creates a mock Express Request object for testing
 */
export function createMockRequest(overrides: Partial<Request> = {}): Partial<Request> {
  return {
    headers: {},
    params: {},
    query: {},
    body: {},
    method: 'GET',
    path: '/test',
    url: '/test',
    originalUrl: '/test',
    ...overrides,
  };
}

/**
 * Creates a mock Express Response object for testing
 */
export function createMockResponse(): Partial<Response> {
  const res: Partial<Response> = {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
    send: vi.fn().mockReturnThis(),
    cookie: vi.fn().mockReturnThis(),
    clearCookie: vi.fn().mockReturnThis(),
    redirect: vi.fn().mockReturnThis(),
    setHeader: vi.fn().mockReturnThis(),
    getHeader: vi.fn(),
    locals: {},
  };

  return res;
}

/**
 * Creates a mock authenticated request with user data
 */
export function createMockAuthenticatedRequest(user: any, overrides: Partial<Request> = {}): Partial<Request> {
  return createMockRequest({
    user,
    headers: {
      authorization: 'Bearer valid-token',
    },
    ...overrides,
  });
}

/**
 * Creates a mock request with room claims
 */
export function createMockRoomRequest(user: any, roomClaims: any, overrides: Partial<Request> = {}): Partial<Request> {
  return createMockRequest({
    user,
    roomClaims,
    headers: {
      authorization: 'Bearer valid-token',
    },
    ...overrides,
  });
}
