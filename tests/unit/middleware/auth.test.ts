// Unit Tests for Server Middleware
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createMockRequest, createMockResponse } from '@tests/utils';
import type { Request, Response, NextFunction } from 'express';
import { authenticateToken } from '../../../server/auth/middleware';
import { validateFirebaseToken, extractTokenFromRequest, validateTokenFreshness } from '../../../server/auth/tokenValidator';

// Mock the tokenValidator module
vi.mock('../../../server/auth/tokenValidator', () => ({
  validateFirebaseToken: vi.fn(),
  extractTokenFromRequest: vi.fn(),
  validateTokenFreshness: vi.fn(),
}));

// Mock the roomAuth module
vi.mock('../../../server/auth/roomAuth', () => ({
  roomAuthManager: {
    validateRoomMembership: vi.fn(),
  },
}));

const mockValidateFirebaseToken = vi.mocked(validateFirebaseToken);
const mockExtractTokenFromRequest = vi.mocked(extractTokenFromRequest);
const mockValidateTokenFreshness = vi.mocked(validateTokenFreshness);

describe('Authentication Middleware', () => {
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let nextFunction: NextFunction;

  beforeEach(() => {
    mockRequest = createMockRequest();
    mockResponse = createMockResponse();
    nextFunction = vi.fn();
    vi.clearAllMocks();
  });

  describe('authenticateToken', () => {
    it('should authenticate valid token and attach user to request', async () => {
      const mockUser = {
        uid: 'test-uid',
        email: 'test@example.com',
        displayName: 'Test User',
        photoURL: null,
        emailVerified: true,
        source: 'firebase' as const,
        issuedAt: Date.now(),
        expiresAt: Date.now() + 3600000
      };

      mockExtractTokenFromRequest.mockReturnValue('valid-token');
      mockValidateFirebaseToken.mockResolvedValue(mockUser);
      mockValidateTokenFreshness.mockReturnValue(true);

      await authenticateToken(mockRequest as Request, mockResponse as Response, nextFunction);

      expect(mockExtractTokenFromRequest).toHaveBeenCalledWith(mockRequest);
      expect(mockValidateFirebaseToken).toHaveBeenCalledWith('valid-token');
      expect(mockValidateTokenFreshness).toHaveBeenCalledWith(mockUser);
      expect(mockRequest.user).toEqual(mockUser);
      expect(nextFunction).toHaveBeenCalledWith();
      expect(mockResponse.status).not.toHaveBeenCalled();
    });

    it('should reject request when token extraction fails', async () => {
      mockExtractTokenFromRequest.mockReturnValue(null);

      await authenticateToken(mockRequest as Request, mockResponse as Response, nextFunction);

      expect(mockExtractTokenFromRequest).toHaveBeenCalledWith(mockRequest);
      expect(mockValidateFirebaseToken).not.toHaveBeenCalled();
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Authentication required',
        message: 'Valid authentication token must be provided'
      });
      expect(nextFunction).not.toHaveBeenCalled();
    });

    it('should handle invalid token validation', async () => {
      mockExtractTokenFromRequest.mockReturnValue('invalid-token');
      mockValidateFirebaseToken.mockRejectedValue(new Error('Invalid token'));

      await authenticateToken(mockRequest as Request, mockResponse as Response, nextFunction);

      expect(mockExtractTokenFromRequest).toHaveBeenCalledWith(mockRequest);
      expect(mockValidateFirebaseToken).toHaveBeenCalledWith('invalid-token');
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Authentication failed',
        message: 'Invalid token'
      });
      expect(nextFunction).not.toHaveBeenCalled();
    });

    it('should handle expired token', async () => {
      const mockUser = {
        uid: 'test-uid',
        email: 'test@example.com',
        displayName: 'Test User',
        photoURL: null,
        emailVerified: true,
        source: 'firebase' as const,
        issuedAt: Date.now() - 7200000, // 2 hours ago
        expiresAt: Date.now() - 3600000  // 1 hour ago (expired)
      };

      mockExtractTokenFromRequest.mockReturnValue('expired-token');
      mockValidateFirebaseToken.mockResolvedValue(mockUser);
      mockValidateTokenFreshness.mockReturnValue(false);

      await authenticateToken(mockRequest as Request, mockResponse as Response, nextFunction);

      expect(mockExtractTokenFromRequest).toHaveBeenCalledWith(mockRequest);
      expect(mockValidateFirebaseToken).toHaveBeenCalledWith('expired-token');
      expect(mockValidateTokenFreshness).toHaveBeenCalledWith(mockUser);
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Token expired',
        message: 'Authentication token has expired, please sign in again'
      });
      expect(nextFunction).not.toHaveBeenCalled();
    });

    it('should handle server errors during token validation', async () => {
      mockExtractTokenFromRequest.mockReturnValue('valid-token');
      mockValidateFirebaseToken.mockRejectedValue(new Error('Server error'));

      await authenticateToken(mockRequest as Request, mockResponse as Response, nextFunction);

      expect(mockExtractTokenFromRequest).toHaveBeenCalledWith(mockRequest);
      expect(mockValidateFirebaseToken).toHaveBeenCalledWith('valid-token');
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Authentication failed',
        message: 'Server error'
      });
      expect(nextFunction).not.toHaveBeenCalled();
    });

    it('should handle non-Error exceptions', async () => {
      mockExtractTokenFromRequest.mockReturnValue('valid-token');
      mockValidateFirebaseToken.mockRejectedValue('String error');

      await authenticateToken(mockRequest as Request, mockResponse as Response, nextFunction);

      expect(mockExtractTokenFromRequest).toHaveBeenCalledWith(mockRequest);
      expect(mockValidateFirebaseToken).toHaveBeenCalledWith('valid-token');
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Authentication failed',
        message: 'Invalid authentication token'
      });
      expect(nextFunction).not.toHaveBeenCalled();
    });
  });
});

// Rate limiting middleware tests
describe('Rate Limiting Middleware', () => {
  function createRateLimiter(maxRequests: number, windowMs: number) {
    const requests = new Map<string, number[]>();
    
    return (req: Request, res: Response, next: NextFunction) => {
      const clientId = req.ip || 'unknown';
      const now = Date.now();
      const windowStart = now - windowMs;
      
      if (!requests.has(clientId)) {
        requests.set(clientId, []);
      }
      
      const clientRequests = requests.get(clientId)!;
      // Remove old requests outside the window
      const validRequests = clientRequests.filter(time => time > windowStart);
      
      if (validRequests.length >= maxRequests) {
        res.status(429).json({
          error: 'Too many requests',
          message: `Rate limit exceeded. Try again in ${windowMs / 1000} seconds.`
        });
        return;
      }
      
      validRequests.push(now);
      requests.set(clientId, validRequests);
      next();
    };
  }

  it('should allow requests within rate limit', () => {
    const rateLimiter = createRateLimiter(5, 60000); // 5 requests per minute
    const mockReq = createMockRequest({ ip: '127.0.0.1' });
    const mockRes = createMockResponse();
    const next = vi.fn();

    rateLimiter(mockReq as Request, mockRes as Response, next);

    expect(next).toHaveBeenCalled();
    expect(mockRes.status).not.toHaveBeenCalled();
  });

  it('should block requests exceeding rate limit', () => {
    const rateLimiter = createRateLimiter(2, 60000); // 2 requests per minute
    const mockReq = createMockRequest({ ip: '127.0.0.1' });
    const mockRes = createMockResponse();
    const next = vi.fn();

    // First two requests should pass
    rateLimiter(mockReq as Request, mockRes as Response, next);
    rateLimiter(mockReq as Request, mockRes as Response, next);
    
    // Third request should be blocked
    rateLimiter(mockReq as Request, mockRes as Response, next);

    expect(next).toHaveBeenCalledTimes(2);
    expect(mockRes.status).toHaveBeenCalledWith(429);
    expect(mockRes.json).toHaveBeenCalledWith({
      error: 'Too many requests',
      message: 'Rate limit exceeded. Try again in 60 seconds.'
    });
  });
});

// Error handling middleware tests
describe('Error Handling Middleware', () => {
  function errorHandler(
    error: Error,
    _req: Request,
    res: Response,
    _next: NextFunction
  ): void {
    console.error('Error:', error);

    if (error.name === 'ValidationError') {
      res.status(400).json({
        error: 'Validation failed',
        message: error.message
      });
      return;
    }

    if (error.name === 'UnauthorizedError') {
      res.status(401).json({
        error: 'Unauthorized',
        message: 'Access denied'
      });
      return;
    }

    // Default error response
    res.status(500).json({
      error: 'Internal server error',
      message: 'An unexpected error occurred'
    });
  }

  it('should handle validation errors', () => {
    const validationError = new Error('Invalid input data');
    validationError.name = 'ValidationError';
    
    const mockReq = createMockRequest();
    const mockRes = createMockResponse();
    const next = vi.fn();

    errorHandler(validationError, mockReq as Request, mockRes as Response, next);

    expect(mockRes.status).toHaveBeenCalledWith(400);
    expect(mockRes.json).toHaveBeenCalledWith({
      error: 'Validation failed',
      message: 'Invalid input data'
    });
  });

  it('should handle unauthorized errors', () => {
    const unauthorizedError = new Error('Access denied');
    unauthorizedError.name = 'UnauthorizedError';
    
    const mockReq = createMockRequest();
    const mockRes = createMockResponse();
    const next = vi.fn();

    errorHandler(unauthorizedError, mockReq as Request, mockRes as Response, next);

    expect(mockRes.status).toHaveBeenCalledWith(401);
    expect(mockRes.json).toHaveBeenCalledWith({
      error: 'Unauthorized',
      message: 'Access denied'
    });
  });

  it('should handle generic errors', () => {
    const genericError = new Error('Something went wrong');
    
    const mockReq = createMockRequest();
    const mockRes = createMockResponse();
    const next = vi.fn();

    errorHandler(genericError, mockReq as Request, mockRes as Response, next);

    expect(mockRes.status).toHaveBeenCalledWith(500);
    expect(mockRes.json).toHaveBeenCalledWith({
      error: 'Internal server error',
      message: 'An unexpected error occurred'
    });
  });
});
