// Unit Tests for Server Middleware
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createMockRequest, createMockResponse } from '@tests/utils';
import type { Request, Response, NextFunction } from 'express';

// Mock authentication middleware function
interface AuthenticatedRequest extends Request {
  user?: {
    uid: string;
    email: string;
    displayName: string;
  };
}

async function authenticateToken(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    res.status(401).json({
      error: 'Authentication required',
      message: 'Valid authentication token must be provided'
    });
    return;
  }

  const token = authHeader.split(' ')[1];
  
  if (!token) {
    res.status(401).json({
      error: 'Invalid token format',
      message: 'Token must be provided in Bearer format'
    });
    return;
  }

  try {
    // Mock token validation
    if (token === 'valid-token') {
      (req as AuthenticatedRequest).user = {
        uid: 'user123',
        email: 'test@example.com',
        displayName: 'Test User'
      };
      next();
    } else {
      throw new Error('Invalid token');
    }
  } catch (error) {
    res.status(401).json({
      error: 'Authentication failed',
      message: 'Invalid or expired token'
    });
  }
}

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
    it('should authenticate valid token', async () => {
      mockRequest.headers = {
        authorization: 'Bearer valid-token'
      };

      await authenticateToken(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect((mockRequest as AuthenticatedRequest).user).toEqual({
        uid: 'user123',
        email: 'test@example.com',
        displayName: 'Test User'
      });
      expect(nextFunction).toHaveBeenCalled();
      expect(mockResponse.status).not.toHaveBeenCalled();
    });

    it('should reject request without authorization header', async () => {
      mockRequest.headers = {};

      await authenticateToken(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Authentication required',
        message: 'Valid authentication token must be provided'
      });
      expect(nextFunction).not.toHaveBeenCalled();
    });

    it('should reject malformed authorization header', async () => {
      mockRequest.headers = {
        authorization: 'InvalidFormat'
      };

      await authenticateToken(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Invalid token format',
        message: 'Token must be provided in Bearer format'
      });
      expect(nextFunction).not.toHaveBeenCalled();
    });

    it('should reject invalid token', async () => {
      mockRequest.headers = {
        authorization: 'Bearer invalid-token'
      };

      await authenticateToken(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Authentication failed',
        message: 'Invalid or expired token'
      });
      expect(nextFunction).not.toHaveBeenCalled();
    });

    it('should handle missing Bearer prefix', async () => {
      mockRequest.headers = {
        authorization: 'Bearer '
      };

      await authenticateToken(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.status).toHaveBeenCalledWith(401);
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
    req: Request,
    res: Response,
    next: NextFunction
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
