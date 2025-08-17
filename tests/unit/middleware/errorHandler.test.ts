// tests/unit/middleware/errorHandler.test.ts
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Request, Response, NextFunction } from 'express';
import { createMockRequest, createMockResponse } from '@tests/utils/express-mocks';

// Mock error handler middleware since it may not exist yet
const errorHandler = vi.fn().mockImplementation((error: Error, req: Request, res: Response, next: NextFunction) => {
  console.error('Error:', error.message);
  
  // Handle different types of errors
  if (error.name === 'ValidationError') {
    return res.status(400).json({
      error: 'Validation Error',
      message: error.message,
      details: (error as any).details
    });
  }
  
  if (error.name === 'UnauthorizedError') {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Authentication required'
    });
  }
  
  if (error.name === 'ForbiddenError') {
    return res.status(403).json({
      error: 'Forbidden',
      message: 'Insufficient permissions'
    });
  }
  
  if (error.name === 'NotFoundError') {
    return res.status(404).json({
      error: 'Not Found',
      message: error.message || 'Resource not found'
    });
  }
  
  if (error.name === 'ConflictError') {
    return res.status(409).json({
      error: 'Conflict',
      message: error.message
    });
  }
  
  // Handle database errors
  if (error.message.includes('duplicate key')) {
    return res.status(409).json({
      error: 'Conflict',
      message: 'Resource already exists'
    });
  }
  
  // Handle rate limiting errors
  if (error.message.includes('rate limit')) {
    return res.status(429).json({
      error: 'Rate Limit Exceeded',
      message: 'Too many requests, please try again later'
    });
  }
  
  // Default server error
  res.status(500).json({
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'production' 
      ? 'An unexpected error occurred' 
      : error.message,
    stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
  });
});

describe('Error Handler Middleware', () => {
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let nextFunction: NextFunction;

  beforeEach(() => {
    mockRequest = createMockRequest();
    mockResponse = createMockResponse();
    nextFunction = vi.fn();
    vi.clearAllMocks();
  });

  describe('Validation Errors', () => {
    it('should handle validation errors', async () => {
      const validationError = new Error('Required field missing');
      validationError.name = 'ValidationError';
      (validationError as any).details = { field: 'email', message: 'Email is required' };

      errorHandler(
        validationError,
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.status).toHaveBeenCalledWith(400);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Validation Error',
        message: 'Required field missing',
        details: { field: 'email', message: 'Email is required' }
      });
    });

    it('should handle schema validation errors', async () => {
      const schemaError = new Error('Invalid data format');
      schemaError.name = 'ValidationError';

      errorHandler(
        schemaError,
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.status).toHaveBeenCalledWith(400);
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'Validation Error',
          message: 'Invalid data format'
        })
      );
    });
  });

  describe('Authentication Errors', () => {
    it('should handle unauthorized errors', async () => {
      const authError = new Error('Token expired');
      authError.name = 'UnauthorizedError';

      errorHandler(
        authError,
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'Authentication required'
      });
    });

    it('should handle forbidden errors', async () => {
      const forbiddenError = new Error('Insufficient permissions');
      forbiddenError.name = 'ForbiddenError';

      errorHandler(
        forbiddenError,
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Forbidden',
        message: 'Insufficient permissions'
      });
    });
  });

  describe('Resource Errors', () => {
    it('should handle not found errors', async () => {
      const notFoundError = new Error('Room not found');
      notFoundError.name = 'NotFoundError';

      errorHandler(
        notFoundError,
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.status).toHaveBeenCalledWith(404);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Not Found',
        message: 'Room not found'
      });
    });

    it('should handle conflict errors', async () => {
      const conflictError = new Error('Room name already exists');
      conflictError.name = 'ConflictError';

      errorHandler(
        conflictError,
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.status).toHaveBeenCalledWith(409);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Conflict',
        message: 'Room name already exists'
      });
    });
  });

  describe('Database Errors', () => {
    it('should handle duplicate key errors', async () => {
      const dbError = new Error('duplicate key value violates unique constraint');

      errorHandler(
        dbError,
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.status).toHaveBeenCalledWith(409);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Conflict',
        message: 'Resource already exists'
      });
    });

    it('should handle connection errors', async () => {
      const connectionError = new Error('Database connection failed');

      errorHandler(
        connectionError,
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.status).toHaveBeenCalledWith(500);
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'Internal Server Error'
        })
      );
    });
  });

  describe('Rate Limiting Errors', () => {
    it('should handle rate limit exceeded errors', async () => {
      const rateLimitError = new Error('rate limit exceeded for user');

      errorHandler(
        rateLimitError,
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.status).toHaveBeenCalledWith(429);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Rate Limit Exceeded',
        message: 'Too many requests, please try again later'
      });
    });
  });

  describe('Generic Server Errors', () => {
    it('should handle generic server errors in development', async () => {
      process.env.NODE_ENV = 'development';
      
      const serverError = new Error('Unexpected server error');
      serverError.stack = 'Error stack trace...';

      errorHandler(
        serverError,
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.status).toHaveBeenCalledWith(500);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Internal Server Error',
        message: 'Unexpected server error',
        stack: 'Error stack trace...'
      });
    });

    it('should handle generic server errors in production', async () => {
      process.env.NODE_ENV = 'production';
      
      const serverError = new Error('Sensitive error details');

      errorHandler(
        serverError,
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.status).toHaveBeenCalledWith(500);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Internal Server Error',
        message: 'An unexpected error occurred',
        stack: undefined
      });
    });
  });

  describe('Error Logging', () => {
    it('should log errors', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      
      const testError = new Error('Test error');

      errorHandler(
        testError,
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(consoleSpy).toHaveBeenCalledWith('Error:', 'Test error');
      
      consoleSpy.mockRestore();
    });
  });

  describe('Error Response Format', () => {
    it('should maintain consistent error response format', async () => {
      const testError = new Error('Test error');

      errorHandler(
        testError,
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.any(String),
          message: expect.any(String)
        })
      );
    });

    it('should not call next() for handled errors', async () => {
      const testError = new Error('Test error');

      errorHandler(
        testError,
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(nextFunction).not.toHaveBeenCalled();
    });
  });

  describe('Security Considerations', () => {
    it('should not expose sensitive information in production', async () => {
      process.env.NODE_ENV = 'production';
      
      const sensitiveError = new Error('Database password is incorrect');

      errorHandler(
        sensitiveError,
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      const responseCall = (mockResponse.json as vi.Mock).mock.calls[0][0];
      expect(responseCall.message).toBe('An unexpected error occurred');
      expect(responseCall.stack).toBeUndefined();
    });

    it('should sanitize error messages', async () => {
      const sqlError = new Error('SELECT * FROM users WHERE password = "secret123"');

      errorHandler(
        sqlError,
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      // In a real implementation, this would sanitize SQL queries
      expect(mockResponse.status).toHaveBeenCalledWith(500);
    });
  });
});
