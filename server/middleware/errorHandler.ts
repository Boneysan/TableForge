import type { Request, Response, NextFunction } from 'express';
import { ZodError } from 'zod';
import { logger } from '../utils/logger';
import { randomUUID } from 'crypto';

// Standard error envelope
export interface ErrorEnvelope {
  code: string;
  message: string;
  details?: any;
  requestId: string;
  timestamp: string;
}

// Error types for consistent handling
export enum ErrorCode {
  // Client errors (4xx)
  VALIDATION_ERROR = 'VALIDATION_ERROR',
  AUTHENTICATION_ERROR = 'AUTHENTICATION_ERROR',
  AUTHORIZATION_ERROR = 'AUTHORIZATION_ERROR',
  NOT_FOUND = 'NOT_FOUND',
  CONFLICT = 'CONFLICT',
  RATE_LIMITED = 'RATE_LIMITED',
  BAD_REQUEST = 'BAD_REQUEST',
  
  // Server errors (5xx)
  INTERNAL_ERROR = 'INTERNAL_ERROR',
  DATABASE_ERROR = 'DATABASE_ERROR',
  EXTERNAL_SERVICE_ERROR = 'EXTERNAL_SERVICE_ERROR',
  CONFIGURATION_ERROR = 'CONFIGURATION_ERROR'
}

// Custom error classes
export class AppError extends Error {
  constructor(
    public code: ErrorCode,
    public message: string,
    public details?: any,
    public statusCode: number = 500
  ) {
    super(message);
    this.name = 'AppError';
    Object.setPrototypeOf(this, AppError.prototype);
  }
}

export class ValidationError extends AppError {
  constructor(message: string, details?: any) {
    super(ErrorCode.VALIDATION_ERROR, message, details, 400);
  }
}

export class AuthenticationError extends AppError {
  constructor(message: string, details?: any) {
    super(ErrorCode.AUTHENTICATION_ERROR, message, details, 401);
  }
}

export class AuthorizationError extends AppError {
  constructor(message: string, details?: any) {
    super(ErrorCode.AUTHORIZATION_ERROR, message, details, 403);
  }
}

export class NotFoundError extends AppError {
  constructor(message: string, details?: any) {
    super(ErrorCode.NOT_FOUND, message, details, 404);
  }
}

export class ConflictError extends AppError {
  constructor(message: string, details?: any) {
    super(ErrorCode.CONFLICT, message, details, 409);
  }
}

export class RateLimitError extends AppError {
  constructor(message: string, details?: any) {
    super(ErrorCode.RATE_LIMITED, message, details, 429);
  }
}

export class DatabaseError extends AppError {
  constructor(message: string, details?: any) {
    super(ErrorCode.DATABASE_ERROR, message, details, 500);
  }
}

export class ExternalServiceError extends AppError {
  constructor(message: string, details?: any) {
    super(ErrorCode.EXTERNAL_SERVICE_ERROR, message, details, 502);
  }
}

// Add correlation ID to request
export function addCorrelationId(req: Request, res: Response, next: NextFunction) {
  const correlationId = randomUUID();
  req.correlationId = correlationId;
  res.setHeader('X-Correlation-ID', correlationId);
  
  // Add correlation context to logger
  req.log = logger.child({
    correlationId,
    method: req.method,
    url: req.url,
    userAgent: req.get('User-Agent')
  });
  
  next();
}

// Map different error types to standard envelope
function mapErrorToEnvelope(error: any, requestId: string): ErrorEnvelope {
  // Zod validation errors
  if (error instanceof ZodError) {
    const details = error.errors.map(err => ({
      field: err.path.join('.'),
      message: err.message,
      code: err.code
    }));
    
    return {
      code: ErrorCode.VALIDATION_ERROR,
      message: 'Validation failed',
      details,
      requestId,
      timestamp: new Date().toISOString()
    };
  }
  
  // Custom app errors
  if (error instanceof AppError) {
    return {
      code: error.code,
      message: error.message,
      details: error.details,
      requestId,
      timestamp: new Date().toISOString()
    };
  }
  
  // Database errors (Drizzle/PostgreSQL)
  if (error?.code?.startsWith?.('23')) { // PostgreSQL constraint violations
    const code = error.code === '23505' ? ErrorCode.CONFLICT : ErrorCode.DATABASE_ERROR;
    const message = error.code === '23505' ? 'Resource already exists' : 'Database constraint violation';
    
    return {
      code,
      message,
      details: {
        constraint: error.constraint,
        detail: error.detail,
        table: error.table
      },
      requestId,
      timestamp: new Date().toISOString()
    };
  }
  
  // Firebase auth errors
  if (error?.code?.startsWith?.('auth/')) {
    return {
      code: ErrorCode.AUTHENTICATION_ERROR,
      message: 'Authentication failed',
      details: {
        firebaseCode: error.code,
        firebaseMessage: error.message
      },
      requestId,
      timestamp: new Date().toISOString()
    };
  }
  
  // Rate limiting errors
  if (error?.status === 429 || error?.message?.includes?.('rate limit')) {
    return {
      code: ErrorCode.RATE_LIMITED,
      message: 'Too many requests',
      details: {
        retryAfter: error.retryAfter || 60
      },
      requestId,
      timestamp: new Date().toISOString()
    };
  }
  
  // Default to internal server error
  return {
    code: ErrorCode.INTERNAL_ERROR,
    message: process.env.NODE_ENV === 'production' 
      ? 'An unexpected error occurred' 
      : error.message || 'Internal server error',
    details: process.env.NODE_ENV === 'production' 
      ? undefined 
      : {
          stack: error.stack,
          name: error.name
        },
    requestId,
    timestamp: new Date().toISOString()
  };
}

// Central error handling middleware
export function errorHandler(
  error: any, 
  req: Request, 
  res: Response, 
  next: NextFunction
) {
  const requestId = req.correlationId || randomUUID();
  const errorEnvelope = mapErrorToEnvelope(error, requestId);
  
  // Determine status code
  let statusCode = 500;
  if (error instanceof AppError) {
    statusCode = error.statusCode;
  } else if (error instanceof ZodError) {
    statusCode = 400;
  } else if (error?.code?.startsWith?.('23')) {
    statusCode = error.code === '23505' ? 409 : 400;
  } else if (error?.code?.startsWith?.('auth/')) {
    statusCode = 401;
  } else if (error?.status === 429) {
    statusCode = 429;
  }
  
  // Log error with context
  const logContext = {
    error: {
      ...errorEnvelope,
      originalError: error.message,
      stack: error.stack
    },
    request: {
      method: req.method,
      url: req.url,
      headers: req.headers,
      body: req.method !== 'GET' ? req.body : undefined,
      user: req.user?.uid || null
    },
    response: {
      statusCode
    }
  };
  
  if (statusCode >= 500) {
    req.log?.error(logContext, '🚨 Server error occurred');
  } else if (statusCode >= 400) {
    req.log?.warn(logContext, '⚠️ Client error occurred');
  }
  
  // Send error response
  res.status(statusCode).json(errorEnvelope);
}

// Handle async route errors
export function asyncHandler<T extends Request, U extends Response>(
  fn: (req: T, res: U, next: NextFunction) => Promise<any>
) {
  return (req: T, res: U, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

// Handle unhandled promise rejections and uncaught exceptions
export function setupGlobalErrorHandlers() {
  process.on('unhandledRejection', (reason, promise) => {
    logger.error({
      error: reason,
      promise: promise,
      type: 'unhandledRejection'
    }, '🚨 Unhandled promise rejection');
    
    // Graceful shutdown in production
    if (process.env.NODE_ENV === 'production') {
      process.exit(1);
    }
  });
  
  process.on('uncaughtException', (error) => {
    logger.error({
      error: {
        message: error.message,
        stack: error.stack,
        name: error.name
      },
      type: 'uncaughtException'
    }, '🚨 Uncaught exception');
    
    // Force exit
    process.exit(1);
  });
}

// Extend Express Request type
declare global {
  namespace Express {
    interface Request {
      correlationId?: string;
      log?: any;
    }
  }
}

export type { ErrorEnvelope };