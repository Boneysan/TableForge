import rateLimit from 'express-rate-limit';
import type { Request, Response, NextFunction } from 'express';

// Store for per-user rate limiting
const userRequestCounts = new Map<string, { count: number; resetTime: number }>();

// Custom rate limit store for per-user limits
class UserRateLimitStore {
  private windowMs: number;
  private max: number;

  constructor(windowMs: number, max: number) {
    this.windowMs = windowMs;
    this.max = max;
  }

  async increment(key: string): Promise<{ totalHits: number; timeToExpire?: number }> {
    const now = Date.now();
    const userKey = `user:${key}`;
    let userData = userRequestCounts.get(userKey);

    if (!userData || now > userData.resetTime) {
      userData = {
        count: 1,
        resetTime: now + this.windowMs,
      };
      userRequestCounts.set(userKey, userData);
      return { totalHits: 1 };
    }

    userData.count++;
    userRequestCounts.set(userKey, userData);

    return {
      totalHits: userData.count,
      timeToExpire: Math.max(0, userData.resetTime - now),
    };
  }

  async decrement(key: string): Promise<void> {
    const userKey = `user:${key}`;
    const userData = userRequestCounts.get(userKey);
    if (userData && userData.count > 0) {
      userData.count--;
      userRequestCounts.set(userKey, userData);
    }
  }

  async resetKey(key: string): Promise<void> {
    const userKey = `user:${key}`;
    userRequestCounts.delete(userKey);
  }
}

// Cleanup old entries every 10 minutes
setInterval(() => {
  const now = Date.now();
  const entries = Array.from(userRequestCounts.entries());
  for (const [key, data] of entries) {
    if (now > data.resetTime) {
      userRequestCounts.delete(key);
    }
  }
}, 10 * 60 * 1000);

// Rate limiting configurations
export const createRateLimiter = (windowMs: number, max: number, message?: string) => {
  return rateLimit({
    windowMs,
    max,
    message: message || {
      error: 'rate_limit_exceeded',
      message: 'Too many requests, please try again later.',
      retryAfter: Math.ceil(windowMs / 1000),
    },
    standardHeaders: true,
    legacyHeaders: false,
    // Use default key generator to handle IPv6 properly
    skip: (req: Request) => {
      // Skip rate limiting for health checks
      return req.path === '/health' || req.path === '/api/health';
    },
    // Enhanced logging
    handler: (req: Request, res: Response) => {
      const ip = req.get('x-forwarded-for')?.split(',')[0]?.trim() || req.ip;
      const userAgent = req.get('user-agent') || 'unknown';
      console.warn(`🚫 [Rate Limit] IP ${ip} exceeded rate limit on ${req.path}`, {
        userAgent,
        method: req.method,
        path: req.path,
      });
      return res.status(429).json({
        error: 'rate_limit_exceeded',
        message: 'Too many requests, please try again later.',
      });
    },
  });
};

// Per-user rate limiter for authenticated endpoints
export const createUserRateLimiter = (windowMs: number, max: number, message?: string | object) => {
  const store = new UserRateLimitStore(windowMs, max);

  return async (req: any, res: Response, next: NextFunction) => {
    const userId = req.user?.uid || req.user?.id;
    
    if (!userId) {
      // If no user ID, fall back to IP-based limiting
      return createRateLimiter(windowMs, max, message)(req, res, next);
    }

    try {
      const result = await store.increment(userId);
      
      // Set rate limit headers
      res.set({
        'X-RateLimit-Limit': max.toString(),
        'X-RateLimit-Remaining': Math.max(0, max - result.totalHits).toString(),
        'X-RateLimit-Reset': result.timeToExpire 
          ? new Date(Date.now() + result.timeToExpire).toISOString()
          : new Date(Date.now() + windowMs).toISOString(),
      });

      if (result.totalHits > max) {
        console.warn(`🚫 [User Rate Limit] User ${userId} exceeded rate limit on ${req.path}`, {
          totalHits: result.totalHits,
          limit: max,
          path: req.path,
        });

        const errorResponse = typeof message === 'string' ? { 
          error: 'rate_limit_exceeded',
          message: message,
          retryAfter: Math.ceil((result.timeToExpire || windowMs) / 1000),
        } : message || {
          error: 'rate_limit_exceeded',
          message: 'Too many requests for this user, please try again later.',
          retryAfter: Math.ceil((result.timeToExpire || windowMs) / 1000),
        };
        return res.status(429).json(errorResponse);
      }

      next();
    } catch (error) {
      console.error('Rate limiting error:', error);
      next(); // Continue on error to avoid blocking legitimate requests
    }
  };
};

// Predefined rate limiters for different endpoint types

// General API rate limiting - per IP
export const generalRateLimit = createRateLimiter(
  15 * 60 * 1000, // 15 minutes
  1000, // 1000 requests per window
  {
    error: 'rate_limit_exceeded',
    message: 'Too many requests from this IP, please try again later.',
    retryAfter: 900, // 15 minutes
  }
);

// Auth endpoints - stricter per IP
export const authRateLimit = createRateLimiter(
  15 * 60 * 1000, // 15 minutes
  50, // 50 auth requests per window per IP
  {
    error: 'auth_rate_limit_exceeded',
    message: 'Too many authentication requests, please try again later.',
    retryAfter: 900,
  }
);

// Per-user auth rate limiting - prevents single user from making too many auth requests
export const userAuthRateLimit = createUserRateLimiter(
  15 * 60 * 1000, // 15 minutes
  30, // 30 auth requests per user per window
  {
    error: 'user_auth_rate_limit_exceeded',
    message: 'Too many authentication requests for this account, please try again later.',
    retryAfter: 900,
  }
);

// Asset upload endpoints - per user (more restrictive)
export const assetUploadRateLimit = createUserRateLimiter(
  60 * 60 * 1000, // 1 hour
  100, // 100 uploads per user per hour
  {
    error: 'upload_rate_limit_exceeded',
    message: 'Too many uploads, please wait before uploading more assets.',
    retryAfter: 3600,
  }
);

// Game room operations - per user
export const roomOperationRateLimit = createUserRateLimiter(
  5 * 60 * 1000, // 5 minutes
  200, // 200 room operations per user per 5 minutes
  {
    error: 'room_operation_rate_limit_exceeded',
    message: 'Too many room operations, please slow down.',
    retryAfter: 300,
  }
);

// WebSocket connection rate limiting - per IP
export const websocketRateLimit = createRateLimiter(
  60 * 1000, // 1 minute
  10, // 10 connection attempts per minute
  {
    error: 'websocket_rate_limit_exceeded',
    message: 'Too many WebSocket connection attempts.',
    retryAfter: 60,
  }
);

// Admin endpoints - very restrictive per IP
export const adminRateLimit = createRateLimiter(
  60 * 60 * 1000, // 1 hour
  20, // 20 admin requests per hour per IP
  {
    error: 'admin_rate_limit_exceeded',
    message: 'Too many admin requests, please wait.',
    retryAfter: 3600,
  }
);