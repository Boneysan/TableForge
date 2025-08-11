import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import type { Request, Response, NextFunction } from 'express';
import { config } from '../configLoader';
import { getCorsOrigins } from '../../shared/config';

// Rate limiting middleware
export const createRateLimiter = () => {
  // In development, be very permissive with rate limiting
  const limit = config.NODE_ENV === 'development' ? 1000 : config.RATE_LIMIT_PER_MINUTE;
  
  return rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: limit,
    message: {
      error: 'Too many requests',
      message: `Rate limit exceeded. Maximum ${limit} requests per minute.`,
      retryAfter: '1 minute'
    },
    standardHeaders: true,
    legacyHeaders: false,
    // Skip rate limiting for health checks, static assets, and in development mode
    skip: (req) => {
      return req.path === '/health' || 
             req.path.startsWith('/assets/') || 
             req.path.startsWith('/src/') ||
             config.NODE_ENV === 'development';
    },
  });
};

// API-specific rate limiter (stricter)
export const createApiRateLimiter = () => {
  // In development, disable API rate limiting
  if (config.NODE_ENV === 'development') {
    return (req: Request, res: Response, next: NextFunction) => next();
  }
  
  return rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: Math.floor(config.RATE_LIMIT_PER_MINUTE * 0.8), // 80% of general limit
    message: {
      error: 'API rate limit exceeded',
      message: 'Too many API requests. Please slow down.',
      retryAfter: '1 minute'
    },
    standardHeaders: true,
    legacyHeaders: false,
  });
};

// Authentication rate limiter (very strict)
export const createAuthRateLimiter = () => {
  // In development, disable auth rate limiting
  if (config.NODE_ENV === 'development') {
    return (req: Request, res: Response, next: NextFunction) => next();
  }
  
  return rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per 15 minutes
    message: {
      error: 'Authentication rate limit exceeded',
      message: 'Too many authentication attempts. Please try again in 15 minutes.',
      retryAfter: '15 minutes'
    },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true, // Don't count successful auth attempts
  });
};

// Security headers middleware
export const createSecurityHeaders = () => {
  const corsOrigins = getCorsOrigins();
  
  // CORS configuration
  const corsOptions = {
    origin: (origin, callback) => {
      // Allow requests with no origin (mobile apps, Postman, etc.)
      if (!origin) return callback(null, true);
      
      // In development, allow localhost origins
      if (config.NODE_ENV === 'development') {
        if (origin.includes('localhost') || origin.includes('127.0.0.1') || origin.includes('replit.dev')) {
          return callback(null, true);
        }
      }
      
      // Check configured origins
      if (corsOrigins.length === 0 || corsOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error(`Origin ${origin} not allowed by CORS policy`));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    maxAge: 86400, // 24 hours
  };

  // Helmet security headers configuration - very permissive in development
  const helmetOptions = config.NODE_ENV === 'development' ? {
    contentSecurityPolicy: false, // Disable CSP in development
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: false,
  } : {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:", "https:", "blob:"],
        scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
        connectSrc: ["'self'", "https:", "wss:", "ws:"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'", "https:", "blob:"],
        frameSrc: ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" as const },
  };

  return {
    cors: (req: Request, res: Response, next: NextFunction) => {
      // In development, allow all origins
      if (config.NODE_ENV === 'development') {
        res.header('Access-Control-Allow-Origin', '*');
        res.header('Access-Control-Allow-Credentials', 'true');
        res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,PATCH,OPTIONS');
        res.header('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Requested-With');
        res.header('Access-Control-Max-Age', '86400');
        
        if (req.method === 'OPTIONS') {
          return res.sendStatus(200);
        }
        
        return next();
      }
      
      // Production CORS handling
      const origin = req.get('origin');
      const allowedOrigins = getCorsOrigins();
      
      if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
        res.header('Access-Control-Allow-Origin', origin || '*');
        res.header('Access-Control-Allow-Credentials', 'true');
        res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,PATCH,OPTIONS');
        res.header('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Requested-With');
        res.header('Access-Control-Max-Age', '86400');
      }
      
      if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
      }
      
      next();
    },
    helmet: helmet(helmetOptions),
  };
};

// Request logging middleware for security monitoring
export const securityLogger = (req: Request, res: Response, next: NextFunction) => {
  // Log potentially suspicious requests
  const suspiciousPatterns = [
    /\.\./,  // Directory traversal
    /union.*select/i,  // SQL injection
    /<script/i,  // XSS
    /javascript:/i,  // XSS
    /eval\(/i,  // Code injection
  ];

  const url = req.url.toLowerCase();
  const body = JSON.stringify(req.body || {}).toLowerCase();
  
  const isSuspicious = suspiciousPatterns.some(pattern => 
    pattern.test(url) || pattern.test(body)
  );

  if (isSuspicious) {
    console.warn(`🚨 [Security] Suspicious request detected:`, {
      ip: req.ip,
      method: req.method,
      url: req.url,
      userAgent: req.get('User-Agent'),
      timestamp: new Date().toISOString(),
    });
  }

  // Add security headers to response
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  next();
};