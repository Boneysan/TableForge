import cors from 'cors';
import type { CorsOptions } from 'cors';
import { config } from '../configLoader';

// Using imported config object

// Define allowed origins based on environment
function getAllowedOrigins(): (string | RegExp)[] {
  const origins: (string | RegExp)[] = [];

  if (config.NODE_ENV === 'development') {
    // Development origins
    origins.push(
      'http://localhost:3000',
      'http://localhost:5000',
      'http://127.0.0.1:3000',
      'http://127.0.0.1:5000',
    );

    // Add Replit development domains if available
    if (config.REPLIT_DEV_DOMAIN) {
      origins.push(`https://${config.REPLIT_DEV_DOMAIN}`);
    }

    // Allow any Replit dev domain pattern for development
    if (process.env.REPL_SLUG) {
      origins.push(/^https:\/\/.*\.replit\.dev$/);
    }
  } else {
    // Production origins - be very specific
    if (config.ALLOWED_ORIGINS) {
      origins.push(...config.ALLOWED_ORIGINS.split(',').map(origin => origin.trim()));
    }

    // Add production Replit app domain
    if (config.REPLIT_APP_DOMAIN) {
      origins.push(`https://${config.REPLIT_APP_DOMAIN}`);
    }
  }

  return origins;
}

// CORS configuration
const corsOptions: CorsOptions = {
  origin: (origin: string | undefined, callback: (error: Error | null, allow?: boolean) => void) => {
    const allowedOrigins = getAllowedOrigins();

    console.log(`🌐 [CORS] Checking origin: ${origin}`);
    console.log(`🌐 [CORS] Allowed origins:`, allowedOrigins);

    // Allow requests with no origin (like mobile apps, Postman, etc.)
    if (!origin && config.NODE_ENV === 'development') {
      console.log(`🌐 [CORS] Allowing request with no origin (development mode)`);
      return callback(null, true);
    }

    if (!origin) {
      console.log(`❌ [CORS] Rejecting request with no origin (production mode)`);
      return callback(new Error('CORS: No origin header'), false);
    }

    // Check if origin is in allowed list
    const isAllowed = allowedOrigins.some(allowedOrigin => {
      if (typeof allowedOrigin === 'string') {
        return allowedOrigin === origin;
      }
      if (allowedOrigin instanceof RegExp) {
        return allowedOrigin.test(origin);
      }
      return false;
    });

    if (isAllowed) {
      console.log(`✅ [CORS] Allowing origin: ${origin}`);
      callback(null, true);
    } else {
      console.warn(`❌ [CORS] Blocking origin: ${origin}`);
      console.warn(`❌ [CORS] Allowed origins were:`, allowedOrigins);
      callback(new Error(`CORS: Origin ${origin} not allowed`), false);
    }
  },

  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],

  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'Accept',
    'Origin',
    'Cache-Control',
    'X-File-Name',
  ],

  credentials: true,

  // Preflight cache duration
  maxAge: config.NODE_ENV === 'production' ? 86400 : 300, // 24 hours in prod, 5 minutes in dev

  // Only send Access-Control-Allow-Credentials header when needed
  preflightContinue: false,

  // Handle preflight OPTIONS requests
  optionsSuccessStatus: 204,
};

// Enhanced CORS middleware with logging
export const corsMiddleware = cors(corsOptions);

// CORS error handler
export const corsErrorHandler = (error: Error, req: any, res: any, next: any) => {
  if (error.message.includes('CORS')) {
    console.error(`🚫 [CORS Error] ${error.message}`, {
      origin: req.get('origin'),
      userAgent: req.get('user-agent'),
      method: req.method,
      path: req.path,
      ip: req.ip,
    });

    return res.status(403).json({
      error: 'cors_blocked',
      message: 'Cross-origin request blocked by CORS policy',
    });
  }

  next(error);
};

// Additional security headers for CORS
export const additionalSecurityHeaders = (req: any, res: any, next: any) => {
  // Set additional security headers
  res.header('X-Content-Type-Options', 'nosniff');
  res.header('X-Frame-Options', 'DENY');
  res.header('X-XSS-Protection', '1; mode=block');
  res.header('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Prevent caching of sensitive endpoints
  if (req.path.includes('/api/auth/') || req.path.includes('/api/admin/')) {
    res.header('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.header('Pragma', 'no-cache');
    res.header('Expires', '0');
  }

  next();
};

// WebSocket CORS validation
export const validateWebSocketOrigin = (origin: string): boolean => {
  const allowedOrigins = getAllowedOrigins();

  console.log(`🔌 [WebSocket CORS] Validating origin: ${origin}`);

  return allowedOrigins.some(allowedOrigin => {
    if (typeof allowedOrigin === 'string') {
      return allowedOrigin === origin;
    }
    if (allowedOrigin instanceof RegExp) {
      return allowedOrigin.test(origin);
    }
    return false;
  });
};
