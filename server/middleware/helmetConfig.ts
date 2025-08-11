import helmet from 'helmet';
import type { HelmetOptions } from 'helmet';
import { config } from '../configLoader';

// Using imported config object

// Get allowed domains for CSP
function getAllowedDomains(): { 
  connect: string[], 
  img: string[], 
  font: string[],
  style: string[],
  script: string[]
} {
  const domains = {
    connect: [
      "'self'",
      'https://*.googleapis.com',
      'https://*.firebaseio.com',
      'https://*.cloudfunctions.net',
      'wss://*.replit.dev',
      'ws://*.replit.dev',
      'wss://*.replit.app',
      'ws://*.replit.app',
    ],
    img: [
      "'self'",
      'data:',
      'blob:',
      'https://*.googleapis.com',
      'https://*.googleusercontent.com',
      'https://*.gstatic.com',
      'https://storage.googleapis.com',
      'https://storage.cloud.google.com',
    ],
    font: [
      "'self'",
      'https://fonts.gstatic.com',
    ],
    style: [
      "'self'",
      "'unsafe-inline'", // Required for Tailwind and inline styles
      'https://fonts.googleapis.com',
    ],
    script: [
      "'self'",
      "'unsafe-inline'", // Required for Vite dev server
      "'unsafe-eval'", // Required for Vite dev server
    ]
  };

  // Add environment-specific domains
  if (config.NODE_ENV === 'development') {
    domains.connect.push(
      'http://localhost:*',
      'ws://localhost:*',
      'wss://localhost:*'
    );
    domains.img.push('http://localhost:*');
  }

  // Add custom domains if configured
  if (config.REPLIT_DEV_DOMAIN) {
    const devDomain = `https://${config.REPLIT_DEV_DOMAIN}`;
    domains.connect.push(devDomain);
    domains.img.push(devDomain);
  }

  if (config.REPLIT_APP_DOMAIN) {
    const appDomain = `https://${config.REPLIT_APP_DOMAIN}`;
    domains.connect.push(appDomain);
    domains.img.push(appDomain);
  }

  return domains;
}

// Helmet configuration with strict CSP
const helmetOptions: HelmetOptions = {
  // Content Security Policy
  contentSecurityPolicy: {
    directives: (() => {
      const domains = getAllowedDomains();
      
      return {
        defaultSrc: ["'self'"],
        
        // Scripts - strict in production, relaxed in development for Vite
        scriptSrc: domains.script,
        scriptSrcAttr: ["'none'"],
        
        // Styles
        styleSrc: domains.style,
        styleSrcAttr: ["'unsafe-inline'"], // Required for some UI components
        
        // Images - allow our storage and common image sources
        imgSrc: domains.img,
        
        // Fonts
        fontSrc: domains.font,
        
        // Connections - API calls, WebSockets
        connectSrc: domains.connect,
        
        // Media
        mediaSrc: ["'self'", 'https:', 'blob:'],
        
        // Objects and embeds
        objectSrc: ["'none'"],
        embedSrc: ["'none'"],
        
        // Forms
        formAction: ["'self'"],
        
        // Frames
        frameSrc: ["'none'"],
        frameAncestors: ["'self'"],
        
        // Base URI
        baseUri: ["'self'"],
        
        // Upgrade insecure requests in production
        ...(config.NODE_ENV === 'production' && { upgradeInsecureRequests: [] }),
      };
    })(),
    reportOnly: config.NODE_ENV === 'development', // Report only in development
  },

  // Cross Origin Embedder Policy
  crossOriginEmbedderPolicy: false, // Disabled for compatibility

  // Cross Origin Opener Policy
  crossOriginOpenerPolicy: { policy: 'same-origin' },

  // Cross Origin Resource Policy
  crossOriginResourcePolicy: { policy: 'cross-origin' },

  // DNS Prefetch Control
  dnsPrefetchControl: { allow: false },

  // Frameguard
  frameguard: { action: 'deny' },

  // Hide Powered-By
  hidePoweredBy: true,

  // HTTP Strict Transport Security
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true,
  },

  // IE No Open
  ieNoOpen: true,

  // No Sniff
  noSniff: true,

  // Origin Agent Cluster
  originAgentCluster: true,

  // Permitted Cross Domain Policies
  permittedCrossDomainPolicies: false,

  // Referrer Policy
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },

  // X-XSS-Protection
  xssFilter: true,
};

// Export configured helmet middleware
export const helmetMiddleware = helmet(helmetOptions);

// CSP violation reporting endpoint middleware
export const cspViolationHandler = (req: any, res: any, next: any) => {
  if (req.path === '/api/csp-violation-report' && req.method === 'POST') {
    console.warn('🚨 [CSP Violation]', {
      timestamp: new Date().toISOString(),
      userAgent: req.get('user-agent'),
      violation: req.body,
      ip: req.ip,
    });
    
    return res.status(204).end();
  }
  
  next();
};

// Enhanced security headers for sensitive endpoints
export const strictSecurityHeaders = (req: any, res: any, next: any) => {
  // Additional headers for sensitive endpoints
  if (req.path.includes('/api/auth/') || req.path.includes('/api/admin/')) {
    res.header('X-Content-Type-Options', 'nosniff');
    res.header('X-Frame-Options', 'DENY');
    res.header('X-XSS-Protection', '1; mode=block');
    res.header('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.header('Pragma', 'no-cache');
    res.header('Expires', '0');
    res.header('Clear-Site-Data', '"cache", "cookies", "storage"');
  }
  
  next();
};

// Log CSP violations for monitoring
export const logSecurityEvents = (req: any, res: any, next: any) => {
  const securityHeaders = [
    'x-forwarded-for',
    'x-real-ip',
    'user-agent',
    'origin',
    'referer'
  ];
  
  const suspiciousPatterns = [
    /script.*src.*http/i,
    /javascript:/i,
    /vbscript:/i,
    /data:text\/html/i,
    /<script/i,
    /eval\(/i,
  ];
  
  // Check for suspicious patterns in headers and query params
  const requestData = {
    headers: Object.fromEntries(
      securityHeaders.map(header => [header, req.get(header)])
    ),
    query: req.query,
    path: req.path,
    method: req.method,
  };
  
  const requestString = JSON.stringify(requestData);
  const hasSuspiciousContent = suspiciousPatterns.some(pattern => 
    pattern.test(requestString)
  );
  
  if (hasSuspiciousContent) {
    console.warn('🚨 [Suspicious Request]', {
      timestamp: new Date().toISOString(),
      ip: req.ip,
      ...requestData,
    });
  }
  
  next();
};