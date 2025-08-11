import pino from 'pino';
import { randomUUID } from 'crypto';

// Log levels
export enum LogLevel {
  TRACE = 'trace',
  DEBUG = 'debug',
  INFO = 'info',
  WARN = 'warn',
  ERROR = 'error',
  FATAL = 'fatal'
}

// Create structured logger
const isProduction = process.env.NODE_ENV === 'production';
const isDevelopment = process.env.NODE_ENV === 'development';

export const logger = pino({
  level: process.env.LOG_LEVEL || (isDevelopment ? 'debug' : 'info'),

  // Production configuration
  ...(isProduction && {
    // Structured JSON logs for production
    serializers: pino.stdSerializers,
    redact: {
      paths: [
        'req.headers.authorization',
        'req.headers.cookie',
        'password',
        'token',
        'secret',
        'apiKey',
      ],
      remove: true,
    },
  }),

  // Development configuration
  ...(isDevelopment && {
    transport: {
      target: 'pino-pretty',
      options: {
        colorize: true,
        translateTime: 'yyyy-mm-dd HH:MM:ss',
        ignore: 'hostname,pid',
      },
    },
  }),

  // Base fields
  base: {
    pid: process.pid,
    hostname: process.env.HOSTNAME || 'unknown',
    service: 'vorpal-board',
    version: process.env.npm_package_version || '1.0.0',
    environment: process.env.NODE_ENV || 'development',
  },

  // Custom formatters
  formatters: {
    level: (label) => {
      return { level: label };
    },
  },
});

// Specialized loggers for different domains
export const authLogger = logger.child({ domain: 'auth' });
export const dbLogger = logger.child({ domain: 'database' });
export const wsLogger = logger.child({ domain: 'websocket' });
export const apiLogger = logger.child({ domain: 'api' });
export const securityLogger = logger.child({ domain: 'security' });
export const uploadLogger = logger.child({ domain: 'upload' });

// Context-aware logging helpers
export interface LogContext {
  correlationId?: string;
  userId?: string;
  roomId?: string;
  sessionId?: string;
  operation?: string;
  duration?: number;
  [key: string]: any;
}

export class ContextLogger {
  private baseLogger: any;
  private context: LogContext;

  constructor(baseLogger: any, context: LogContext = {}) {
    this.baseLogger = baseLogger;
    this.context = context;
  }

  child(additionalContext: LogContext): ContextLogger {
    return new ContextLogger(
      this.baseLogger,
      { ...this.context, ...additionalContext },
    );
  }

  trace(message: string, data?: any) {
    this.baseLogger.trace({ ...this.context, ...data }, message);
  }

  debug(message: string, data?: any) {
    this.baseLogger.debug({ ...this.context, ...data }, message);
  }

  info(message: string, data?: any) {
    this.baseLogger.info({ ...this.context, ...data }, message);
  }

  warn(message: string, data?: any) {
    this.baseLogger.warn({ ...this.context, ...data }, message);
  }

  error(message: string, data?: any) {
    this.baseLogger.error({ ...this.context, ...data }, message);
  }

  fatal(message: string, data?: any) {
    this.baseLogger.fatal({ ...this.context, ...data }, message);
  }

  // Timing helpers
  time(operation: string): () => void {
    const start = Date.now();
    return () => {
      const duration = Date.now() - start;
      this.info(`Operation completed: ${operation}`, {
        operation,
        duration,
        durationMs: duration,
      });
    };
  }

  // Security event logging
  security(event: string, data?: any) {
    securityLogger.warn({
      ...this.context,
      securityEvent: event,
      timestamp: new Date().toISOString(),
      ...data,
    }, `🔒 Security Event: ${event}`);
  }
}

// Create room-aware logger
export function createRoomLogger(roomId: string, userId?: string): ContextLogger {
  return new ContextLogger(wsLogger, {
    roomId,
    userId,
    correlationId: randomUUID(),
  });
}

// Create user-aware logger
export function createUserLogger(userId: string, correlationId?: string): ContextLogger {
  return new ContextLogger(authLogger, {
    userId,
    correlationId: correlationId || randomUUID(),
  });
}

// Create API request logger
export function createRequestLogger(req: any): ContextLogger {
  return new ContextLogger(apiLogger, {
    correlationId: req.correlationId,
    userId: req.user?.uid,
    method: req.method,
    url: req.url,
    ip: req.ip || req.connection?.remoteAddress,
    userAgent: req.get('User-Agent'),
  });
}

// Performance monitoring helpers
export interface PerformanceMetrics {
  operation: string;
  duration: number;
  success: boolean;
  error?: string;
  metadata?: any;
}

export function logPerformance(metrics: PerformanceMetrics, context: LogContext = {}) {
  const level = metrics.success ? 'info' : 'error';
  const symbol = metrics.success ? '⚡' : '🐌';

  logger[level]({
    ...context,
    performance: {
      ...metrics,
      timestamp: new Date().toISOString(),
    },
  }, `${symbol} Performance: ${metrics.operation} (${metrics.duration}ms)`);
}

// Audit logging for sensitive operations
export function auditLog(
  action: string,
  resource: string,
  context: LogContext & {
    userId: string;
    result: 'success' | 'failure';
    details?: any
  },
) {
  logger.info({
    audit: {
      action,
      resource,
      userId: context.userId,
      result: context.result,
      timestamp: new Date().toISOString(),
      correlationId: context.correlationId || randomUUID(),
      details: context.details,
    },
  }, `📋 Audit: ${context.userId} ${action} ${resource} - ${context.result}`);
}

// Health check logging
export function healthCheck(service: string, status: 'healthy' | 'unhealthy', details?: any) {
  const level = status === 'healthy' ? 'info' : 'error';
  const symbol = status === 'healthy' ? '✅' : '❌';

  logger[level]({
    health: {
      service,
      status,
      timestamp: new Date().toISOString(),
      details,
    },
  }, `${symbol} Health Check: ${service} is ${status}`);
}

export default logger;
