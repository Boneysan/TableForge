import type { Request, Response, NextFunction } from 'express';
import { recordHttpRequest, recordError } from '@server/observability/metrics';
import { withSpan, recordCustomEvent } from '@server/observability/telemetry';
import { logger } from '@server/utils/logger';

// HTTP request metrics middleware
export function metricsMiddleware(req: Request, res: Response, next: NextFunction): void {
  const startTime = Date.now();
  const originalSend = res.send;
  const originalJson = res.json;

  // Override response methods to capture metrics
  res.send = function(body: any) {
    captureMetrics();
    return originalSend.call(this, body);
  };

  res.json = function(body: any) {
    captureMetrics();
    return originalJson.call(this, body);
  };

  function captureMetrics(): void {
    const duration = (Date.now() - startTime) / 1000;
    const route = getRoutePattern(req);
    
    recordHttpRequest(
      req.method,
      route,
      res.statusCode,
      duration
    );

    // Record error metrics for non-2xx responses
    if (res.statusCode >= 400) {
      const errorType = res.statusCode >= 500 ? 'server_error' : 'client_error';
      const severity = res.statusCode >= 500 ? 'high' : 'medium';
      
      recordError(errorType, severity, 'http_request');
    }

    // Log slow requests
    if (duration > 1) {
      logger.warn('Slow HTTP request detected', {
        method: req.method,
        route,
        duration,
        statusCode: res.statusCode,
        userAgent: req.get('User-Agent'),
        ip: req.ip,
      });
    }

    // Record custom events in active trace
    recordCustomEvent('http.request.completed', {
      'http.method': req.method,
      'http.route': route,
      'http.status_code': res.statusCode,
      'http.duration_ms': duration * 1000,
      'http.user_agent': req.get('User-Agent') || '',
      'http.content_length': parseInt(res.get('Content-Length') || '0', 10),
    });
  }

  next();
}

// Enhanced metrics middleware with tracing
export function tracedMetricsMiddleware(req: Request, res: Response, next: NextFunction): void {
  const route = getRoutePattern(req);
  const operationName = `http.${req.method.toLowerCase()}.${route.replace(/[/:]/g, '_')}`;

  withSpan(
    operationName,
    (span) => {
      // Set HTTP attributes on span
      span.setAttributes({
        'http.method': req.method,
        'http.route': route,
        'http.url': req.url,
        'http.scheme': req.protocol,
        'http.host': req.get('host') || '',
        'http.user_agent': req.get('User-Agent') || '',
        'http.remote_addr': req.ip || '',
        'user.id': (req as any).user?.id || '',
        'room.id': req.params.roomId || req.query.roomId || '',
      });

      // Add custom request tracking
      const startTime = Date.now();
      
      res.on('finish', () => {
        const duration = Date.now() - startTime;
        
        span.setAttributes({
          'http.status_code': res.statusCode,
          'http.response.size': parseInt(res.get('Content-Length') || '0', 10),
          'http.duration_ms': duration,
        });

        // Record success/error in span
        if (res.statusCode >= 400) {
          span.recordException(new Error(`HTTP ${res.statusCode}: ${res.statusMessage}`));
        }

        recordCustomEvent('http.response.sent', {
          'http.status_code': res.statusCode,
          'http.duration_ms': duration,
        });
      });

      return new Promise<void>((resolve) => {
        res.on('finish', resolve);
        metricsMiddleware(req, res, next);
      });
    },
    {
      'component': 'http_middleware',
      'operation.type': 'http_request',
    }
  ).catch((error) => {
    recordError('middleware_error', 'high', 'metrics_middleware');
    logger.error('Error in traced metrics middleware', { error: error.message });
    next(error);
  });
}

// Extract route pattern for consistent metrics labeling
function getRoutePattern(req: Request): string {
  // Use the matched route if available (Express route matching)
  if (req.route && req.route.path) {
    return req.route.path;
  }

  // Fallback to URL pattern extraction
  let path = req.path;
  
  // Replace common ID patterns with placeholders
  path = path.replace(/\/[a-f0-9-]{36}(?=\/|$)/gi, '/:id'); // UUIDs
  path = path.replace(/\/[a-f0-9]{24}(?=\/|$)/gi, '/:id'); // MongoDB ObjectIds
  path = path.replace(/\/\d+(?=\/|$)/g, '/:id'); // Numeric IDs
  
  // Replace room-specific patterns
  path = path.replace(/\/rooms\/[^/]+/, '/rooms/:roomId');
  path = path.replace(/\/users\/[^/]+/, '/users/:userId');
  path = path.replace(/\/assets\/[^/]+/, '/assets/:assetId');
  path = path.replace(/\/systems\/[^/]+/, '/systems/:systemId');
  path = path.replace(/\/templates\/[^/]+/, '/templates/:templateId');

  return path || '/';
}

// WebSocket metrics middleware
export function websocketMetricsMiddleware(socket: any, next: Function): void {
  const startTime = Date.now();
  const connectionId = socket.id;
  
  withSpan(
    'websocket.connection.established',
    (span) => {
      span.setAttributes({
        'websocket.connection.id': connectionId,
        'websocket.remote_addr': socket.handshake?.address || '',
        'websocket.user_agent': socket.handshake?.headers['user-agent'] || '',
        'room.id': socket.roomId || '',
        'user.id': socket.userId || '',
      });

      // Record connection metrics
      recordCustomEvent('websocket.connection.established', {
        'connection.id': connectionId,
        'connection.duration_ms': Date.now() - startTime,
      });

      // Track message events
      const originalEmit = socket.emit;
      const originalOn = socket.on;

      socket.emit = function(event: string, ...args: any[]) {
        recordCustomEvent('websocket.message.sent', {
          'message.type': event,
          'message.size': JSON.stringify(args).length,
          'connection.id': connectionId,
        });
        
        return originalEmit.apply(this, [event, ...args]);
      };

      socket.on = function(event: string, listener: Function) {
        const wrappedListener = (...args: any[]) => {
          recordCustomEvent('websocket.message.received', {
            'message.type': event,
            'message.size': JSON.stringify(args).length,
            'connection.id': connectionId,
          });
          
          return listener.apply(this, args);
        };
        
        return originalOn.call(this, event, wrappedListener);
      };

      next();
    },
    {
      'component': 'websocket_middleware',
      'operation.type': 'websocket_connection',
    }
  ).catch((error) => {
    recordError('websocket_middleware_error', 'medium', 'websocket_metrics');
    logger.error('Error in WebSocket metrics middleware', { 
      error: error.message,
      connectionId 
    });
    next(error);
  });
}

// Database query metrics middleware
export function databaseMetricsWrapper<T>(
  operation: string,
  table: string,
  query: () => Promise<T>
): Promise<T> {
  return withSpan(
    `db.${operation}.${table}`,
    async (span) => {
      const startTime = Date.now();
      
      try {
        span.setAttributes({
          'db.system': 'postgresql',
          'db.operation': operation,
          'db.table': table,
          'component': 'database',
        });

        const result = await query();
        
        const duration = (Date.now() - startTime) / 1000;
        
        span.setAttributes({
          'db.duration_ms': duration * 1000,
          'db.success': true,
        });

        recordCustomEvent('db.query.completed', {
          'db.operation': operation,
          'db.table': table,
          'db.duration_ms': duration * 1000,
        });

        return result;
      } catch (error) {
        const duration = (Date.now() - startTime) / 1000;
        
        span.setAttributes({
          'db.duration_ms': duration * 1000,
          'db.success': false,
          'db.error': (error as Error).message,
        });

        recordError('database_query_error', 'high', 'database');
        throw error;
      }
    },
    {
      'operation.type': 'database_query',
    }
  );
}

// Asset upload metrics middleware
export function assetUploadMetricsWrapper<T>(
  assetType: string,
  operation: () => Promise<T>,
  getSize?: () => number
): Promise<T> {
  return withSpan(
    `asset.upload.${assetType}`,
    async (span) => {
      const startTime = Date.now();
      
      try {
        span.setAttributes({
          'asset.type': assetType,
          'asset.operation': 'upload',
          'component': 'asset_upload',
        });

        const result = await operation();
        
        const duration = (Date.now() - startTime) / 1000;
        const size = getSize ? getSize() : 0;
        
        span.setAttributes({
          'asset.upload.duration_ms': duration * 1000,
          'asset.upload.size_bytes': size,
          'asset.upload.success': true,
        });

        recordCustomEvent('asset.upload.completed', {
          'asset.type': assetType,
          'asset.size': size,
          'asset.duration_ms': duration * 1000,
        });

        return result;
      } catch (error) {
        const duration = (Date.now() - startTime) / 1000;
        
        span.setAttributes({
          'asset.upload.duration_ms': duration * 1000,
          'asset.upload.success': false,
          'asset.upload.error': (error as Error).message,
        });

        recordError('asset_upload_error', 'medium', 'asset_upload');
        throw error;
      }
    }
  );
}