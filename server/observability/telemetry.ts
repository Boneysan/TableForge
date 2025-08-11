import { trace, context, SpanStatusCode, SpanKind } from '@opentelemetry/api';
import type { Span } from '@opentelemetry/api';
import { logger } from '@server/utils/logger';

// Simple telemetry implementation without full SDK for now
let telemetryInitialized = false;

// Initialize telemetry
export function initializeTelemetry(): void {
  try {
    if (telemetryInitialized) return;
    
    telemetryInitialized = true;
    logger.info('Telemetry system initialized (lightweight mode)', {
      endpoint: process.env.OTLP_ENDPOINT || 'not configured',
      service: 'vorpal-board',
      version: '1.0.0',
    });
  } catch (error) {
    logger.error('Failed to initialize telemetry system', { error });
  }
}

// Shutdown telemetry
export async function shutdownTelemetry(): Promise<void> {
  try {
    telemetryInitialized = false;
    logger.info('Telemetry system shutdown successfully');
  } catch (error) {
    logger.error('Failed to shutdown telemetry system', { error });
  }
}

// Get tracer instance
const tracer = trace.getTracer('vorpal-board', '1.0.0');

// Common trace utilities
export interface TraceContext {
  traceId: string;
  spanId: string;
  userId?: string;
  roomId?: string;
  sessionId?: string;
}

export function getCurrentTraceContext(): TraceContext | null {
  const span = trace.getActiveSpan();
  if (!span) return null;

  const spanContext = span.spanContext();
  return {
    traceId: spanContext.traceId,
    spanId: spanContext.spanId,
  };
}

// Trace decorator for methods
export function traced(operationName: string, attributes: Record<string, string | number> = {}) {
  return function (target: any, propertyName: string, descriptor: PropertyDescriptor) {
    const method = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      const span = tracer.startSpan(`${operationName}.${propertyName}`, {
        kind: SpanKind.INTERNAL,
        attributes: {
          'operation.name': operationName,
          'method.name': propertyName,
          ...attributes,
        },
      });

      try {
        const result = await context.with(trace.setSpan(context.active(), span), () => {
          return method.apply(this, args);
        });

        span.setStatus({ code: SpanStatusCode.OK });
        return result;
      } catch (error) {
        span.recordException(error as Error);
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: (error as Error).message,
        });
        throw error;
      } finally {
        span.end();
      }
    };

    return descriptor;
  };
}

// Manual span creation utilities
export function createSpan(
  name: string,
  attributes: Record<string, string | number | boolean> = {},
  kind: SpanKind = SpanKind.INTERNAL
): Span {
  return tracer.startSpan(name, {
    kind,
    attributes: {
      'service.name': 'vorpal-board',
      ...attributes,
    },
  });
}

export function withSpan<T>(
  name: string,
  fn: (span: Span) => Promise<T> | T,
  attributes: Record<string, string | number | boolean> = {}
): Promise<T> {
  const span = createSpan(name, attributes);

  return context.with(trace.setSpan(context.active(), span), async () => {
    try {
      const result = await fn(span);
      span.setStatus({ code: SpanStatusCode.OK });
      return result;
    } catch (error) {
      span.recordException(error as Error);
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: (error as Error).message,
      });
      throw error;
    } finally {
      span.end();
    }
  });
}

// Deck move specific tracing
export interface DeckMoveTraceAttributes {
  roomId: string;
  playerId: string;
  moveType: string;
  sourceType: string;
  targetType: string;
  cardCount: number;
  sourceId?: string;
  targetId?: string;
  moveId: string;
  clientId: string;
}

export function traceDeckMoveOperation<T>(
  operationName: string,
  attributes: DeckMoveTraceAttributes,
  fn: (span: Span) => Promise<T> | T
): Promise<T> {
  return withSpan(
    `deck.move.${operationName}`,
    fn,
    {
      'deck.move.type': attributes.moveType,
      'deck.move.source.type': attributes.sourceType,
      'deck.move.target.type': attributes.targetType,
      'deck.move.card.count': attributes.cardCount,
      'deck.move.id': attributes.moveId,
      'deck.move.client.id': attributes.clientId,
      'room.id': attributes.roomId,
      'player.id': attributes.playerId,
      'deck.move.source.id': attributes.sourceId || '',
      'deck.move.target.id': attributes.targetId || '',
    }
  );
}

// WebSocket tracing utilities
export interface WebSocketTraceAttributes {
  roomId?: string;
  playerId?: string;
  eventType: string;
  messageId?: string;
  connectionId: string;
}

export function traceWebSocketOperation<T>(
  operationName: string,
  attributes: WebSocketTraceAttributes,
  fn: (span: Span) => Promise<T> | T
): Promise<T> {
  return withSpan(
    `websocket.${operationName}`,
    fn,
    {
      'websocket.event.type': attributes.eventType,
      'websocket.connection.id': attributes.connectionId,
      'websocket.message.id': attributes.messageId || '',
      'room.id': attributes.roomId || '',
      'player.id': attributes.playerId || '',
    }
  );
}

// Database operation tracing
export function traceDatabaseOperation<T>(
  operationName: string,
  table: string,
  operation: 'select' | 'insert' | 'update' | 'delete',
  fn: (span: Span) => Promise<T> | T
): Promise<T> {
  return withSpan(
    `db.${operationName}`,
    fn,
    {
      'db.operation': operation,
      'db.table': table,
      'db.system': 'postgresql',
    }
  );
}

// Custom event recording
export function recordCustomEvent(
  name: string,
  attributes: Record<string, string | number | boolean> = {}
): void {
  const span = trace.getActiveSpan();
  if (span) {
    span.addEvent(name, attributes);
  }
}

// Error tracking
export function recordError(error: Error, attributes: Record<string, string | number> = {}): void {
  const span = trace.getActiveSpan();
  if (span) {
    span.recordException(error);
    span.setAttributes({
      'error.type': error.constructor.name,
      'error.message': error.message,
      'error.stack': error.stack || '',
      ...attributes,
    });
  }
}

// Performance timing utilities
export class PerformanceTimer {
  private startTime: number;
  private span: Span | null;

  constructor(operationName: string, attributes: Record<string, string | number> = {}) {
    this.startTime = Date.now();
    this.span = trace.getActiveSpan();
    
    if (this.span) {
      this.span.setAttributes({
        'performance.operation': operationName,
        'performance.start_time': this.startTime,
        ...attributes,
      });
    }
  }

  end(): number {
    const duration = Date.now() - this.startTime;
    
    if (this.span) {
      this.span.setAttributes({
        'performance.duration_ms': duration,
        'performance.end_time': Date.now(),
      });
    }
    
    return duration;
  }
}

// Trace sampling utilities
export function shouldSampleTrace(operation: string, roomId?: string): boolean {
  // Always sample errors and critical operations
  if (operation.includes('error') || operation.includes('auth')) {
    return true;
  }

  // Sample 10% of regular operations
  if (Math.random() < 0.1) {
    return true;
  }

  // Sample all operations for specific rooms (for debugging)
  if (roomId && process.env.TRACE_ROOM_IDS?.split(',').includes(roomId)) {
    return true;
  }

  return false;
}

export { tracer };