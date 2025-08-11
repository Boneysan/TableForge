import { WebSocket } from 'ws';
import { createRoomLogger, createUserLogger, ContextLogger, auditLog, LogContext } from '../utils/logger';

// Extended WebSocket interface with logging context
export interface LoggedWebSocket extends WebSocket {
  logger?: ContextLogger;
  userId?: string;
  roomId?: string;
  sessionId?: string;
  correlationId?: string;
}

// WebSocket event types for logging
export enum WSEventType {
  CONNECTION = 'connection',
  DISCONNECTION = 'disconnection',
  JOIN_ROOM = 'join_room',
  LEAVE_ROOM = 'leave_room',
  MESSAGE = 'message',
  ERROR = 'error',
  AUTHENTICATION = 'authentication',
  AUTHORIZATION = 'authorization'
}

// Initialize WebSocket logging context
export function initializeWebSocketLogging(
  ws: LoggedWebSocket, 
  userId?: string, 
  roomId?: string,
  sessionId?: string
) {
  ws.userId = userId;
  ws.roomId = roomId;
  ws.sessionId = sessionId;
  ws.correlationId = ws.correlationId || randomUUID();
  
  // Create context-aware logger
  if (roomId && userId) {
    ws.logger = createRoomLogger(roomId, userId);
  } else if (userId) {
    ws.logger = createUserLogger(userId, ws.correlationId);
  } else {
    ws.logger = createUserLogger('anonymous', ws.correlationId);
  }
  
  ws.logger.info('WebSocket logging initialized', {
    sessionId,
    hasRoomId: !!roomId,
    hasUserId: !!userId
  });
}

// Log WebSocket events with context
export function logWebSocketEvent(
  ws: LoggedWebSocket,
  eventType: WSEventType,
  data?: any,
  error?: Error
) {
  const context: LogContext = {
    userId: ws.userId,
    roomId: ws.roomId,
    sessionId: ws.sessionId,
    correlationId: ws.correlationId,
    eventType,
    timestamp: new Date().toISOString()
  };
  
  const message = `🔌 WebSocket ${eventType}: ${ws.userId || 'anonymous'}${ws.roomId ? ` in room ${ws.roomId}` : ''}`;
  
  if (error) {
    ws.logger?.error(message, { ...context, error: error.message, data });
  } else {
    ws.logger?.info(message, { ...context, data });
  }
  
  // Audit sensitive events
  if (ws.userId && [WSEventType.JOIN_ROOM, WSEventType.LEAVE_ROOM, WSEventType.AUTHENTICATION].includes(eventType)) {
    auditLog(
      eventType,
      ws.roomId ? `room:${ws.roomId}` : 'websocket',
      {
        userId: ws.userId,
        result: error ? 'failure' : 'success',
        correlationId: ws.correlationId,
        details: { sessionId: ws.sessionId, data, error: error?.message }
      }
    );
  }
}

// Log message events with detailed context
export function logWebSocketMessage(
  ws: LoggedWebSocket,
  messageType: string,
  messageData: any,
  direction: 'incoming' | 'outgoing' = 'incoming'
) {
  const context = {
    userId: ws.userId,
    roomId: ws.roomId,
    sessionId: ws.sessionId,
    correlationId: ws.correlationId,
    messageType,
    direction,
    timestamp: new Date().toISOString(),
    messageSize: JSON.stringify(messageData).length
  };
  
  ws.logger?.debug(`📨 WebSocket ${direction} message: ${messageType}`, {
    ...context,
    messageData: process.env.NODE_ENV === 'development' ? messageData : '[REDACTED]'
  });
}

// Log authentication events
export function logWebSocketAuth(
  ws: LoggedWebSocket,
  authEvent: 'token_received' | 'token_validated' | 'auth_failed' | 'auth_expired',
  details?: any
) {
  const context = {
    userId: ws.userId,
    sessionId: ws.sessionId,
    correlationId: ws.correlationId,
    authEvent,
    timestamp: new Date().toISOString()
  };
  
  const isError = authEvent === 'auth_failed' || authEvent === 'auth_expired';
  const message = `🔐 WebSocket auth event: ${authEvent}`;
  
  if (isError) {
    ws.logger?.warn(message, { ...context, details });
  } else {
    ws.logger?.info(message, { ...context, details });
  }
}

// Log room operations with enhanced context
export function logRoomOperation(
  ws: LoggedWebSocket,
  operation: string,
  target?: string,
  result: 'success' | 'failure' = 'success',
  details?: any
) {
  const context = {
    userId: ws.userId,
    roomId: ws.roomId,
    sessionId: ws.sessionId,
    correlationId: ws.correlationId,
    operation,
    target,
    result,
    timestamp: new Date().toISOString()
  };
  
  const message = `🎲 Room operation: ${operation}${target ? ` on ${target}` : ''} - ${result}`;
  
  if (result === 'failure') {
    ws.logger?.warn(message, { ...context, details });
  } else {
    ws.logger?.info(message, { ...context, details });
  }
  
  // Audit room modifications
  if (ws.userId && ws.roomId && ['move_asset', 'create_deck', 'roll_dice', 'resize_board'].includes(operation)) {
    auditLog(
      operation,
      `room:${ws.roomId}`,
      {
        userId: ws.userId,
        result,
        correlationId: ws.correlationId,
        details: { target, ...details }
      }
    );
  }
}

// Performance timing for WebSocket operations
export function timeWebSocketOperation(
  ws: LoggedWebSocket,
  operation: string
): () => void {
  const start = Date.now();
  
  return () => {
    const duration = Date.now() - start;
    
    ws.logger?.info(`⚡ WebSocket operation timing: ${operation}`, {
      userId: ws.userId,
      roomId: ws.roomId,
      sessionId: ws.sessionId,
      correlationId: ws.correlationId,
      operation,
      duration,
      timestamp: new Date().toISOString()
    });
    
    // Log slow operations
    if (duration > 1000) {
      ws.logger?.warn(`🐌 Slow WebSocket operation: ${operation} took ${duration}ms`, {
        userId: ws.userId,
        roomId: ws.roomId,
        operation,
        duration
      });
    }
  };
}

// Clean up WebSocket logging context
export function cleanupWebSocketLogging(ws: LoggedWebSocket, reason?: string) {
  logWebSocketEvent(ws, WSEventType.DISCONNECTION, { reason });
  
  // Clear context
  delete ws.logger;
  delete ws.userId;
  delete ws.roomId;
  delete ws.sessionId;
  delete ws.correlationId;
}

// Helper to extract meaningful WebSocket error info
export function extractWebSocketError(error: any) {
  return {
    message: error?.message || 'Unknown WebSocket error',
    code: error?.code,
    type: error?.type,
    stack: process.env.NODE_ENV === 'development' ? error?.stack : undefined
  };
}

import { randomUUID } from 'crypto';

export { LoggedWebSocket, WSEventType };