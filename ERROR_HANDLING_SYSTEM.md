# Error Handling & Logging System

## Overview

This document describes the comprehensive error handling and structured logging system implemented in Vorpal Board. The system provides standardized error responses, centralized error handling, and rich contextual logging with correlation IDs.

## Error Envelope Format

All API errors follow a standardized envelope format:

```json
{
  "code": "VALIDATION_ERROR",
  "message": "User-friendly error message",
  "details": {
    "field": "email",
    "constraint": "required"
  },
  "requestId": "uuid-correlation-id",
  "timestamp": "2025-08-11T05:00:00.000Z"
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `VALIDATION_ERROR` | 400 | Input validation failed |
| `AUTHENTICATION_ERROR` | 401 | Authentication required or failed |
| `AUTHORIZATION_ERROR` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `CONFLICT` | 409 | Resource conflict (e.g., duplicate) |
| `RATE_LIMITED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Unexpected server error |
| `DATABASE_ERROR` | 500 | Database operation failed |
| `EXTERNAL_SERVICE_ERROR` | 502 | External service unavailable |

## Error Handling Middleware

### Central Error Handler

The `errorHandler` middleware automatically maps different error types to standardized responses:

- **Zod Validation Errors** → 400 with field-level details
- **Database Constraint Errors** → 409 for conflicts, 400 for other constraints
- **Firebase Auth Errors** → 401 with Firebase error context
- **Custom App Errors** → Status code from error class
- **Unexpected Errors** → 500 with sanitized message in production

### Custom Error Classes

```typescript
// Usage examples
throw new ValidationError("Invalid email format", { field: "email" });
throw new AuthenticationError("Token expired");
throw new AuthorizationError("GM role required");
throw new NotFoundError("Room not found", { resource: "room" });
throw new ConflictError("Username already taken");
```

### Async Route Wrapper

Use `asyncHandler` to automatically catch async errors:

```typescript
app.get('/api/users', asyncHandler(async (req, res) => {
  const users = await storage.getUsers();
  res.json(users);
}));
```

## Structured Logging System

### Logger Configuration

The system uses Pino for structured JSON logging with different configurations for development and production:

- **Development**: Pretty-printed logs with colors and timestamps
- **Production**: Structured JSON logs with sensitive field redaction

### Correlation IDs

Every request gets a unique correlation ID that tracks the request across all logs and error responses:

```typescript
// Automatically added to request
req.correlationId // "uuid-v4"

// Available in response headers
X-Correlation-ID: "uuid-v4"
```

### Context-Aware Logging

The system provides context-aware loggers that automatically include relevant metadata:

```typescript
// API request logger
const requestLogger = createRequestLogger(req);
requestLogger.info("Processing user request", { action: "create_room" });

// Room operation logger  
const roomLogger = createRoomLogger(roomId, userId);
roomLogger.info("User joined room", { role: "player" });

// User-specific logger
const userLogger = createUserLogger(userId);
userLogger.warn("Failed login attempt", { reason: "invalid_password" });
```

## WebSocket Logging

### Enhanced WebSocket Context

WebSockets are enhanced with logging context that persists throughout the connection:

```typescript
interface LoggedWebSocket extends WebSocket {
  logger?: ContextLogger;
  userId?: string;
  roomId?: string;
  sessionId?: string;
  correlationId?: string;
}
```

### WebSocket Event Logging

All WebSocket events are logged with full context:

```typescript
// Connection events
logWebSocketEvent(ws, WSEventType.CONNECTION, { userAgent });
logWebSocketEvent(ws, WSEventType.JOIN_ROOM, { roomId });
logWebSocketEvent(ws, WSEventType.DISCONNECTION, { reason });

// Message events
logWebSocketMessage(ws, 'asset_moved', messageData, 'incoming');

// Authentication events
logWebSocketAuth(ws, 'token_validated', { expiresAt });

// Room operations
logRoomOperation(ws, 'move_asset', 'token-123', 'success');
```

### Performance Timing

WebSocket operations can be timed for performance monitoring:

```typescript
const endTimer = timeWebSocketOperation(ws, 'move_asset');
// ... perform operation
endTimer(); // Automatically logs duration
```

## Security & Audit Logging

### Audit Trail

Sensitive operations are automatically logged to the audit trail:

```typescript
auditLog('user_created', 'user:123', {
  userId: '123',
  result: 'success',
  correlationId: req.correlationId,
  details: { source: 'firebase' }
});
```

### Security Events

Security-relevant events are logged with special handling:

```typescript
const logger = createUserLogger(userId);
logger.security('suspicious_login', {
  attempts: 5,
  timeWindow: '5min',
  ipAddress: req.ip
});
```

## Health Monitoring

### Health Checks

Services can report health status:

```typescript
healthCheck('database', 'healthy', { connectionCount: 10 });
healthCheck('firebase', 'unhealthy', { error: 'connection_timeout' });
```

### Performance Metrics

Performance data is automatically captured:

```typescript
logPerformance({
  operation: 'create_room',
  duration: 150,
  success: true,
  metadata: { roomType: 'private' }
});
```

## Implementation Files

- `server/middleware/errorHandler.ts` - Error handling middleware and classes
- `server/utils/logger.ts` - Structured logging utilities
- `server/websocket/logging.ts` - WebSocket-specific logging
- `shared/validators.ts` - Error response schemas

## Environment Configuration

```env
LOG_LEVEL=debug|info|warn|error
NODE_ENV=development|production
```

## Integration Examples

### API Route with Full Error Handling

```typescript
app.post('/api/rooms', 
  hybridAuthMiddleware,
  validateBody(createRoomRequestSchema),
  asyncHandler(async (req, res) => {
    const requestLogger = createRequestLogger(req);
    const endTimer = requestLogger.time('create_room');
    
    try {
      if (!req.user?.uid) {
        throw new AuthenticationError("User not authenticated");
      }
      
      const room = await storage.createRoom({
        name: req.body.name,
        ownerId: req.user.uid
      });
      
      auditLog('room_created', `room:${room.id}`, {
        userId: req.user.uid,
        result: 'success',
        correlationId: req.correlationId
      });
      
      requestLogger.info("Room created successfully", { roomId: room.id });
      res.status(201).json(room);
      
    } finally {
      endTimer();
    }
  })
);
```

### WebSocket Handler with Context Logging

```typescript
function handleWebSocketMessage(ws: LoggedWebSocket, message: any) {
  const endTimer = timeWebSocketOperation(ws, message.type);
  
  try {
    logWebSocketMessage(ws, message.type, message.payload, 'incoming');
    
    switch (message.type) {
      case 'move_asset':
        // Process message
        logRoomOperation(ws, 'move_asset', message.payload.assetId, 'success');
        break;
    }
  } catch (error) {
    ws.logger?.error("WebSocket message processing failed", { 
      messageType: message.type,
      error: error.message 
    });
    logRoomOperation(ws, message.type, undefined, 'failure', { error: error.message });
  } finally {
    endTimer();
  }
}
```

This comprehensive error handling and logging system provides enterprise-grade observability, debugging capabilities, and security monitoring for the Vorpal Board platform.