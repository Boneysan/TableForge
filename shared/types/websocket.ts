/**
 * WebSocket type definitions for real-time communication
 */
import type { ValidatedUser } from './user';

// Core WebSocket event types
export type WebSocketEventType = 
  | 'connection'
  | 'disconnect'
  | 'joinRoom'
  | 'leaveRoom'
  | 'gameAction'
  | 'chatMessage'
  | 'systemNotification'
  | 'error'
  | 'ping'
  | 'pong';

// Base WebSocket message structure
export interface BaseWebSocketMessage {
  id: string;
  type: WebSocketEventType;
  timestamp: string;
  roomId?: string;
  correlationId?: string;
}

// Client to server messages
export interface ClientToServerMessage extends BaseWebSocketMessage {
  data: unknown;
}

// Server to client messages
export interface ServerToClientMessage extends BaseWebSocketMessage {
  data: unknown;
  broadcast?: boolean;
  targetUsers?: string[];
}

// Authenticated WebSocket message
export interface AuthenticatedWebSocketMessage extends ClientToServerMessage {
  userId: string;
  user: ValidatedUser;
}

// Room-specific WebSocket message
export interface RoomWebSocketMessage extends AuthenticatedWebSocketMessage {
  roomId: string;
}

// Game action messages
export interface GameActionMessage extends RoomWebSocketMessage {
  type: 'gameAction';
  data: {
    action: string;
    payload: Record<string, unknown>;
    sequence: number;
    clientTime: string;
  };
}

// Chat message structure
export interface ChatMessage extends RoomWebSocketMessage {
  type: 'chatMessage';
  data: {
    message: string;
    messageType: 'text' | 'emote' | 'system' | 'whisper';
    targetUser?: string;
    metadata?: {
      color?: string;
      fontSize?: number;
      effects?: string[];
    };
  };
}

// Connection event
export interface ConnectionMessage extends BaseWebSocketMessage {
  type: 'connection';
  data: {
    userId?: string;
    sessionId: string;
    clientInfo: {
      userAgent: string;
      platform: string;
      version: string;
    };
  };
}

// Disconnection event
export interface DisconnectionMessage extends BaseWebSocketMessage {
  type: 'disconnect';
  data: {
    userId?: string;
    reason: 'client_disconnect' | 'server_shutdown' | 'timeout' | 'error';
    code?: number;
    message?: string;
  };
}

// Room join/leave events
export interface RoomJoinMessage extends AuthenticatedWebSocketMessage {
  type: 'joinRoom';
  data: {
    roomId: string;
    password?: string;
    role?: 'player' | 'observer';
  };
}

export interface RoomLeaveMessage extends AuthenticatedWebSocketMessage {
  type: 'leaveRoom';
  data: {
    roomId: string;
    reason?: 'voluntary' | 'kicked' | 'banned' | 'error';
  };
}

// System notifications
export interface SystemNotificationMessage extends BaseWebSocketMessage {
  type: 'systemNotification';
  data: {
    level: 'info' | 'warning' | 'error' | 'success';
    title: string;
    message: string;
    duration?: number;
    actions?: Array<{
      label: string;
      action: string;
      style?: 'primary' | 'secondary' | 'danger';
    }>;
  };
}

// Error messages
export interface ErrorMessage extends BaseWebSocketMessage {
  type: 'error';
  data: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
    recoverable: boolean;
    retryable: boolean;
  };
}

// Ping/Pong for connection health
export interface PingMessage extends BaseWebSocketMessage {
  type: 'ping';
  data: {
    timestamp: string;
    sequence: number;
  };
}

export interface PongMessage extends BaseWebSocketMessage {
  type: 'pong';
  data: {
    timestamp: string;
    sequence: number;
    latency?: number;
  };
}

// WebSocket connection state
export interface WebSocketConnection {
  id: string;
  userId?: string;
  user?: ValidatedUser;
  roomIds: Set<string>;
  state: 'connecting' | 'connected' | 'authenticated' | 'disconnecting' | 'disconnected';
  connectedAt: string;
  lastActivity: string;
  metadata: {
    userAgent: string;
    ip: string;
    platform: string;
    version: string;
  };
  metrics: {
    messagesSent: number;
    messagesReceived: number;
    bytesTransferred: number;
    latency: number;
    errors: number;
  };
}

// Room state for WebSocket management
export interface WebSocketRoom {
  id: string;
  name: string;
  connections: Map<string, WebSocketConnection>;
  messageHistory: ServerToClientMessage[];
  settings: {
    maxConnections: number;
    messageRateLimit: number;
    historyLimit: number;
    requireAuth: boolean;
  };
  state: {
    isActive: boolean;
    lastActivity: string;
    connectionCount: number;
  };
}

// WebSocket server events
export interface WebSocketServerEvents {
  connection: (connection: WebSocketConnection) => void;
  disconnect: (connection: WebSocketConnection, reason: string) => void;
  message: (connection: WebSocketConnection, message: ClientToServerMessage) => void;
  authenticated: (connection: WebSocketConnection, user: ValidatedUser) => void;
  joinRoom: (connection: WebSocketConnection, roomId: string) => void;
  leaveRoom: (connection: WebSocketConnection, roomId: string) => void;
  error: (connection: WebSocketConnection, error: Error) => void;
}

// WebSocket client events
export interface WebSocketClientEvents {
  connect: () => void;
  disconnect: (reason: string) => void;
  message: (message: ServerToClientMessage) => void;
  error: (error: ErrorMessage) => void;
  roomJoined: (roomId: string) => void;
  roomLeft: (roomId: string) => void;
  userJoined: (user: ValidatedUser, roomId: string) => void;
  userLeft: (userId: string, roomId: string) => void;
  gameAction: (action: GameActionMessage) => void;
  chatMessage: (message: ChatMessage) => void;
  systemNotification: (notification: SystemNotificationMessage) => void;
}

// Message handlers
export type MessageHandler<T extends ClientToServerMessage = ClientToServerMessage> = (
  connection: WebSocketConnection,
  message: T
) => Promise<void> | void;

export type AuthenticatedMessageHandler<T extends AuthenticatedWebSocketMessage = AuthenticatedWebSocketMessage> = (
  connection: WebSocketConnection & { user: ValidatedUser },
  message: T
) => Promise<void> | void;

export type RoomMessageHandler<T extends RoomWebSocketMessage = RoomWebSocketMessage> = (
  connection: WebSocketConnection & { user: ValidatedUser },
  message: T,
  room: WebSocketRoom
) => Promise<void> | void;

// WebSocket middleware
export interface WebSocketMiddleware {
  name: string;
  priority: number;
  handler: (
    connection: WebSocketConnection,
    message: ClientToServerMessage,
    next: () => Promise<void>
  ) => Promise<void>;
}

// Rate limiting for WebSocket
export interface WebSocketRateLimit {
  windowMs: number;
  maxMessages: number;
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
  keyGenerator?: (connection: WebSocketConnection) => string;
}

// WebSocket authentication context
export interface WebSocketAuthContext {
  isAuthenticated: boolean;
  user?: ValidatedUser;
  token?: string;
  sessionId: string;
  permissions: string[];
  roomClaims: Map<string, {
    role: 'owner' | 'admin' | 'player';
    permissions: string[];
  }>;
}

// Message validation schemas
export interface MessageValidationSchema {
  type: WebSocketEventType;
  required: string[];
  properties: Record<string, {
    type: 'string' | 'number' | 'boolean' | 'object' | 'array';
    format?: string;
    minLength?: number;
    maxLength?: number;
    min?: number;
    max?: number;
    enum?: unknown[];
    pattern?: string;
  }>;
  additionalProperties?: boolean;
}

// WebSocket configuration
export interface WebSocketConfig {
  port: number;
  path: string;
  cors: {
    origin: string | string[];
    credentials: boolean;
  };
  authentication: {
    required: boolean;
    tokenHeader: string;
    tokenParam: string;
  };
  limits: {
    maxConnections: number;
    maxRoomsPerUser: number;
    messageRateLimit: WebSocketRateLimit;
    payloadLimit: number;
  };
  heartbeat: {
    interval: number;
    timeout: number;
  };
  cleanup: {
    inactiveTimeout: number;
    orphanedRoomTimeout: number;
  };
}

// Type guards
export function isAuthenticatedMessage(
  message: ClientToServerMessage
): message is AuthenticatedWebSocketMessage {
  return 'userId' in message && 'user' in message;
}

export function isRoomMessage(
  message: ClientToServerMessage
): message is RoomWebSocketMessage {
  return isAuthenticatedMessage(message) && 'roomId' in message && !!message.roomId;
}

export function isGameActionMessage(
  message: ClientToServerMessage
): message is GameActionMessage {
  return message.type === 'gameAction' && isRoomMessage(message);
}

export function isChatMessage(
  message: ClientToServerMessage
): message is ChatMessage {
  return message.type === 'chatMessage' && isRoomMessage(message);
}

export function isSystemNotification(
  message: ServerToClientMessage
): message is SystemNotificationMessage {
  return message.type === 'systemNotification';
}

export function isErrorMessage(
  message: ServerToClientMessage
): message is ErrorMessage {
  return message.type === 'error';
}

// WebSocket utilities
export interface WebSocketUtils {
  generateMessageId(): string;
  validateMessage(message: unknown, schema: MessageValidationSchema): boolean;
  sanitizeMessage(message: ClientToServerMessage): ClientToServerMessage;
  broadcastToRoom(roomId: string, message: ServerToClientMessage): Promise<void>;
  broadcastToUser(userId: string, message: ServerToClientMessage): Promise<void>;
  getConnectionsByRoom(roomId: string): WebSocketConnection[];
  getUserConnections(userId: string): WebSocketConnection[];
  getRoomState(roomId: string): WebSocketRoom | null;
  cleanupInactiveConnections(): Promise<void>;
}

// Message queuing for offline delivery
export interface OfflineMessage {
  id: string;
  userId: string;
  message: ServerToClientMessage;
  createdAt: string;
  expiresAt: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  deliveryAttempts: number;
  maxDeliveryAttempts: number;
}

// WebSocket analytics
export interface WebSocketMetrics {
  totalConnections: number;
  activeConnections: number;
  totalRooms: number;
  activeRooms: number;
  messagesPerSecond: number;
  bytesPerSecond: number;
  averageLatency: number;
  errorRate: number;
  connectionDuration: {
    average: number;
    p50: number;
    p95: number;
    p99: number;
  };
}

// Connection pool management
export interface ConnectionPool {
  maxSize: number;
  currentSize: number;
  availableConnections: number;
  busyConnections: number;
  queuedRequests: number;
  acquire(): Promise<WebSocketConnection>;
  release(connection: WebSocketConnection): void;
  drain(): Promise<void>;
  clear(): Promise<void>;
}

// Load balancing for WebSocket servers
export interface WebSocketLoadBalancer {
  strategy: 'round-robin' | 'least-connections' | 'weighted' | 'hash';
  servers: Array<{
    id: string;
    url: string;
    weight: number;
    health: 'healthy' | 'unhealthy' | 'unknown';
    connections: number;
    lastCheck: string;
  }>;
  selectServer(userId?: string): string | null;
  updateServerHealth(serverId: string, isHealthy: boolean): void;
  redistributeConnections(): Promise<void>;
}
