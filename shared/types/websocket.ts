/**
 * WebSocket type definitions for real-time communication
 * Following Phase 1 Type Safety Enhancement Guide
 */
import type { ValidatedUser } from './user';

// Strict typing for all WebSocket events as per Phase 1 guide section 2.1
export interface WebSocketEventMap {
  // Authentication events
  'auth:success': { user: ValidatedUser };
  'auth:failed': { error: string; details?: unknown };
  'token:expired': { message: string };
  
  // Room events
  'room:joined': { roomId: string; players: RoomPlayer[] };
  'room:left': { roomId: string; playerId: string };
  'room:state_updated': { roomId: string; state: GameState };
  
  // Asset events
  'asset:moved': { assetId: string; position: Position; playerId: string };
  'asset:flipped': { assetId: string; isFlipped: boolean; playerId: string };
  
  // Game events
  'dice:rolled': { roomId: string; result: DiceRoll; playerId: string };
  'chat:message': { roomId: string; message: ChatMessage };
  'card:action': { roomId: string; action: CardAction };
}

// Type-safe WebSocket event structure from Phase 1 guide section 2.1
export type WebSocketEvent<K extends keyof WebSocketEventMap> = {
  type: K;
  data: WebSocketEventMap[K];
  timestamp: string;
  correlationId: string;
};

// Enhanced WebSocket interface with authentication from Phase 1 guide section 2.1
export interface AuthenticatedWebSocket extends WebSocket {
  user?: ValidatedUser;
  roomId?: string;
  isAuthenticated: boolean;
  lastActivity: number;
}

// Logger interface for handler context
export interface Logger {
  info: (message: string, meta?: object) => void;
  warn: (message: string, meta?: object) => void;
  error: (message: string, meta?: object) => void;
  debug: (message: string, meta?: object) => void;
}

// Type-safe WebSocket message handlers from Phase 1 guide section 2.2
export type WebSocketHandler<K extends keyof WebSocketEventMap> = (
  socket: AuthenticatedWebSocket,
  data: WebSocketEventMap[K],
  context: {
    correlationId: string;
    timestamp: string;
    logger: Logger;
  }
) => Promise<void> | void;

export type WebSocketHandlerMap = {
  [K in keyof WebSocketEventMap]: WebSocketHandler<K>;
}

// Supporting types for the event map
export interface RoomPlayer {
  id: string;
  userId: string;
  displayName: string;
  role: 'owner' | 'gm' | 'player' | 'observer';
  isOnline: boolean;
  joinedAt: string;
  character?: {
    id: string;
    name: string;
    avatar?: string;
  };
}

export interface GameState {
  id: string;
  turn: number;
  phase: string;
  activePlayer: string | null;
  board?: BoardState;
  players: Record<string, PlayerState>;
  metadata: Record<string, unknown>;
  lastUpdated: string;
}

export interface BoardState {
  width: number;
  height: number;
  assets: BoardAsset[];
  background?: string;
  grid?: {
    size: number;
    visible: boolean;
    snapToGrid: boolean;
  };
}

export interface BoardAsset {
  id: string;
  type: 'token' | 'card' | 'dice' | 'marker' | 'area';
  position: Position;
  ownerId: string;
  properties: Record<string, unknown>;
  locked: boolean;
  visible: boolean;
}

export interface Position {
  x: number;
  y: number;
  z?: number;
  rotation?: number;
}

export interface PlayerState {
  id: string;
  resources: Record<string, number>;
  hand: Card[];
  score: number;
  status: 'active' | 'inactive' | 'ready' | 'waiting';
  turnOrder: number;
}

export interface Card {
  id: string;
  deckId: string;
  name: string;
  type: string;
  properties: Record<string, unknown>;
  faceUp: boolean;
}

export interface DiceRoll {
  id: string;
  dice: Array<{
    sides: number;
    result: number;
    modifier?: number;
  }>;
  total: number;
  timestamp: string;
  expression?: string; // e.g., "2d6+3"
}

export interface ChatMessage {
  id: string;
  userId: string;
  displayName: string;
  message: string;
  messageType: 'text' | 'emote' | 'system' | 'whisper' | 'ooc';
  targetUserId?: string; // for whispers
  timestamp: string;
  metadata?: {
    color?: string;
    fontSize?: number;
    effects?: string[];
  };
}

export interface CardAction {
  id: string;
  type: 'play' | 'draw' | 'discard' | 'shuffle' | 'peek' | 'pass';
  cardId?: string;
  deckId?: string;
  targetPlayerId?: string;
  position?: Position;
  properties?: Record<string, unknown>;
}

// Type guards for event validation
export function isWebSocketEvent<K extends keyof WebSocketEventMap>(
  message: unknown,
  type: K
): message is WebSocketEvent<K> {
  return (
    typeof message === 'object' &&
    message !== null &&
    'type' in message &&
    'data' in message &&
    'timestamp' in message &&
    'correlationId' in message &&
    (message as WebSocketEvent<K>).type === type
  );
}

export function isAuthenticatedConnection(
  socket: AuthenticatedWebSocket
): socket is AuthenticatedWebSocket & { user: ValidatedUser } {
  return socket.isAuthenticated && !!socket.user;
}

// Event factory functions for type safety
export function createWebSocketEvent<K extends keyof WebSocketEventMap>(
  type: K,
  data: WebSocketEventMap[K],
  correlationId?: string
): WebSocketEvent<K> {
  return {
    type,
    data,
    timestamp: new Date().toISOString(),
    correlationId: correlationId || crypto.randomUUID()
  };
}

// Helper functions for common events
export const WebSocketEventFactory = {
  authSuccess: (user: ValidatedUser): WebSocketEvent<'auth:success'> =>
    createWebSocketEvent('auth:success', { user }),
    
  authFailed: (error: string, details?: unknown): WebSocketEvent<'auth:failed'> =>
    createWebSocketEvent('auth:failed', { error, details }),
    
  roomJoined: (roomId: string, players: RoomPlayer[]): WebSocketEvent<'room:joined'> =>
    createWebSocketEvent('room:joined', { roomId, players }),
    
  chatMessage: (roomId: string, message: ChatMessage): WebSocketEvent<'chat:message'> =>
    createWebSocketEvent('chat:message', { roomId, message }),
    
  diceRolled: (roomId: string, result: DiceRoll, playerId: string): WebSocketEvent<'dice:rolled'> =>
    createWebSocketEvent('dice:rolled', { roomId, result, playerId }),
    
  cardAction: (roomId: string, action: CardAction): WebSocketEvent<'card:action'> =>
    createWebSocketEvent('card:action', { roomId, action })
};
