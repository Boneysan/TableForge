// Core type exports for TableForge Phase 1 Type Safety Enhancement
// This file provides centralized exports for all shared types

// API Response Types
export type {
  ApiResponse,
  PaginatedResponse,
  ErrorResponse,
  HttpStatusCode
} from './types/api.js';

// Request Types
export type {
  AuthenticatedRequest,
  RoomRequest,
  TypedResponse,
  PaginatedRequest
} from './types/requests.js';

// User Types
export type {
  ValidatedUser,
  RoomClaims,
  UserRole,
  UserSession,
  UserPreferences as SharedUserPreferences
} from './types/user.js';

// WebSocket Types
export type {
  WebSocketEventMap,
  WebSocketEvent,
  WebSocketHandler,
  WebSocketHandlerMap,
  AuthenticatedWebSocket,
  Logger,
  RoomPlayer,
  GameState,
  Position,
  DiceRoll,
  ChatMessage,
  CardAction
} from './types/websocket.js';

// Middleware Types
export type {
  RequestContext,
  AuthenticatedRequest as MiddlewareAuthenticatedRequest,
  RoomAuthorizedRequest,
  MiddlewareFunction,
  AuthMiddleware,
  AuthenticatedMiddleware,
  RoomMiddleware
} from '../server/middleware/types.js';

// Database Types
export type {
  QueryResult,
  TransactionResult,
  DatabaseConnection,
  DatabaseError,
  Transaction,
  PaginationOptions,
  PaginatedQueryResult
} from '../server/types/database.js';

// Repository Types
export type {
  Repository,
  GameRoomRepository,
  UserRepository,
  AssetRepository,
  GameRoom,
  CreateRoomInput,
  UpdateRoomInput,
  GameRoomWithPlayers,
  User,
  CreateUserInput,
  UpdateUserInput,
  Asset,
  CreateAssetInput,
  UpdateAssetInput
} from '../server/repositories/types.js';

// Re-export validation schemas from shared/schema
export * from './schema.js';

// Type utility helpers
export type Prettify<T> = {
  [K in keyof T]: T[K];
} & {};

export type Optional<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;

export type RequiredKeys<T> = {
  [K in keyof T]-?: {} extends Pick<T, K> ? never : K;
}[keyof T];

export type OptionalKeys<T> = {
  [K in keyof T]-?: {} extends Pick<T, K> ? K : never;
}[keyof T];
