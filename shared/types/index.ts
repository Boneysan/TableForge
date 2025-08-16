/**
 * Centralized type exports for TableForge
 * 
 * This index file provides a single point of access to all type definitions
 * across the application, making imports cleaner and more maintainable.
 */

// API response types
export type {
  ApiResponse,
  SuccessResponse,
  ErrorResponse,
  PaginatedResponse,
  ValidationErrorResponse,
  ErrorCode,
  HttpStatusCode
} from './api';

// Request types
export type {
  BaseRequest,
  AuthenticatedRequest,
  RoomRequest,
  AdminRequest,
  UploadRequest,
  PaginatedRequest,
  SearchRequest,
  TypedResponse,
  WebSocketRequest,
  AuthenticatedWebSocketRequest,
  BatchRequest,
  FileProcessingRequest,
  AnalyticsRequest,
  ExportRequest,
  ImportRequest,
  RequestContext,
  PaginationParams,
  SearchParams,
  DateRangeParams,
  CreateResourceRequest,
  UpdateResourceRequest,
  DeleteResourceRequest,
  ExtractParams,
  ExtractQuery,
  ExtractBody
} from './requests';

// User types
export type {
  ValidatedUser,
  RoomClaims,
  UserRole,
  AdminLevel,
  UserPermissions,
  UserSession,
  PublicUserProfile,
  UserProfile,
  UserPreferences,
  UserStatistics,
  AuthContext,
  UnauthenticatedContext,
  AuthenticationContext,
  UserActivity,
  UserConnection,
  CreateUserRequest,
  UpdateUserRequest,
  UserSearchFilters,
  UserListItem,
  AdminUserInfo,
  UserModerationAction,
  BatchUserOperation,
  BatchUserResult
} from './user';

// WebSocket types (available in websocket.ts)
// Note: Import directly from './websocket' when needed
// export type { WebSocketEventMap, WebSocketEvent, AuthenticatedWebSocket } from './websocket';

// Middleware types
export type {
  NextFunction,
  MiddlewareFunction,
  ErrorMiddlewareFunction,
  AuthenticationMiddleware,
  AuthorizationMiddleware,
  ValidationSchema,
  ValidationRule,
  ValidationMiddleware,
  RateLimitRule,
  RateLimitMiddleware,
  CorsOptions,
  CorsMiddleware,
  SecurityHeaders,
  SecurityMiddleware,
  CompressionOptions,
  CompressionMiddleware,
  LoggingOptions,
  LoggingMiddleware,
  BodyParserOptions,
  BodyParserMiddleware,
  SessionOptions,
  SessionMiddleware,
  FileUploadOptions,
  FileUploadMiddleware,
  ErrorContext,
  ErrorHandlingOptions,
  ErrorHandlingMiddleware,
  HealthCheckOptions,
  HealthCheckMiddleware,
  MetricsOptions,
  MetricsMiddleware,
  CacheOptions,
  CacheMiddleware,
  VersioningOptions,
  VersioningMiddleware,
  ContentNegotiationOptions,
  ContentNegotiationMiddleware,
  TracingOptions,
  TracingMiddleware,
  Middleware,
  MiddlewareStack,
  MiddlewareFactory,
  RouteMiddleware,
  ConditionalMiddleware,
  MiddlewareMetrics,
  MiddlewareContext,
  MiddlewareUtils,
  MiddlewareTest,
  MiddlewareTestSuite
} from './middleware';

// Database types
export type {
  BaseEntity,
  SoftDeleteEntity,
  UserEntity,
  UserPreferences as DatabaseUserPreferences,
  UserStatistics as DatabaseUserStatistics,
  RoomEntity,
  RoomSettings,
  GameSystemEntity,
  GameSystemRules,
  DiceRule,
  CardRule,
  TokenRule,
  BoardRule,
  BoardLayer,
  TurnRule,
  VictoryCondition,
  SetupRule,
  AssetEntity,
  AssetMetadata,
  RoomMemberEntity,
  GameSessionEntity,
  SessionParticipant,
  SessionEvent,
  GameState,
  BoardState,
  BoardObject,
  PlayerState,
  Card,
  Token,
  SessionStatistics,
  QueryOptions,
  FilterOptions,
  WhereClause,
  SimpleClause,
  CompoundClause,
  BaseRepository,
  SoftDeleteRepository,
  UserRepository,
  RoomRepository,
  GameSystemRepository,
  AssetRepository,
  RoomMemberRepository,
  GameSessionRepository,
  DatabaseTransaction,
  TransactionCallback,
  DatabaseService,
  MigrationScript,
  MigrationService,
  DatabaseHealth,
  DatabaseMetrics,
  DatabaseConfig,
  BackupOptions,
  BackupResult,
  RestoreOptions,
  DatabaseBackupService,
  SeedData,
  SeedService,
  EntityKeys,
  EntityValues,
  PartialEntity,
  CreateEntity,
  UpdateEntity
} from './database';

// Type guards (re-exported for convenience)
export {
  isAuthenticatedRequest,
  isRoomRequest,
  isAdminRequest,
  isPaginatedRequest,
  isSearchRequest,
  isUploadRequest
} from './requests';

export {
  isValidatedUser,
  isAuthenticatedContext,
  hasRoomPermission,
  isRoomOwner,
  isGameMaster
} from './user';

// WebSocket functions (available in websocket.ts)
// Note: Import directly from './websocket' when needed
// export { isWebSocketEvent, createWebSocketEvent } from './websocket';

export {
  isErrorMiddleware,
  isAsyncMiddleware
} from './middleware';

export {
  isBaseEntity,
  isSoftDeleteEntity,
  isUserEntity,
  isRoomEntity
} from './database';

// Common utility types
export type ID = string;
export type Timestamp = string;
export type JSONValue = string | number | boolean | null | JSONObject | JSONArray;
export type JSONObject = { [key: string]: JSONValue };
export type JSONArray = JSONValue[];

// Generic utility types
export type Nullable<T> = T | null;
export type Optional<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;
export type RequiredFields<T, K extends keyof T> = T & globalThis.Required<Pick<T, K>>;
export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};
export type DeepRequired<T> = {
  [P in keyof T]-?: T[P] extends object ? DeepRequired<T[P]> : T[P];
};

// Event types for type-safe event emitters
export interface TypedEventEmitter<T extends Record<string, (...args: any[]) => any>> {
  on<K extends keyof T>(event: K, listener: T[K]): this;
  off<K extends keyof T>(event: K, listener: T[K]): this;
  emit<K extends keyof T>(event: K, ...args: Parameters<T[K]>): boolean;
  once<K extends keyof T>(event: K, listener: T[K]): this;
  removeAllListeners<K extends keyof T>(event?: K): this;
}

// Promise utility types
export type PromiseOr<T> = T | Promise<T>;
export type AwaitedOr<T> = T extends Promise<infer U> ? U : T;

// Function utility types
export type AsyncFunction<T extends unknown[] = unknown[], R = unknown> = (...args: T) => Promise<R>;
export type SyncFunction<T extends unknown[] = unknown[], R = unknown> = (...args: T) => R;
export type AnyFunction<T extends unknown[] = unknown[], R = unknown> = SyncFunction<T, R> | AsyncFunction<T, R>;

// Environment and configuration types
export type Environment = 'development' | 'test' | 'staging' | 'production';

export interface ApplicationConfig {
  environment: Environment;
  port: number;
  host: string;
  cors: {
    origins: string[];
    credentials: boolean;
  };
  database: {
    host: string;
    port: number;
    database: string;
    username: string;
    password: string;
    ssl: boolean;
    pool: {
      min: number;
      max: number;
      acquireTimeoutMillis: number;
      idleTimeoutMillis: number;
    };
  };
  auth: {
    firebase: {
      projectId: string;
      clientEmail: string;
      privateKey: string;
    };
    replit: {
      clientId: string;
      clientSecret: string;
    };
    jwt: {
      secret: string;
      expiresIn: string;
      refreshExpiresIn: string;
    };
  };
  storage: {
    provider: 'local' | 's3' | 'gcs';
    bucket?: string;
    region?: string;
    accessKey?: string;
    secretKey?: string;
    endpoint?: string;
  };
  redis: {
    host: string;
    port: number;
    password?: string;
    db: number;
  };
  monitoring: {
    enabled: boolean;
    endpoint?: string;
    apiKey?: string;
    sampleRate: number;
  };
  features: {
    registration: boolean;
    guestAccess: boolean;
    fileUploads: boolean;
    realTimeSync: boolean;
    analytics: boolean;
  };
}

// Error types
export class ApplicationError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode: number = 500,
    public details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'ApplicationError';
  }
}

export class ValidationError extends ApplicationError {
  constructor(
    message: string,
    public fields: Record<string, string[]>,
    details?: Record<string, unknown>
  ) {
    super(message, 'VALIDATION_ERROR', 400, details);
    this.name = 'ValidationError';
  }
}

export class AuthenticationError extends ApplicationError {
  constructor(message: string = 'Authentication required', details?: Record<string, unknown>) {
    super(message, 'AUTHENTICATION_ERROR', 401, details);
    this.name = 'AuthenticationError';
  }
}

export class AuthorizationError extends ApplicationError {
  constructor(
    message: string = 'Insufficient permissions',
    public requiredPermissions?: string[],
    details?: Record<string, unknown>
  ) {
    super(message, 'AUTHORIZATION_ERROR', 403, details);
    this.name = 'AuthorizationError';
  }
}

export class NotFoundError extends ApplicationError {
  constructor(
    resource: string = 'Resource',
    id?: string,
    details?: Record<string, unknown>
  ) {
    const message = id ? `${resource} with ID ${id} not found` : `${resource} not found`;
    super(message, 'NOT_FOUND_ERROR', 404, details);
    this.name = 'NotFoundError';
  }
}

export class ConflictError extends ApplicationError {
  constructor(
    message: string,
    public conflictingField?: string,
    details?: Record<string, unknown>
  ) {
    super(message, 'CONFLICT_ERROR', 409, details);
    this.name = 'ConflictError';
  }
}

export class RateLimitError extends ApplicationError {
  constructor(
    public limit: number,
    public remaining: number,
    public resetTime: string,
    details?: Record<string, unknown>
  ) {
    super('Rate limit exceeded', 'RATE_LIMIT_ERROR', 429, details);
    this.name = 'RateLimitError';
  }
}

// Type assertion helpers
export function assertNever(value: never): never {
  throw new Error(`Unexpected value: ${value}`);
}

export function assertExists<T>(value: T | null | undefined, message?: string): asserts value is T {
  if (value == null) {
    throw new Error(message || 'Expected value to exist');
  }
}

export function assertIsString(value: unknown): asserts value is string {
  if (typeof value !== 'string') {
    throw new Error('Expected string value');
  }
}

export function assertIsNumber(value: unknown): asserts value is number {
  if (typeof value !== 'number') {
    throw new Error('Expected number value');
  }
}

export function assertIsArray<T>(value: unknown): asserts value is T[] {
  if (!Array.isArray(value)) {
    throw new Error('Expected array value');
  }
}

export function assertIsObject(value: unknown): asserts value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('Expected object value');
  }
}
