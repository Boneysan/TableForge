import type { ValidatedUser } from './user';

// Base interfaces that don't rely on Express types

/**
 * Base request context information attached to all requests
 */
export interface RequestContext {
  correlationId: string;
  startTime: number;
  userId?: string;
  roomId?: string;
  userAgent: string;
  ip: string;
  method: string;
  path: string;
}

/**
 * Enhanced Express Request with common extensions
 */
export interface BaseRequest {
  context: RequestContext;
  correlationId: string;
  log: {
    info: (message: string, meta?: object) => void;
    warn: (message: string, meta?: object) => void;
    error: (message: string, meta?: object) => void;
    debug: (message: string, meta?: object) => void;
  };
  body?: any;
  params: Record<string, string>;
  query: Record<string, any>;
  headers: Record<string, string | string[] | undefined>;
}

/**
 * Authenticated request with validated user information
 */
export interface AuthenticatedRequest extends BaseRequest {
  user: ValidatedUser;
}

/**
 * Room-authorized request with room access validation
 */
export interface RoomRequest extends AuthenticatedRequest {
  roomId: string;
  roomClaims?: {
    role: 'owner' | 'admin' | 'player';
    permissions: string[];
    joinedAt: string;
  };
}

/**
 * Admin-level request requiring elevated permissions
 */
export interface AdminRequest extends AuthenticatedRequest {
  adminLevel: 'super' | 'moderator' | 'support';
  permissions: string[];
}

/**
 * File upload request with multipart data
 */
export interface UploadRequest extends AuthenticatedRequest {
  files: Array<{
    fieldname: string;
    originalname: string;
    encoding: string;
    mimetype: string;
    size: number;
    buffer: Uint8Array;
  }>;
  uploadContext: {
    maxSize: number;
    allowedTypes: string[];
    destination: string;
  };
}

/**
 * Paginated request with standardized pagination parameters
 */
export interface PaginatedRequest extends BaseRequest {
  pagination: {
    page: number;
    limit: number;
    offset: number;
    sort?: string;
    order?: 'asc' | 'desc';
  };
}

/**
 * Search request with filtering and sorting
 */
export interface SearchRequest extends PaginatedRequest {
  search: {
    query?: string;
    filters: Record<string, unknown>;
    facets?: string[];
    highlight?: boolean;
  };
}

/**
 * Typed Response interface with API response methods
 */
export interface TypedResponse<T = unknown> {
  /**
   * Send a successful API response
   */
  apiSuccess(data: T, message?: string, statusCode?: number): TypedResponse<T>;
  
  /**
   * Send an error API response
   */
  apiError(
    error: string,
    message: string,
    statusCode?: number,
    code?: string,
    details?: Record<string, unknown>
  ): TypedResponse<never>;
  
  /**
   * Send a paginated API response
   */
  apiPaginated<U>(
    data: U[],
    pagination: {
      page: number;
      limit: number;
      total: number;
      hasNext: boolean;
      hasPrevious: boolean;
    },
    message?: string
  ): TypedResponse<U[]>;
  
  /**
   * Send a validation error response
   */
  apiValidationError(
    fields: Record<string, string[]>,
    message?: string
  ): TypedResponse<never>;
  
  /**
   * Send an authorization error response
   */
  apiAuthError(
    message?: string,
    requiredPermissions?: string[]
  ): TypedResponse<never>;
  
  /**
   * Send a not found error response
   */
  apiNotFound(resource?: string, id?: string): TypedResponse<never>;
  
  /**
   * Send a conflict error response
   */
  apiConflict(message?: string, conflictingField?: string): TypedResponse<never>;
  
  /**
   * Send a rate limit error response
   */
  apiRateLimit(
    limit: number,
    remaining: number,
    resetTime: string
  ): TypedResponse<never>;
}

/**
 * WebSocket request types for real-time communication
 */
export interface WebSocketRequest {
  type: string;
  data: unknown;
  correlationId: string;
  timestamp: string;
}

export interface AuthenticatedWebSocketRequest extends WebSocketRequest {
  user: ValidatedUser;
  roomId?: string;
}

/**
 * Batch operation request for processing multiple items
 */
export interface BatchRequest<T> extends AuthenticatedRequest {
  batchData: {
    items: T[];
    options?: {
      continueOnError?: boolean;
      validateAll?: boolean;
      maxBatchSize?: number;
    };
  };
}

/**
 * File processing request for asset operations
 */
export interface FileProcessingRequest extends AuthenticatedRequest {
  file: {
    id: string;
    path: string;
    originalName: string;
    mimeType: string;
    size: number;
  };
  processing: {
    resize?: {
      width: number;
      height: number;
      quality?: number;
    };
    compress?: boolean;
    thumbnail?: boolean;
  };
}

/**
 * Analytics request for reporting endpoints
 */
export interface AnalyticsRequest extends AuthenticatedRequest {
  analytics: {
    metrics: string[];
    period: {
      start: string;
      end: string;
    };
    granularity: 'hour' | 'day' | 'week' | 'month';
    filters?: Record<string, unknown>;
    groupBy?: string[];
  };
}

/**
 * Export request for data export operations
 */
export interface ExportRequest extends AuthenticatedRequest {
  export: {
    format: 'json' | 'csv' | 'xlsx' | 'pdf';
    filters?: Record<string, unknown>;
    fields?: string[];
    compress?: boolean;
  };
}

/**
 * Import request for data import operations
 */
export interface ImportRequest extends UploadRequest {
  import: {
    format: 'json' | 'csv' | 'xlsx';
    mapping?: Record<string, string>;
    validation?: {
      strict?: boolean;
      skipErrors?: boolean;
    };
    preview?: boolean;
  };
}

/**
 * Type guards for request validation
 */
export function isAuthenticatedRequest(req: BaseRequest): req is AuthenticatedRequest {
  return 'user' in req && req.user !== undefined;
}

export function isRoomRequest(req: BaseRequest): req is RoomRequest {
  return isAuthenticatedRequest(req) && 'roomId' in req;
}

export function isAdminRequest(req: BaseRequest): req is AdminRequest {
  return isAuthenticatedRequest(req) && 'adminLevel' in req;
}

export function isPaginatedRequest(req: BaseRequest): req is PaginatedRequest {
  return 'pagination' in req && typeof req.pagination === 'object';
}

export function isSearchRequest(req: BaseRequest): req is SearchRequest {
  return isPaginatedRequest(req) && 'search' in req;
}

export function isUploadRequest(req: BaseRequest): req is UploadRequest {
  return isAuthenticatedRequest(req) && 'files' in req;
}

/**
 * Request validation schemas for common patterns
 */
export interface PaginationParams {
  page?: string | number;
  limit?: string | number;
  sort?: string;
  order?: 'asc' | 'desc';
}

export interface SearchParams extends PaginationParams {
  q?: string;
  query?: string;
  filter?: string | Record<string, unknown>;
  facets?: string | string[];
}

export interface DateRangeParams {
  startDate?: string;
  endDate?: string;
  period?: 'day' | 'week' | 'month' | 'year';
}

/**
 * Common request body interfaces
 */
export interface CreateResourceRequest<T> {
  data: Omit<T, 'id' | 'createdAt' | 'updatedAt'>;
  options?: {
    validate?: boolean;
    notify?: boolean;
  };
}

export interface UpdateResourceRequest<T> {
  data: Partial<Omit<T, 'id' | 'createdAt'>>;
  options?: {
    merge?: boolean;
    validate?: boolean;
    notify?: boolean;
  };
}

export interface DeleteResourceRequest {
  options?: {
    soft?: boolean;
    cascade?: boolean;
    notify?: boolean;
  };
}

/**
 * Utility types for request parameter extraction
 */
export type ExtractParams<T extends string> = T extends `${string}:${infer Param}/${infer Rest}`
  ? { [K in Param | keyof ExtractParams<Rest>]: string }
  : T extends `${string}:${infer Param}`
  ? { [K in Param]: string }
  : {};

export type ExtractQuery<T> = {
  [K in keyof T]?: string | string[];
};

export type ExtractBody<T> = T;
