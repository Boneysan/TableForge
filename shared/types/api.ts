import type { ValidatedUser } from './user';

/**
 * Standard API response envelope for all endpoints
 * Provides consistent structure across the application
 */
export interface ApiResponse<T = unknown> {
  data?: T;
  error?: string;
  message?: string;
  timestamp: string;
  correlationId: string;
}

/**
 * Paginated response for endpoints that return lists
 * Extends ApiResponse with pagination metadata
 */
export interface PaginatedResponse<T> extends ApiResponse<T[]> {
  pagination: {
    page: number;
    limit: number;
    total: number;
    hasNext: boolean;
    hasPrevious: boolean;
  };
}

/**
 * Error response for all error scenarios
 * Provides detailed error information with context
 */
export interface ErrorResponse extends ApiResponse<never> {
  error: string;
  message: string;
  details?: Record<string, unknown>;
  code: string;
}

/**
 * Success response for operations that don't return data
 * Used for DELETE, UPDATE operations without return values
 */
export interface SuccessResponse extends ApiResponse<null> {
  message: string;
  success: true;
}

/**
 * Authentication response containing user data and tokens
 */
export interface AuthResponse extends ApiResponse<{
  user: ValidatedUser;
  token?: string;
  refreshToken?: string;
  expiresAt?: number;
}> {
  message: string;
}

/**
 * Health check response for monitoring endpoints
 */
export interface HealthResponse extends ApiResponse<{
  status: 'healthy' | 'degraded' | 'unhealthy';
  services: {
    database: 'healthy' | 'unhealthy';
    cache: 'healthy' | 'unhealthy';
    storage: 'healthy' | 'unhealthy';
  };
  uptime: number;
  version: string;
}> {}

/**
 * Upload response for file upload operations
 */
export interface UploadResponse extends ApiResponse<{
  fileId: string;
  fileName: string;
  filePath: string;
  fileSize: number;
  mimeType: string;
  uploadedAt: string;
}> {}

/**
 * Batch operation response for operations affecting multiple items
 */
export interface BatchResponse<T> extends ApiResponse<{
  successful: T[];
  failed: Array<{
    item: Partial<T>;
    error: string;
    code: string;
  }>;
  totalProcessed: number;
  successCount: number;
  failureCount: number;
}> {}

/**
 * Search response for search endpoints with facets
 */
export interface SearchResponse<T> extends PaginatedResponse<T> {
  data: T[];
  facets?: Record<string, Array<{
    value: string;
    count: number;
  }>>;
  searchTime: number;
  query: string;
}

/**
 * Analytics response for reporting endpoints
 */
export interface AnalyticsResponse<T = Record<string, unknown>> extends ApiResponse<{
  metrics: T;
  period: {
    start: string;
    end: string;
  };
  granularity: 'hour' | 'day' | 'week' | 'month';
}> {}

/**
 * Validation error response with field-specific errors
 */
export interface ValidationErrorResponse extends ErrorResponse {
  code: 'VALIDATION_ERROR';
  details: {
    fields: Record<string, string[]>;
    count: number;
  };
}

/**
 * Rate limit error response
 */
export interface RateLimitErrorResponse extends ErrorResponse {
  code: 'RATE_LIMITED';
  details: {
    limit: number;
    remaining: number;
    resetTime: string;
    retryAfter: number;
  };
}

/**
 * Authorization error response
 */
export interface AuthorizationErrorResponse extends ErrorResponse {
  code: 'AUTHORIZATION_ERROR' | 'AUTHENTICATION_ERROR';
  details?: {
    requiredPermissions?: string[];
    userPermissions?: string[];
    resource?: string;
  };
}

/**
 * Type guards for API responses
 */
export function isApiResponse<T>(response: unknown): response is ApiResponse<T> {
  return (
    typeof response === 'object' &&
    response !== null &&
    'timestamp' in response &&
    'correlationId' in response
  );
}

export function isErrorResponse(response: ApiResponse<unknown>): response is ErrorResponse {
  return 'error' in response && typeof response.error === 'string';
}

export function isSuccessResponse<T>(response: ApiResponse<T>): response is ApiResponse<T> {
  return !isErrorResponse(response) && 'data' in response;
}

export function isPaginatedResponse<T>(
  response: ApiResponse<unknown>
): response is PaginatedResponse<T> {
  return (
    isSuccessResponse(response) &&
    'pagination' in response &&
    typeof response.pagination === 'object'
  );
}

/**
 * Helper function to create consistent API responses
 */
export function createApiResponse<T>(
  data: T,
  correlationId: string,
  message?: string
): ApiResponse<T> {
  return {
    data,
    message: message || '',
    timestamp: new Date().toISOString(),
    correlationId,
  };
}

export function createErrorResponse(
  error: string,
  message: string,
  correlationId: string,
  code: string,
  details?: Record<string, unknown>
): ErrorResponse {
  return {
    error,
    message,
    code,
    details: details || {},
    timestamp: new Date().toISOString(),
    correlationId,
  };
}

export function createPaginatedResponse<T>(
  data: T[],
  pagination: PaginatedResponse<T>['pagination'],
  correlationId: string,
  message?: string
): PaginatedResponse<T> {
  return {
    data,
    pagination,
    message: message || '',
    timestamp: new Date().toISOString(),
    correlationId,
  };
}

export function createSuccessResponse(
  correlationId: string,
  message: string = 'Operation completed successfully'
): SuccessResponse {
  return {
    data: null,
    success: true,
    message,
    timestamp: new Date().toISOString(),
    correlationId,
  };
}

/**
 * HTTP status code mapping for different response types
 */
export const HTTP_STATUS = {
  // Success responses
  OK: 200,
  CREATED: 201,
  ACCEPTED: 202,
  NO_CONTENT: 204,

  // Client error responses
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  METHOD_NOT_ALLOWED: 405,
  CONFLICT: 409,
  VALIDATION_ERROR: 422,
  TOO_MANY_REQUESTS: 429,

  // Server error responses
  INTERNAL_SERVER_ERROR: 500,
  NOT_IMPLEMENTED: 501,
  BAD_GATEWAY: 502,
  SERVICE_UNAVAILABLE: 503,
  GATEWAY_TIMEOUT: 504,
} as const;

/**
 * Standard error codes used across the application
 */
export const ERROR_CODES = {
  // Authentication & Authorization
  AUTHENTICATION_ERROR: 'AUTHENTICATION_ERROR',
  AUTHORIZATION_ERROR: 'AUTHORIZATION_ERROR',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',

  // Validation
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  INVALID_INPUT: 'INVALID_INPUT',
  MISSING_REQUIRED_FIELD: 'MISSING_REQUIRED_FIELD',

  // Resource Management
  NOT_FOUND: 'NOT_FOUND',
  ALREADY_EXISTS: 'ALREADY_EXISTS',
  CONFLICT: 'CONFLICT',
  RESOURCE_LOCKED: 'RESOURCE_LOCKED',

  // Rate Limiting
  RATE_LIMITED: 'RATE_LIMITED',
  QUOTA_EXCEEDED: 'QUOTA_EXCEEDED',

  // Server Errors
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  DATABASE_ERROR: 'DATABASE_ERROR',
  EXTERNAL_SERVICE_ERROR: 'EXTERNAL_SERVICE_ERROR',
  CONFIGURATION_ERROR: 'CONFIGURATION_ERROR',

  // Business Logic
  ROOM_FULL: 'ROOM_FULL',
  GAME_IN_PROGRESS: 'GAME_IN_PROGRESS',
  INVALID_GAME_STATE: 'INVALID_GAME_STATE',
  PERMISSION_DENIED: 'PERMISSION_DENIED',
} as const;

export type ErrorCode = typeof ERROR_CODES[keyof typeof ERROR_CODES];
export type HttpStatusCode = typeof HTTP_STATUS[keyof typeof HTTP_STATUS];
