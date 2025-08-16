/**
 * Middleware type definitions for Express and custom middleware
 */
import type { ValidatedUser } from './user';
import type { BaseRequest, TypedResponse } from './requests';

// Core middleware types
export type NextFunction = () => void | Promise<void>;

export type MiddlewareFunction<
  TReq extends BaseRequest = BaseRequest,
  TRes = TypedResponse
> = (req: TReq, res: TRes, next: NextFunction) => void | Promise<void>;

export type ErrorMiddlewareFunction<
  TReq extends BaseRequest = BaseRequest,
  TRes = TypedResponse
> = (error: Error, req: TReq, res: TRes, next: NextFunction) => void | Promise<void>;

// Authentication middleware types
export interface AuthenticationMiddleware {
  name: 'authentication';
  handler: MiddlewareFunction<BaseRequest, TypedResponse>;
  options: {
    required: boolean;
    skipPaths?: string[];
    headerName?: string;
    cookieName?: string;
    queryParam?: string;
  };
}

export interface AuthorizationMiddleware {
  name: 'authorization';
  handler: MiddlewareFunction<BaseRequest & { user: ValidatedUser }, TypedResponse>;
  options: {
    permissions?: string[];
    roles?: string[];
    resource?: string;
    action?: string;
    ownerField?: string;
  };
}

// Validation middleware
export interface ValidationSchema {
  body?: Record<string, ValidationRule>;
  params?: Record<string, ValidationRule>;
  query?: Record<string, ValidationRule>;
  headers?: Record<string, ValidationRule>;
}

export interface ValidationRule {
  type: 'string' | 'number' | 'boolean' | 'array' | 'object' | 'date' | 'email' | 'url';
  required?: boolean;
  minLength?: number;
  maxLength?: number;
  min?: number;
  max?: number;
  pattern?: RegExp | string;
  enum?: unknown[];
  custom?: (value: unknown) => boolean | string;
  nested?: ValidationSchema;
}

export interface ValidationMiddleware {
  name: 'validation';
  handler: MiddlewareFunction;
  options: {
    schema: ValidationSchema;
    abortEarly?: boolean;
    stripUnknown?: boolean;
    allowUnknown?: boolean;
  };
}

// Rate limiting middleware
export interface RateLimitRule {
  windowMs: number;
  maxRequests: number;
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
  keyGenerator?: (req: BaseRequest) => string;
  skip?: (req: BaseRequest) => boolean;
  onLimitReached?: (req: BaseRequest, res: TypedResponse) => void;
}

export interface RateLimitMiddleware {
  name: 'rateLimit';
  handler: MiddlewareFunction;
  options: {
    global?: RateLimitRule;
    perUser?: RateLimitRule;
    perIP?: RateLimitRule;
    perRoute?: Map<string, RateLimitRule>;
  };
}

// CORS middleware
export interface CorsOptions {
  origin: string | string[] | boolean | ((origin: string) => boolean);
  methods?: string[];
  allowedHeaders?: string[];
  exposedHeaders?: string[];
  credentials?: boolean;
  maxAge?: number;
  preflightContinue?: boolean;
  optionsSuccessStatus?: number;
}

export interface CorsMiddleware {
  name: 'cors';
  handler: MiddlewareFunction;
  options: CorsOptions;
}

// Security middleware
export interface SecurityHeaders {
  contentSecurityPolicy?: {
    directives: Record<string, string[]>;
    reportOnly?: boolean;
  };
  frameOptions?: 'deny' | 'sameorigin' | string;
  contentTypeOptions?: boolean;
  xssProtection?: boolean;
  hsts?: {
    maxAge: number;
    includeSubDomains?: boolean;
    preload?: boolean;
  };
  noSniff?: boolean;
  referrerPolicy?: string;
}

export interface SecurityMiddleware {
  name: 'security';
  handler: MiddlewareFunction;
  options: SecurityHeaders;
}

// Compression middleware
export interface CompressionOptions {
  level?: number;
  threshold?: number;
  chunkSize?: number;
  filter?: (req: BaseRequest, res: TypedResponse) => boolean;
}

export interface CompressionMiddleware {
  name: 'compression';
  handler: MiddlewareFunction;
  options: CompressionOptions;
}

// Logging middleware
export interface LoggingOptions {
  format: 'combined' | 'common' | 'dev' | 'short' | 'tiny' | 'custom';
  customFormat?: string;
  skip?: (req: BaseRequest, res: TypedResponse) => boolean;
  stream?: {
    write: (message: string) => void;
  };
  tokens?: Record<string, (req: BaseRequest, res: TypedResponse) => string>;
}

export interface LoggingMiddleware {
  name: 'logging';
  handler: MiddlewareFunction;
  options: LoggingOptions;
}

// Body parsing middleware
export interface BodyParserOptions {
  json?: {
    limit?: string;
    strict?: boolean;
    type?: string | string[];
    verify?: (req: BaseRequest, res: TypedResponse, buf: Uint8Array, encoding: string) => void;
  };
  urlencoded?: {
    extended?: boolean;
    limit?: string;
    parameterLimit?: number;
    type?: string | string[];
  };
  raw?: {
    limit?: string;
    type?: string | string[];
  };
  text?: {
    limit?: string;
    type?: string | string[];
    defaultCharset?: string;
  };
}

export interface BodyParserMiddleware {
  name: 'bodyParser';
  handler: MiddlewareFunction;
  options: BodyParserOptions;
}

// Session middleware
export interface SessionOptions {
  secret: string;
  name?: string;
  resave?: boolean;
  saveUninitialized?: boolean;
  rolling?: boolean;
  cookie?: {
    maxAge?: number;
    expires?: Date;
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: 'strict' | 'lax' | 'none' | boolean;
    domain?: string;
    path?: string;
  };
  store?: {
    get: (sid: string) => Promise<any>;
    set: (sid: string, session: any) => Promise<void>;
    destroy: (sid: string) => Promise<void>;
    touch: (sid: string, session: any) => Promise<void>;
  };
}

export interface SessionMiddleware {
  name: 'session';
  handler: MiddlewareFunction;
  options: SessionOptions;
}

// File upload middleware
export interface FileUploadOptions {
  destination?: string | ((req: BaseRequest, file: any) => string);
  filename?: (req: BaseRequest, file: any) => string;
  limits?: {
    fieldNameSize?: number;
    fieldSize?: number;
    fields?: number;
    fileSize?: number;
    files?: number;
    parts?: number;
    headerPairs?: number;
  };
  fileFilter?: (req: BaseRequest, file: any) => boolean;
  preservePath?: boolean;
}

export interface FileUploadMiddleware {
  name: 'fileUpload';
  handler: MiddlewareFunction;
  options: FileUploadOptions;
}

// Error handling middleware
export interface ErrorContext {
  correlationId: string;
  userId?: string;
  ip: string;
  userAgent: string;
  method: string;
  url: string;
  stack?: string;
  timestamp: string;
}

export interface ErrorHandlingOptions {
  includeStack?: boolean;
  logErrors?: boolean;
  notifyAdmins?: boolean;
  customHandler?: (error: Error, context: ErrorContext) => any;
  ignoreCodes?: string[];
  transformError?: (error: Error) => any;
}

export interface ErrorHandlingMiddleware {
  name: 'errorHandler';
  handler: ErrorMiddlewareFunction;
  options: ErrorHandlingOptions;
}

// Health check middleware
export interface HealthCheckOptions {
  path?: string;
  checks?: Array<{
    name: string;
    check: () => Promise<boolean>;
    critical?: boolean;
    timeout?: number;
  }>;
  includeDetails?: boolean;
  cacheTimeout?: number;
}

export interface HealthCheckMiddleware {
  name: 'healthCheck';
  handler: MiddlewareFunction;
  options: HealthCheckOptions;
}

// Metrics middleware
export interface MetricsOptions {
  path?: string;
  includeSystem?: boolean;
  customMetrics?: Array<{
    name: string;
    description: string;
    type: 'counter' | 'gauge' | 'histogram' | 'summary';
    collect: () => number;
  }>;
}

export interface MetricsMiddleware {
  name: 'metrics';
  handler: MiddlewareFunction;
  options: MetricsOptions;
}

// Cache middleware
export interface CacheOptions {
  ttl?: number;
  keyGenerator?: (req: BaseRequest) => string;
  skip?: (req: BaseRequest, res: TypedResponse) => boolean;
  vary?: string[];
  store?: {
    get: (key: string) => Promise<any>;
    set: (key: string, value: any, ttl?: number) => Promise<void>;
    del: (key: string) => Promise<void>;
    clear: () => Promise<void>;
  };
}

export interface CacheMiddleware {
  name: 'cache';
  handler: MiddlewareFunction;
  options: CacheOptions;
}

// API versioning middleware
export interface VersioningOptions {
  strategy: 'header' | 'query' | 'path' | 'accept';
  parameterName?: string;
  headerName?: string;
  acceptMimeType?: string;
  defaultVersion?: string;
  versions: string[];
  deprecatedVersions?: Array<{
    version: string;
    deprecatedAt: string;
    sunsetAt?: string;
    message?: string;
  }>;
}

export interface VersioningMiddleware {
  name: 'versioning';
  handler: MiddlewareFunction;
  options: VersioningOptions;
}

// Content negotiation middleware
export interface ContentNegotiationOptions {
  supportedTypes: string[];
  defaultType?: string;
  charsets?: string[];
  encodings?: string[];
  languages?: string[];
}

export interface ContentNegotiationMiddleware {
  name: 'contentNegotiation';
  handler: MiddlewareFunction;
  options: ContentNegotiationOptions;
}

// Request tracing middleware
export interface TracingOptions {
  headerName?: string;
  generateTraceId?: () => string;
  includeHeaders?: string[];
  includeBody?: boolean;
  sanitizeBody?: (body: any) => any;
}

export interface TracingMiddleware {
  name: 'tracing';
  handler: MiddlewareFunction;
  options: TracingOptions;
}

// Combined middleware configuration
export type Middleware = 
  | AuthenticationMiddleware
  | AuthorizationMiddleware
  | ValidationMiddleware
  | RateLimitMiddleware
  | CorsMiddleware
  | SecurityMiddleware
  | CompressionMiddleware
  | LoggingMiddleware
  | BodyParserMiddleware
  | SessionMiddleware
  | FileUploadMiddleware
  | ErrorHandlingMiddleware
  | HealthCheckMiddleware
  | MetricsMiddleware
  | CacheMiddleware
  | VersioningMiddleware
  | ContentNegotiationMiddleware
  | TracingMiddleware;

// Middleware stack configuration
export interface MiddlewareStack {
  middlewares: Middleware[];
  errorHandlers: ErrorHandlingMiddleware[];
  order: string[];
  conditions?: Record<string, {
    when: (req: BaseRequest) => boolean;
    then: string[];
    else?: string[];
  }>;
}

// Middleware factory
export interface MiddlewareFactory {
  create<T extends Middleware>(
    type: T['name'],
    options: T['options']
  ): T['handler'];
  
  createStack(config: MiddlewareStack): MiddlewareFunction[];
  
  compose(middlewares: MiddlewareFunction[]): MiddlewareFunction;
}

// Route-specific middleware
export interface RouteMiddleware {
  path: string | RegExp;
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS' | 'HEAD' | '*';
  middlewares: string[];
  excludeGlobal?: string[];
}

// Conditional middleware
export interface ConditionalMiddleware {
  condition: (req: BaseRequest) => boolean;
  middleware: MiddlewareFunction;
  fallback?: MiddlewareFunction;
}

// Middleware performance metrics
export interface MiddlewareMetrics {
  name: string;
  executionTime: number;
  memoryUsage: number;
  errorCount: number;
  callCount: number;
  lastExecuted: string;
}

// Middleware execution context
export interface MiddlewareContext {
  startTime: number;
  metadata: Record<string, unknown>;
  performance: MiddlewareMetrics[];
  errors: Error[];
  skipped: string[];
}

// Type guards for middleware
export function isErrorMiddleware(
  middleware: MiddlewareFunction | ErrorMiddlewareFunction
): middleware is ErrorMiddlewareFunction {
  return middleware.length === 4;
}

export function isAsyncMiddleware(
  middleware: MiddlewareFunction
): boolean {
  return middleware.constructor.name === 'AsyncFunction';
}

// Middleware utilities
export interface MiddlewareUtils {
  wrapAsync(fn: MiddlewareFunction): MiddlewareFunction;
  timeout(ms: number): MiddlewareFunction;
  retry(attempts: number, delay?: number): MiddlewareFunction;
  conditional(condition: (req: BaseRequest) => boolean): MiddlewareFunction;
  compose(...middlewares: MiddlewareFunction[]): MiddlewareFunction;
  parallel(...middlewares: MiddlewareFunction[]): MiddlewareFunction;
  circuit(options: {
    errorThreshold: number;
    resetTimeout: number;
    monitor?: (error: Error) => void;
  }): MiddlewareFunction;
}

// Middleware testing types
export interface MiddlewareTest {
  name: string;
  middleware: MiddlewareFunction;
  request: Partial<BaseRequest>;
  expectedStatus?: number;
  expectedHeaders?: Record<string, string>;
  expectedBody?: any;
  shouldCallNext?: boolean;
  shouldThrow?: boolean;
  setup?: () => Promise<void>;
  teardown?: () => Promise<void>;
}

export interface MiddlewareTestSuite {
  name: string;
  tests: MiddlewareTest[];
  beforeAll?: () => Promise<void>;
  afterAll?: () => Promise<void>;
  beforeEach?: () => Promise<void>;
  afterEach?: () => Promise<void>;
}
