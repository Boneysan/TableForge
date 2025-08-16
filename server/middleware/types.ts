import { ValidatedUser, RoomClaims } from '../../shared/types/user.js';
import { Logger } from '../../shared/types/websocket.js';

// Basic Express-like interfaces for type safety
export interface Request {
  headers: Record<string, string | string[] | undefined>;
  ip?: string;
  connection: { remoteAddress?: string };
  body?: any;
  params?: Record<string, string>;
  query?: Record<string, string | string[] | undefined>;
}

export interface Response {
  status(code: number): Response;
  json(body: any): Response;
  send(body?: any): Response;
  setHeader(name: string, value: string | string[]): Response;
}

export interface NextFunction {
  (error?: any): void;
}

// Enhanced Response interface with typed JSON responses
export interface TypedResponse<T = unknown> extends Response {
  json(body: T): TypedResponse<T>;
}

// Enhanced Request Types from Phase 1 guide section 3.1
export interface RequestContext {
  correlationId: string;
  startTime: number;
  userId?: string;
  roomId?: string;
  userAgent: string;
  ip: string;
}

export interface AuthenticatedRequest extends Request {
  user: ValidatedUser;
  context: RequestContext;
  log: Logger;
}

export interface RoomAuthorizedRequest extends AuthenticatedRequest {
  roomId: string;
  roomClaims: RoomClaims;
}

// Middleware Function Types from Phase 1 guide section 3.2
export type MiddlewareFunction<
  TRequest extends Request = Request,
  TResponse extends Response = Response
> = (
  req: TRequest,
  res: TResponse,
  next: NextFunction
) => void | Promise<void>;

export type AuthMiddleware = MiddlewareFunction<Request, Response>;
export type AuthenticatedMiddleware = MiddlewareFunction<AuthenticatedRequest, TypedResponse>;
export type RoomMiddleware = MiddlewareFunction<RoomAuthorizedRequest, TypedResponse>;

// Type guards for request validation
export function isAuthenticatedRequest(req: Request): req is AuthenticatedRequest {
  return 'user' in req && 'context' in req && 'log' in req;
}

export function isRoomAuthorizedRequest(req: Request): req is RoomAuthorizedRequest {
  return isAuthenticatedRequest(req) && 'roomId' in req && 'roomClaims' in req;
}

// Request context creation helper
export function createRequestContext(req: Request): RequestContext {
  const userAgent = req.headers['user-agent'];
  const userAgentString = Array.isArray(userAgent) ? userAgent[0] : userAgent;
  
  return {
    correlationId: req.headers['x-correlation-id'] as string || 
                  `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
    startTime: Date.now(),
    userAgent: userAgentString || 'unknown',
    ip: req.ip || req.connection.remoteAddress || 'unknown'
  };
}
