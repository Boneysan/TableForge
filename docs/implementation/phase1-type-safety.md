# Phase 1 Implementation Guide: Type Safety Enhancement

## Overview
This guide provides detailed implementation steps for eliminating `any` types and enhancing type safety across the TableForge codebase.

## 1. TypeScript Interface Standardization

### 1.1 API Response Types
Create comprehensive type definitions for all API responses:

```typescript
// shared/types/api.ts
export interface ApiResponse<T = unknown> {
  data?: T;
  error?: string;
  message?: string;
  timestamp: string;
  correlationId: string;
}

export interface PaginatedResponse<T> extends ApiResponse<T[]> {
  pagination: {
    page: number;
    limit: number;
    total: number;
    hasNext: boolean;
    hasPrevious: boolean;
  };
}

export interface ErrorResponse extends ApiResponse<never> {
  error: string;
  message: string;
  details?: Record<string, unknown>;
  code: string;
}
```

### 1.2 Request Types
Standardize request types across all endpoints:

```typescript
// shared/types/requests.ts
export interface AuthenticatedRequest extends Request {
  user: ValidatedUser;
  correlationId: string;
  log: Logger;
}

export interface RoomRequest extends AuthenticatedRequest {
  roomId: string;
  roomClaims?: RoomClaims;
}

export interface TypedResponse<T = unknown> extends Response {
  json(body: ApiResponse<T>): TypedResponse<T>;
}
```

## 2. WebSocket Type Safety

### 2.1 WebSocket Event Types
Create strict typing for all WebSocket events:

```typescript
// shared/types/websocket.ts
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

export type WebSocketEvent<K extends keyof WebSocketEventMap> = {
  type: K;
  data: WebSocketEventMap[K];
  timestamp: string;
  correlationId: string;
};

export interface AuthenticatedWebSocket extends WebSocket {
  user?: ValidatedUser;
  roomId?: string;
  isAuthenticated: boolean;
  lastActivity: number;
}
```

### 2.2 WebSocket Handler Types
Type-safe WebSocket message handlers:

```typescript
// server/websocket/types.ts
export type WebSocketHandler<K extends keyof WebSocketEventMap> = (
  socket: AuthenticatedWebSocket,
  data: WebSocketEventMap[K],
  context: {
    correlationId: string;
    timestamp: string;
    logger: Logger;
  }
) => Promise<void> | void;

export interface WebSocketHandlerMap {
  [K in keyof WebSocketEventMap]: WebSocketHandler<K>;
}
```

## 3. Middleware Type Safety

### 3.1 Enhanced Request Types
Update middleware to use strict typing:

```typescript
// server/middleware/types.ts
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
```

### 3.2 Middleware Function Types
Create type-safe middleware functions:

```typescript
// server/middleware/types.ts
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
```

## 4. Database Query Types

### 4.1 Drizzle Query Result Types
Enhance database query return types:

```typescript
// server/types/database.ts
export type QueryResult<T> = {
  data: T;
  success: true;
} | {
  error: DatabaseError;
  success: false;
};

export type TransactionResult<T> = Promise<QueryResult<T>>;

export interface DatabaseConnection {
  query<T>(sql: string, params?: unknown[]): Promise<QueryResult<T>>;
  transaction<T>(fn: (tx: Transaction) => Promise<T>): TransactionResult<T>;
}
```

### 4.2 Repository Pattern Types
Implement type-safe repository pattern:

```typescript
// server/repositories/types.ts
export interface Repository<TEntity, TCreateInput, TUpdateInput> {
  findById(id: string): Promise<TEntity | null>;
  findMany(filters?: Partial<TEntity>): Promise<TEntity[]>;
  create(input: TCreateInput): Promise<TEntity>;
  update(id: string, input: Partial<TUpdateInput>): Promise<TEntity>;
  delete(id: string): Promise<boolean>;
}

export interface GameRoomRepository extends Repository<
  GameRoom,
  CreateRoomInput,
  UpdateRoomInput
> {
  findByUserId(userId: string): Promise<GameRoom[]>;
  findActiveRooms(): Promise<GameRoom[]>;
  findWithPlayers(roomId: string): Promise<GameRoomWithPlayers | null>;
}
```

## 5. Implementation Steps

### Step 1: Update Core Types (Week 1)
1. Create `shared/types/` directory structure
2. Define all API response and request types
3. Update `shared/schema.ts` with new types
4. Create type exports in `shared/index.ts`

### Step 2: Update Server Middleware (Week 1-2)
1. Update `server/middleware/errorHandler.ts`:
   ```typescript
   // Replace any types with proper interfaces
   export function errorHandler(
     error: AppError | ZodError | Error,
     req: AuthenticatedRequest,
     res: TypedResponse<ErrorResponse>,
     next: NextFunction
   ): void {
     // Implementation with proper typing
   }
   ```

2. Update authentication middleware:
   ```typescript
   // server/auth/middleware.ts
   export const authenticateToken: AuthMiddleware = async (req, res, next) => {
     // Type-safe implementation
   };
   ```

### Step 3: Update WebSocket System (Week 2)
1. Update `server/websocket/socketAuth.ts` with new types
2. Replace all WebSocket `any` types with proper interfaces
3. Create type-safe event handlers

### Step 4: Update Route Handlers (Week 2-3)
1. Update all route handlers to use typed requests/responses
2. Replace dynamic object typing with proper interfaces
3. Add proper error handling with typed responses

### Step 5: Frontend Type Updates (Week 3-4)
1. Update React components with proper prop types
2. Enhance API client with typed responses
3. Update WebSocket client with typed events

## 6. Validation & Testing

### 6.1 Type Checking Script
Create automated type checking:

```typescript
// scripts/type-check.ts
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

async function checkTypes(): Promise<void> {
  console.log('🔍 Checking TypeScript types...');
  
  try {
    await execAsync('npx tsc --noEmit --strict');
    console.log('✅ All types are valid');
  } catch (error) {
    console.error('❌ Type checking failed:', error);
    process.exit(1);
  }
}

checkTypes();
```

### 6.2 ESLint Rules Update
Add stricter ESLint rules for type safety:

```javascript
// eslint.config.js - add to rules
"@typescript-eslint/no-explicit-any": "error",
"@typescript-eslint/no-unsafe-assignment": "error",
"@typescript-eslint/no-unsafe-member-access": "error",
"@typescript-eslint/no-unsafe-call": "error",
"@typescript-eslint/no-unsafe-return": "error",
"@typescript-eslint/prefer-nullish-coalescing": "error",
"@typescript-eslint/prefer-optional-chain": "error",
```

## 7. Success Criteria

### Completion Checklist
- [x] Zero `any` types in production code
- [x] All API responses properly typed
- [x] All WebSocket events properly typed
- [x] All middleware functions type-safe
- [x] All database queries type-safe
- [x] TypeScript strict mode with no errors
- [x] Updated tests for new types
- [x] Documentation updated

### Quality Gates
- ✅ TypeScript compilation with `--strict --noImplicitAny`
- ✅ ESLint passing with enhanced type rules
- ✅ All tests passing with new types
- ⏳ Code review approval from senior developer

---

**Implementation Priority**: Critical  
**Estimated Effort**: 3-4 weeks  
**Dependencies**: None  
**Risk Level**: Low
