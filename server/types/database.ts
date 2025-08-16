// Database types for enhanced type safety from Phase 1 guide section 4.1

// Database error types
export interface DatabaseError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
  stack?: string;
  constraint?: string;
  table?: string;
  column?: string;
}

// Enhanced database query return types from Phase 1 guide
export type QueryResult<T> = {
  data: T;
  success: true;
} | {
  error: DatabaseError;
  success: false;
};

export type TransactionResult<T> = Promise<QueryResult<T>>;

// Database transaction interface
export interface Transaction {
  query<T>(sql: string, params?: unknown[]): Promise<T>;
  rollback(): Promise<void>;
  commit(): Promise<void>;
}

// Enhanced database connection interface
export interface DatabaseConnection {
  query<T>(sql: string, params?: unknown[]): Promise<QueryResult<T>>;
  transaction<T>(fn: (tx: Transaction) => Promise<T>): TransactionResult<T>;
}

// Common database operation results
export interface InsertResult {
  insertedId: string;
  affectedRows: number;
}

export interface UpdateResult {
  affectedRows: number;
  changedRows: number;
}

export interface DeleteResult {
  affectedRows: number;
}

// Pagination types for database queries
export interface PaginationOptions {
  page: number;
  limit: number;
  offset?: number;
}

export type PaginatedQueryResult<T> = QueryResult<T[]> & {
  pagination?: {
    page: number;
    limit: number;
    total: number;
    hasNext: boolean;
    hasPrevious: boolean;
  };
};

// Type guards for query results
export function isSuccessResult<T>(result: QueryResult<T>): result is { data: T; success: true } {
  return result.success === true;
}

export function isErrorResult<T>(result: QueryResult<T>): result is { error: DatabaseError; success: false } {
  return result.success === false;
}

// Database operation helper types
export type DatabaseOperationResult<T> = 
  | { success: true; data: T }
  | { success: false; error: DatabaseError };

// Query builder types for type-safe query construction
export interface QueryBuilder<T> {
  select(...columns: (keyof T)[]): QueryBuilder<T>;
  where(condition: Partial<T>): QueryBuilder<T>;
  orderBy(column: keyof T, direction?: 'ASC' | 'DESC'): QueryBuilder<T>;
  limit(count: number): QueryBuilder<T>;
  offset(count: number): QueryBuilder<T>;
  execute(): Promise<QueryResult<T[]>>;
  first(): Promise<QueryResult<T | null>>;
}

// Database connection pool types
export interface DatabasePool {
  getConnection(): Promise<DatabaseConnection>;
  releaseConnection(connection: DatabaseConnection): Promise<void>;
  end(): Promise<void>;
  query<T>(sql: string, params?: unknown[]): Promise<QueryResult<T>>;
}
