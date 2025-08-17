// server/database/enhanced-db.ts
// Enhanced database service using the optimized connection pool
import { DatabaseConnectionPool, getConnectionPool } from './connection-pool';
import { createUserLogger } from '../utils/logger';

export class EnhancedDatabaseService {
  private connectionPool: DatabaseConnectionPool;
  private readonly logger = createUserLogger('enhanced-db');

  constructor() {
    this.connectionPool = getConnectionPool();
  }

  // Get the Drizzle database instance
  getDb() {
    return this.connectionPool.getDb();
  }

  // Get raw connection pool for direct access
  getPool() {
    return this.connectionPool.getPool();
  }

  // Execute a single query with connection pooling
  async query<T>(text: string, params?: any[]): Promise<T> {
    return this.connectionPool.query<T>(text, params);
  }

  // Execute multiple queries in a transaction
  async transaction<T>(callback: (tx: any) => Promise<T>): Promise<T> {
    return this.connectionPool.transaction(callback);
  }

  // Execute multiple queries in batch (more efficient than individual queries)
  async batchQuery<T>(queries: Array<{ text: string; params?: any[] }>): Promise<T[]> {
    return this.connectionPool.batchQuery<T>(queries);
  }

  // Health check for monitoring
  async healthCheck() {
    return this.connectionPool.healthCheck();
  }

  // Get pool statistics for monitoring
  async getStats() {
    return this.connectionPool.getDetailedStats();
  }

  // Optimize pool performance
  async optimize() {
    return this.connectionPool.optimizeConnections();
  }

  // Graceful shutdown
  async shutdown(timeoutMs?: number) {
    return this.connectionPool.gracefulShutdown(timeoutMs);
  }
}

// Singleton instance for global use
let globalDb: EnhancedDatabaseService | null = null;

export function getEnhancedDb(): EnhancedDatabaseService {
  if (!globalDb) {
    globalDb = new EnhancedDatabaseService();
  }
  return globalDb;
}

export function createEnhancedDb(): EnhancedDatabaseService {
  return new EnhancedDatabaseService();
}

// Export for backward compatibility
export { DatabaseConnectionPool, getConnectionPool, createConnectionPool } from './connection-pool';
