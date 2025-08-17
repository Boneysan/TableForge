// server/database/connection-pool.ts
// Phase 3 Database Connection Pool Optimization
import { Pool, PoolConfig } from 'pg';
import { drizzle } from 'drizzle-orm/node-postgres';
import { createUserLogger } from '../utils/logger';
// import { metrics } from '../observability/metrics'; // TODO: Uncomment when metrics system is available
import * as schema from '@shared/schema';

// Mock metrics for development (replace with actual metrics implementation)
const metrics = {
  dbConnections: { inc: (_labels: any) => {}, dec: (_labels: any) => {} },
  dbErrors: { inc: (_labels: any) => {} },
  dbPoolSize: { set: (_value: number) => {} },
  dbPoolIdle: { set: (_value: number) => {} },
  dbPoolWaiting: { set: (_value: number) => {} },
  dbQueryDuration: { observe: (_labels: any, _duration: number) => {} },
  dbTransactionDuration: { observe: (_duration: number) => {} }
};

export class DatabaseConnectionPool {
  private pool: Pool;
  private drizzleDb: any;
  private readonly logger = createUserLogger('db-pool');
  private monitoringInterval?: NodeJS.Timeout;

  constructor() {
    const poolConfig: PoolConfig = {
      host: process.env.DATABASE_HOST || 'localhost',
      port: parseInt(process.env.DATABASE_PORT || '5432'),
      database: process.env.DATABASE_NAME || 'tableforge',
      user: process.env.DATABASE_USER || 'postgres',
      password: process.env.DATABASE_PASSWORD,
      
      // Connection pool settings
      min: parseInt(process.env.DB_POOL_MIN || '5'),
      max: parseInt(process.env.DB_POOL_MAX || '20'),
      idleTimeoutMillis: parseInt(process.env.DB_IDLE_TIMEOUT || '30000'),
      connectionTimeoutMillis: parseInt(process.env.DB_CONNECTION_TIMEOUT || '10000'),
      
      // Performance settings
      statement_timeout: parseInt(process.env.DB_STATEMENT_TIMEOUT || '30000'),
      query_timeout: parseInt(process.env.DB_QUERY_TIMEOUT || '30000'),
      
      // SSL settings
      ssl: process.env.NODE_ENV === 'production' ? {
        rejectUnauthorized: false
      } : false,

      // Additional performance optimizations
      application_name: 'tableforge-app',
      keepAlive: true,
      keepAliveInitialDelayMillis: 10000,
      allowExitOnIdle: true
    };

    // Use DATABASE_URL if available (for compatibility with existing setup)
    if (process.env.DATABASE_URL) {
      this.pool = new Pool({
        connectionString: process.env.DATABASE_URL,
        ...poolConfig
      });
    } else {
      this.pool = new Pool(poolConfig);
    }

    this.drizzleDb = drizzle(this.pool, { schema });
    
    this.setupMonitoring();
    
    this.logger.info('Database connection pool initialized', {
      min: poolConfig.min,
      max: poolConfig.max,
      host: poolConfig.host || 'from_connection_string',
      database: poolConfig.database || 'from_connection_string'
    });
  }

  private setupMonitoring(): void {
    this.pool.on('connect', (client) => {
      this.logger.debug('Database client connected');
      metrics.dbConnections.inc({ status: 'connected' });
    });

    this.pool.on('remove', (client) => {
      this.logger.debug('Database client removed');
      metrics.dbConnections.dec({ status: 'connected' });
    });

    this.pool.on('error', (error, client) => {
      this.logger.error('Database pool error', { error: error.message });
      metrics.dbErrors.inc({ type: 'pool_error' });
    });

    this.pool.on('acquire', (client) => {
      this.logger.debug('Database client acquired from pool');
    });

    this.pool.on('release', (client) => {
      this.logger.debug('Database client released to pool');
    });

    // Monitor pool statistics periodically
    this.monitoringInterval = setInterval(() => {
      metrics.dbPoolSize.set(this.pool.totalCount);
      metrics.dbPoolIdle.set(this.pool.idleCount);
      metrics.dbPoolWaiting.set(this.pool.waitingCount);
      
      // Log pool statistics for debugging
      this.logger.debug('Pool statistics', {
        total: this.pool.totalCount,
        idle: this.pool.idleCount,
        waiting: this.pool.waitingCount
      });
    }, 10000);
  }

  getDb() {
    return this.drizzleDb;
  }

  getPool() {
    return this.pool;
  }

  async query<T>(text: string, params?: any[]): Promise<T> {
    const client = await this.pool.connect();
    const startTime = Date.now();
    
    try {
      const result = await client.query(text, params);
      const duration = Date.now() - startTime;
      
      metrics.dbQueryDuration.observe(
        { query_type: this.getQueryType(text) },
        duration
      );

      this.logger.debug('Database query executed', {
        query: text.substring(0, 100),
        duration,
        rowCount: result.rowCount
      });

      return result.rows as T;
    } catch (error: any) {
      metrics.dbErrors.inc({ type: 'query_error' });
      this.logger.error('Database query failed', {
        query: text.substring(0, 100),
        error: error.message,
        duration: Date.now() - startTime
      });
      throw error;
    } finally {
      client.release();
    }
  }

  async transaction<T>(callback: (tx: any) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    const startTime = Date.now();

    try {
      await client.query('BEGIN');
      this.logger.debug('Transaction started');
      
      const result = await callback(client);
      
      await client.query('COMMIT');
      const duration = Date.now() - startTime;
      
      metrics.dbTransactionDuration.observe(duration);
      
      this.logger.debug('Database transaction completed', { duration });
      return result;
    } catch (error: any) {
      await client.query('ROLLBACK');
      const duration = Date.now() - startTime;
      
      metrics.dbErrors.inc({ type: 'transaction_error' });
      this.logger.error('Database transaction failed', { 
        error: error.message,
        duration
      });
      throw error;
    } finally {
      client.release();
    }
  }

  async batchQuery<T>(queries: Array<{ text: string; params?: any[] }>): Promise<T[]> {
    const client = await this.pool.connect();
    const startTime = Date.now();
    
    try {
      const results: T[] = [];
      
      for (const query of queries) {
        const result = await client.query(query.text, query.params);
        results.push(result.rows as T);
      }
      
      const duration = Date.now() - startTime;
      
      metrics.dbQueryDuration.observe(
        { query_type: 'batch' },
        duration
      );

      this.logger.debug('Batch queries executed', {
        queryCount: queries.length,
        duration
      });

      return results;
    } catch (error: any) {
      metrics.dbErrors.inc({ type: 'batch_error' });
      this.logger.error('Batch query failed', {
        queryCount: queries.length,
        error: error.message
      });
      throw error;
    } finally {
      client.release();
    }
  }

  private getQueryType(query: string): string {
    const normalized = query.trim().toLowerCase();
    if (normalized.startsWith('select')) return 'select';
    if (normalized.startsWith('insert')) return 'insert';
    if (normalized.startsWith('update')) return 'update';
    if (normalized.startsWith('delete')) return 'delete';
    if (normalized.startsWith('with')) return 'cte';
    return 'other';
  }

  async getPoolStats(): Promise<PoolStats> {
    return {
      totalCount: this.pool.totalCount,
      idleCount: this.pool.idleCount,
      waitingCount: this.pool.waitingCount,
      config: {
        min: this.pool.options.min || 0,
        max: this.pool.options.max || 0
      }
    };
  }

  async getDetailedStats(): Promise<DetailedPoolStats> {
    const basicStats = await this.getPoolStats();
    
    return {
      ...basicStats,
      performance: {
        averageAcquireTime: await this.calculateAverageAcquireTime(),
        connectionUtilization: basicStats.totalCount > 0 
          ? ((basicStats.totalCount - basicStats.idleCount) / basicStats.totalCount) * 100 
          : 0,
        queuedRequests: basicStats.waitingCount
      },
      health: {
        isHealthy: await this.isPoolHealthy(),
        lastHealthCheck: new Date(),
        uptime: process.uptime()
      }
    };
  }

  private async calculateAverageAcquireTime(): Promise<number> {
    // In a real implementation, this would track acquisition times
    // For now, return 0 as placeholder
    return 0;
  }

  private async isPoolHealthy(): Promise<boolean> {
    try {
      const stats = await this.getPoolStats();
      
      // Pool is unhealthy if:
      // - Too many waiting connections
      // - No idle connections and at max capacity
      // - Basic health check fails
      
      if (stats.waitingCount > 10) return false;
      if (stats.idleCount === 0 && stats.totalCount >= (this.pool.options.max || 20)) return false;
      
      const healthCheck = await this.healthCheck();
      return healthCheck.status === 'healthy';
    } catch {
      return false;
    }
  }

  async healthCheck(): Promise<{ status: string; latency?: number; details?: any }> {
    const startTime = Date.now();
    
    try {
      await this.query('SELECT 1 as health_check');
      const latency = Date.now() - startTime;
      const stats = await this.getPoolStats();
      
      return { 
        status: 'healthy', 
        latency,
        details: {
          poolSize: stats.totalCount,
          idleConnections: stats.idleCount,
          waitingConnections: stats.waitingCount
        }
      };
    } catch (error: any) {
      return { 
        status: 'unhealthy',
        details: {
          error: error.message,
          timestamp: new Date().toISOString()
        }
      };
    }
  }

  async optimizeConnections(): Promise<OptimizationResult> {
    const results: OptimizationResult = {
      actions: [],
      recommendations: [],
      beforeStats: await this.getDetailedStats()
    };

    try {
      // Check if pool needs scaling
      const stats = await this.getPoolStats();
      
      if (stats.waitingCount > 5) {
        results.recommendations.push(
          'Consider increasing DB_POOL_MAX - high queue detected'
        );
      }
      
      if (stats.idleCount > (stats.totalCount * 0.8)) {
        results.recommendations.push(
          'Consider decreasing DB_POOL_MIN - many idle connections'
        );
      }

      // Perform maintenance operations
      await this.performMaintenance();
      results.actions.push('Performed connection pool maintenance');

      results.afterStats = await this.getDetailedStats();
      
      this.logger.info('Connection pool optimization completed', results);
      return results;
    } catch (error: any) {
      this.logger.error('Connection pool optimization failed', { error: error.message });
      throw error;
    }
  }

  private async performMaintenance(): Promise<void> {
    // In a real implementation, this could:
    // - Close idle connections that have been idle too long
    // - Validate connection health
    // - Clear any stuck connections
    
    this.logger.debug('Performing connection pool maintenance');
  }

  async gracefulShutdown(timeoutMs: number = 5000): Promise<void> {
    this.logger.info('Starting graceful database shutdown');
    
    // Clear monitoring interval
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
    }

    // Wait for active connections to finish or timeout
    const shutdownPromise = this.pool.end();
    const timeoutPromise = new Promise((_, reject) => 
      setTimeout(() => reject(new Error('Shutdown timeout')), timeoutMs)
    );

    try {
      await Promise.race([shutdownPromise, timeoutPromise]);
      this.logger.info('Database connections closed gracefully');
    } catch (error) {
      this.logger.warn('Forced database shutdown due to timeout');
      // Force close if needed
      await this.pool.end();
    }
  }

  async close(): Promise<void> {
    await this.gracefulShutdown();
  }
}

export interface PoolStats {
  totalCount: number;
  idleCount: number;
  waitingCount: number;
  config: {
    min: number;
    max: number;
  };
}

export interface DetailedPoolStats extends PoolStats {
  performance: {
    averageAcquireTime: number;
    connectionUtilization: number;
    queuedRequests: number;
  };
  health: {
    isHealthy: boolean;
    lastHealthCheck: Date;
    uptime: number;
  };
}

export interface OptimizationResult {
  actions: string[];
  recommendations: string[];
  beforeStats: DetailedPoolStats;
  afterStats?: DetailedPoolStats;
}

// Singleton instance for global use
let globalPool: DatabaseConnectionPool | null = null;

export function getConnectionPool(): DatabaseConnectionPool {
  if (!globalPool) {
    globalPool = new DatabaseConnectionPool();
  }
  return globalPool;
}

export function createConnectionPool(): DatabaseConnectionPool {
  return new DatabaseConnectionPool();
}
