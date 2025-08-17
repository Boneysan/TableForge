// server/database/optimized-connection-pool.ts
// Phase 3 Database Optimization: Enhanced connection pooling with monitoring

import { Pool, PoolClient, PoolConfig } from '@neondatabase/serverless';
import { drizzle } from 'drizzle-orm/neon-serverless';
import { createUserLogger } from '../utils/logger';
import { metrics } from '../observability/metrics';
import * as schema from '@shared/schema';

const logger = createUserLogger('db-pool');

export interface PoolStats {
  totalConnections: number;
  idleConnections: number;
  activeConnections: number;
  waitingClients: number;
  maxConnections: number;
  averageAcquireTime: number;
  longestWaitTime: number;
}

export interface ConnectionMetrics {
  acquisitions: number;
  releases: number;
  errors: number;
  timeouts: number;
  totalAcquireTime: number;
  acquisitionTimes: number[];
}

export class OptimizedConnectionPool {
  private pool!: Pool;
  private drizzleDb!: ReturnType<typeof drizzle>;
  private connectionMetrics: ConnectionMetrics;
  private healthCheckInterval: NodeJS.Timeout | null = null;
  private statsInterval: NodeJS.Timeout | null = null;
  private activeConnections = new Set<PoolClient>();
  private waitingQueue: Array<{ resolve: Function; reject: Function; timestamp: number }> = [];

  constructor() {
    this.connectionMetrics = {
      acquisitions: 0,
      releases: 0,
      errors: 0,
      timeouts: 0,
      totalAcquireTime: 0,
      acquisitionTimes: []
    };

    this.initializePool();
    this.setupMonitoring();
  }

  private initializePool(): void {
    const poolConfig: PoolConfig = {
      connectionString: process.env['DATABASE_URL'],
      
      // Optimized pool settings for high concurrency
      max: parseInt(process.env['DB_POOL_MAX'] || '20'), // Maximum connections
      min: parseInt(process.env['DB_POOL_MIN'] || '5'),  // Minimum connections
      
      // Connection timeouts
      connectionTimeoutMillis: parseInt(process.env['DB_CONNECTION_TIMEOUT'] || '10000'),
      idleTimeoutMillis: parseInt(process.env['DB_IDLE_TIMEOUT'] || '30000'),
      
      // Advanced pool configuration
      maxUses: parseInt(process.env['DB_MAX_USES'] || '7500'), // Rotate connections
      // Additional pool config properties removed as they don't exist in PoolConfig type
      
      // Performance optimizations
      // createRetryIntervalMillis and acquireMaxRetries removed as they don't exist in PoolConfig
      
      // Validation and health checks removed as properties don't exist in PoolConfig
      // Most advanced pool configuration options are not supported by pg Pool
    };

    this.pool = new Pool(poolConfig);
    this.drizzleDb = drizzle({ client: this.pool, schema });

    // Pool event handlers
    this.pool.on('connect', (client) => {
      this.activeConnections.add(client);
      logger.debug('Database client connected', {
        activeConnections: this.activeConnections.size,
        poolSize: this.pool.totalCount
      });
      
      metrics.dbConnections?.set({ status: 'active' }, this.activeConnections.size);
    });

    this.pool.on('acquire', (_client) => {
      this.connectionMetrics.acquisitions++;
      // metrics.dbPoolOperations?.inc({ operation: 'acquire' }); // Commented out until metric is defined
    });

    this.pool.on('remove', (client) => {
      this.activeConnections.delete(client);
      logger.debug('Database client removed', {
        activeConnections: this.activeConnections.size
      });
    });

    this.pool.on('error', (error, client) => {
      this.connectionMetrics.errors++;
      logger.error('Database pool error', { 
        error: error.message,
        stack: error.stack,
        clientConnected: client ? 'yes' : 'no'
      });
      
      metrics.dbErrors?.inc({ type: 'pool_error' });
    });

    logger.info('Optimized database connection pool initialized', {
      maxConnections: poolConfig.max,
      minConnections: poolConfig.min,
      connectionTimeout: poolConfig.connectionTimeoutMillis,
      idleTimeout: poolConfig.idleTimeoutMillis
    });
  }

  private setupMonitoring(): void {
    // Health check every 30 seconds
    this.healthCheckInterval = setInterval(async () => {
      await this.performHealthCheck();
    }, 30000);

    // Stats reporting every 10 seconds
    this.statsInterval = setInterval(() => {
      this.reportStats();
    }, 10000);

    // Cleanup old acquisition times (keep last 1000)
    setInterval(() => {
      if (this.connectionMetrics.acquisitionTimes.length > 1000) {
        this.connectionMetrics.acquisitionTimes = 
          this.connectionMetrics.acquisitionTimes.slice(-1000);
      }
    }, 60000);
  }

  // Enhanced connection acquisition with monitoring
  async acquireConnection(): Promise<PoolClient> {
    const startTime = Date.now();
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => {
        this.connectionMetrics.timeouts++;
        reject(new Error('Connection acquisition timeout'));
      }, parseInt(process.env['DB_ACQUIRE_TIMEOUT'] || '15000'));
    });

    try {
      const client = await Promise.race([
        this.pool.connect(),
        timeoutPromise
      ]);

      const acquireTime = Date.now() - startTime;
      this.connectionMetrics.totalAcquireTime += acquireTime;
      this.connectionMetrics.acquisitionTimes.push(acquireTime);

      // Record metrics
      // metrics.dbConnectionAcquireTime?.observe(acquireTime); // Commented out until metric is defined
      
      if (acquireTime > 1000) { // Log slow acquisitions
        logger.warn('Slow database connection acquisition', {
          acquireTime,
          activeConnections: this.activeConnections.size,
          poolSize: this.pool.totalCount
        });
      }

      return client;

    } catch (error) {
      this.connectionMetrics.errors++;
      metrics.dbErrors?.inc({ type: 'connection_acquire' });
      
      logger.error('Failed to acquire database connection', {
        error: error instanceof Error ? error.message : String(error),
        acquireTime: Date.now() - startTime,
        activeConnections: this.activeConnections.size
      });
      
      throw error;
    }
  }

  // Safe connection release with error handling
  releaseConnection(client: PoolClient): void {
    try {
      if (client && typeof client.release === 'function') {
        client.release();
        logger.debug('Database connection released successfully');
      }
    } catch (error) {
      logger.error('Error releasing database connection', {
        error: error instanceof Error ? error.message : String(error)
      });
      metrics.dbErrors?.inc({ type: 'connection_release' });
    }
  }

  // Enhanced query execution with connection management
  async executeQuery<T>(
    query: string, 
    params: any[] = [],
    options: { timeout?: number; retries?: number } = {}
  ): Promise<T> {
    const { timeout = 30000, retries = 2 } = options;
    const startTime = Date.now();
    let lastError: Error | null = null;
    
    for (let attempt = 0; attempt <= retries; attempt++) {
      const client = await this.acquireConnection();
      
      try {
        // Set statement timeout
        if (timeout !== 30000) {
          await client.query(`SET statement_timeout = ${timeout}`);
        }
        
        const result = await client.query(query, params);
        const duration = Date.now() - startTime;
        
        // Record query metrics
        const queryType = this.getQueryType(query);
        // metrics.dbQueryDuration?.observe({ operation: queryType }, duration); // Fixed label name
        
        if (duration > 1000) { // Log slow queries
          logger.warn('Slow database query detected', {
            query: query.substring(0, 200),
            duration,
            attempt: attempt + 1,
            rowCount: result.rowCount
          });
        }
        
        logger.debug('Database query executed', {
          queryType,
          duration,
          rowCount: result.rowCount,
          attempt: attempt + 1
        });

        return result.rows as T;

      } catch (error) {
        lastError = error as Error;
        
        logger.error('Database query failed', {
          query: query.substring(0, 200),
          error: lastError.message,
          attempt: attempt + 1,
          duration: Date.now() - startTime
        });
        
        metrics.dbErrors?.inc({ 
          type: 'query_error'
        });
        
        // Don't retry for certain types of errors
        if (this.isNonRetryableError(lastError)) {
          throw lastError;
        }
        
        // Wait before retry (exponential backoff)
        if (attempt < retries) {
          await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 100));
        }
        
      } finally {
        this.releaseConnection(client);
        
        // Reset statement timeout
        if (timeout !== 30000) {
          try {
            await client.query('RESET statement_timeout');
          } catch (resetError) {
            logger.warn('Failed to reset statement timeout', { 
              error: resetError 
            });
          }
        }
      }
    }
    
    throw lastError || new Error('Query failed after all retries');
  }

  // Transaction execution with enhanced error handling
  async executeTransaction<T>(
    callback: (client: PoolClient) => Promise<T>,
    options: { timeout?: number; isolationLevel?: string } = {}
  ): Promise<T> {
    const { timeout = 60000, isolationLevel = 'READ COMMITTED' } = options;
    const startTime = Date.now();
    const client = await this.acquireConnection();

    try {
      // Set transaction timeout and isolation level
      await client.query(`SET statement_timeout = ${timeout}`);
      await client.query(`BEGIN ISOLATION LEVEL ${isolationLevel}`);
      
      const result = await callback(client);
      await client.query('COMMIT');
      
      const duration = Date.now() - startTime;
      metrics.dbTransactionDuration?.observe(duration);
      
      logger.debug('Database transaction completed', { 
        duration,
        isolationLevel 
      });
      
      return result;

    } catch (error) {
      try {
        await client.query('ROLLBACK');
        logger.debug('Database transaction rolled back');
      } catch (rollbackError) {
        logger.error('Failed to rollback transaction', { 
          rollbackError,
          originalError: error 
        });
      }
      
      metrics.dbErrors?.inc({ type: 'transaction_error' });
      
      logger.error('Database transaction failed', {
        error: (error as Error).message,
        duration: Date.now() - startTime,
        isolationLevel
      });
      
      throw error;

    } finally {
      try {
        await client.query('RESET statement_timeout');
      } catch (resetError) {
        logger.warn('Failed to reset statement timeout after transaction', { 
          error: resetError 
        });
      }
      
      this.releaseConnection(client);
    }
  }

  // Pool statistics and monitoring
  getPoolStats(): PoolStats {
    const averageAcquireTime = this.connectionMetrics.acquisitions > 0
      ? this.connectionMetrics.totalAcquireTime / this.connectionMetrics.acquisitions
      : 0;

    const longestWaitTime = this.connectionMetrics.acquisitionTimes.length > 0
      ? Math.max(...this.connectionMetrics.acquisitionTimes)
      : 0;

    return {
      totalConnections: this.pool.totalCount || 0,
      idleConnections: this.pool.idleCount || 0,
      activeConnections: this.activeConnections.size,
      waitingClients: this.waitingQueue.length,
      maxConnections: parseInt(process.env['DB_POOL_MAX'] || '20'),
      averageAcquireTime,
      longestWaitTime
    };
  }

  getConnectionMetrics(): ConnectionMetrics {
    return { ...this.connectionMetrics };
  }

  // Health monitoring
  private async performHealthCheck(): Promise<void> {
    try {
      const startTime = Date.now();
      await this.executeQuery('SELECT 1 as health_check');
      const latency = Date.now() - startTime;
      
      // metrics.dbHealthCheck?.set({ status: 'healthy' }, 1); // Commented out until metric is defined
      // metrics.dbHealthCheckLatency?.observe(latency); // Commented out until metric is defined
      
      if (latency > 5000) { // 5 second threshold
        logger.warn('Database health check slow', { latency });
      }

    } catch (error) {
      // metrics.dbHealthCheck?.set({ status: 'unhealthy' }, 1); // Commented out until metric is defined
      logger.error('Database health check failed', { error });
    }
  }

  private reportStats(): void {
    const stats = this.getPoolStats();
    
    // Update Prometheus metrics
    // Commenting out until metrics are properly defined
    // metrics.dbPoolSize?.set(stats.totalConnections);
    // metrics.dbPoolIdle?.set(stats.idleConnections);
    // metrics.dbPoolActive?.set(stats.activeConnections);
    // metrics.dbPoolWaiting?.set(stats.waitingClients);
    
    // Log stats if pool utilization is high
    const utilization = stats.activeConnections / stats.maxConnections;
    if (utilization > 0.8) {
      logger.warn('High database pool utilization', {
        utilization: `${(utilization * 100).toFixed(1)}%`,
        activeConnections: stats.activeConnections,
        maxConnections: stats.maxConnections,
        waitingClients: stats.waitingClients
      });
    }
  }

  // Utility methods
  private getQueryType(query: string): string {
    const normalized = query.trim().toLowerCase();
    if (normalized.startsWith('select')) return 'select';
    if (normalized.startsWith('insert')) return 'insert';
    if (normalized.startsWith('update')) return 'update';
    if (normalized.startsWith('delete')) return 'delete';
    if (normalized.startsWith('with')) return 'cte';
    return 'other';
  }

  private isNonRetryableError(error: Error): boolean {
    const message = error.message.toLowerCase();
    
    // Don't retry syntax errors, constraint violations, etc.
    return message.includes('syntax error') ||
           message.includes('duplicate key') ||
           message.includes('foreign key') ||
           message.includes('check constraint') ||
           message.includes('not null violation') ||
           message.includes('permission denied');
  }

  // Getters for external access
  get db() {
    return this.drizzleDb;
  }

  get rawPool() {
    return this.pool;
  }

  // Cleanup and shutdown
  async close(): Promise<void> {
    logger.info('Closing optimized database connection pool');
    
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
      this.healthCheckInterval = null;
    }
    
    if (this.statsInterval) {
      clearInterval(this.statsInterval);
      this.statsInterval = null;
    }
    
    try {
      await this.pool.end();
      logger.info('Database connection pool closed successfully');
    } catch (error) {
      logger.error('Error closing database connection pool', { error });
      throw error;
    }
  }

  // Pool warming for production
  async warmPool(): Promise<void> {
    const minConnections = parseInt(process.env['DB_POOL_MIN'] || '5');
    const connections: PoolClient[] = [];
    
    logger.info(`Warming database pool with ${minConnections} connections`);
    
    try {
      // Create minimum number of connections
      for (let i = 0; i < minConnections; i++) {
        const client = await this.acquireConnection();
        connections.push(client);
      }
      
      // Test each connection
      await Promise.all(
        connections.map(async (client, index) => {
          try {
            await client.query('SELECT 1');
            logger.debug(`Pool connection ${index + 1} warmed successfully`);
          } catch (error) {
            logger.warn(`Pool connection ${index + 1} warm-up failed`, { error });
          }
        })
      );
      
    } finally {
      // Release all connections back to pool
      connections.forEach(client => this.releaseConnection(client));
    }
    
    logger.info('Database pool warming completed');
  }
}

// Export singleton instance
export const optimizedPool = new OptimizedConnectionPool();
export default optimizedPool;
