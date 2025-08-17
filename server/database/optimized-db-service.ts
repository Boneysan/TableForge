// server/database/optimized-db-service.ts
import { DatabaseConnectionPool } from './connection-pool';
import { RedisCacheService } from '../cache/redis-cache';
import { QueryOptimizer, RoomWithAssets, GameAsset, GameSystem, GameSystemFilters } from './query-optimizer';
import { dbLogger as logger } from '../utils/logger';

/**
 * Enhanced database service that combines connection pooling, 
 * caching, and query optimization for maximum performance.
 */
export class OptimizedDatabaseService {
  private queryOptimizer: QueryOptimizer;

  constructor(
    private connectionPool: DatabaseConnectionPool,
    private cacheService: RedisCacheService
  ) {
    this.queryOptimizer = new QueryOptimizer(connectionPool, cacheService);
    logger.info('Optimized database service initialized');
  }

  // High-level room operations with optimization
  async getRoomWithCompleteData(roomId: string): Promise<RoomWithAssets | null> {
    try {
      return await this.queryOptimizer.getRoomWithAssets(roomId);
    } catch (error) {
      logger.error({ roomId, error: error instanceof Error ? error.message : String(error) }, 'Failed to get room with assets');
      throw error;
    }
  }

  async getActiveRoomPlayers(roomId: string) {
    try {
      return await this.queryOptimizer.getActivePlayersInRoom(roomId);
    } catch (error) {
      logger.error({ roomId, error: error instanceof Error ? error.message : String(error) }, 'Failed to get active players');
      throw error;
    }
  }

  // Optimized asset operations
  async getMultipleAssets(assetIds: string[]): Promise<GameAsset[]> {
    try {
      return await this.queryOptimizer.getAssetsBatch(assetIds);
    } catch (error) {
      logger.error({ assetIds: assetIds.length, error: error instanceof Error ? error.message : String(error) }, 'Failed to get multiple assets');
      throw error;
    }
  }

  // Enhanced search with caching
  async searchGameSystems(
    filters: GameSystemFilters = {},
    page: number = 1,
    limit: number = 20
  ): Promise<{ systems: GameSystem[]; total: number; page: number; totalPages: number }> {
    try {
      const result = await this.queryOptimizer.searchGameSystems(filters, { page, limit });
      
      return {
        ...result,
        page,
        totalPages: Math.ceil(result.total / limit)
      };
    } catch (error) {
      logger.error({ filters, page, limit, error: error instanceof Error ? error.message : String(error) }, 'Failed to search game systems');
      throw error;
    }
  }

  // Database performance and monitoring
  async getPerformanceReport(): Promise<DatabasePerformanceReport> {
    try {
      const [
        performanceMetrics,
        poolStats,
        cacheEfficiency,
        slowQueries,
        tableStats
      ] = await Promise.all([
        this.queryOptimizer.getPerformanceMetrics(),
        this.connectionPool.getPoolStats(),
        this.queryOptimizer.getCacheEfficiency(),
        this.queryOptimizer.getSlowQueries(),
        this.queryOptimizer.getTableStats()
      ]);

      const healthCheck = await this.connectionPool.healthCheck();

      return {
        timestamp: new Date(),
        database: {
          status: healthCheck.status,
          latency: healthCheck.latency || 0,
          poolStats,
          slowQueryCount: slowQueries.length,
          averageQueryTime: performanceMetrics.averageQueryTime
        },
        cache: {
          hitRate: cacheEfficiency.hitRate,
          keyCount: cacheEfficiency.keyCount,
          memoryUsage: cacheEfficiency.memoryUsage
        },
        tables: {
          totalRows: tableStats.reduce((sum, t) => sum + t.live_tuples, 0),
          totalTables: tableStats.length,
          needsVacuum: tableStats.filter(t => {
            const deadRatio = t.dead_tuples / (t.live_tuples + t.dead_tuples);
            return deadRatio > 0.1;
          }).length
        },
        recommendations: performanceMetrics.recommendations
      };
    } catch (error) {
      logger.error({ error: error instanceof Error ? error.message : String(error) }, 'Failed to generate performance report');
      throw error;
    }
  }

  // Automated optimization and maintenance
  async runOptimization(): Promise<OptimizationReport> {
    try {
      logger.info('Starting database optimization');
      const startTime = Date.now();

      const [
        queryOptimization,
        maintenance,
        cacheOptimization
      ] = await Promise.all([
        this.queryOptimizer.optimizeQueries(),
        this.queryOptimizer.optimizeTableMaintenance(),
        this.optimizeCacheConfiguration()
      ]);

      // Cleanup old statistics
      await this.queryOptimizer.cleanupOldStatistics();

      const duration = Date.now() - startTime;
      const report: OptimizationReport = {
        timestamp: new Date(),
        duration,
        queryOptimization,
        maintenance,
        cacheOptimization,
        success: true
      };

      logger.info(report, 'Database optimization completed');
      return report;
    } catch (error) {
      logger.error({ error: error instanceof Error ? error.message : String(error) }, 'Database optimization failed');
      return {
        timestamp: new Date(),
        duration: 0,
        queryOptimization: { analyzedTables: 0, updatedIndexes: 0, vacuumedTables: 0, recommendations: [] },
        maintenance: { reindexedTables: 0, vacuumedTables: 0, analyzedTables: 0, recommendations: [] },
        cacheOptimization: { keysEvicted: 0, recommendations: [] },
        success: false,
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  // Cache optimization helper
  private async optimizeCacheConfiguration(): Promise<CacheOptimizationResult> {
    try {
      const result: CacheOptimizationResult = {
        keysEvicted: 0,
        recommendations: []
      };

      // Get cache efficiency report
      const efficiency = await this.queryOptimizer.getCacheEfficiency();
      
      // Clean up expired or low-usage cache entries if hit rate is low
      if (efficiency.hitRate < 0.7) {
        // This would involve cache cleanup logic
        result.recommendations.push('Low cache hit rate detected, consider reviewing cache TTL settings');
      }

      if (efficiency.keyCount > 50000) {
        result.recommendations.push('High cache key count, consider implementing more aggressive eviction policies');
      }

      return result;
    } catch (error) {
      logger.error({ error: error instanceof Error ? error.message : String(error) }, 'Cache optimization failed');
      return { keysEvicted: 0, recommendations: ['Cache optimization failed'] };
    }
  }

  // Health monitoring
  async performHealthCheck(): Promise<HealthCheckResult> {
    try {
      const [dbHealth, cacheHealth] = await Promise.all([
        this.connectionPool.healthCheck(),
        this.cacheService.healthCheck()
      ]);

      const poolStats = await this.connectionPool.getPoolStats();
      
      return {
        timestamp: new Date(),
        database: {
          healthy: dbHealth.status === 'healthy',
          latency: dbHealth.latency || 0,
          poolUtilization: poolStats.totalCount / (poolStats.config.max || 1)
        },
        cache: {
          healthy: cacheHealth.status === 'healthy',
          connected: cacheHealth.status === 'healthy'
        },
        overall: dbHealth.status === 'healthy' && cacheHealth.status === 'healthy'
      };
    } catch (error) {
      logger.error({ error: error instanceof Error ? error.message : String(error) }, 'Health check failed');
      return {
        timestamp: new Date(),
        database: { healthy: false, latency: 0, poolUtilization: 0 },
        cache: { healthy: false, connected: false },
        overall: false,
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  // Utility methods for direct access to optimized services
  getQueryOptimizer(): QueryOptimizer {
    return this.queryOptimizer;
  }

  getConnectionPool(): DatabaseConnectionPool {
    return this.connectionPool;
  }

  getCacheService(): RedisCacheService {
    return this.cacheService;
  }

  // Graceful shutdown
  async shutdown(): Promise<void> {
    try {
      logger.info('Shutting down optimized database service');
      await Promise.all([
        this.connectionPool.close(),
        this.cacheService.close()
      ]);
      logger.info('Optimized database service shutdown complete');
    } catch (error) {
      logger.error({ error: error instanceof Error ? error.message : String(error) }, 'Error during database service shutdown');
    }
  }
}

// Type definitions for the service
export interface DatabasePerformanceReport {
  timestamp: Date;
  database: {
    status: string;
    latency: number;
    poolStats: any;
    slowQueryCount: number;
    averageQueryTime: number;
  };
  cache: {
    hitRate: number;
    keyCount: number;
    memoryUsage: any;
  };
  tables: {
    totalRows: number;
    totalTables: number;
    needsVacuum: number;
  };
  recommendations: string[];
}

export interface OptimizationReport {
  timestamp: Date;
  duration: number;
  queryOptimization: {
    analyzedTables: number;
    updatedIndexes: number;
    vacuumedTables: number;
    recommendations: string[];
  };
  maintenance: {
    reindexedTables: number;
    vacuumedTables: number;
    analyzedTables: number;
    recommendations: string[];
  };
  cacheOptimization: CacheOptimizationResult;
  success: boolean;
  error?: string;
}

export interface CacheOptimizationResult {
  keysEvicted: number;
  recommendations: string[];
}

export interface HealthCheckResult {
  timestamp: Date;
  database: {
    healthy: boolean;
    latency: number;
    poolUtilization: number;
  };
  cache: {
    healthy: boolean;
    connected: boolean;
  };
  overall: boolean;
  error?: string;
}
