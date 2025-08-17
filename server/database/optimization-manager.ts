// server/database/optimization-manager.ts
import { OptimizedConnectionPool } from './optimized-connection-pool';
import { OptimizedDatabaseService } from './optimized-db-service';
import { DatabaseMonitoringService } from './monitoring-service';
import { RedisCacheService } from '../cache/redis-cache';
import { dbLogger as logger } from '../utils/logger';

/**
 * Central database optimization manager that coordinates all database
 * optimization services and provides a unified interface for Phase 3
 * database performance enhancements.
 */
export class DatabaseOptimizationManager {
  private connectionPool!: OptimizedConnectionPool;
  private databaseService!: OptimizedDatabaseService;
  private monitoringService!: DatabaseMonitoringService;
  private isInitialized = false;

  constructor(private cacheService: RedisCacheService) {
    logger.info('Database optimization manager created');
  }

  // Initialize all optimization services
  async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('Database optimization manager already initialized');
      return;
    }

    try {
      logger.info('Initializing database optimization services');

      // Initialize optimized connection pool
      this.connectionPool = new OptimizedConnectionPool();
      // Connection pool auto-initializes on first use

      // Initialize optimized database service
      this.databaseService = new OptimizedDatabaseService(
        this.connectionPool as any, // Type compatibility
        this.cacheService
      );

      // Initialize monitoring service
      this.monitoringService = new DatabaseMonitoringService(this.databaseService);
      await this.monitoringService.start();

      this.isInitialized = true;
      logger.info('Database optimization services initialized successfully');

      // Perform initial optimization check
      await this.performInitialOptimization();

    } catch (error) {
      logger.error('Failed to initialize database optimization services', { 
        error: error instanceof Error ? error.message : String(error) 
      });
      throw error;
    }
  }

  // Perform initial optimization when starting up
  private async performInitialOptimization(): Promise<void> {
    try {
      logger.info('Performing initial database optimization');

      // Check health first
      const healthCheck = await this.databaseService.performHealthCheck();
      
      if (!healthCheck.overall) {
        logger.warn('Skipping initial optimization due to health issues', { healthCheck });
        return;
      }

      // Get performance report to assess optimization needs
      const report = await this.databaseService.getPerformanceReport();
      
      // Run optimization if needed
      const needsOptimization = 
        report.cache.hitRate < 0.8 ||
        report.database.averageQueryTime > 50 ||
        report.tables.needsVacuum > 0;

      if (needsOptimization) {
        logger.info('Initial optimization needed', {
          cacheHitRate: report.cache.hitRate,
          avgQueryTime: report.database.averageQueryTime,
          tablesNeedingVacuum: report.tables.needsVacuum
        });

        await this.databaseService.runOptimization();
        logger.info('Initial optimization completed');
      } else {
        logger.info('Database already optimized, skipping initial optimization');
      }

    } catch (error) {
      logger.error('Initial optimization failed', { 
        error: error instanceof Error ? error.message : String(error) 
      });
      // Don't throw - initialization should continue even if optimization fails
    }
  }

  // Get comprehensive status of all optimization services
  async getOptimizationStatus(): Promise<OptimizationStatus> {
    if (!this.isInitialized) {
      throw new Error('Database optimization manager not initialized');
    }

    try {
      const [
        healthCheck,
        performanceReport,
        monitoringStats,
        poolStats
      ] = await Promise.all([
        this.databaseService.performHealthCheck(),
        this.databaseService.getPerformanceReport(),
        this.monitoringService.getMonitoringStats(),
        Promise.resolve(this.connectionPool.getPoolStats())
      ]);

      return {
        timestamp: new Date(),
        initialized: this.isInitialized,
        services: {
          connectionPool: {
            status: poolStats.totalConnections > 0 ? 'healthy' : 'unhealthy',
            totalConnections: poolStats.totalConnections,
            activeConnections: poolStats.activeConnections,
            idleConnections: poolStats.idleConnections,
            configuration: {
              maxConnections: poolStats.maxConnections,
              averageAcquireTime: poolStats.averageAcquireTime
            }
          },
          database: {
            status: healthCheck.database.healthy ? 'healthy' : 'unhealthy',
            latency: healthCheck.database.latency,
            poolUtilization: healthCheck.database.poolUtilization
          },
          cache: {
            status: healthCheck.cache.healthy ? 'healthy' : 'unhealthy',
            hitRate: performanceReport.cache.hitRate,
            keyCount: performanceReport.cache.keyCount
          },
          monitoring: {
            status: 'healthy', // Monitoring service doesn't have explicit health check
            isRunning: monitoringStats.lastHealthCheck !== null,
            lastCheck: monitoringStats.lastHealthCheck,
            alertsTriggered: monitoringStats.alertsTriggered
          }
        },
        performance: {
          overallHealth: healthCheck.overall,
          averageQueryTime: performanceReport.database.averageQueryTime,
          slowQueryCount: performanceReport.database.slowQueryCount,
          tablesNeedingOptimization: performanceReport.tables.needsVacuum,
          recommendations: performanceReport.recommendations
        },
        optimization: {
          lastRun: monitoringStats.lastOptimization,
          totalRuns: monitoringStats.optimizationRuns,
          averageHealthScore: monitoringStats.averageHealthScore,
          autoOptimizationEnabled: true
        }
      };

    } catch (error) {
      logger.error('Failed to get optimization status', { error });
      throw error;
    }
  }

  // Run comprehensive optimization across all services
  async runFullOptimization(): Promise<FullOptimizationReport> {
    if (!this.isInitialized) {
      throw new Error('Database optimization manager not initialized');
    }

    logger.info('Starting full database optimization');
    const startTime = Date.now();

    try {
      const [
        connectionPoolOptimization,
        databaseOptimization,
        cacheOptimization
      ] = await Promise.all([
        this.optimizeConnectionPool(),
        this.databaseService.runOptimization(),
        this.optimizeCacheConfiguration()
      ]);

      const duration = Date.now() - startTime;

      const report: FullOptimizationReport = {
        timestamp: new Date(),
        duration,
        success: true,
        connectionPool: connectionPoolOptimization,
        database: databaseOptimization,
        cache: cacheOptimization,
        summary: {
          totalTablesOptimized: databaseOptimization.queryOptimization.analyzedTables +
                               databaseOptimization.maintenance.vacuumedTables,
          totalRecommendations: [
            ...connectionPoolOptimization.recommendations,
            ...databaseOptimization.queryOptimization.recommendations,
            ...databaseOptimization.maintenance.recommendations,
            ...cacheOptimization.recommendations
          ].length,
          performanceImprovement: await this.calculatePerformanceImprovement()
        }
      };

      logger.info('Full optimization completed successfully', {
        duration,
        tablesOptimized: report.summary.totalTablesOptimized,
        recommendations: report.summary.totalRecommendations
      });

      return report;

    } catch (error) {
      logger.error('Full optimization failed', { 
        error: error instanceof Error ? error.message : String(error) 
      });

      return {
        timestamp: new Date(),
        duration: Date.now() - startTime,
        success: false,
        error: error instanceof Error ? error.message : String(error),
        connectionPool: { recommendations: [] },
        database: {
          queryOptimization: { analyzedTables: 0, updatedIndexes: 0, vacuumedTables: 0, recommendations: [] },
          maintenance: { reindexedTables: 0, vacuumedTables: 0, analyzedTables: 0, recommendations: [] },
          cacheOptimization: { keysEvicted: 0, recommendations: [] },
          success: false
        },
        cache: { recommendations: [] },
        summary: {
          totalTablesOptimized: 0,
          totalRecommendations: 0,
          performanceImprovement: 0
        }
      };
    }
  }

  // Optimize connection pool configuration
  private async optimizeConnectionPool(): Promise<ConnectionPoolOptimizationResult> {
    try {
      const stats = this.connectionPool.getPoolStats();
      const recommendations: string[] = [];

      // Analyze pool utilization and make recommendations
      const utilizationRatio = stats.activeConnections / stats.totalConnections;
      
      if (utilizationRatio > 0.9) {
        recommendations.push('High pool utilization detected, consider increasing max connections');
      } else if (utilizationRatio < 0.1) {
        recommendations.push('Low pool utilization, consider reducing min connections to save resources');
      }

      if (stats.averageAcquireTime > 5000) {
        recommendations.push('Consider increasing acquire timeout for better resilience');
      }

      // Warm up pool if needed
      if (stats.idleConnections < 2) {
        await this.connectionPool.warmPool();
        recommendations.push('Connection pool warmed up for better performance');
      }

      return { recommendations };

    } catch (error) {
      logger.error('Connection pool optimization failed', { error });
      return { 
        recommendations: ['Connection pool optimization failed'],
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  // Optimize cache configuration
  private async optimizeCacheConfiguration(): Promise<CacheOptimizationResult> {
    try {
      const recommendations: string[] = [];
      
      // Get cache health
      const healthCheck = await this.cacheService.healthCheck();
      
      if (healthCheck.status !== 'healthy') {
        recommendations.push('Cache service health issues detected');
      }

      // Additional cache optimization logic would go here
      // This could include analyzing cache hit rates, eviction patterns, etc.
      
      return { recommendations };

    } catch (error) {
      logger.error('Cache optimization failed', { error });
      return { 
        recommendations: ['Cache optimization failed'],
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  // Calculate performance improvement after optimization
  private async calculatePerformanceImprovement(): Promise<number> {
    try {
      // This is a simplified calculation - in production you'd compare
      // before/after metrics stored over time
      const report = await this.databaseService.getPerformanceReport();
      
      // Return a basic improvement score based on current metrics
      let score = 0;
      
      if (report.cache.hitRate > 0.9) score += 30;
      else if (report.cache.hitRate > 0.8) score += 20;
      else if (report.cache.hitRate > 0.7) score += 10;
      
      if (report.database.averageQueryTime < 50) score += 25;
      else if (report.database.averageQueryTime < 100) score += 15;
      else if (report.database.averageQueryTime < 200) score += 5;
      
      if (report.tables.needsVacuum === 0) score += 20;
      else if (report.tables.needsVacuum < 3) score += 10;
      
      if (report.database.slowQueryCount === 0) score += 25;
      else if (report.database.slowQueryCount < 5) score += 15;
      else if (report.database.slowQueryCount < 10) score += 5;
      
      return Math.min(100, score);

    } catch (error) {
      logger.error('Failed to calculate performance improvement', { error });
      return 0;
    }
  }

  // Get monitoring dashboard
  async getMonitoringDashboard() {
    if (!this.isInitialized) {
      throw new Error('Database optimization manager not initialized');
    }

    return this.monitoringService.getMonitoringDashboard();
  }

  // Perform load test
  async performLoadTest(config?: any) {
    if (!this.isInitialized) {
      throw new Error('Database optimization manager not initialized');
    }

    return this.monitoringService.performLoadTest(config);
  }

  // Get individual service instances for direct access
  getConnectionPool(): OptimizedConnectionPool {
    if (!this.isInitialized) {
      throw new Error('Database optimization manager not initialized');
    }
    return this.connectionPool;
  }

  getDatabaseService(): OptimizedDatabaseService {
    if (!this.isInitialized) {
      throw new Error('Database optimization manager not initialized');
    }
    return this.databaseService;
  }

  getMonitoringService(): DatabaseMonitoringService {
    if (!this.isInitialized) {
      throw new Error('Database optimization manager not initialized');
    }
    return this.monitoringService;
  }

  // Graceful shutdown
  async shutdown(): Promise<void> {
    try {
      logger.info('Shutting down database optimization manager');

      if (this.monitoringService) {
        await this.monitoringService.stop();
      }

      if (this.databaseService) {
        await this.databaseService.shutdown();
      }

      if (this.connectionPool) {
        await this.connectionPool.close();
      }

      this.isInitialized = false;
      logger.info('Database optimization manager shutdown complete');

    } catch (error) {
      logger.error('Error during optimization manager shutdown', { error });
    }
  }
}

// Type definitions
export interface OptimizationStatus {
  timestamp: Date;
  initialized: boolean;
  services: {
    connectionPool: {
      status: 'healthy' | 'unhealthy';
      totalConnections: number;
      activeConnections: number;
      idleConnections: number;
      configuration: any;
    };
    database: {
      status: 'healthy' | 'unhealthy';
      latency: number;
      poolUtilization: number;
    };
    cache: {
      status: 'healthy' | 'unhealthy';
      hitRate: number;
      keyCount: number;
    };
    monitoring: {
      status: 'healthy' | 'unhealthy';
      isRunning: boolean;
      lastCheck: Date | null;
      alertsTriggered: number;
    };
  };
  performance: {
    overallHealth: boolean;
    averageQueryTime: number;
    slowQueryCount: number;
    tablesNeedingOptimization: number;
    recommendations: string[];
  };
  optimization: {
    lastRun: Date | null;
    totalRuns: number;
    averageHealthScore: number;
    autoOptimizationEnabled: boolean;
  };
}

export interface FullOptimizationReport {
  timestamp: Date;
  duration: number;
  success: boolean;
  error?: string;
  connectionPool: ConnectionPoolOptimizationResult;
  database: any; // Use existing OptimizationReport type
  cache: CacheOptimizationResult;
  summary: {
    totalTablesOptimized: number;
    totalRecommendations: number;
    performanceImprovement: number;
  };
}

export interface ConnectionPoolOptimizationResult {
  recommendations: string[];
  error?: string;
}

export interface CacheOptimizationResult {
  recommendations: string[];
  error?: string;
}
