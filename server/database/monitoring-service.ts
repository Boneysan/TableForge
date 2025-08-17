// server/database/monitoring-service.ts
import { OptimizedDatabaseService } from './optimized-db-service';
import { dbLogger as logger } from '../utils/logger';
import cron from 'node-cron';

/**
 * Database monitoring service that provides continuous monitoring,
 * automated optimization routines, and alerting for database performance.
 */
export class DatabaseMonitoringService {
  private isRunning = false;
  private optimizationSchedule?: cron.ScheduledTask;
  private healthCheckSchedule?: cron.ScheduledTask;
  private monitoringStats: MonitoringStats = {
    lastHealthCheck: null,
    lastOptimization: null,
    alertsTriggered: 0,
    optimizationRuns: 0,
    averageHealthScore: 100
  };

  constructor(private dbService: OptimizedDatabaseService) {
    logger.info('Database monitoring service initialized');
  }

  // Start automated monitoring routines
  async start(): Promise<void> {
    if (this.isRunning) {
      logger.warn('Database monitoring service already running');
      return;
    }

    this.isRunning = true;
    logger.info('Starting database monitoring service');

    // Schedule optimization every 6 hours
    this.optimizationSchedule = cron.schedule('0 */6 * * *', async () => {
      await this.performAutomatedOptimization();
    });

    // Schedule health checks every 5 minutes
    this.healthCheckSchedule = cron.schedule('*/5 * * * *', async () => {
      await this.performHealthMonitoring();
    });

    // Perform initial health check
    await this.performHealthMonitoring();
    logger.info('Database monitoring service started');
  }

  // Stop monitoring routines
  async stop(): Promise<void> {
    if (!this.isRunning) return;

    this.isRunning = false;
    
    if (this.optimizationSchedule) {
      this.optimizationSchedule.stop();
      this.optimizationSchedule.destroy();
    }
    
    if (this.healthCheckSchedule) {
      this.healthCheckSchedule.stop();
      this.healthCheckSchedule.destroy();
    }

    logger.info('Database monitoring service stopped');
  }

  // Automated optimization routine
  private async performAutomatedOptimization(): Promise<void> {
    try {
      logger.info('Starting automated database optimization');
      const startTime = Date.now();

      // Get current performance metrics
      const healthCheck = await this.dbService.performHealthCheck();
      
      // Only run optimization if database is healthy
      if (!healthCheck.overall) {
        logger.warn('Skipping optimization - database health check failed');
        return;
      }

      // Run optimization if health score is below threshold or enough time has passed
      const shouldOptimize = await this.shouldRunOptimization();
      
      if (shouldOptimize) {
        const report = await this.dbService.runOptimization();
        this.monitoringStats.lastOptimization = new Date();
        this.monitoringStats.optimizationRuns++;

        if (report.success) {
          logger.info('Automated optimization completed successfully', {
            duration: report.duration,
            tablesAnalyzed: report.queryOptimization.analyzedTables,
            tablesVacuumed: report.maintenance.vacuumedTables
          });
        } else {
          logger.error('Automated optimization failed', { error: report.error });
          await this.triggerAlert('optimization_failed', report.error);
        }
      } else {
        logger.debug('Skipping optimization - conditions not met');
      }

    } catch (error) {
      logger.error('Automated optimization routine failed', { 
        error: error instanceof Error ? error.message : String(error) 
      });
      await this.triggerAlert('optimization_error', error instanceof Error ? error.message : String(error));
    }
  }

  // Health monitoring routine
  private async performHealthMonitoring(): Promise<void> {
    try {
      const healthCheck = await this.dbService.performHealthCheck();
      this.monitoringStats.lastHealthCheck = new Date();

      // Calculate health score
      const healthScore = this.calculateHealthScore(healthCheck);
      this.updateAverageHealthScore(healthScore);

      // Check for issues that need alerts
      await this.checkAlertConditions(healthCheck, healthScore);

      logger.debug('Health monitoring completed', {
        healthy: healthCheck.overall,
        score: healthScore,
        dbLatency: healthCheck.database.latency,
        poolUtilization: healthCheck.database.poolUtilization
      });

    } catch (error) {
      logger.error('Health monitoring failed', { 
        error: error instanceof Error ? error.message : String(error) 
      });
      await this.triggerAlert('health_check_failed', error instanceof Error ? error.message : String(error));
    }
  }

  // Determine if optimization should run
  private async shouldRunOptimization(): Promise<boolean> {
    try {
      // Get performance report
      const report = await this.dbService.getPerformanceReport();
      
      // Run optimization if:
      // 1. It's been more than 24 hours since last optimization
      // 2. Cache hit rate is below 70%
      // 3. Average query time is above 100ms
      // 4. More than 5 slow queries detected
      // 5. More than 3 tables need vacuum
      
      const timeSinceLastOpt = this.monitoringStats.lastOptimization 
        ? Date.now() - this.monitoringStats.lastOptimization.getTime()
        : Infinity;
      
      const reasons: string[] = [];
      
      if (timeSinceLastOpt > 24 * 60 * 60 * 1000) {
        reasons.push('24 hours since last optimization');
      }
      
      if (report.cache.hitRate < 0.7) {
        reasons.push(`low cache hit rate: ${(report.cache.hitRate * 100).toFixed(1)}%`);
      }
      
      if (report.database.averageQueryTime > 100) {
        reasons.push(`high average query time: ${report.database.averageQueryTime.toFixed(1)}ms`);
      }
      
      if (report.database.slowQueryCount > 5) {
        reasons.push(`${report.database.slowQueryCount} slow queries detected`);
      }
      
      if (report.tables.needsVacuum > 3) {
        reasons.push(`${report.tables.needsVacuum} tables need vacuum`);
      }

      if (reasons.length > 0) {
        logger.info('Optimization triggered', { reasons });
        return true;
      }

      return false;
    } catch (error) {
      logger.error('Failed to determine optimization need', { error });
      return false;
    }
  }

  // Calculate overall health score (0-100)
  private calculateHealthScore(healthCheck: any): number {
    let score = 100;

    // Deduct points for various issues
    if (!healthCheck.database.healthy) score -= 50;
    if (!healthCheck.cache.healthy) score -= 30;
    
    // Latency penalties
    if (healthCheck.database.latency > 100) score -= 10;
    if (healthCheck.database.latency > 500) score -= 20;
    
    // Pool utilization penalties
    if (healthCheck.database.poolUtilization > 0.8) score -= 10;
    if (healthCheck.database.poolUtilization > 0.9) score -= 20;

    return Math.max(0, score);
  }

  // Update rolling average health score
  private updateAverageHealthScore(currentScore: number): void {
    const alpha = 0.1; // Smoothing factor
    this.monitoringStats.averageHealthScore = 
      this.monitoringStats.averageHealthScore * (1 - alpha) + currentScore * alpha;
  }

  // Check conditions that should trigger alerts
  private async checkAlertConditions(healthCheck: any, healthScore: number): Promise<void> {
    // Critical health score
    if (healthScore < 50) {
      await this.triggerAlert('critical_health', `Health score dropped to ${healthScore}`);
    }

    // High latency
    if (healthCheck.database.latency > 1000) {
      await this.triggerAlert('high_latency', `Database latency: ${healthCheck.database.latency}ms`);
    }

    // High pool utilization
    if (healthCheck.database.poolUtilization > 0.95) {
      await this.triggerAlert('pool_exhaustion', `Pool utilization: ${(healthCheck.database.poolUtilization * 100).toFixed(1)}%`);
    }

    // Cache issues
    if (!healthCheck.cache.healthy) {
      await this.triggerAlert('cache_failure', 'Cache health check failed');
    }
  }

  // Trigger alert (extend this to integrate with your alerting system)
  private async triggerAlert(type: string, message: string): Promise<void> {
    this.monitoringStats.alertsTriggered++;
    
    logger.warn('Database alert triggered', {
      type,
      message,
      timestamp: new Date().toISOString()
    });

    // TODO: Integrate with external alerting systems
    // - Email notifications
    // - Slack/Teams webhooks
    // - PagerDuty integration
    // - SMS alerts for critical issues
  }

  // Get comprehensive monitoring dashboard data
  async getMonitoringDashboard(): Promise<MonitoringDashboard> {
    try {
      const [performanceReport, healthCheck] = await Promise.all([
        this.dbService.getPerformanceReport(),
        this.dbService.performHealthCheck()
      ]);

      const currentHealthScore = this.calculateHealthScore(healthCheck);

      return {
        timestamp: new Date(),
        status: {
          overall: healthCheck.overall ? 'healthy' : 'unhealthy',
          database: healthCheck.database.healthy ? 'healthy' : 'unhealthy',
          cache: healthCheck.cache.healthy ? 'healthy' : 'unhealthy',
          currentHealthScore,
          averageHealthScore: Math.round(this.monitoringStats.averageHealthScore)
        },
        performance: {
          databaseLatency: healthCheck.database.latency,
          poolUtilization: Math.round(healthCheck.database.poolUtilization * 100),
          cacheHitRate: Math.round(performanceReport.cache.hitRate * 100),
          slowQueryCount: performanceReport.database.slowQueryCount,
          averageQueryTime: Math.round(performanceReport.database.averageQueryTime)
        },
        resources: {
          totalConnections: performanceReport.database.poolStats.totalCount || 0,
          activeConnections: performanceReport.database.poolStats.idleCount || 0,
          totalRows: performanceReport.tables.totalRows,
          totalTables: performanceReport.tables.totalTables,
          tablesNeedingVacuum: performanceReport.tables.needsVacuum,
          cacheKeyCount: performanceReport.cache.keyCount
        },
        monitoring: {
          isRunning: this.isRunning,
          lastHealthCheck: this.monitoringStats.lastHealthCheck,
          lastOptimization: this.monitoringStats.lastOptimization,
          alertsTriggered: this.monitoringStats.alertsTriggered,
          optimizationRuns: this.monitoringStats.optimizationRuns
        },
        alerts: await this.getRecentAlerts(),
        recommendations: [
          ...performanceReport.recommendations.slice(0, 5),
          ...(currentHealthScore < 80 ? ['Consider running manual optimization'] : []),
          ...(performanceReport.cache.hitRate < 0.8 ? ['Review cache configuration'] : [])
        ]
      };
    } catch (error) {
      logger.error('Failed to generate monitoring dashboard', { error });
      throw error;
    }
  }

  // Get recent alerts (implement with persistent storage if needed)
  private async getRecentAlerts(): Promise<Alert[]> {
    // For now, return empty array - in production, implement with database storage
    return [];
  }

  // Force optimization run (manual trigger)
  async runOptimizationNow(): Promise<void> {
    logger.info('Manual optimization triggered');
    await this.performAutomatedOptimization();
  }

  // Get monitoring statistics
  getMonitoringStats(): MonitoringStats {
    return { ...this.monitoringStats };
  }

  // Test database performance with synthetic load
  async performLoadTest(config: LoadTestConfig = {}): Promise<LoadTestResult> {
    const {
      queryCount = 100,
      concurrency = 10,
      queryType = 'mixed'
    } = config;

    logger.info('Starting database load test', { queryCount, concurrency, queryType });
    const startTime = Date.now();

    try {
      const results: QueryResult[] = [];
      const queries = this.generateTestQueries(queryType, queryCount);
      
      // Execute queries with controlled concurrency
      const chunks = this.chunkArray(queries, Math.ceil(queries.length / concurrency));
      
      for (const chunk of chunks) {
        const chunkResults = await Promise.all(
          chunk.map(async (query, index) => {
            const queryStart = Date.now();
            try {
              await this.dbService.getConnectionPool().query(query.sql, query.params);
              return {
                index,
                success: true,
                duration: Date.now() - queryStart,
                error: null
              };
            } catch (error) {
              return {
                index,
                success: false,
                duration: Date.now() - queryStart,
                error: error instanceof Error ? error.message : String(error)
              };
            }
          })
        );
        results.push(...chunkResults);
      }

      const totalDuration = Date.now() - startTime;
      const successCount = results.filter(r => r.success).length;
      const avgDuration = results.reduce((sum, r) => sum + r.duration, 0) / results.length;

      const result: LoadTestResult = {
        timestamp: new Date(),
        config: { queryCount, concurrency, queryType },
        results: {
          totalQueries: queryCount,
          successfulQueries: successCount,
          failedQueries: queryCount - successCount,
          totalDuration,
          averageQueryTime: avgDuration,
          queriesPerSecond: queryCount / (totalDuration / 1000),
          successRate: successCount / queryCount
        },
        errors: results.filter(r => !r.success).map(r => r.error!).slice(0, 10)
      };

      logger.info('Load test completed', result.results);
      return result;

    } catch (error) {
      logger.error('Load test failed', { error });
      throw error;
    }
  }

  // Generate test queries for load testing
  private generateTestQueries(type: string, count: number): TestQuery[] {
    const queries: TestQuery[] = [];
    
    for (let i = 0; i < count; i++) {
      switch (type) {
        case 'read':
          queries.push({
            sql: 'SELECT id, name FROM game_rooms WHERE is_active = $1 LIMIT 10',
            params: [true]
          });
          break;
        case 'write':
          queries.push({
            sql: 'INSERT INTO game_assets (id, name, type, room_id, file_path) VALUES ($1, $2, $3, $4, $5)',
            params: [`test-${i}`, `Test Asset ${i}`, 'image', 'test-room', `/test/${i}.png`]
          });
          break;
        default: // mixed
          if (i % 3 === 0) {
            queries.push({
              sql: 'SELECT COUNT(*) FROM room_players WHERE is_online = $1',
              params: [true]
            });
          } else {
            queries.push({
              sql: 'SELECT id, name FROM game_rooms WHERE created_at > $1 LIMIT 5',
              params: [new Date(Date.now() - 24 * 60 * 60 * 1000)]
            });
          }
      }
    }
    
    return queries;
  }

  // Utility function to chunk arrays
  private chunkArray<T>(array: T[], chunkSize: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < array.length; i += chunkSize) {
      chunks.push(array.slice(i, i + chunkSize));
    }
    return chunks;
  }
}

// Type definitions
export interface MonitoringStats {
  lastHealthCheck: Date | null;
  lastOptimization: Date | null;
  alertsTriggered: number;
  optimizationRuns: number;
  averageHealthScore: number;
}

export interface MonitoringDashboard {
  timestamp: Date;
  status: {
    overall: 'healthy' | 'unhealthy';
    database: 'healthy' | 'unhealthy';
    cache: 'healthy' | 'unhealthy';
    currentHealthScore: number;
    averageHealthScore: number;
  };
  performance: {
    databaseLatency: number;
    poolUtilization: number;
    cacheHitRate: number;
    slowQueryCount: number;
    averageQueryTime: number;
  };
  resources: {
    totalConnections: number;
    activeConnections: number;
    totalRows: number;
    totalTables: number;
    tablesNeedingVacuum: number;
    cacheKeyCount: number;
  };
  monitoring: {
    isRunning: boolean;
    lastHealthCheck: Date | null;
    lastOptimization: Date | null;
    alertsTriggered: number;
    optimizationRuns: number;
  };
  alerts: Alert[];
  recommendations: string[];
}

export interface Alert {
  id: string;
  type: string;
  message: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  timestamp: Date;
  resolved: boolean;
}

export interface LoadTestConfig {
  queryCount?: number;
  concurrency?: number;
  queryType?: 'read' | 'write' | 'mixed';
}

export interface LoadTestResult {
  timestamp: Date;
  config: Required<LoadTestConfig>;
  results: {
    totalQueries: number;
    successfulQueries: number;
    failedQueries: number;
    totalDuration: number;
    averageQueryTime: number;
    queriesPerSecond: number;
    successRate: number;
  };
  errors: string[];
}

interface TestQuery {
  sql: string;
  params: any[];
}

interface QueryResult {
  index: number;
  success: boolean;
  duration: number;
  error: string | null;
}
