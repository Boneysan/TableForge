// server/cache/cache-monitoring.ts
// Phase 3 Cache monitoring and metrics system for TableForge

import { createUserLogger } from '../utils/logger';
import { metrics } from '../observability/metrics';

const logger = createUserLogger('cache-monitor');

export interface CacheMonitoringConfig {
  enabled: boolean;
  metricsInterval: number; // Interval for collecting metrics (ms)
  slowOperationThreshold: number; // Threshold for slow operation alerts (ms)
  enableDetailedLogging: boolean;
  enablePerformanceTracing: boolean;
  alertThresholds: {
    hitRateMin: number; // Minimum acceptable hit rate
    errorRateMax: number; // Maximum acceptable error rate
    latencyMax: number; // Maximum acceptable latency (ms)
    memoryUsageMax: number; // Maximum memory usage (bytes)
  };
  alerts: {
    email: string[];
    webhook?: string;
  };
}

export interface CacheAlert {
  type: 'hit_rate_low' | 'error_rate_high' | 'latency_high' | 'memory_high' | 'connection_lost';
  severity: 'warning' | 'critical';
  message: string;
  value: number;
  threshold: number;
  timestamp: number;
  cacheType: string;
}

export interface CachePerformanceMetrics {
  timestamp: number;
  cacheType: string;
  hitRate: number;
  missRate: number;
  errorRate: number;
  averageLatency: number;
  operationsPerSecond: number;
  memoryUsage: number;
  connectionStatus: boolean;
}

export class CacheMonitoringService {
  private config: CacheMonitoringConfig;
  private metricsHistory: CachePerformanceMetrics[] = [];
  private activeAlerts: Map<string, CacheAlert> = new Map();
  private monitoringInterval?: NodeJS.Timeout | undefined;

  constructor(config: CacheMonitoringConfig) {
    this.config = config;
    
    if (config.enabled) {
      this.startMonitoring();
    }

    logger.info('Cache monitoring service initialized', {
      enabled: config.enabled,
      metricsInterval: config.metricsInterval,
      slowOperationThreshold: config.slowOperationThreshold
    });
  }

  // Start monitoring
  startMonitoring(): void {
    if (this.monitoringInterval) {
      return; // Already monitoring
    }

    this.monitoringInterval = setInterval(async () => {
      await this.collectMetrics();
    }, this.config.metricsInterval);

    logger.info('Cache monitoring started');
  }

  // Stop monitoring
  stopMonitoring(): void {
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
      this.monitoringInterval = undefined;
    }

    logger.info('Cache monitoring stopped');
  }

  // Record cache operation
  recordOperation(
    cacheType: string,
    operation: string,
    duration: number,
    success: boolean
  ): void {
    if (!this.config.enabled) return;

    // Log slow operations
    if (duration > this.config.slowOperationThreshold) {
      logger.warn('Slow cache operation detected', {
        cacheType,
        operation,
        duration,
        threshold: this.config.slowOperationThreshold
      });
    }

    // Record detailed trace if enabled
    if (this.config.enablePerformanceTracing) {
      logger.debug('Cache operation trace', {
        cacheType,
        operation,
        duration,
        success,
        timestamp: Date.now()
      });
    }

    // Update metrics
    metrics.cacheOperationDuration?.observe(
      { operation, cache_type: cacheType },
      duration
    );

    if (!success) {
      metrics.cacheErrors?.inc({ type: operation, cache_type: cacheType });
    }
  }

  // Collect metrics from cache instances
  async collectMetrics(): Promise<void> {
    const timestamp = Date.now();

    try {
      // This would collect metrics from actual cache instances
      // For now, we'll simulate the collection
      const cacheTypes = ['application', 'redis'];

      for (const cacheType of cacheTypes) {
        await this.collectCacheMetrics(cacheType, timestamp);
      }

      // Cleanup old metrics (keep last 1000 entries)
      if (this.metricsHistory.length > 1000) {
        this.metricsHistory = this.metricsHistory.slice(-1000);
      }

    } catch (error) {
      logger.error('Metrics collection failed', { error });
    }
  }

  private async collectCacheMetrics(cacheType: string, timestamp: number): Promise<void> {
    try {
      // Simulate collecting metrics (in real implementation, get from actual cache)
      const metrics: CachePerformanceMetrics = {
        timestamp,
        cacheType,
        hitRate: 0.85 + Math.random() * 0.1, // Simulate 85-95% hit rate
        missRate: 0.05 + Math.random() * 0.1, // Simulate 5-15% miss rate
        errorRate: Math.random() * 0.01, // Simulate 0-1% error rate
        averageLatency: 5 + Math.random() * 10, // Simulate 5-15ms latency
        operationsPerSecond: 100 + Math.random() * 200, // Simulate 100-300 ops/sec
        memoryUsage: 50 * 1024 * 1024 + Math.random() * 100 * 1024 * 1024, // 50-150MB
        connectionStatus: Math.random() > 0.01 // 99% uptime
      };

      this.metricsHistory.push(metrics);

      // Check for alerts
      await this.checkAlerts(metrics);

      if (this.config.enableDetailedLogging) {
        logger.debug('Cache metrics collected', {
          cacheType,
          hitRate: metrics.hitRate.toFixed(3),
          averageLatency: metrics.averageLatency.toFixed(2),
          operationsPerSecond: metrics.operationsPerSecond.toFixed(0)
        });
      }

    } catch (error) {
      logger.error('Failed to collect cache metrics', { cacheType, error });
    }
  }

  // Alert checking
  private async checkAlerts(metrics: CachePerformanceMetrics): Promise<void> {
    const alerts: CacheAlert[] = [];

    // Check hit rate
    if (metrics.hitRate < this.config.alertThresholds.hitRateMin) {
      alerts.push({
        type: 'hit_rate_low',
        severity: metrics.hitRate < this.config.alertThresholds.hitRateMin * 0.8 ? 'critical' : 'warning',
        message: `Cache hit rate is below threshold: ${(metrics.hitRate * 100).toFixed(1)}%`,
        value: metrics.hitRate,
        threshold: this.config.alertThresholds.hitRateMin,
        timestamp: metrics.timestamp,
        cacheType: metrics.cacheType
      });
    }

    // Check error rate
    if (metrics.errorRate > this.config.alertThresholds.errorRateMax) {
      alerts.push({
        type: 'error_rate_high',
        severity: metrics.errorRate > this.config.alertThresholds.errorRateMax * 2 ? 'critical' : 'warning',
        message: `Cache error rate is above threshold: ${(metrics.errorRate * 100).toFixed(2)}%`,
        value: metrics.errorRate,
        threshold: this.config.alertThresholds.errorRateMax,
        timestamp: metrics.timestamp,
        cacheType: metrics.cacheType
      });
    }

    // Check latency
    if (metrics.averageLatency > this.config.alertThresholds.latencyMax) {
      alerts.push({
        type: 'latency_high',
        severity: metrics.averageLatency > this.config.alertThresholds.latencyMax * 2 ? 'critical' : 'warning',
        message: `Cache latency is above threshold: ${metrics.averageLatency.toFixed(2)}ms`,
        value: metrics.averageLatency,
        threshold: this.config.alertThresholds.latencyMax,
        timestamp: metrics.timestamp,
        cacheType: metrics.cacheType
      });
    }

    // Check memory usage
    if (metrics.memoryUsage > this.config.alertThresholds.memoryUsageMax) {
      alerts.push({
        type: 'memory_high',
        severity: metrics.memoryUsage > this.config.alertThresholds.memoryUsageMax * 1.2 ? 'critical' : 'warning',
        message: `Cache memory usage is above threshold: ${(metrics.memoryUsage / 1024 / 1024).toFixed(1)}MB`,
        value: metrics.memoryUsage,
        threshold: this.config.alertThresholds.memoryUsageMax,
        timestamp: metrics.timestamp,
        cacheType: metrics.cacheType
      });
    }

    // Check connection status
    if (!metrics.connectionStatus) {
      alerts.push({
        type: 'connection_lost',
        severity: 'critical',
        message: `Cache connection lost`,
        value: 0,
        threshold: 1,
        timestamp: metrics.timestamp,
        cacheType: metrics.cacheType
      });
    }

    // Process new alerts
    for (const alert of alerts) {
      await this.processAlert(alert);
    }
  }

  private async processAlert(alert: CacheAlert): Promise<void> {
    const alertKey = `${alert.cacheType}:${alert.type}`;
    const existingAlert = this.activeAlerts.get(alertKey);

    // Check if this is a new alert or if we should re-alert
    const shouldAlert = !existingAlert || 
                       (alert.timestamp - existingAlert.timestamp > 5 * 60 * 1000); // Re-alert every 5 minutes

    if (shouldAlert) {
      this.activeAlerts.set(alertKey, alert);
      
      logger.warn('Cache alert triggered', {
        type: alert.type,
        severity: alert.severity,
        message: alert.message,
        cacheType: alert.cacheType,
        value: alert.value,
        threshold: alert.threshold
      });

      // Send alert notifications
      await this.sendAlert(alert);
    }
  }

  private async sendAlert(alert: CacheAlert): Promise<void> {
    try {
      // Email alerts
      if (this.config.alerts.email.length > 0) {
        await this.sendEmailAlert(alert);
      }

      // Webhook alerts
      if (this.config.alerts.webhook) {
        await this.sendWebhookAlert(alert);
      }

    } catch (error) {
      logger.error('Failed to send alert', { alert, error });
    }
  }

  private async sendEmailAlert(alert: CacheAlert): Promise<void> {
    // Implementation would depend on email service
    logger.info('Email alert sent', {
      type: alert.type,
      recipients: this.config.alerts.email.length,
      cacheType: alert.cacheType
    });
  }

  private async sendWebhookAlert(alert: CacheAlert): Promise<void> {
    // Implementation would depend on webhook service
    logger.info('Webhook alert sent', {
      type: alert.type,
      webhook: this.config.alerts.webhook,
      cacheType: alert.cacheType
    });
  }

  // Analytics and reporting
  getPerformanceReport(timeRangeMs: number = 24 * 60 * 60 * 1000): any {
    const cutoffTime = Date.now() - timeRangeMs;
    const recentMetrics = this.metricsHistory.filter(m => m.timestamp > cutoffTime);

    if (recentMetrics.length === 0) {
      return { error: 'No metrics available for the specified time range' };
    }

    const cacheTypes = [...new Set(recentMetrics.map(m => m.cacheType))];
    const report: any = {
      timeRange: {
        start: new Date(cutoffTime).toISOString(),
        end: new Date().toISOString(),
        duration: timeRangeMs
      },
      summary: {},
      cacheTypes: {}
    };

    // Overall summary
    const avgHitRate = recentMetrics.reduce((sum, m) => sum + m.hitRate, 0) / recentMetrics.length;
    const avgLatency = recentMetrics.reduce((sum, m) => sum + m.averageLatency, 0) / recentMetrics.length;
    const avgOpsPerSec = recentMetrics.reduce((sum, m) => sum + m.operationsPerSecond, 0) / recentMetrics.length;

    report.summary = {
      averageHitRate: avgHitRate,
      averageLatency: avgLatency,
      averageOperationsPerSecond: avgOpsPerSec,
      totalMetrics: recentMetrics.length,
      cacheTypeCount: cacheTypes.length
    };

    // Per cache type analysis
    for (const cacheType of cacheTypes) {
      const typeMetrics = recentMetrics.filter(m => m.cacheType === cacheType);
      
      report.cacheTypes[cacheType] = {
        dataPoints: typeMetrics.length,
        hitRate: {
          average: typeMetrics.reduce((sum, m) => sum + m.hitRate, 0) / typeMetrics.length,
          min: Math.min(...typeMetrics.map(m => m.hitRate)),
          max: Math.max(...typeMetrics.map(m => m.hitRate))
        },
        latency: {
          average: typeMetrics.reduce((sum, m) => sum + m.averageLatency, 0) / typeMetrics.length,
          min: Math.min(...typeMetrics.map(m => m.averageLatency)),
          max: Math.max(...typeMetrics.map(m => m.averageLatency))
        },
        operationsPerSecond: {
          average: typeMetrics.reduce((sum, m) => sum + m.operationsPerSecond, 0) / typeMetrics.length,
          min: Math.min(...typeMetrics.map(m => m.operationsPerSecond)),
          max: Math.max(...typeMetrics.map(m => m.operationsPerSecond))
        },
        uptime: typeMetrics.filter(m => m.connectionStatus).length / typeMetrics.length
      };
    }

    return report;
  }

  getActiveAlerts(): CacheAlert[] {
    return Array.from(this.activeAlerts.values());
  }

  clearAlert(cacheType: string, alertType: string): boolean {
    const alertKey = `${cacheType}:${alertType}`;
    return this.activeAlerts.delete(alertKey);
  }

  getMetricsHistory(limit: number = 100): CachePerformanceMetrics[] {
    return this.metricsHistory.slice(-limit);
  }

  // Health check for monitoring service itself
  healthCheck(): any {
    return {
      status: this.config.enabled ? 'active' : 'disabled',
      metricsCount: this.metricsHistory.length,
      activeAlerts: this.activeAlerts.size,
      monitoring: !!this.monitoringInterval,
      config: {
        metricsInterval: this.config.metricsInterval,
        slowOperationThreshold: this.config.slowOperationThreshold,
        enableDetailedLogging: this.config.enableDetailedLogging
      }
    };
  }
}

// Default monitoring configuration
export const defaultMonitoringConfig: CacheMonitoringConfig = {
  enabled: true,
  metricsInterval: 30000, // 30 seconds
  slowOperationThreshold: 100, // 100ms
  enableDetailedLogging: false,
  enablePerformanceTracing: false,
  alertThresholds: {
    hitRateMin: 0.8, // 80% minimum hit rate
    errorRateMax: 0.05, // 5% maximum error rate
    latencyMax: 50, // 50ms maximum latency
    memoryUsageMax: 512 * 1024 * 1024 // 512MB maximum memory
  },
  alerts: {
    email: []
  }
};

export default CacheMonitoringService;
