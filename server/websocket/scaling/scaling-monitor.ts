// server/websocket/scaling/scaling-monitor.ts
import { WebSocketScalingManager, InstanceInfo, RoomDistribution } from './redis-pubsub';
import { WebSocketLoadBalancer, LoadBalancerStats } from './load-balancer';
import { logger } from '../../utils/logger';
import { metrics } from '../../observability/metrics';
import cron from 'node-cron';

/**
 * Scaling Monitoring and Metrics System
 * Provides comprehensive monitoring, alerting, and analytics for WebSocket scaling
 */
export class ScalingMonitoringService {
  private scalingManager: WebSocketScalingManager;
  private loadBalancer: WebSocketLoadBalancer;
  private monitoringInterval: NodeJS.Timeout | null = null;
  private alertingInterval: NodeJS.Timeout | null = null;
  private reportingSchedule?: cron.ScheduledTask;
  private isRunning = false;

  private readonly thresholds = {
    instanceCritical: 0.95,      // 95% load is critical
    instanceWarning: 0.8,        // 80% load is warning
    responseTimeWarning: 100,    // 100ms response time warning
    responseTimeCritical: 500,   // 500ms response time critical
    connectionDropThreshold: 0.05, // 5% connection drop rate
    memoryWarning: 0.8,          // 80% memory usage warning
    memoryeCritical: 0.9         // 90% memory usage critical
  };

  private metricsHistory: MetricsHistory = {
    instanceMetrics: new Map(),
    systemMetrics: [],
    alerts: [],
    performanceData: []
  };

  constructor(scalingManager: WebSocketScalingManager, loadBalancer: WebSocketLoadBalancer) {
    this.scalingManager = scalingManager;
    this.loadBalancer = loadBalancer;
  }

  async start(): Promise<void> {
    if (this.isRunning) {
      logger.warn('Scaling monitoring service already running');
      return;
    }

    this.isRunning = true;
    logger.info('Starting scaling monitoring service');

    // Start real-time monitoring (every 15 seconds)
    this.monitoringInterval = setInterval(async () => {
      await this.collectMetrics();
    }, 15000);

    // Start alerting checks (every 30 seconds)
    this.alertingInterval = setInterval(async () => {
      await this.checkAlerts();
    }, 30000);

    // Schedule detailed reports (every hour)
    this.reportingSchedule = cron.schedule('0 * * * *', async () => {
      await this.generateHourlyReport();
    });

    // Perform initial metrics collection
    await this.collectMetrics();

    logger.info('Scaling monitoring service started');
  }

  async stop(): Promise<void> {
    if (!this.isRunning) return;

    this.isRunning = false;

    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
      this.monitoringInterval = null;
    }

    if (this.alertingInterval) {
      clearInterval(this.alertingInterval);
      this.alertingInterval = null;
    }

    if (this.reportingSchedule) {
      this.reportingSchedule.stop();
      this.reportingSchedule.destroy();
    }

    logger.info('Scaling monitoring service stopped');
  }

  // Metrics collection
  private async collectMetrics(): Promise<void> {
    try {
      const timestamp = Date.now();
      
      // Collect instance metrics
      const instances = await this.scalingManager.getActiveInstances();
      const loadBalancerStats = await this.loadBalancer.getLoadBalancerStats();
      
      // Store instance-specific metrics
      for (const instance of instances) {
        const instanceMetrics = this.calculateInstanceMetrics(instance);
        this.updateInstanceHistory(instance.instanceId, instanceMetrics);
        
        // Update Prometheus metrics
        this.updatePrometheusMetrics(instance, instanceMetrics);
      }

      // Store system-wide metrics
      const systemMetrics: SystemMetrics = {
        timestamp: new Date(timestamp),
        totalInstances: instances.length,
        totalConnections: instances.reduce((sum, i) => sum + i.connections, 0),
        totalRooms: instances.reduce((sum, i) => sum + i.rooms, 0),
        totalUsers: instances.reduce((sum, i) => sum + i.users, 0),
        averageLoad: loadBalancerStats.averageLoad,
        memoryUsage: this.calculateTotalMemoryUsage(instances),
        distributionBalance: this.calculateDistributionBalance(instances),
        responseTime: await this.measureSystemResponseTime(),
        throughput: this.calculateSystemThroughput(instances)
      };

      this.metricsHistory.systemMetrics.push(systemMetrics);
      
      // Keep only last 1000 entries (about 4 hours at 15s intervals)
      if (this.metricsHistory.systemMetrics.length > 1000) {
        this.metricsHistory.systemMetrics = this.metricsHistory.systemMetrics.slice(-1000);
      }

      // Log metrics summary
      logger.debug('Metrics collected', {
        instances: instances.length,
        totalConnections: systemMetrics.totalConnections,
        averageLoad: systemMetrics.averageLoad.toFixed(2),
        responseTime: systemMetrics.responseTime
      });

    } catch (error) {
      logger.error('Failed to collect metrics', { error });
      metrics.scalingMonitoringErrors?.inc({ type: 'metrics_collection' });
    }
  }

  // Alert monitoring
  private async checkAlerts(): Promise<void> {
    try {
      const instances = await this.scalingManager.getActiveInstances();
      const currentTime = new Date();

      for (const instance of instances) {
        const instanceMetrics = this.calculateInstanceMetrics(instance);
        
        // Check instance-level alerts
        await this.checkInstanceAlerts(instance, instanceMetrics, currentTime);
      }

      // Check system-level alerts
      await this.checkSystemAlerts(instances, currentTime);

    } catch (error) {
      logger.error('Failed to check alerts', { error });
      metrics.scalingMonitoringErrors?.inc({ type: 'alert_checking' });
    }
  }

  private async checkInstanceAlerts(
    instance: InstanceInfo, 
    metrics: InstanceMetrics, 
    timestamp: Date
  ): Promise<void> {
    const alerts: ScalingAlert[] = [];

    // High load alert
    if (metrics.loadScore >= this.thresholds.instanceCritical) {
      alerts.push({
        id: `instance-critical-${instance.instanceId}-${timestamp.getTime()}`,
        type: 'instance_critical_load',
        severity: 'critical',
        instanceId: instance.instanceId,
        message: `Instance ${instance.instanceId} is at critical load: ${(metrics.loadScore * 100).toFixed(1)}%`,
        timestamp,
        metrics: { loadScore: metrics.loadScore, connections: instance.connections },
        resolved: false
      });
    } else if (metrics.loadScore >= this.thresholds.instanceWarning) {
      alerts.push({
        id: `instance-warning-${instance.instanceId}-${timestamp.getTime()}`,
        type: 'instance_high_load',
        severity: 'warning',
        instanceId: instance.instanceId,
        message: `Instance ${instance.instanceId} has high load: ${(metrics.loadScore * 100).toFixed(1)}%`,
        timestamp,
        metrics: { loadScore: metrics.loadScore, connections: instance.connections },
        resolved: false
      });
    }

    // Memory usage alert
    if (metrics.memoryUsageRatio >= this.thresholds.memoryeCritical) {
      alerts.push({
        id: `memory-critical-${instance.instanceId}-${timestamp.getTime()}`,
        type: 'instance_memory_critical',
        severity: 'critical',
        instanceId: instance.instanceId,
        message: `Instance ${instance.instanceId} has critical memory usage: ${(metrics.memoryUsageRatio * 100).toFixed(1)}%`,
        timestamp,
        metrics: { memoryUsage: metrics.memoryUsageRatio },
        resolved: false
      });
    } else if (metrics.memoryUsageRatio >= this.thresholds.memoryWarning) {
      alerts.push({
        id: `memory-warning-${instance.instanceId}-${timestamp.getTime()}`,
        type: 'instance_memory_high',
        severity: 'warning',
        instanceId: instance.instanceId,
        message: `Instance ${instance.instanceId} has high memory usage: ${(metrics.memoryUsageRatio * 100).toFixed(1)}%`,
        timestamp,
        metrics: { memoryUsage: metrics.memoryUsageRatio },
        resolved: false
      });
    }

    // Connection drop alert
    if (metrics.connectionDropRate >= this.thresholds.connectionDropThreshold) {
      alerts.push({
        id: `connection-drop-${instance.instanceId}-${timestamp.getTime()}`,
        type: 'instance_connection_drops',
        severity: 'warning',
        instanceId: instance.instanceId,
        message: `Instance ${instance.instanceId} has high connection drop rate: ${(metrics.connectionDropRate * 100).toFixed(1)}%`,
        timestamp,
        metrics: { connectionDropRate: metrics.connectionDropRate },
        resolved: false
      });
    }

    // Store alerts and trigger notifications
    for (const alert of alerts) {
      this.metricsHistory.alerts.push(alert);
      await this.triggerAlert(alert);
    }
  }

  private async checkSystemAlerts(instances: InstanceInfo[], timestamp: Date): Promise<void> {
    const alerts: ScalingAlert[] = [];

    // System-wide checks
    const systemMetrics = this.metricsHistory.systemMetrics[this.metricsHistory.systemMetrics.length - 1];
    
    if (systemMetrics) {
      // High response time alert
      if (systemMetrics.responseTime >= this.thresholds.responseTimeCritical) {
        alerts.push({
          id: `system-response-critical-${timestamp.getTime()}`,
          type: 'system_response_time_critical',
          severity: 'critical',
          message: `System response time is critical: ${systemMetrics.responseTime}ms`,
          timestamp,
          metrics: { responseTime: systemMetrics.responseTime },
          resolved: false
        });
      } else if (systemMetrics.responseTime >= this.thresholds.responseTimeWarning) {
        alerts.push({
          id: `system-response-warning-${timestamp.getTime()}`,
          type: 'system_response_time_high',
          severity: 'warning',
          message: `System response time is high: ${systemMetrics.responseTime}ms`,
          timestamp,
          metrics: { responseTime: systemMetrics.responseTime },
          resolved: false
        });
      }

      // Load distribution imbalance
      if (systemMetrics.distributionBalance < 0.7) { // Less than 70% balance
        alerts.push({
          id: `load-imbalance-${timestamp.getTime()}`,
          type: 'load_distribution_imbalance',
          severity: 'warning',
          message: `Load distribution is imbalanced: ${(systemMetrics.distributionBalance * 100).toFixed(1)}% balance`,
          timestamp,
          metrics: { distributionBalance: systemMetrics.distributionBalance },
          resolved: false
        });
      }
    }

    // Instance availability check
    const healthyInstances = instances.filter(i => 
      Date.now() - i.lastHeartbeat.getTime() < 60000 // Healthy if heartbeat within 1 minute
    );

    if (healthyInstances.length < instances.length * 0.8) { // Less than 80% healthy
      alerts.push({
        id: `instance-availability-${timestamp.getTime()}`,
        type: 'instance_availability_low',
        severity: 'critical',
        message: `Low instance availability: ${healthyInstances.length}/${instances.length} instances healthy`,
        timestamp,
        metrics: { healthyInstances: healthyInstances.length, totalInstances: instances.length },
        resolved: false
      });
    }

    // Store alerts
    for (const alert of alerts) {
      this.metricsHistory.alerts.push(alert);
      await this.triggerAlert(alert);
    }
  }

  private async triggerAlert(alert: ScalingAlert): Promise<void> {
    // Log the alert
    const logLevel = alert.severity === 'critical' ? 'error' : 'warn';
    logger[logLevel]('Scaling alert triggered', {
      id: alert.id,
      type: alert.type,
      severity: alert.severity,
      message: alert.message,
      instanceId: alert.instanceId,
      metrics: alert.metrics
    });

    // Update metrics
    metrics.scalingAlerts?.inc({ 
      type: alert.type, 
      severity: alert.severity,
      instance: alert.instanceId || 'system'
    });

    // TODO: Integrate with external alerting systems
    // - Send to Slack/Teams
    // - Send email notifications
    // - Trigger PagerDuty for critical alerts
    // - Send to monitoring dashboards
  }

  // Metrics calculation methods
  private calculateInstanceMetrics(instance: InstanceInfo): InstanceMetrics {
    const memoryUsageRatio = instance.memory.heapUsed / (instance.memory.heapTotal || 1);
    const loadScore = this.calculateLoadScore(instance);
    
    // Get historical data for trends
    const history = this.metricsHistory.instanceMetrics.get(instance.instanceId) || [];
    const previousMetrics = history[history.length - 1];
    
    let connectionDropRate = 0;
    if (previousMetrics) {
      const timeDiff = (Date.now() - previousMetrics.timestamp.getTime()) / 1000; // seconds
      const connectionDiff = Math.max(0, previousMetrics.connections - instance.connections);
      connectionDropRate = timeDiff > 0 ? connectionDiff / (previousMetrics.connections * timeDiff) : 0;
    }

    return {
      timestamp: new Date(),
      instanceId: instance.instanceId,
      connections: instance.connections,
      rooms: instance.rooms,
      users: instance.users,
      memoryUsageRatio,
      loadScore,
      connectionDropRate,
      uptime: instance.uptime,
      isHealthy: Date.now() - instance.lastHeartbeat.getTime() < 60000
    };
  }

  private calculateLoadScore(instance: InstanceInfo): number {
    const connectionFactor = instance.connections / 1000;
    const memoryFactor = instance.memory.heapUsed / (instance.memory.heapTotal || 1);
    const roomFactor = instance.rooms / 100;
    
    return (connectionFactor * 0.5) + (memoryFactor * 0.3) + (roomFactor * 0.2);
  }

  private calculateTotalMemoryUsage(instances: InstanceInfo[]): number {
    const totalUsed = instances.reduce((sum, i) => sum + i.memory.heapUsed, 0);
    const totalAvailable = instances.reduce((sum, i) => sum + (i.memory.heapTotal || 0), 0);
    
    return totalAvailable > 0 ? totalUsed / totalAvailable : 0;
  }

  private calculateDistributionBalance(instances: InstanceInfo[]): number {
    if (instances.length === 0) return 1;

    const connections = instances.map(i => i.connections);
    const average = connections.reduce((sum, c) => sum + c, 0) / connections.length;
    
    if (average === 0) return 1;

    const variance = connections.reduce((sum, c) => sum + Math.pow(c - average, 2), 0) / connections.length;
    const stdDev = Math.sqrt(variance);
    
    // Return balance score (1 = perfect balance, 0 = completely imbalanced)
    return Math.max(0, 1 - (stdDev / average));
  }

  private async measureSystemResponseTime(): Promise<number> {
    // Simple ping test to measure system responsiveness
    const startTime = Date.now();
    
    try {
      const instances = await this.scalingManager.getActiveInstances();
      return Date.now() - startTime;
    } catch (error) {
      return Date.now() - startTime;
    }
  }

  private calculateSystemThroughput(instances: InstanceInfo[]): number {
    // Calculate messages per second across all instances
    // This would need to be integrated with actual message tracking
    return instances.reduce((sum, i) => sum + i.connections, 0) * 0.1; // Estimate: 0.1 msg/sec per connection
  }

  private updateInstanceHistory(instanceId: string, metrics: InstanceMetrics): void {
    if (!this.metricsHistory.instanceMetrics.has(instanceId)) {
      this.metricsHistory.instanceMetrics.set(instanceId, []);
    }

    const history = this.metricsHistory.instanceMetrics.get(instanceId)!;
    history.push(metrics);

    // Keep only last 240 entries (1 hour at 15s intervals)
    if (history.length > 240) {
      this.metricsHistory.instanceMetrics.set(instanceId, history.slice(-240));
    }
  }

  private updatePrometheusMetrics(instance: InstanceInfo, instanceMetrics: InstanceMetrics): void {
    // Update Prometheus metrics
    metrics.wsInstanceConnections?.set({ instance: instance.instanceId }, instance.connections);
    metrics.wsInstanceRooms?.set({ instance: instance.instanceId }, instance.rooms);
    metrics.wsInstanceUsers?.set({ instance: instance.instanceId }, instance.users);
    metrics.wsInstanceLoad?.set({ instance: instance.instanceId }, instanceMetrics.loadScore);
    metrics.wsInstanceMemory?.set({ instance: instance.instanceId }, instanceMetrics.memoryUsageRatio);
    metrics.wsInstanceUptime?.set({ instance: instance.instanceId }, instance.uptime);
  }

  // Reporting
  private async generateHourlyReport(): Promise<void> {
    try {
      const report = await this.generateScalingReport('hourly');
      
      logger.info('Hourly scaling report generated', {
        reportId: report.id,
        instances: report.summary.totalInstances,
        connections: report.summary.totalConnections,
        alerts: report.alerts.length
      });

      // Store report for later retrieval
      this.metricsHistory.performanceData.push({
        timestamp: new Date(),
        reportType: 'hourly',
        data: report
      });

      // Keep only last 168 hourly reports (1 week)
      if (this.metricsHistory.performanceData.length > 168) {
        this.metricsHistory.performanceData = this.metricsHistory.performanceData.slice(-168);
      }

    } catch (error) {
      logger.error('Failed to generate hourly report', { error });
    }
  }

  // Public API
  async generateScalingReport(period: 'hourly' | 'daily' | 'current' = 'current'): Promise<ScalingReport> {
    try {
      const instances = await this.scalingManager.getActiveInstances();
      const loadBalancerStats = await this.loadBalancer.getLoadBalancerStats();
      const currentTime = new Date();

      // Calculate time range for historical data
      let timeRange: { start: Date; end: Date };
      switch (period) {
        case 'hourly':
          timeRange = {
            start: new Date(currentTime.getTime() - 60 * 60 * 1000),
            end: currentTime
          };
          break;
        case 'daily':
          timeRange = {
            start: new Date(currentTime.getTime() - 24 * 60 * 60 * 1000),
            end: currentTime
          };
          break;
        default:
          timeRange = {
            start: new Date(currentTime.getTime() - 15 * 60 * 1000), // Last 15 minutes
            end: currentTime
          };
      }

      // Filter metrics by time range
      const filteredSystemMetrics = this.metricsHistory.systemMetrics.filter(m =>
        m.timestamp >= timeRange.start && m.timestamp <= timeRange.end
      );

      const filteredAlerts = this.metricsHistory.alerts.filter(a =>
        a.timestamp >= timeRange.start && a.timestamp <= timeRange.end
      );

      return {
        id: `scaling-report-${currentTime.getTime()}`,
        timestamp: currentTime,
        period,
        timeRange,
        summary: {
          totalInstances: instances.length,
          totalConnections: instances.reduce((sum, i) => sum + i.connections, 0),
          totalRooms: instances.reduce((sum, i) => sum + i.rooms, 0),
          totalUsers: instances.reduce((sum, i) => sum + i.users, 0),
          averageLoad: loadBalancerStats.averageLoad,
          systemHealth: this.calculateSystemHealth(instances, filteredAlerts)
        },
        instances: instances.map(i => ({
          instanceId: i.instanceId,
          connections: i.connections,
          rooms: i.rooms,
          users: i.users,
          load: this.calculateLoadScore(i),
          memory: i.memory.heapUsed / (i.memory.heapTotal || 1),
          uptime: i.uptime,
          lastHeartbeat: i.lastHeartbeat,
          isHealthy: Date.now() - i.lastHeartbeat.getTime() < 60000
        })),
        metrics: {
          systemMetrics: filteredSystemMetrics,
          trends: this.calculateTrends(filteredSystemMetrics),
          performance: this.calculatePerformanceMetrics(filteredSystemMetrics)
        },
        alerts: filteredAlerts,
        recommendations: this.generateRecommendations(instances, filteredSystemMetrics, filteredAlerts)
      };

    } catch (error) {
      logger.error('Failed to generate scaling report', { error });
      throw error;
    }
  }

  private calculateSystemHealth(instances: InstanceInfo[], alerts: ScalingAlert[]): number {
    let healthScore = 100;

    // Deduct for unhealthy instances
    const unhealthyInstances = instances.filter(i => 
      Date.now() - i.lastHeartbeat.getTime() > 60000
    ).length;
    healthScore -= (unhealthyInstances / instances.length) * 30;

    // Deduct for critical alerts
    const criticalAlerts = alerts.filter(a => a.severity === 'critical' && !a.resolved).length;
    healthScore -= Math.min(criticalAlerts * 10, 40);

    // Deduct for warning alerts
    const warningAlerts = alerts.filter(a => a.severity === 'warning' && !a.resolved).length;
    healthScore -= Math.min(warningAlerts * 5, 20);

    return Math.max(0, healthScore);
  }

  private calculateTrends(metrics: SystemMetrics[]): MetricsTrends {
    if (metrics.length < 2) {
      return {
        connectionsGrowth: 0,
        loadTrend: 0,
        responseTimeTrend: 0,
        memoryUsageTrend: 0
      };
    }

    const first = metrics[0];
    const last = metrics[metrics.length - 1];
    const timeDiff = (last.timestamp.getTime() - first.timestamp.getTime()) / (1000 * 60 * 60); // hours

    return {
      connectionsGrowth: timeDiff > 0 ? (last.totalConnections - first.totalConnections) / timeDiff : 0,
      loadTrend: last.averageLoad - first.averageLoad,
      responseTimeTrend: last.responseTime - first.responseTime,
      memoryUsageTrend: last.memoryUsage - first.memoryUsage
    };
  }

  private calculatePerformanceMetrics(metrics: SystemMetrics[]): PerformanceMetrics {
    if (metrics.length === 0) {
      return {
        averageResponseTime: 0,
        maxResponseTime: 0,
        averageLoad: 0,
        maxLoad: 0,
        availability: 0
      };
    }

    const responseTimes = metrics.map(m => m.responseTime);
    const loads = metrics.map(m => m.averageLoad);

    return {
      averageResponseTime: responseTimes.reduce((sum, rt) => sum + rt, 0) / responseTimes.length,
      maxResponseTime: Math.max(...responseTimes),
      averageLoad: loads.reduce((sum, l) => sum + l, 0) / loads.length,
      maxLoad: Math.max(...loads),
      availability: 1.0 // Simplified calculation
    };
  }

  private generateRecommendations(
    instances: InstanceInfo[], 
    systemMetrics: SystemMetrics[], 
    alerts: ScalingAlert[]
  ): string[] {
    const recommendations: string[] = [];

    // Analyze current state and provide recommendations
    const totalConnections = instances.reduce((sum, i) => sum + i.connections, 0);
    const averageConnections = totalConnections / instances.length;

    if (instances.length < 2) {
      recommendations.push('Consider adding more instances for redundancy and load distribution');
    }

    if (averageConnections > 800) {
      recommendations.push('High connection count per instance detected, consider horizontal scaling');
    }

    const criticalAlerts = alerts.filter(a => a.severity === 'critical' && !a.resolved);
    if (criticalAlerts.length > 0) {
      recommendations.push(`Address ${criticalAlerts.length} critical alerts to improve system stability`);
    }

    const highLoadInstances = instances.filter(i => this.calculateLoadScore(i) > 0.8);
    if (highLoadInstances.length > 0) {
      recommendations.push(`${highLoadInstances.length} instances have high load, consider load rebalancing`);
    }

    if (systemMetrics.length > 0) {
      const latestMetrics = systemMetrics[systemMetrics.length - 1];
      if (latestMetrics.distributionBalance < 0.7) {
        recommendations.push('Load distribution is imbalanced, review load balancing strategy');
      }

      if (latestMetrics.responseTime > 200) {
        recommendations.push('High response times detected, investigate performance bottlenecks');
      }
    }

    return recommendations;
  }

  // Public getters
  getMetricsHistory(): MetricsHistory {
    return this.metricsHistory;
  }

  async getCurrentMetrics(): Promise<ScalingReport> {
    return this.generateScalingReport('current');
  }
}

// Type definitions
export interface InstanceMetrics {
  timestamp: Date;
  instanceId: string;
  connections: number;
  rooms: number;
  users: number;
  memoryUsageRatio: number;
  loadScore: number;
  connectionDropRate: number;
  uptime: number;
  isHealthy: boolean;
}

export interface SystemMetrics {
  timestamp: Date;
  totalInstances: number;
  totalConnections: number;
  totalRooms: number;
  totalUsers: number;
  averageLoad: number;
  memoryUsage: number;
  distributionBalance: number;
  responseTime: number;
  throughput: number;
}

export interface ScalingAlert {
  id: string;
  type: string;
  severity: 'warning' | 'critical';
  instanceId?: string;
  message: string;
  timestamp: Date;
  metrics: Record<string, any>;
  resolved: boolean;
}

export interface MetricsHistory {
  instanceMetrics: Map<string, InstanceMetrics[]>;
  systemMetrics: SystemMetrics[];
  alerts: ScalingAlert[];
  performanceData: Array<{
    timestamp: Date;
    reportType: string;
    data: any;
  }>;
}

export interface ScalingReport {
  id: string;
  timestamp: Date;
  period: string;
  timeRange: { start: Date; end: Date };
  summary: {
    totalInstances: number;
    totalConnections: number;
    totalRooms: number;
    totalUsers: number;
    averageLoad: number;
    systemHealth: number;
  };
  instances: Array<{
    instanceId: string;
    connections: number;
    rooms: number;
    users: number;
    load: number;
    memory: number;
    uptime: number;
    lastHeartbeat: Date;
    isHealthy: boolean;
  }>;
  metrics: {
    systemMetrics: SystemMetrics[];
    trends: MetricsTrends;
    performance: PerformanceMetrics;
  };
  alerts: ScalingAlert[];
  recommendations: string[];
}

export interface MetricsTrends {
  connectionsGrowth: number;
  loadTrend: number;
  responseTimeTrend: number;
  memoryUsageTrend: number;
}

export interface PerformanceMetrics {
  averageResponseTime: number;
  maxResponseTime: number;
  averageLoad: number;
  maxLoad: number;
  availability: number;
}
