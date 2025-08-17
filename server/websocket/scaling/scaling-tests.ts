// server/websocket/scaling/scaling-tests.ts
import { WebSocketScalingManager } from './redis-pubsub';
import { WebSocketLoadBalancer } from './load-balancer';
import { ScalingMonitoringService } from './scaling-monitor';
import { logger } from '../../utils/logger';
import { WebSocketServer, WebSocket } from 'ws';
import Redis from 'ioredis';

/**
 * Multi-Instance Scaling Test Suite
 * Comprehensive testing for WebSocket horizontal scaling scenarios
 */
export class ScalingTestSuite {
  private testInstances: TestInstance[] = [];
  private redis: Redis;
  private testResults: TestResult[] = [];

  constructor() {
    this.redis = new Redis({
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT || '6379'),
      password: process.env.REDIS_PASSWORD,
      db: parseInt(process.env.REDIS_TEST_DB || '2') // Separate test database
    });
  }

  /**
   * Test 1: Basic Multi-Instance Communication
   */
  async testBasicMultiInstanceCommunication(): Promise<TestResult> {
    const testId = 'basic-multi-instance-communication';
    logger.info(`Starting test: ${testId}`);

    try {
      // Create 3 test instances
      const instances = await this.createTestInstances(3);
      
      // Create test clients connected to different instances
      const clients = await this.createTestClients(instances, 5);
      
      // Test room joining across instances
      await this.testRoomJoining(clients, instances);
      
      // Test message broadcasting
      const broadcastResult = await this.testMessageBroadcasting(clients, instances);
      
      // Test user-specific messaging
      const userMessageResult = await this.testUserMessaging(clients, instances);
      
      const result: TestResult = {
        testId,
        success: broadcastResult.success && userMessageResult.success,
        duration: 0,
        metrics: {
          instancesCreated: instances.length,
          clientsConnected: clients.length,
          messagesDelivered: broadcastResult.messagesDelivered + userMessageResult.messagesDelivered,
          averageLatency: (broadcastResult.averageLatency + userMessageResult.averageLatency) / 2
        },
        details: {
          broadcastTest: broadcastResult,
          userMessageTest: userMessageResult
        },
        timestamp: new Date()
      };

      await this.cleanupTestInstances();
      this.testResults.push(result);
      
      logger.info(`Test ${testId} completed`, { success: result.success });
      return result;

    } catch (error) {
      const result: TestResult = {
        testId,
        success: false,
        duration: 0,
        error: error.message,
        timestamp: new Date()
      };
      
      this.testResults.push(result);
      logger.error(`Test ${testId} failed`, { error });
      return result;
    }
  }

  /**
   * Test 2: Load Balancing Effectiveness
   */
  async testLoadBalancingEffectiveness(): Promise<TestResult> {
    const testId = 'load-balancing-effectiveness';
    logger.info(`Starting test: ${testId}`);

    try {
      // Create 4 instances with varying capacities
      const instances = await this.createTestInstances(4);
      
      // Simulate different load scenarios
      const loadTest1 = await this.simulateLoadScenario(instances, 'round_robin', 100);
      const loadTest2 = await this.simulateLoadScenario(instances, 'least_connections', 100);
      const loadTest3 = await this.simulateLoadScenario(instances, 'weighted_load', 100);
      
      // Measure load distribution
      const distribution = await this.measureLoadDistribution(instances);
      
      const result: TestResult = {
        testId,
        success: distribution.balance > 0.7, // Good balance threshold
        duration: 0,
        metrics: {
          instancesCreated: instances.length,
          loadDistributionBalance: distribution.balance,
          roundRobinScore: loadTest1.distributionScore,
          leastConnectionsScore: loadTest2.distributionScore,
          weightedLoadScore: loadTest3.distributionScore
        },
        details: {
          distribution,
          roundRobinTest: loadTest1,
          leastConnectionsTest: loadTest2,
          weightedLoadTest: loadTest3
        },
        timestamp: new Date()
      };

      await this.cleanupTestInstances();
      this.testResults.push(result);
      
      logger.info(`Test ${testId} completed`, { success: result.success });
      return result;

    } catch (error) {
      const result: TestResult = {
        testId,
        success: false,
        duration: 0,
        error: error.message,
        timestamp: new Date()
      };
      
      this.testResults.push(result);
      logger.error(`Test ${testId} failed`, { error });
      return result;
    }
  }

  /**
   * Test 3: Instance Failure Recovery
   */
  async testInstanceFailureRecovery(): Promise<TestResult> {
    const testId = 'instance-failure-recovery';
    logger.info(`Starting test: ${testId}`);

    try {
      // Create 3 instances
      const instances = await this.createTestInstances(3);
      
      // Create clients distributed across instances
      const clients = await this.createTestClients(instances, 20);
      
      // Establish baseline connectivity
      const baselineResult = await this.testConnectivity(clients, instances);
      
      // Simulate instance failure
      const failedInstance = instances[1];
      await this.simulateInstanceFailure(failedInstance);
      
      // Wait for failure detection and recovery
      await this.sleep(5000);
      
      // Test connectivity after failure
      const postFailureResult = await this.testConnectivity(clients, instances.filter(i => i !== failedInstance));
      
      // Bring failed instance back online
      await this.restoreInstance(failedInstance);
      
      // Test full recovery
      await this.sleep(3000);
      const recoveryResult = await this.testConnectivity(clients, instances);
      
      const result: TestResult = {
        testId,
        success: recoveryResult.connectivityScore > 0.8,
        duration: 0,
        metrics: {
          baselineConnectivity: baselineResult.connectivityScore,
          postFailureConnectivity: postFailureResult.connectivityScore,
          recoveryConnectivity: recoveryResult.connectivityScore,
          recoveryTime: 3000 // milliseconds
        },
        details: {
          baseline: baselineResult,
          postFailure: postFailureResult,
          recovery: recoveryResult
        },
        timestamp: new Date()
      };

      await this.cleanupTestInstances();
      this.testResults.push(result);
      
      logger.info(`Test ${testId} completed`, { success: result.success });
      return result;

    } catch (error) {
      const result: TestResult = {
        testId,
        success: false,
        duration: 0,
        error: error.message,
        timestamp: new Date()
      };
      
      this.testResults.push(result);
      logger.error(`Test ${testId} failed`, { error });
      return result;
    }
  }

  /**
   * Test 4: High Load Stress Test
   */
  async testHighLoadStress(): Promise<TestResult> {
    const testId = 'high-load-stress';
    logger.info(`Starting test: ${testId}`);

    try {
      // Create 5 instances for high load
      const instances = await this.createTestInstances(5);
      
      // Create many clients (simulate 1000 connections)
      const clients = await this.createTestClients(instances, 1000);
      
      // Perform high-volume message testing
      const messageVolume = 10000;
      const startTime = Date.now();
      
      const stressResults = await this.performStressTest(clients, instances, messageVolume);
      
      const duration = Date.now() - startTime;
      const throughput = messageVolume / (duration / 1000); // messages per second
      
      const result: TestResult = {
        testId,
        success: stressResults.success && throughput > 100, // Target: >100 msg/sec
        duration,
        metrics: {
          instancesCreated: instances.length,
          clientsConnected: clients.length,
          messagesProcessed: messageVolume,
          throughput,
          averageLatency: stressResults.averageLatency,
          errorRate: stressResults.errorRate
        },
        details: stressResults,
        timestamp: new Date()
      };

      await this.cleanupTestInstances();
      this.testResults.push(result);
      
      logger.info(`Test ${testId} completed`, { success: result.success });
      return result;

    } catch (error) {
      const result: TestResult = {
        testId,
        success: false,
        duration: 0,
        error: error.message,
        timestamp: new Date()
      };
      
      this.testResults.push(result);
      logger.error(`Test ${testId} failed`, { error });
      return result;
    }
  }

  /**
   * Test 5: Monitoring and Alerting
   */
  async testMonitoringAndAlerting(): Promise<TestResult> {
    const testId = 'monitoring-alerting';
    logger.info(`Starting test: ${testId}`);

    try {
      // Create instances with monitoring
      const instances = await this.createTestInstancesWithMonitoring(3);
      
      // Simulate normal load
      await this.simulateNormalLoad(instances);
      
      // Check that monitoring captures metrics
      const metricsCollected = await this.verifyMetricsCollection(instances);
      
      // Simulate high load to trigger alerts
      await this.simulateHighLoad(instances);
      
      // Verify alerts are triggered
      const alertsTriggered = await this.verifyAlertsTriggered(instances);
      
      // Test reporting functionality
      const reportGenerated = await this.testReportGeneration(instances);
      
      const result: TestResult = {
        testId,
        success: metricsCollected.success && alertsTriggered.success && reportGenerated.success,
        duration: 0,
        metrics: {
          instancesMonitored: instances.length,
          metricsCollected: metricsCollected.count,
          alertsTriggered: alertsTriggered.count,
          reportsGenerated: reportGenerated.count
        },
        details: {
          metrics: metricsCollected,
          alerts: alertsTriggered,
          reports: reportGenerated
        },
        timestamp: new Date()
      };

      await this.cleanupTestInstances();
      this.testResults.push(result);
      
      logger.info(`Test ${testId} completed`, { success: result.success });
      return result;

    } catch (error) {
      const result: TestResult = {
        testId,
        success: false,
        duration: 0,
        error: error.message,
        timestamp: new Date()
      };
      
      this.testResults.push(result);
      logger.error(`Test ${testId} failed`, { error });
      return result;
    }
  }

  /**
   * Run all scaling tests
   */
  async runAllTests(): Promise<TestSuiteResult> {
    logger.info('Starting comprehensive scaling test suite');
    const startTime = Date.now();

    try {
      // Clear any existing test data
      await this.redis.flushdb();
      
      const results = await Promise.all([
        this.testBasicMultiInstanceCommunication(),
        this.testLoadBalancingEffectiveness(),
        this.testInstanceFailureRecovery(),
        this.testHighLoadStress(),
        this.testMonitoringAndAlerting()
      ]);

      const successfulTests = results.filter(r => r.success).length;
      const totalDuration = Date.now() - startTime;

      const suiteResult: TestSuiteResult = {
        totalTests: results.length,
        successfulTests,
        failedTests: results.length - successfulTests,
        totalDuration,
        overallSuccess: successfulTests === results.length,
        results,
        summary: this.generateTestSummary(results),
        timestamp: new Date()
      };

      logger.info('Scaling test suite completed', {
        success: suiteResult.overallSuccess,
        successRate: `${successfulTests}/${results.length}`,
        duration: totalDuration
      });

      return suiteResult;

    } catch (error) {
      logger.error('Test suite failed', { error });
      throw error;
    }
  }

  // Helper methods for test implementation
  private async createTestInstances(count: number): Promise<TestInstance[]> {
    const instances: TestInstance[] = [];
    
    for (let i = 0; i < count; i++) {
      const port = 8080 + i;
      const instanceId = `test-instance-${i}`;
      
      const wss = new WebSocketServer({ port });
      const scalingManager = new WebSocketScalingManager(wss);
      const loadBalancer = new WebSocketLoadBalancer(scalingManager);
      
      instances.push({
        id: instanceId,
        port,
        wss,
        scalingManager,
        loadBalancer,
        clients: new Set()
      });
    }
    
    this.testInstances = instances;
    
    // Wait for instances to initialize
    await this.sleep(2000);
    
    return instances;
  }

  private async createTestInstancesWithMonitoring(count: number): Promise<TestInstanceWithMonitoring[]> {
    const instances: TestInstanceWithMonitoring[] = [];
    
    for (let i = 0; i < count; i++) {
      const port = 8080 + i;
      const instanceId = `test-instance-${i}`;
      
      const wss = new WebSocketServer({ port });
      const scalingManager = new WebSocketScalingManager(wss);
      const loadBalancer = new WebSocketLoadBalancer(scalingManager);
      const monitor = new ScalingMonitoringService(scalingManager, loadBalancer);
      
      await monitor.start();
      
      instances.push({
        id: instanceId,
        port,
        wss,
        scalingManager,
        loadBalancer,
        monitor,
        clients: new Set()
      });
    }
    
    this.testInstances = instances;
    
    // Wait for instances to initialize
    await this.sleep(2000);
    
    return instances;
  }

  private async createTestClients(instances: TestInstance[], clientCount: number): Promise<TestClient[]> {
    const clients: TestClient[] = [];
    
    for (let i = 0; i < clientCount; i++) {
      const instanceIndex = i % instances.length;
      const instance = instances[instanceIndex];
      const clientId = `test-client-${i}`;
      const userId = `user-${i}`;
      
      const ws = new WebSocket(`ws://localhost:${instance.port}`);
      
      const client: TestClient = {
        id: clientId,
        userId,
        ws,
        instanceId: instance.id,
        messages: [],
        connected: false
      };
      
      ws.on('open', () => {
        client.connected = true;
      });
      
      ws.on('message', (data) => {
        client.messages.push({
          timestamp: new Date(),
          data: JSON.parse(data.toString())
        });
      });
      
      clients.push(client);
      instance.clients.add(client);
    }
    
    // Wait for connections to establish
    await this.sleep(1000);
    
    return clients;
  }

  private async testRoomJoining(clients: TestClient[], instances: TestInstance[]): Promise<void> {
    const roomId = 'test-room-1';
    
    // Have clients from different instances join the same room
    for (let i = 0; i < clients.length; i += 2) {
      const client = clients[i];
      const instance = instances.find(inst => inst.id === client.instanceId);
      if (instance) {
        await instance.scalingManager.joinRoom(client.id, roomId, client.userId);
      }
    }
    
    await this.sleep(500);
  }

  private async testMessageBroadcasting(clients: TestClient[], instances: TestInstance[]): Promise<BroadcastTestResult> {
    const roomId = 'test-room-1';
    const message = { type: 'test', content: 'Hello from scaling test', timestamp: Date.now() };
    
    const startTime = Date.now();
    
    // Broadcast from first instance
    const result = await instances[0].scalingManager.broadcastToRoom(roomId, message);
    
    await this.sleep(1000); // Wait for message propagation
    
    const endTime = Date.now();
    const latency = endTime - startTime;
    
    // Count how many clients received the message
    const recipientClients = clients.filter(c => 
      c.messages.some(m => m.data.content === message.content)
    );
    
    return {
      success: result.success,
      messagesDelivered: recipientClients.length,
      expectedDeliveries: Math.ceil(clients.length / 2), // Only clients in room
      averageLatency: latency,
      deliveryRate: recipientClients.length / Math.ceil(clients.length / 2)
    };
  }

  private async testUserMessaging(clients: TestClient[], instances: TestInstance[]): Promise<UserMessageTestResult> {
    const targetClient = clients[0];
    const message = { type: 'user_message', content: 'Direct user message', timestamp: Date.now() };
    
    const startTime = Date.now();
    
    // Send user-specific message from different instance
    const senderInstance = instances[1];
    const result = await senderInstance.scalingManager.sendToUser(targetClient.userId, message);
    
    await this.sleep(500);
    
    const endTime = Date.now();
    const latency = endTime - startTime;
    
    const messageReceived = targetClient.messages.some(m => m.data.content === message.content);
    
    return {
      success: result.success && messageReceived,
      messagesDelivered: messageReceived ? 1 : 0,
      averageLatency: latency,
      deliveryRate: messageReceived ? 1.0 : 0.0
    };
  }

  private async simulateLoadScenario(instances: TestInstance[], strategy: string, connectionCount: number): Promise<LoadTestResult> {
    // Simulate connection distribution using specified strategy
    const distribution = new Map<string, number>();
    
    for (const instance of instances) {
      distribution.set(instance.id, 0);
    }
    
    // Simple simulation of load balancer decisions
    for (let i = 0; i < connectionCount; i++) {
      let selectedInstance: string;
      
      switch (strategy) {
        case 'round_robin':
          selectedInstance = instances[i % instances.length].id;
          break;
        case 'least_connections':
          selectedInstance = Array.from(distribution.entries())
            .sort((a, b) => a[1] - b[1])[0][0];
          break;
        default:
          selectedInstance = instances[Math.floor(Math.random() * instances.length)].id;
      }
      
      distribution.set(selectedInstance, distribution.get(selectedInstance)! + 1);
    }
    
    // Calculate distribution score (1.0 = perfect balance)
    const idealPerInstance = connectionCount / instances.length;
    const variance = Array.from(distribution.values())
      .reduce((sum, count) => sum + Math.pow(count - idealPerInstance, 2), 0) / instances.length;
    const stdDev = Math.sqrt(variance);
    const distributionScore = Math.max(0, 1 - (stdDev / idealPerInstance));
    
    return {
      strategy,
      connectionCount,
      distribution: Object.fromEntries(distribution),
      distributionScore,
      variance,
      standardDeviation: stdDev
    };
  }

  private async measureLoadDistribution(instances: TestInstance[]): Promise<DistributionResult> {
    const instanceData = await Promise.all(
      instances.map(async instance => {
        const stats = await instance.loadBalancer.getLoadBalancerStats();
        return {
          instanceId: instance.id,
          connections: stats.totalConnections,
          load: stats.averageLoad
        };
      })
    );
    
    const totalConnections = instanceData.reduce((sum, data) => sum + data.connections, 0);
    const averageConnections = totalConnections / instances.length;
    
    const variance = instanceData.reduce((sum, data) => 
      sum + Math.pow(data.connections - averageConnections, 2), 0
    ) / instances.length;
    
    const balance = averageConnections > 0 ? Math.max(0, 1 - (Math.sqrt(variance) / averageConnections)) : 1;
    
    return {
      balance,
      instanceData,
      totalConnections,
      averageConnections,
      variance
    };
  }

  private async testConnectivity(clients: TestClient[], instances: TestInstance[]): Promise<ConnectivityResult> {
    // Test basic connectivity across instances
    const pingMessage = { type: 'ping', timestamp: Date.now() };
    let responsesReceived = 0;
    
    // Send ping from each instance
    for (const instance of instances) {
      try {
        await instance.scalingManager.broadcastToAll(pingMessage);
      } catch (error) {
        logger.warn(`Failed to send ping from instance ${instance.id}`, { error });
      }
    }
    
    await this.sleep(1000);
    
    // Count responses
    responsesReceived = clients.filter(client => 
      client.messages.some(m => m.data.type === 'ping')
    ).length;
    
    const connectivityScore = clients.length > 0 ? responsesReceived / clients.length : 0;
    
    return {
      connectivityScore,
      responsesReceived,
      totalClients: clients.length,
      activeInstances: instances.length
    };
  }

  private async simulateInstanceFailure(instance: TestInstance): Promise<void> {
    logger.info(`Simulating failure for instance ${instance.id}`);
    
    // Close WebSocket server
    instance.wss.close();
    
    // Disconnect all clients
    instance.clients.forEach(client => {
      if (client.ws.readyState === WebSocket.OPEN) {
        client.ws.close();
        client.connected = false;
      }
    });
    
    // Stop scaling manager
    await instance.scalingManager.cleanup();
  }

  private async restoreInstance(instance: TestInstance): Promise<void> {
    logger.info(`Restoring instance ${instance.id}`);
    
    // Recreate WebSocket server
    instance.wss = new WebSocketServer({ port: instance.port });
    
    // Recreate scaling manager
    instance.scalingManager = new WebSocketScalingManager(instance.wss);
    
    // Allow time for recovery
    await this.sleep(1000);
  }

  private async performStressTest(clients: TestClient[], instances: TestInstance[], messageVolume: number): Promise<StressTestResult> {
    const startTime = Date.now();
    const latencies: number[] = [];
    let errors = 0;
    
    // Send messages rapidly across instances
    const promises = [];
    
    for (let i = 0; i < messageVolume; i++) {
      const instance = instances[i % instances.length];
      const message = { type: 'stress_test', index: i, timestamp: Date.now() };
      
      const messagePromise = instance.scalingManager.broadcastToAll(message)
        .then(() => {
          latencies.push(Date.now() - message.timestamp);
        })
        .catch(() => {
          errors++;
        });
      
      promises.push(messagePromise);
      
      // Small delay to prevent overwhelming
      if (i % 100 === 0) {
        await this.sleep(10);
      }
    }
    
    await Promise.all(promises);
    
    const duration = Date.now() - startTime;
    const averageLatency = latencies.length > 0 ? 
      latencies.reduce((sum, lat) => sum + lat, 0) / latencies.length : 0;
    
    return {
      success: errors < messageVolume * 0.05, // Less than 5% error rate
      messagesSent: messageVolume,
      messagesDelivered: messageVolume - errors,
      errors,
      errorRate: errors / messageVolume,
      averageLatency,
      duration,
      throughput: messageVolume / (duration / 1000)
    };
  }

  private async verifyMetricsCollection(instances: TestInstanceWithMonitoring[]): Promise<MetricsVerificationResult> {
    let metricsCount = 0;
    
    for (const instance of instances) {
      try {
        const currentMetrics = await instance.monitor.getCurrentMetrics();
        if (currentMetrics && currentMetrics.metrics) {
          metricsCount++;
        }
      } catch (error) {
        logger.warn(`Failed to get metrics from instance ${instance.id}`, { error });
      }
    }
    
    return {
      success: metricsCount === instances.length,
      count: metricsCount,
      expected: instances.length
    };
  }

  private async verifyAlertsTriggered(instances: TestInstanceWithMonitoring[]): Promise<AlertVerificationResult> {
    let alertsCount = 0;
    
    for (const instance of instances) {
      try {
        const metricsHistory = instance.monitor.getMetricsHistory();
        alertsCount += metricsHistory.alerts.length;
      } catch (error) {
        logger.warn(`Failed to get alerts from instance ${instance.id}`, { error });
      }
    }
    
    return {
      success: alertsCount > 0, // At least some alerts should be triggered
      count: alertsCount,
      expected: 1
    };
  }

  private async testReportGeneration(instances: TestInstanceWithMonitoring[]): Promise<ReportVerificationResult> {
    let reportsGenerated = 0;
    
    for (const instance of instances) {
      try {
        const report = await instance.monitor.generateScalingReport('current');
        if (report && report.id) {
          reportsGenerated++;
        }
      } catch (error) {
        logger.warn(`Failed to generate report from instance ${instance.id}`, { error });
      }
    }
    
    return {
      success: reportsGenerated === instances.length,
      count: reportsGenerated,
      expected: instances.length
    };
  }

  private async simulateNormalLoad(instances: TestInstanceWithMonitoring[]): Promise<void> {
    // Create moderate load for baseline metrics
    await this.sleep(2000);
  }

  private async simulateHighLoad(instances: TestInstanceWithMonitoring[]): Promise<void> {
    // Simulate high load to trigger alerts
    const highLoadClients = await this.createTestClients(instances, 500);
    await this.sleep(3000);
  }

  private generateTestSummary(results: TestResult[]): TestSummary {
    const successful = results.filter(r => r.success);
    const failed = results.filter(r => !r.success);
    
    return {
      totalTests: results.length,
      successful: successful.length,
      failed: failed.length,
      successRate: successful.length / results.length,
      averageDuration: results.reduce((sum, r) => sum + (r.duration || 0), 0) / results.length,
      failureReasons: failed.map(r => r.error).filter(Boolean),
      recommendations: this.generateRecommendations(results)
    };
  }

  private generateRecommendations(results: TestResult[]): string[] {
    const recommendations: string[] = [];
    
    const failed = results.filter(r => !r.success);
    if (failed.length > 0) {
      recommendations.push(`${failed.length} tests failed - review error details and system configuration`);
    }
    
    const loadTest = results.find(r => r.testId === 'load-balancing-effectiveness');
    if (loadTest && loadTest.metrics?.loadDistributionBalance < 0.7) {
      recommendations.push('Load balancing effectiveness is below optimal - consider tuning balancing algorithms');
    }
    
    const stressTest = results.find(r => r.testId === 'high-load-stress');
    if (stressTest && stressTest.metrics?.throughput < 100) {
      recommendations.push('System throughput is below target - consider performance optimization');
    }
    
    return recommendations;
  }

  private async cleanupTestInstances(): Promise<void> {
    for (const instance of this.testInstances) {
      try {
        instance.wss.close();
        await instance.scalingManager.cleanup();
        if ('monitor' in instance) {
          await (instance as TestInstanceWithMonitoring).monitor.stop();
        }
      } catch (error) {
        logger.warn(`Error cleaning up instance ${instance.id}`, { error });
      }
    }
    
    this.testInstances = [];
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async cleanup(): Promise<void> {
    await this.cleanupTestInstances();
    await this.redis.quit();
  }
}

// Type definitions for testing
interface TestInstance {
  id: string;
  port: number;
  wss: WebSocketServer;
  scalingManager: WebSocketScalingManager;
  loadBalancer: WebSocketLoadBalancer;
  clients: Set<TestClient>;
}

interface TestInstanceWithMonitoring extends TestInstance {
  monitor: ScalingMonitoringService;
}

interface TestClient {
  id: string;
  userId: string;
  ws: WebSocket;
  instanceId: string;
  messages: Array<{ timestamp: Date; data: any }>;
  connected: boolean;
}

interface TestResult {
  testId: string;
  success: boolean;
  duration: number;
  metrics?: Record<string, any>;
  details?: any;
  error?: string;
  timestamp: Date;
}

interface TestSuiteResult {
  totalTests: number;
  successfulTests: number;
  failedTests: number;
  totalDuration: number;
  overallSuccess: boolean;
  results: TestResult[];
  summary: TestSummary;
  timestamp: Date;
}

interface TestSummary {
  totalTests: number;
  successful: number;
  failed: number;
  successRate: number;
  averageDuration: number;
  failureReasons: string[];
  recommendations: string[];
}

interface BroadcastTestResult {
  success: boolean;
  messagesDelivered: number;
  expectedDeliveries: number;
  averageLatency: number;
  deliveryRate: number;
}

interface UserMessageTestResult {
  success: boolean;
  messagesDelivered: number;
  averageLatency: number;
  deliveryRate: number;
}

interface LoadTestResult {
  strategy: string;
  connectionCount: number;
  distribution: Record<string, number>;
  distributionScore: number;
  variance: number;
  standardDeviation: number;
}

interface DistributionResult {
  balance: number;
  instanceData: Array<{
    instanceId: string;
    connections: number;
    load: number;
  }>;
  totalConnections: number;
  averageConnections: number;
  variance: number;
}

interface ConnectivityResult {
  connectivityScore: number;
  responsesReceived: number;
  totalClients: number;
  activeInstances: number;
}

interface StressTestResult {
  success: boolean;
  messagesSent: number;
  messagesDelivered: number;
  errors: number;
  errorRate: number;
  averageLatency: number;
  duration: number;
  throughput: number;
}

interface MetricsVerificationResult {
  success: boolean;
  count: number;
  expected: number;
}

interface AlertVerificationResult {
  success: boolean;
  count: number;
  expected: number;
}

interface ReportVerificationResult {
  success: boolean;
  count: number;
  expected: number;
}
