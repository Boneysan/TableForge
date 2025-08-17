// server/websocket/scaling/load-balancer.ts
import { WebSocketScalingManager, RoomDistribution } from './redis-pubsub';
import { logger } from '../../utils/logger';

/**
 * Load Balancing Strategies for WebSocket Horizontal Scaling
 * Implements intelligent routing and load distribution across instances
 */
export class WebSocketLoadBalancer {
  private scalingManager: WebSocketScalingManager;
  private loadCheckInterval: NodeJS.Timeout | null = null;
  private rebalanceInterval: NodeJS.Timeout | null = null;
  private readonly loadThresholds = {
    high: 0.8,        // 80% load threshold
    critical: 0.95,   // 95% critical threshold
    target: 0.6       // Target load after rebalancing
  };

  constructor(scalingManager: WebSocketScalingManager) {
    this.scalingManager = scalingManager;
    this.startLoadMonitoring();
  }

  private startLoadMonitoring(): void {
    // Monitor load every 30 seconds
    this.loadCheckInterval = setInterval(async () => {
      await this.checkLoadAndRebalance();
    }, 30000);

    // Perform deep rebalancing every 5 minutes
    this.rebalanceInterval = setInterval(async () => {
      await this.performDeepRebalancing();
    }, 300000);

    logger.info('Load balancer monitoring started');
  }

  /**
   * Round Robin Strategy - Distributes connections evenly
   */
  async roundRobinSelect(): Promise<string | null> {
    try {
      const instances = await this.scalingManager.getRoomDistribution();
      if (instances.length === 0) return null;

      // Sort by connection count (ascending) to balance load
      instances.sort((a, b) => a.connections - b.connections);
      
      const selectedInstance = instances[0];
      
      if (!selectedInstance) {
        return null;
      }
      
      // metrics.loadBalancerSelection?.inc({ 
      //   strategy: 'round_robin', 
      //   instance: selectedInstance.instanceId 
      // });

      return selectedInstance.instanceId;
    } catch (error) {
      logger.error({ error }, 'Round robin selection failed');
      return null;
    }
  }

  /**
   * Least Connections Strategy - Routes to instance with fewest connections
   */
  async leastConnectionsSelect(): Promise<string | null> {
    try {
      const instances = await this.scalingManager.getRoomDistribution();
      if (instances.length === 0) return null;

      // Find instance with minimum connections
      const selectedInstance = instances.reduce((min, current) => 
        current.connections < min.connections ? current : min
      );

      // metrics.loadBalancerSelection?.inc({ 
      //   strategy: 'least_connections', 
      //   instance: selectedInstance.instanceId 
      // });

      return selectedInstance.instanceId;
    } catch (error) {
      logger.error({ error }, 'Least connections selection failed');
      return null;
    }
  }

  /**
   * Weighted Load Strategy - Routes based on instance capacity and current load
   */
  async weightedLoadSelect(): Promise<string | null> {
    try {
      const instances = await this.scalingManager.getRoomDistribution();
      if (instances.length === 0) return null;

      // Calculate load scores for each instance
      const scoredInstances = instances.map(instance => ({
        ...instance,
        loadScore: this.calculateLoadScore(instance)
      }));

      // Select instance with lowest load score
      const selectedInstance = scoredInstances.reduce((min, current) => 
        current.loadScore < min.loadScore ? current : min
      );

      // metrics.loadBalancerSelection?.inc({ 
      //   strategy: 'weighted_load', 
      //   instance: selectedInstance.instanceId 
      // });

      return selectedInstance.instanceId;
    } catch (error) {
      logger.error({ error }, 'Weighted load selection failed');
      return null;
    }
  }

  /**
   * Geographic/Affinity Strategy - Routes based on location or user affinity
   */
  async weightedSelect(_userLocation?: string, _userId?: string): Promise<string | null> {
    try {
      const instances = await this.scalingManager.getActiveInstances();
      if (instances.length === 0) return null;

      // For now, implement simple affinity based on user ID hash
      if (_userId) {
        const hash = this.hashUserId(_userId);
        const instanceIndex = hash % instances.length;
        const selectedInstance = instances[instanceIndex];

        if (!selectedInstance) {
          return null;
        }

        // metrics.loadBalancerSelection?.inc({ 
        //   strategy: 'affinity', 
        //   instance: selectedInstance 
        // });

        return selectedInstance;
      }

      // Fallback to weighted load
      return this.weightedLoadSelect();
    } catch (error) {
      logger.error({ error }, 'Affinity selection failed');
      return null;
    }
  }

  /**
   * Room-based Strategy - Routes to instance already hosting the room
   */
  async roomAffinitySelect(roomId: string): Promise<string | null> {
    try {
      const distribution = await this.scalingManager.getRoomDistribution();
      
      // Check if any instance already has this room
      const roomInstances = distribution.filter(dist => dist.rooms > 0);
      
      if (roomInstances.length > 0) {
        // Select the instance with lowest load among those with rooms
        const selectedInstance = roomInstances.reduce((min, current) => 
          this.calculateLoadScore(current) < this.calculateLoadScore(min) ? current : min
        );

        // metrics.loadBalancerSelection?.inc({ 
        //   strategy: 'room_affinity', 
        //   instance: selectedInstance.instanceId,
        //   room_id: roomId
        // });

        return selectedInstance.instanceId;
      }

      // If no instance has the room, use weighted load strategy
      return this.weightedLoadSelect();
    } catch (error) {
      logger.error({ error, roomId }, 'Room affinity selection failed');
      return null;
    }
  }

  /**
   * Adaptive Strategy - Automatically selects best strategy based on current conditions
   */
  async adaptiveSelect(context?: SelectionContext): Promise<string | null> {
    try {
      const instances = await this.scalingManager.getRoomDistribution();
      if (instances.length === 0) return null;

      // Analyze current system state
      const systemState = await this.analyzeSystemState(instances);
      
      // Select strategy based on system state
      let selectedInstance: string | null = null;

      if (context?.roomId) {
        // For room-specific requests, prefer room affinity
        selectedInstance = await this.roomAffinitySelect(context.roomId);
      } else if (systemState.highLoadInstances > 0) {
        // Under high load, use least connections
        selectedInstance = await this.leastConnectionsSelect();
      } else if (context?.userId) {
        // For user-specific requests with normal load, use affinity
        selectedInstance = await this.weightedSelect(context.userLocation, context.userId);
      } else {
        // Default to weighted load for best performance
        selectedInstance = await this.weightedLoadSelect();
      }

      // metrics.loadBalancerSelection?.inc({ 
      //   strategy: 'adaptive', 
      //   instance: selectedInstance || 'none',
      //   system_state: systemState.state
      // });

      return selectedInstance;
    } catch (error) {
      logger.error({ error }, 'Adaptive selection failed');
      return this.leastConnectionsSelect(); // Fallback
    }
  }

  // Load monitoring and rebalancing
  private async checkLoadAndRebalance(): Promise<void> {
    try {
      const instances = await this.scalingManager.getRoomDistribution();
      const overloadedInstances = instances.filter(instance => 
        this.calculateLoadScore(instance) > this.loadThresholds.high
      );

      if (overloadedInstances.length > 0) {
        logger.warn({ 
          overloadedCount: overloadedInstances.length,
          instances: overloadedInstances.map(i => ({
            id: i.instanceId,
            connections: i.connections,
            load: this.calculateLoadScore(i)
          }))
        }, 'High load detected on instances');

        // Trigger rebalancing for overloaded instances
        for (const instance of overloadedInstances) {
          await this.rebalanceInstance(instance);
        }

        // metrics.loadBalancerRebalance?.inc({ type: 'auto', reason: 'high_load' });
      }
    } catch (error) {
      logger.error({ error }, 'Load check failed');
    }
  }

  private async performDeepRebalancing(): Promise<void> {
    try {
      const distribution = await this.scalingManager.getRoomDistribution();
      const totalConnections = distribution.reduce((sum, dist) => sum + dist.connections, 0);
      const averageLoad = totalConnections / distribution.length;

      // Find instances that deviate significantly from average
      const imbalancedInstances = distribution.filter(dist => 
        Math.abs(dist.connections - averageLoad) > averageLoad * 0.3
      );

      if (imbalancedInstances.length > 1) {
        logger.info({
          totalConnections,
          averageLoad,
          imbalancedCount: imbalancedInstances.length
        }, 'Performing deep rebalancing');

        await this.performGradualRebalancing(imbalancedInstances);
        // metrics.loadBalancerRebalance?.inc({ type: 'deep', reason: 'imbalance' });
      }
    } catch (error) {
      logger.error({ error }, 'Deep rebalancing failed');
    }
  }

  private async rebalanceInstance(instance: RoomDistribution): Promise<void> {
    try {
      const loadScore = this.calculateLoadScore(instance);
      
      if (loadScore > this.loadThresholds.critical) {
        // Critical load - stop accepting new connections
        await this.scalingManager.sendToUser('system', {
          type: 'admin_command',
          command: 'reject_new_connections',
          instanceId: instance.instanceId
        });

        logger.warn({
          instanceId: instance.instanceId,
          load: loadScore
        }, 'Instance marked to reject new connections');
      } else if (loadScore > this.loadThresholds.high) {
        // High load - implement gradual connection migration
        await this.initiateConnectionMigration(instance);
      }
    } catch (error) {
      logger.error({ error, instanceId: instance.instanceId }, 'Instance rebalancing failed');
    }
  }

  private async performGradualRebalancing(instances: RoomDistribution[]): Promise<void> {
    // Implement gradual connection migration between instances
    const overloaded = instances.filter(i => this.calculateLoadScore(i) > this.loadThresholds.target);
    const underloaded = instances.filter(i => this.calculateLoadScore(i) < this.loadThresholds.target);

    for (const overloadedInstance of overloaded) {
      if (underloaded.length === 0) break;

      const targetInstance = underloaded.reduce((min, current) => 
        this.calculateLoadScore(current) < this.calculateLoadScore(min) ? current : min
      );

      // Calculate how many connections to migrate
      const excessConnections = Math.floor(
        (this.calculateLoadScore(overloadedInstance) - this.loadThresholds.target) * overloadedInstance.connections
      );

      if (excessConnections > 10) { // Only migrate if significant
        await this.migrateConnections(overloadedInstance.instanceId, targetInstance.instanceId, excessConnections);
      }
    }
  }

  private async initiateConnectionMigration(instance: RoomDistribution): Promise<void> {
    // Implement smart connection migration logic
    const migrationPlan = await this.createMigrationPlan(instance);
    
    if (migrationPlan.targetInstance) {
      await this.migrateConnections(
        instance.instanceId, 
        migrationPlan.targetInstance, 
        migrationPlan.connectionCount
      );
    }
  }

  private async createMigrationPlan(sourceInstance: RoomDistribution): Promise<MigrationPlan> {
    const instances = await this.scalingManager.getRoomDistribution();
    const availableInstances = instances.filter(i => 
      i.instanceId !== sourceInstance.instanceId &&
      this.calculateLoadScore(i) < this.loadThresholds.target
    );

    if (availableInstances.length === 0) {
      return { targetInstance: null, connectionCount: 0 };
    }

    const targetInstance = availableInstances.reduce((min, current) => 
      this.calculateLoadScore(current) < this.calculateLoadScore(min) ? current : min
    );

    const sourceLoad = this.calculateLoadScore(sourceInstance);
    const connectionsToMigrate = Math.floor(
      (sourceLoad - this.loadThresholds.target) * sourceInstance.connections * 0.1
    ); // Migrate 10% of excess

    return {
      targetInstance: targetInstance.instanceId,
      connectionCount: Math.min(connectionsToMigrate, 50) // Max 50 at a time
    };
  }

  private async migrateConnections(
    sourceInstanceId: string, 
    targetInstanceId: string, 
    connectionCount: number
  ): Promise<void> {
    logger.info({
      source: sourceInstanceId,
      target: targetInstanceId,
      count: connectionCount
    }, 'Initiating connection migration');

    // Send migration command to source instance
    await this.scalingManager.sendToUser('system', {
      type: 'load_balance',
      action: 'migrate_connections',
      sourceInstanceId,
      targetInstanceId,
      connectionCount,
      timestamp: Date.now()
    });

    // metrics.connectionMigrations?.inc({ 
    //   source: sourceInstanceId, 
    //   target: targetInstanceId 
    // }, connectionCount);
  }

  // Utility methods
  private calculateLoadScore(instance: RoomDistribution): number {
    // Multi-factor load calculation
    const connectionFactor = instance.connections / 1000; // Normalize to 1000 connections
    // Memory factor not available in RoomDistribution - would need InstanceStats
    const memoryFactor = 0; // Default to 0 since memory data not available
    const roomFactor = instance.rooms / 100; // Normalize to 100 rooms
    
    // Weighted calculation (adjusted weights since memory unavailable)
    return (connectionFactor * 0.7) + (memoryFactor * 0.0) + (roomFactor * 0.3);
  }

  private hashUserId(userId: string): number {
    let hash = 0;
    for (let i = 0; i < userId.length; i++) {
      const char = userId.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash);
  }

  private async analyzeSystemState(instances: RoomDistribution[]): Promise<SystemState> {
    const highLoadInstances = instances.filter(i => 
      this.calculateLoadScore(i) > this.loadThresholds.high
    ).length;

    const criticalLoadInstances = instances.filter(i => 
      this.calculateLoadScore(i) > this.loadThresholds.critical
    ).length;

    const averageLoad = instances.reduce((sum, i) => 
      sum + this.calculateLoadScore(i), 0
    ) / instances.length;

    let state: 'normal' | 'high_load' | 'critical' = 'normal';
    if (criticalLoadInstances > 0) state = 'critical';
    else if (highLoadInstances > instances.length * 0.3) state = 'high_load';

    return {
      state,
      totalInstances: instances.length,
      highLoadInstances,
      criticalLoadInstances,
      averageLoad
    };
  }

  // Health check and statistics
  async getLoadBalancerStats(): Promise<LoadBalancerStats> {
    try {
      const distribution = await this.scalingManager.getRoomDistribution();

      return {
        timestamp: new Date(),
        totalInstances: distribution.length,
        totalConnections: distribution.reduce((sum, i) => sum + i.connections, 0),
        totalRooms: distribution.reduce((sum, i) => sum + i.rooms, 0),
        averageLoad: distribution.reduce((sum, i) => sum + this.calculateLoadScore(i), 0) / distribution.length,
        loadDistribution: distribution.map(d => ({
          instanceId: d.instanceId,
          connections: d.connections,
          rooms: d.rooms,
          load: this.calculateLoadScore(d)
        })),
        systemState: await this.analyzeSystemState(distribution)
      };
    } catch (error) {
      logger.error({ error }, 'Failed to get load balancer stats');
      throw error;
    }
  }

  async cleanup(): Promise<void> {
    if (this.loadCheckInterval) {
      clearInterval(this.loadCheckInterval);
      this.loadCheckInterval = null;
    }

    if (this.rebalanceInterval) {
      clearInterval(this.rebalanceInterval);
      this.rebalanceInterval = null;
    }

    logger.info('Load balancer cleanup completed');
  }
}

// Type definitions
export interface SelectionContext {
  userId?: string;
  userLocation?: string;
  roomId?: string;
  priority?: 'low' | 'normal' | 'high';
}

export interface MigrationPlan {
  targetInstance: string | null;
  connectionCount: number;
}

export interface SystemState {
  state: 'normal' | 'high_load' | 'critical';
  totalInstances: number;
  highLoadInstances: number;
  criticalLoadInstances: number;
  averageLoad: number;
}

export interface LoadBalancerStats {
  timestamp: Date;
  totalInstances: number;
  totalConnections: number;
  totalRooms: number;
  averageLoad: number;
  loadDistribution: Array<{
    instanceId: string;
    connections: number;
    rooms: number;
    load: number;
  }>;
  systemState: SystemState;
}
