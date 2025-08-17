// server/websocket/scaling/scaling-examples.ts
// WebSocket Scaling System Usage Examples and Integration Guide

import { ScalableWebSocketManager } from './websocket-manager';
import { wsLogger as logger } from '../../utils/logger';
import { createServer, Server } from 'http';

/**
 * Example: Setting up the scalable WebSocket system
 */
export async function setupScalableWebSockets(port: number = 3001): Promise<ScalableWebSocketManager> {
  // Create HTTP server
  const server = createServer();
  
  // Initialize scalable WebSocket manager
  const wsManager = new ScalableWebSocketManager(server);
  
  // Start server
  (server as any).listen(port, () => {
    logger.info({ port }, 'Scalable WebSocket server started');
  });
  
  // Health check endpoint
  server.on('request', async (req, res) => {
    if (req.url === '/health') {
      try {
        const health = await wsManager.healthCheck();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(health));
      } catch (error) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ 
          status: 'error', 
          message: error instanceof Error ? error.message : String(error) 
        }));
      }
    } else if (req.url === '/stats') {
      try {
        const stats = await wsManager.getInstanceStats();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(stats));
      } catch (error) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ 
          status: 'error', 
          message: error instanceof Error ? error.message : String(error) 
        }));
      }
    } else {
      res.writeHead(404);
      res.end('Not found');
    }
  });
  
  logger.info('Scalable WebSocket system initialized successfully');
  return wsManager;
}

/**
 * Example: Room management operations
 */
export async function roomManagementExamples(wsManager: ScalableWebSocketManager) {
  const exampleRoomId = 'game-room-123';
  
  try {
    // Get current room member count across all instances
    const memberCount = await wsManager.getRoomMemberCount(exampleRoomId);
    logger.info({ roomId: exampleRoomId, memberCount }, 'Current room member count');
    
    // Broadcast a game state update to all room members
    await wsManager.broadcastToRoom(exampleRoomId, {
      type: 'game_state_update',
      data: {
        gameState: {
          currentPlayer: 'player-456',
          turnNumber: 15,
          boardState: {
            cards: [],
            tokens: []
          }
        },
        timestamp: Date.now()
      }
    });
    
    // Broadcast a system message to all room members
    await wsManager.broadcastToRoom(exampleRoomId, {
      type: 'system_message',
      data: {
        message: 'Game has been paused by the GM',
        type: 'warning',
        timestamp: Date.now()
      }
    });
    
    logger.info({ roomId: exampleRoomId }, 'Room management examples completed');
    
  } catch (error) {
    logger.error({ 
      roomId: exampleRoomId, 
      error: error instanceof Error ? error.message : String(error) 
    }, 'Room management examples failed');
  }
}

/**
 * Example: User-to-user messaging
 */
export async function userMessagingExamples(wsManager: ScalableWebSocketManager) {
  const senderId = 'user-123';
  const targetUserId = 'user-456';
  
  try {
    // Send a private message to a specific user
    await wsManager.sendToUser(targetUserId, {
      type: 'private_message',
      data: {
        senderId,
        message: 'Hey, want to start a new game?',
        timestamp: Date.now()
      }
    });
    
    // Send a friend request notification
    await wsManager.sendToUser(targetUserId, {
      type: 'friend_request',
      data: {
        senderId,
        senderName: 'Alice',
        message: 'Alice wants to be your friend',
        timestamp: Date.now()
      }
    });
    
    // Send a game invitation
    await wsManager.sendToUser(targetUserId, {
      type: 'game_invitation',
      data: {
        senderId,
        senderName: 'Alice',
        roomId: 'game-room-789',
        gameTitle: 'D&D Campaign - The Lost Mines',
        timestamp: Date.now()
      }
    });
    
    logger.info({ senderId, targetUserId }, 'User messaging examples completed');
    
  } catch (error) {
    logger.error({ 
      senderId, 
      targetUserId, 
      error: error instanceof Error ? error.message : String(error) 
    }, 'User messaging examples failed');
  }
}

/**
 * Example: Global broadcasting
 */
export async function globalBroadcastExamples(wsManager: ScalableWebSocketManager) {
  try {
    // Broadcast maintenance notification to all connected users
    await wsManager.broadcastToAll({
      type: 'maintenance_notification',
      data: {
        message: 'Scheduled maintenance in 30 minutes',
        type: 'warning',
        duration: '2 hours',
        timestamp: Date.now()
      }
    });
    
    // Broadcast server announcement
    await wsManager.broadcastToAll({
      type: 'server_announcement',
      data: {
        title: 'New Features Available!',
        message: 'Check out the new dice rolling system and enhanced card management',
        type: 'info',
        timestamp: Date.now()
      }
    });
    
    // Broadcast emergency shutdown notice
    await wsManager.broadcastToAll({
      type: 'emergency_shutdown',
      data: {
        message: 'Emergency maintenance required. Please save your work.',
        countdown: 300, // 5 minutes
        timestamp: Date.now()
      }
    });
    
    logger.info('Global broadcast examples completed');
    
  } catch (error) {
    logger.error({ 
      error: error instanceof Error ? error.message : String(error) 
    }, 'Global broadcast examples failed');
  }
}

/**
 * Example: Monitoring and analytics
 */
export async function monitoringExamples(wsManager: ScalableWebSocketManager) {
  try {
    // Get comprehensive instance statistics
    const stats = await wsManager.getInstanceStats();
    
    console.log('Instance Statistics:');
    console.log(`- Instance ID: ${stats.instanceId}`);
    console.log(`- Local Connections: ${stats.connections}`);
    console.log(`- Local Rooms: ${stats.rooms}`);
    console.log(`- Total Instances: ${stats.totalInstances}`);
    console.log(`- Memory Usage: ${Math.round(stats.memory.used / 1024 / 1024)}MB`);
    console.log(`- Uptime: ${Math.round(stats.uptime)}s`);
    
    // Get room distribution across instances
    const distribution = await wsManager.getRoomDistribution();
    
    console.log('\nRoom Distribution:');
    distribution.forEach((instance, index) => {
      console.log(`${index + 1}. Instance ${instance.instanceId}:`);
      console.log(`   - Connections: ${instance.connections}`);
      console.log(`   - Rooms: ${instance.rooms}`);
      console.log(`   - Last Heartbeat: ${instance.lastHeartbeat.toISOString()}`);
    });
    
    // Check system health
    const health = await wsManager.healthCheck();
    
    console.log('\nSystem Health:');
    console.log(`- Overall Status: ${health.status}`);
    console.log(`- Publisher Connected: ${health.publisherConnected}`);
    console.log(`- Subscriber Connected: ${health.subscriberConnected}`);
    console.log(`- Active Instances: ${health.activeInstances}`);
    console.log(`- Local Connections: ${health.localConnections}`);
    console.log(`- Local Rooms: ${health.localRooms}`);
    
    if (health.error) {
      console.log(`- Error: ${health.error}`);
    }
    
    logger.info('Monitoring examples completed');
    
  } catch (error) {
    logger.error({ 
      error: error instanceof Error ? error.message : String(error) 
    }, 'Monitoring examples failed');
  }
}

/**
 * Example: Load balancing and scaling scenarios
 */
export async function loadBalancingExamples(wsManager: ScalableWebSocketManager) {
  try {
    // Simulate multiple instances for load balancing
    const distribution = await wsManager.getRoomDistribution();
    
    // Calculate load distribution
    const totalConnections = distribution.reduce((sum, instance) => sum + instance.connections, 0);
    const avgConnectionsPerInstance = totalConnections / distribution.length;
    
    logger.info({
      totalInstances: distribution.length,
      totalConnections,
      avgConnectionsPerInstance: Math.round(avgConnectionsPerInstance)
    }, 'Load balancing metrics');
    
    // Identify overloaded instances
    const overloadedInstances = distribution.filter(
      instance => instance.connections > avgConnectionsPerInstance * 1.5
    );
    
    if (overloadedInstances.length > 0) {
      logger.warn({
        overloadedCount: overloadedInstances.length,
        overloadedInstances: overloadedInstances.map(i => ({
          instanceId: i.instanceId,
          connections: i.connections
        }))
      }, 'Overloaded instances detected');
    }
    
    // Check for instance failures (no recent heartbeat)
    const now = new Date();
    const staleInstances = distribution.filter(
      instance => now.getTime() - instance.lastHeartbeat.getTime() > 60000 // 1 minute
    );
    
    if (staleInstances.length > 0) {
      logger.error({
        staleCount: staleInstances.length,
        staleInstances: staleInstances.map(i => ({
          instanceId: i.instanceId,
          lastHeartbeat: i.lastHeartbeat.toISOString()
        }))
      }, 'Stale instances detected');
    }
    
    logger.info('Load balancing examples completed');
    
  } catch (error) {
    logger.error({ 
      error: error instanceof Error ? error.message : String(error) 
    }, 'Load balancing examples failed');
  }
}

/**
 * Example: Error handling and recovery
 */
export async function errorHandlingExamples(wsManager: ScalableWebSocketManager) {
  try {
    // Test health check and recovery
    const health = await wsManager.healthCheck();
    
    if (health.status !== 'healthy') {
      logger.warn({ health }, 'System health check failed, attempting recovery');
      
      // Implement recovery logic here
      // For example: restart Redis connections, clear stuck state, etc.
      
      // Wait and re-check
      await new Promise(resolve => setTimeout(resolve, 5000));
      const healthRecheck = await wsManager.healthCheck();
      
      if (healthRecheck.status === 'healthy') {
        logger.info('System recovery successful');
      } else {
        logger.error({ health: healthRecheck }, 'System recovery failed');
      }
    }
    
    // Test graceful degradation
    try {
      await wsManager.broadcastToAll({
        type: 'test_message',
        data: { test: true, timestamp: Date.now() }
      });
    } catch (error) {
      logger.warn({ 
        error: error instanceof Error ? error.message : String(error) 
      }, 'Broadcast failed, implementing fallback');
      
      // Fallback to local-only broadcasting
      // Implementation would depend on specific requirements
    }
    
    logger.info('Error handling examples completed');
    
  } catch (error) {
    logger.error({ 
      error: error instanceof Error ? error.message : String(error) 
    }, 'Error handling examples failed');
  }
}

/**
 * Complete workflow example
 */
export async function completeScalingWorkflow() {
  let wsManager: ScalableWebSocketManager | undefined;
  
  try {
    // 1. Setup scalable WebSocket system
    wsManager = await setupScalableWebSockets(3001);
    
    // 2. Run room management examples
    await roomManagementExamples(wsManager);
    
    // 3. Test user messaging
    await userMessagingExamples(wsManager);
    
    // 4. Test global broadcasting
    await globalBroadcastExamples(wsManager);
    
    // 5. Monitor system performance
    await monitoringExamples(wsManager);
    
    // 6. Check load balancing
    await loadBalancingExamples(wsManager);
    
    // 7. Test error handling
    await errorHandlingExamples(wsManager);
    
    logger.info('Complete scaling workflow finished successfully');
    
  } catch (error) {
    logger.error({ 
      error: error instanceof Error ? error.message : String(error) 
    }, 'Complete scaling workflow failed');
  } finally {
    // Cleanup
    if (wsManager) {
      await wsManager.shutdown();
    }
  }
}

/**
 * Production deployment helpers
 */
export class ProductionScalingHelpers {
  static async deployMultipleInstances(instanceCount: number = 3): Promise<ScalableWebSocketManager[]> {
    const instances: ScalableWebSocketManager[] = [];
    const basePort = 3000;
    
    for (let i = 0; i < instanceCount; i++) {
      const port = basePort + i;
      
      // Set unique instance ID for each deployment
      process.env['INSTANCE_ID'] = `production-instance-${i + 1}`;
      
      const wsManager = await setupScalableWebSockets(port);
      instances.push(wsManager);
      
      logger.info({ instanceId: process.env['INSTANCE_ID'], port }, 'Production instance deployed');
    }
    
    return instances;
  }
  
  static setupHealthMonitoring(wsManager: ScalableWebSocketManager): NodeJS.Timeout {
    return setInterval(async () => {
      try {
        const health = await wsManager.healthCheck();
        
        if (health.status !== 'healthy') {
          logger.error({ health }, 'Health check failed in production');
          
          // Implement alerting logic here
          // For example: send to monitoring service, trigger alerts, etc.
        }
        
        // Log metrics for monitoring systems
        const stats = await wsManager.getInstanceStats();
        logger.info({
          connections: stats.connections,
          rooms: stats.rooms,
          memoryUsed: Math.round(stats.memory.used / 1024 / 1024),
          uptime: Math.round(stats.uptime)
        }, 'Production metrics');
        
      } catch (error) {
        logger.error({ 
          error: error instanceof Error ? error.message : String(error) 
        }, 'Health monitoring failed');
      }
    }, 30000); // Every 30 seconds
  }
  
  static async gracefulShutdown(instances: ScalableWebSocketManager[]): Promise<void> {
    logger.info({ instanceCount: instances.length }, 'Starting graceful shutdown');
    
    // Shutdown all instances in parallel
    await Promise.all(
      instances.map(async (wsManager, index) => {
        try {
          await wsManager.shutdown();
          logger.info({ instanceIndex: index }, 'Instance shutdown complete');
        } catch (error) {
          logger.error({ 
            instanceIndex: index,
            error: error instanceof Error ? error.message : String(error) 
          }, 'Instance shutdown failed');
        }
      })
    );
    
    logger.info('Graceful shutdown completed');
  }
}

export default {
  setupScalableWebSockets,
  roomManagementExamples,
  userMessagingExamples,
  globalBroadcastExamples,
  monitoringExamples,
  loadBalancingExamples,
  errorHandlingExamples,
  completeScalingWorkflow,
  ProductionScalingHelpers
};
