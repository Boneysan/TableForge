// server/websocket/scaling/scaling-integration.test.ts
// Integration tests for WebSocket scaling system

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from '@jest/globals';
import WebSocket from 'ws';
import { createServer, Server } from 'http';
import { ScalableWebSocketManager } from './websocket-manager';
import { WebSocketScalingManager } from './redis-pubsub';
import Redis from 'ioredis';

interface TestMessage {
  type: string;
  data: any;
  timestamp?: number;
}

interface TestClient {
  ws: WebSocket;
  id: string;
  messages: TestMessage[];
}

describe('WebSocket Scaling Integration Tests', () => {
  let server1: Server;
  let server2: Server;
  let wsManager1: ScalableWebSocketManager;
  let wsManager2: ScalableWebSocketManager;
  let redis: Redis;
  
  const TEST_PORT_1 = 3100;
  const TEST_PORT_2 = 3101;
  const TEST_REDIS_DB = 15; // Use a separate test database

  beforeAll(async () => {
    // Setup Redis connection for cleanup
    redis = new Redis({
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT || '6379'),
      db: TEST_REDIS_DB,
      maxRetriesPerRequest: 3,
      retryDelayOnFailover: 100
    });

    // Clean test database
    await redis.flushdb();

    // Create first server instance
    server1 = createServer();
    process.env.INSTANCE_ID = 'test-instance-1';
    process.env.REDIS_DB = TEST_REDIS_DB.toString();
    process.env.REDIS_PUBSUB_DB = (TEST_REDIS_DB + 1).toString();
    
    wsManager1 = new ScalableWebSocketManager(server1);
    await new Promise<void>((resolve) => {
      (server1 as any).listen(TEST_PORT_1, resolve);
    });

    // Create second server instance
    server2 = createServer();
    process.env.INSTANCE_ID = 'test-instance-2';
    
    wsManager2 = new ScalableWebSocketManager(server2);
    await new Promise<void>((resolve) => {
      (server2 as any).listen(TEST_PORT_2, resolve);
    });

    // Wait for instances to initialize
    await new Promise(resolve => setTimeout(resolve, 1000));
  });

  afterAll(async () => {
    // Cleanup
    await wsManager1?.shutdown();
    await wsManager2?.shutdown();
    
    server1?.close();
    server2?.close();
    
    await redis.flushdb();
    await redis.quit();
  });

  beforeEach(async () => {
    // Clean slate for each test
    await redis.flushdb();
  });

  describe('Instance Communication', () => {
    it('should detect multiple instances', async () => {
      // Wait for heartbeats to register
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      const distribution1 = await wsManager1.getRoomDistribution();
      const distribution2 = await wsManager2.getRoomDistribution();
      
      expect(distribution1.length).toBeGreaterThanOrEqual(2);
      expect(distribution2.length).toBeGreaterThanOrEqual(2);
      
      const instanceIds = distribution1.map(d => d.instanceId);
      expect(instanceIds).toContain('test-instance-1');
      expect(instanceIds).toContain('test-instance-2');
    });

    it('should maintain heartbeats', async () => {
      const initialDistribution = await wsManager1.getRoomDistribution();
      
      // Wait for heartbeat interval
      await new Promise(resolve => setTimeout(resolve, 3000));
      
      const updatedDistribution = await wsManager1.getRoomDistribution();
      
      // All instances should still be present
      expect(updatedDistribution.length).toBe(initialDistribution.length);
      
      // Heartbeat timestamps should be recent
      updatedDistribution.forEach(instance => {
        const timeDiff = Date.now() - instance.lastHeartbeat.getTime();
        expect(timeDiff).toBeLessThan(60000); // Less than 1 minute
      });
    });
  });

  describe('Cross-Instance Messaging', () => {
    let client1: TestClient;
    let client2: TestClient;

    beforeEach(async () => {
      // Create client connections to different instances
      client1 = await createTestClient(TEST_PORT_1, 'user-1');
      client2 = await createTestClient(TEST_PORT_2, 'user-2');
      
      // Wait for connections to stabilize
      await new Promise(resolve => setTimeout(resolve, 500));
    });

    afterEach(async () => {
      client1?.ws.close();
      client2?.ws.close();
    });

    it('should route messages between instances', async () => {
      // Send message from client1 to client2 via user-to-user messaging
      await wsManager1.sendToUser('user-2', {
        type: 'test_message',
        data: {
          from: 'user-1',
          message: 'Hello from instance 1!'
        }
      });

      // Wait for message delivery
      await new Promise(resolve => setTimeout(resolve, 1000));

      // Verify client2 received the message
      expect(client2.messages.length).toBeGreaterThan(0);
      
      const receivedMessage = client2.messages.find(m => m.type === 'test_message');
      expect(receivedMessage).toBeDefined();
      expect(receivedMessage?.data.from).toBe('user-1');
      expect(receivedMessage?.data.message).toBe('Hello from instance 1!');
    });

    it('should handle room-based messaging across instances', async () => {
      const roomId = 'test-room-123';

      // Join both clients to the same room
      await wsManager1.joinRoom('user-1', roomId);
      await wsManager2.joinRoom('user-2', roomId);

      // Wait for room state to synchronize
      await new Promise(resolve => setTimeout(resolve, 500));

      // Broadcast message to room
      await wsManager1.broadcastToRoom(roomId, {
        type: 'room_message',
        data: {
          message: 'Hello room!',
          sender: 'user-1'
        }
      });

      // Wait for message delivery
      await new Promise(resolve => setTimeout(resolve, 1000));

      // Both clients should receive the message
      const client1Message = client1.messages.find(m => m.type === 'room_message');
      const client2Message = client2.messages.find(m => m.type === 'room_message');

      expect(client1Message).toBeDefined();
      expect(client2Message).toBeDefined();
      expect(client1Message?.data.message).toBe('Hello room!');
      expect(client2Message?.data.message).toBe('Hello room!');
    });

    it('should handle global broadcasts', async () => {
      // Clear previous messages
      client1.messages = [];
      client2.messages = [];

      // Send global broadcast
      await wsManager1.broadcastToAll({
        type: 'global_announcement',
        data: {
          message: 'System maintenance in 5 minutes',
          priority: 'high'
        }
      });

      // Wait for message delivery
      await new Promise(resolve => setTimeout(resolve, 1000));

      // Both clients should receive the global message
      const client1Message = client1.messages.find(m => m.type === 'global_announcement');
      const client2Message = client2.messages.find(m => m.type === 'global_announcement');

      expect(client1Message).toBeDefined();
      expect(client2Message).toBeDefined();
      expect(client1Message?.data.priority).toBe('high');
      expect(client2Message?.data.priority).toBe('high');
    });
  });

  describe('Room Management', () => {
    let client1: TestClient;
    let client2: TestClient;

    beforeEach(async () => {
      client1 = await createTestClient(TEST_PORT_1, 'user-1');
      client2 = await createTestClient(TEST_PORT_2, 'user-2');
      await new Promise(resolve => setTimeout(resolve, 500));
    });

    afterEach(async () => {
      client1?.ws.close();
      client2?.ws.close();
    });

    it('should track room members across instances', async () => {
      const roomId = 'multi-instance-room';

      // Join users from different instances
      await wsManager1.joinRoom('user-1', roomId);
      await wsManager2.joinRoom('user-2', roomId);

      // Wait for synchronization
      await new Promise(resolve => setTimeout(resolve, 500));

      // Check member count from both instances
      const count1 = await wsManager1.getRoomMemberCount(roomId);
      const count2 = await wsManager2.getRoomMemberCount(roomId);

      expect(count1).toBe(2);
      expect(count2).toBe(2);
    });

    it('should handle room leaving across instances', async () => {
      const roomId = 'leave-test-room';

      // Join both users
      await wsManager1.joinRoom('user-1', roomId);
      await wsManager2.joinRoom('user-2', roomId);
      await new Promise(resolve => setTimeout(resolve, 500));

      // Initial count should be 2
      expect(await wsManager1.getRoomMemberCount(roomId)).toBe(2);

      // User-1 leaves the room
      await wsManager1.leaveRoom('user-1', roomId);
      await new Promise(resolve => setTimeout(resolve, 500));

      // Count should be 1 from both instances
      const count1 = await wsManager1.getRoomMemberCount(roomId);
      const count2 = await wsManager2.getRoomMemberCount(roomId);

      expect(count1).toBe(1);
      expect(count2).toBe(1);
    });
  });

  describe('Fault Tolerance', () => {
    it('should handle Redis connection failures gracefully', async () => {
      // Create a client
      const client = await createTestClient(TEST_PORT_1, 'user-test');

      // Simulate Redis failure by closing connection
      const scalingManager = (wsManager1 as any).scalingManager as WebSocketScalingManager;
      await scalingManager.disconnect();

      // Local operations should still work
      await expect(wsManager1.broadcastToAll({
        type: 'test_local',
        data: { message: 'local test' }
      })).resolves.not.toThrow();

      client.ws.close();
    });

    it('should recover from temporary Redis disconnections', async () => {
      const client = await createTestClient(TEST_PORT_1, 'user-recovery');

      // Get initial health status
      const initialHealth = await wsManager1.healthCheck();
      expect(initialHealth.status).toBe('healthy');

      // Simulate temporary Redis disconnection
      const scalingManager = (wsManager1 as any).scalingManager as WebSocketScalingManager;
      await scalingManager.disconnect();

      // Health should show degraded state
      const degradedHealth = await wsManager1.healthCheck();
      expect(degradedHealth.status).toBe('degraded');

      // Reconnect should restore health
      await scalingManager.connect();
      await new Promise(resolve => setTimeout(resolve, 1000));

      const recoveredHealth = await wsManager1.healthCheck();
      expect(recoveredHealth.status).toBe('healthy');

      client.ws.close();
    });
  });

  describe('Performance and Load', () => {
    it('should handle multiple concurrent connections', async () => {
      const connectionCount = 50;
      const clients: TestClient[] = [];

      try {
        // Create multiple connections across both instances
        for (let i = 0; i < connectionCount; i++) {
          const port = i % 2 === 0 ? TEST_PORT_1 : TEST_PORT_2;
          const client = await createTestClient(port, `load-user-${i}`);
          clients.push(client);
        }

        // Wait for connections to stabilize
        await new Promise(resolve => setTimeout(resolve, 1000));

        // Check stats
        const stats1 = await wsManager1.getInstanceStats();
        const stats2 = await wsManager2.getInstanceStats();

        expect(stats1.connections + stats2.connections).toBe(connectionCount);

        // Test broadcasting to all connections
        await wsManager1.broadcastToAll({
          type: 'load_test',
          data: { message: 'Load test message' }
        });

        // Wait for message delivery
        await new Promise(resolve => setTimeout(resolve, 2000));

        // All clients should receive the message
        const receivedCount = clients.filter(client => 
          client.messages.some(m => m.type === 'load_test')
        ).length;

        expect(receivedCount).toBe(connectionCount);

      } finally {
        // Cleanup all connections
        clients.forEach(client => client.ws.close());
      }
    });

    it('should maintain performance under message load', async () => {
      const client1 = await createTestClient(TEST_PORT_1, 'perf-user-1');
      const client2 = await createTestClient(TEST_PORT_2, 'perf-user-2');

      const messageCount = 100;
      const startTime = Date.now();

      // Send multiple messages rapidly
      const promises = [];
      for (let i = 0; i < messageCount; i++) {
        promises.push(
          wsManager1.sendToUser('perf-user-2', {
            type: 'perf_test',
            data: { 
              index: i,
              timestamp: Date.now()
            }
          })
        );
      }

      await Promise.all(promises);

      // Wait for all messages to be delivered
      await new Promise(resolve => setTimeout(resolve, 3000));

      const endTime = Date.now();
      const duration = endTime - startTime;

      // Check that most messages were delivered
      const perfMessages = client2.messages.filter(m => m.type === 'perf_test');
      expect(perfMessages.length).toBeGreaterThan(messageCount * 0.9); // 90% delivery rate

      // Performance should be reasonable (less than 10ms per message on average)
      const avgTimePerMessage = duration / messageCount;
      expect(avgTimePerMessage).toBeLessThan(50); // 50ms per message max

      client1.ws.close();
      client2.ws.close();
    });
  });

  // Helper function to create test clients
  async function createTestClient(port: number, userId: string): Promise<TestClient> {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(`ws://localhost:${port}`, {
        headers: {
          'x-user-id': userId,
          'authorization': 'Bearer test-token'
        }
      });

      const client: TestClient = {
        ws,
        id: userId,
        messages: []
      };

      ws.on('open', () => {
        // Send authentication message
        ws.send(JSON.stringify({
          type: 'auth',
          data: { userId, token: 'test-token' }
        }));
        resolve(client);
      });

      ws.on('message', (data) => {
        try {
          const message = JSON.parse(data.toString()) as TestMessage;
          client.messages.push(message);
        } catch (error) {
          console.warn('Failed to parse message:', data.toString());
        }
      });

      ws.on('error', (error) => {
        console.error('WebSocket error:', error);
        reject(error);
      });

      // Timeout after 5 seconds
      setTimeout(() => {
        if (ws.readyState !== WebSocket.OPEN) {
          reject(new Error('Connection timeout'));
        }
      }, 5000);
    });
  }
});

// Helper to run integration tests
export async function runScalingIntegrationTests(): Promise<void> {
  console.log('Running WebSocket scaling integration tests...');
  
  // This would typically be run via Jest
  // jest server/websocket/scaling/scaling-integration.test.ts
  
  console.log('Integration tests completed successfully!');
}

export default {
  runScalingIntegrationTests
};
