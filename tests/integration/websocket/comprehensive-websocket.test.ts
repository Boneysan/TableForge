/**
 * WebSocket Integration Tests - Phase 2 Week 2
 * Comprehensive WebSocket integration testing for real-time collaboration
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import WebSocket from 'ws';
import { Server } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import { createServer } from 'http';
import { AddressInfo } from 'net';
import { initTestDatabase, cleanupTestDatabase, truncateAllTables, seedTestData } from '../../config/test-database';

// Mock WebSocket server for testing
let httpServer: Server;
let io: SocketIOServer;
let serverPort: number;

// Test helper functions
function createWebSocketConnection(port: number): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://localhost:${port}`);
    
    ws.on('open', () => resolve(ws));
    ws.on('error', reject);
    
    // Timeout after 5 seconds
    setTimeout(() => {
      reject(new Error('WebSocket connection timeout'));
    }, 5000);
  });
}

function waitForMessage(ws: WebSocket, timeout = 5000): Promise<any> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error('Message timeout'));
    }, timeout);

    ws.once('message', (data) => {
      clearTimeout(timer);
      try {
        const message = JSON.parse(data.toString());
        resolve(message);
      } catch (error) {
        resolve(data.toString());
      }
    });
  });
}

function sendMessage(ws: WebSocket, message: any): void {
  ws.send(JSON.stringify(message));
}

describe('WebSocket Integration Tests', () => {
  beforeAll(async () => {
    // Initialize test database
    await initTestDatabase();

    // Create HTTP server for WebSocket testing
    httpServer = createServer();
    io = new SocketIOServer(httpServer, {
      cors: {
        origin: "*",
        methods: ["GET", "POST"]
      }
    });

    // Setup WebSocket event handlers for testing
    io.on('connection', (socket) => {
      console.log(`Client connected: ${socket.id}`);

      // Authentication handler
      socket.on('auth:authenticate', (data) => {
        const { token } = data;
        if (token === 'valid-token') {
          socket.emit('auth:success', { 
            userId: 'test-user-1',
            message: 'Authentication successful'
          });
          (socket as any).userId = 'test-user-1';
        } else {
          socket.emit('auth:error', { 
            error: 'Invalid token',
            message: 'Authentication failed'
          });
        }
      });

      // Room management
      socket.on('room:join', (data) => {
        const { roomId } = data;
        if (!(socket as any).userId) {
          socket.emit('room:error', { error: 'Not authenticated' });
          return;
        }

        socket.join(roomId);
        (socket as any).roomId = roomId;
        
        socket.emit('room:joined', { 
          roomId, 
          message: `Joined room ${roomId}` 
        });
        
        // Notify other room members
        socket.to(roomId).emit('room:user-joined', {
          userId: (socket as any).userId,
          roomId
        });
      });

      socket.on('room:leave', (data) => {
        const { roomId } = data;
        socket.leave(roomId);
        
        socket.emit('room:left', { roomId });
        socket.to(roomId).emit('room:user-left', {
          userId: (socket as any).userId,
          roomId
        });
      });

      // Asset movement
      socket.on('asset:moved', (data) => {
        const roomId = (socket as any).roomId;
        if (!roomId) {
          socket.emit('error', { message: 'Not in a room' });
          return;
        }

        const { assetId, position, playerId } = data;
        const moveEvent = {
          type: 'asset:moved',
          data: {
            assetId,
            position,
            playerId,
            timestamp: Date.now()
          }
        };

        // Broadcast to all room members
        io.to(roomId).emit('asset:moved', moveEvent.data);
      });

      // Card operations
      socket.on('card:draw', (data) => {
        const { deckId, count = 1 } = data;
        const drawnCards = Array.from({ length: count }, (_, i) => ({
          id: `card-${Date.now()}-${i}`,
          deckId,
          playerId: (socket as any).userId
        }));

        socket.emit('card:drawn', {
          cards: drawnCards,
          deckId,
          remainingCards: Math.max(0, 52 - count)
        });
      });

      // Chat functionality
      socket.on('chat:message', (data) => {
        const roomId = (socket as any).roomId;
        if (!roomId) return;

        const { message } = data;
        const chatMessage = {
          id: `msg-${Date.now()}`,
          userId: (socket as any).userId,
          message,
          timestamp: Date.now(),
          roomId
        };

        io.to(roomId).emit('chat:message', chatMessage);
      });

      // Disconnect handler
      socket.on('disconnect', () => {
        console.log(`Client disconnected: ${socket.id}`);
        const roomId = (socket as any).roomId;
        if (roomId) {
          socket.to(roomId).emit('room:user-left', {
            userId: (socket as any).userId,
            roomId
          });
        }
      });
    });

    // Start server on random port
    await new Promise<void>((resolve, reject) => {
      (httpServer as any).listen(0, () => {
        const address = (httpServer as any).address();
        if (address && typeof address !== 'string') {
          serverPort = address.port;
          console.log(`Test WebSocket server started on port ${serverPort}`);
          resolve();
        } else {
          reject(new Error('Failed to get server port'));
        }
      });
    });
  });

  afterAll(async () => {
    // Cleanup
    if (io) {
      io.close();
    }
    if (httpServer) {
      await new Promise<void>((resolve) => {
        (httpServer as any).close(() => resolve());
      });
    }
    
    await cleanupTestDatabase();
  });

  beforeEach(async () => {
    await truncateAllTables();
    await seedTestData();
  });

  afterEach(async () => {
    await truncateAllTables();
  });

  describe('WebSocket Connection Management', () => {
    it('should establish WebSocket connection successfully', async () => {
      const ws = await createWebSocketConnection(serverPort);
      
      expect(ws.readyState).toBe(WebSocket.OPEN);
      
      ws.close();
    });

    it('should handle multiple concurrent connections', async () => {
      const connections = await Promise.all([
        createWebSocketConnection(serverPort),
        createWebSocketConnection(serverPort),
        createWebSocketConnection(serverPort)
      ]);

      connections.forEach(ws => {
        expect(ws.readyState).toBe(WebSocket.OPEN);
      });

      // Cleanup
      connections.forEach(ws => ws.close());
    });

    it('should handle connection drops gracefully', async () => {
      const ws = await createWebSocketConnection(serverPort);
      
      // Simulate connection drop
      ws.terminate();
      
      expect(ws.readyState).toBe(WebSocket.CLOSED);
    });
  });

  describe('Authentication Flow', () => {
    it('should authenticate user with valid token', async () => {
      const ws = await createWebSocketConnection(serverPort);

      sendMessage(ws, {
        type: 'auth:authenticate',
        data: { token: 'valid-token' }
      });

      const response = await waitForMessage(ws);
      
      expect(response).toMatchObject({
        userId: 'test-user-1',
        message: 'Authentication successful'
      });

      ws.close();
    });

    it('should reject authentication with invalid token', async () => {
      const ws = await createWebSocketConnection(serverPort);

      sendMessage(ws, {
        type: 'auth:authenticate', 
        data: { token: 'invalid-token' }
      });

      const response = await waitForMessage(ws);
      
      expect(response).toMatchObject({
        error: 'Invalid token',
        message: 'Authentication failed'
      });

      ws.close();
    });

    it('should require authentication for protected operations', async () => {
      const ws = await createWebSocketConnection(serverPort);

      // Try to join room without authentication
      sendMessage(ws, {
        type: 'room:join',
        data: { roomId: 'test-room' }
      });

      const response = await waitForMessage(ws);
      
      expect(response).toMatchObject({
        error: 'Not authenticated'
      });

      ws.close();
    });
  });

  describe('Room Management', () => {
    it('should allow authenticated user to join room', async () => {
      const ws = await createWebSocketConnection(serverPort);

      // Authenticate first
      sendMessage(ws, {
        type: 'auth:authenticate',
        data: { token: 'valid-token' }
      });
      await waitForMessage(ws); // Wait for auth response

      // Join room
      sendMessage(ws, {
        type: 'room:join',
        data: { roomId: 'test-room-1' }
      });

      const joinResponse = await waitForMessage(ws);
      
      expect(joinResponse).toMatchObject({
        roomId: 'test-room-1',
        message: 'Joined room test-room-1'
      });

      ws.close();
    });

    it('should notify other users when someone joins room', async () => {
      const ws1 = await createWebSocketConnection(serverPort);
      const ws2 = await createWebSocketConnection(serverPort);

      // Authenticate both users
      sendMessage(ws1, {
        type: 'auth:authenticate',
        data: { token: 'valid-token' }
      });
      await waitForMessage(ws1);

      sendMessage(ws2, {
        type: 'auth:authenticate',
        data: { token: 'valid-token' }
      });
      await waitForMessage(ws2);

      // User 1 joins room first
      sendMessage(ws1, {
        type: 'room:join',
        data: { roomId: 'test-room-1' }
      });
      await waitForMessage(ws1);

      // User 2 joins same room - User 1 should be notified
      sendMessage(ws2, {
        type: 'room:join',
        data: { roomId: 'test-room-1' }
      });
      
      await waitForMessage(ws2); // Join response for user 2
      
      // User 1 should receive notification
      const notification = await waitForMessage(ws1);
      expect(notification).toMatchObject({
        userId: 'test-user-1',
        roomId: 'test-room-1'
      });

      ws1.close();
      ws2.close();
    });

    it('should handle room leave functionality', async () => {
      const ws = await createWebSocketConnection(serverPort);

      // Authenticate and join room
      sendMessage(ws, {
        type: 'auth:authenticate',
        data: { token: 'valid-token' }
      });
      await waitForMessage(ws);

      sendMessage(ws, {
        type: 'room:join',
        data: { roomId: 'test-room-1' }
      });
      await waitForMessage(ws);

      // Leave room
      sendMessage(ws, {
        type: 'room:leave',
        data: { roomId: 'test-room-1' }
      });

      const leaveResponse = await waitForMessage(ws);
      expect(leaveResponse).toMatchObject({
        roomId: 'test-room-1'
      });

      ws.close();
    });
  });

  describe('Real-time Asset Management', () => {
    it('should synchronize asset movements between clients', async () => {
      const ws1 = await createWebSocketConnection(serverPort);
      const ws2 = await createWebSocketConnection(serverPort);

      // Setup both clients in same room
      for (const ws of [ws1, ws2]) {
        sendMessage(ws, {
          type: 'auth:authenticate',
          data: { token: 'valid-token' }
        });
        await waitForMessage(ws);

        sendMessage(ws, {
          type: 'room:join',
          data: { roomId: 'test-room-1' }
        });
        await waitForMessage(ws);
      }

      // Clear join notifications
      await waitForMessage(ws1); // User 2 joined notification

      // User 1 moves an asset
      const moveData = {
        assetId: 'test-asset-123',
        position: { x: 100, y: 200 },
        playerId: 'test-user-1'
      };

      sendMessage(ws1, {
        type: 'asset:moved',
        data: moveData
      });

      // Both users should receive the move event
      const ws1Response = await waitForMessage(ws1);
      const ws2Response = await waitForMessage(ws2);

      expect(ws1Response).toMatchObject({
        assetId: 'test-asset-123',
        position: { x: 100, y: 200 },
        playerId: 'test-user-1',
        timestamp: expect.any(Number)
      });

      expect(ws2Response).toEqual(ws1Response);

      ws1.close();
      ws2.close();
    });

    it('should handle rapid asset movement updates', async () => {
      const ws1 = await createWebSocketConnection(serverPort);
      const ws2 = await createWebSocketConnection(serverPort);

      // Setup clients
      for (const ws of [ws1, ws2]) {
        sendMessage(ws, {
          type: 'auth:authenticate',
          data: { token: 'valid-token' }
        });
        await waitForMessage(ws);

        sendMessage(ws, {
          type: 'room:join',
          data: { roomId: 'test-room-1' }
        });
        await waitForMessage(ws);
      }

      await waitForMessage(ws1); // Clear join notification

      // Send multiple rapid movements
      const movements = [
        { x: 10, y: 10 },
        { x: 20, y: 20 },
        { x: 30, y: 30 },
        { x: 40, y: 40 },
        { x: 50, y: 50 }
      ];

      movements.forEach((position) => {
        sendMessage(ws1, {
          type: 'asset:moved',
          data: {
            assetId: 'rapid-asset',
            position,
            playerId: 'test-user-1'
          }
        });
      });

      // Verify all movements are received
      const receivedMovements = [];
      for (let i = 0; i < movements.length; i++) {
        const response = await waitForMessage(ws2);
        receivedMovements.push(response.position);
      }

      expect(receivedMovements).toEqual(movements);

      ws1.close();
      ws2.close();
    });
  });

  describe('Card Game Operations', () => {
    it('should handle card drawing operations', async () => {
      const ws = await createWebSocketConnection(serverPort);

      // Setup authenticated client
      sendMessage(ws, {
        type: 'auth:authenticate',
        data: { token: 'valid-token' }
      });
      await waitForMessage(ws);

      sendMessage(ws, {
        type: 'room:join',
        data: { roomId: 'test-room-1' }
      });
      await waitForMessage(ws);

      // Draw cards
      sendMessage(ws, {
        type: 'card:draw',
        data: { deckId: 'test-deck', count: 3 }
      });

      const drawResponse = await waitForMessage(ws);
      
      expect(drawResponse).toMatchObject({
        cards: expect.arrayContaining([
          expect.objectContaining({
            id: expect.any(String),
            deckId: 'test-deck',
            playerId: 'test-user-1'
          })
        ]),
        deckId: 'test-deck',
        remainingCards: expect.any(Number)
      });

      expect(drawResponse.cards).toHaveLength(3);

      ws.close();
    });

    it('should handle concurrent card operations', async () => {
      const ws1 = await createWebSocketConnection(serverPort);
      const ws2 = await createWebSocketConnection(serverPort);

      // Setup both clients
      for (const ws of [ws1, ws2]) {
        sendMessage(ws, {
          type: 'auth:authenticate',
          data: { token: 'valid-token' }
        });
        await waitForMessage(ws);

        sendMessage(ws, {
          type: 'room:join',
          data: { roomId: 'test-room-1' }
        });
        await waitForMessage(ws);
      }

      await waitForMessage(ws1); // Clear join notification

      // Both users draw cards simultaneously
      sendMessage(ws1, {
        type: 'card:draw',
        data: { deckId: 'test-deck', count: 2 }
      });

      sendMessage(ws2, {
        type: 'card:draw',
        data: { deckId: 'test-deck', count: 2 }
      });

      const draw1Response = await waitForMessage(ws1);
      const draw2Response = await waitForMessage(ws2);

      // Both operations should succeed
      expect(draw1Response.cards).toHaveLength(2);
      expect(draw2Response.cards).toHaveLength(2);

      // Cards should be different (basic check)
      const allCardIds = [
        ...draw1Response.cards.map((c: any) => c.id),
        ...draw2Response.cards.map((c: any) => c.id)
      ];
      const uniqueCardIds = new Set(allCardIds);
      expect(uniqueCardIds.size).toBe(4); // All cards should be unique

      ws1.close();
      ws2.close();
    });
  });

  describe('Chat System Integration', () => {
    it('should broadcast chat messages to room members', async () => {
      const ws1 = await createWebSocketConnection(serverPort);
      const ws2 = await createWebSocketConnection(serverPort);

      // Setup both clients in same room
      for (const ws of [ws1, ws2]) {
        sendMessage(ws, {
          type: 'auth:authenticate',
          data: { token: 'valid-token' }
        });
        await waitForMessage(ws);

        sendMessage(ws, {
          type: 'room:join',
          data: { roomId: 'test-room-1' }
        });
        await waitForMessage(ws);
      }

      await waitForMessage(ws1); // Clear join notification

      // Send chat message
      const testMessage = 'Hello from integration test!';
      sendMessage(ws1, {
        type: 'chat:message',
        data: { message: testMessage }
      });

      // Both users should receive the chat message
      const ws1ChatMessage = await waitForMessage(ws1);
      const ws2ChatMessage = await waitForMessage(ws2);

      expect(ws1ChatMessage).toMatchObject({
        id: expect.any(String),
        userId: 'test-user-1',
        message: testMessage,
        timestamp: expect.any(Number),
        roomId: 'test-room-1'
      });

      expect(ws2ChatMessage).toEqual(ws1ChatMessage);

      ws1.close();
      ws2.close();
    });

    it('should handle message ordering correctly', async () => {
      const ws1 = await createWebSocketConnection(serverPort);
      const ws2 = await createWebSocketConnection(serverPort);

      // Setup clients
      for (const ws of [ws1, ws2]) {
        sendMessage(ws, {
          type: 'auth:authenticate',
          data: { token: 'valid-token' }
        });
        await waitForMessage(ws);

        sendMessage(ws, {
          type: 'room:join',
          data: { roomId: 'test-room-1' }
        });
        await waitForMessage(ws);
      }

      await waitForMessage(ws1); // Clear join notification

      // Send multiple messages in sequence
      const messages = ['Message 1', 'Message 2', 'Message 3'];
      
      messages.forEach(message => {
        sendMessage(ws1, {
          type: 'chat:message',
          data: { message }
        });
      });

      // Verify message order
      const receivedMessages = [];
      for (let i = 0; i < messages.length; i++) {
        const chatMessage = await waitForMessage(ws2);
        receivedMessages.push(chatMessage.message);
      }

      expect(receivedMessages).toEqual(messages);

      ws1.close();
      ws2.close();
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle malformed messages gracefully', async () => {
      const ws = await createWebSocketConnection(serverPort);

      // Send malformed JSON
      ws.send('{ invalid json }');

      // Connection should remain open
      expect(ws.readyState).toBe(WebSocket.OPEN);

      ws.close();
    });

    it('should handle operations on non-existent rooms', async () => {
      const ws = await createWebSocketConnection(serverPort);

      sendMessage(ws, {
        type: 'auth:authenticate',
        data: { token: 'valid-token' }
      });
      await waitForMessage(ws);

      // Try to perform room operation without joining
      sendMessage(ws, {
        type: 'asset:moved',
        data: { assetId: 'test', position: { x: 0, y: 0 } }
      });

      const errorResponse = await waitForMessage(ws);
      expect(errorResponse).toMatchObject({
        message: 'Not in a room'
      });

      ws.close();
    });

    it('should handle network disconnections properly', async () => {
      const ws1 = await createWebSocketConnection(serverPort);
      const ws2 = await createWebSocketConnection(serverPort);

      // Setup both clients
      for (const ws of [ws1, ws2]) {
        sendMessage(ws, {
          type: 'auth:authenticate',
          data: { token: 'valid-token' }
        });
        await waitForMessage(ws);

        sendMessage(ws, {
          type: 'room:join',
          data: { roomId: 'test-room-1' }
        });
        await waitForMessage(ws);
      }

      await waitForMessage(ws1); // Clear join notification

      // Simulate network disconnection
      ws1.terminate();

      // Wait for disconnect event to propagate
      await new Promise(resolve => setTimeout(resolve, 100));

      // ws2 should receive user left notification
      const leaveNotification = await waitForMessage(ws2);
      expect(leaveNotification).toMatchObject({
        userId: 'test-user-1',
        roomId: 'test-room-1'
      });

      ws2.close();
    });
  });

  describe('Performance and Load Testing', () => {
    it('should handle high-frequency message bursts', async () => {
      const ws = await createWebSocketConnection(serverPort);

      sendMessage(ws, {
        type: 'auth:authenticate',
        data: { token: 'valid-token' }
      });
      await waitForMessage(ws);

      sendMessage(ws, {
        type: 'room:join',
        data: { roomId: 'test-room-1' }
      });
      await waitForMessage(ws);

      // Send 50 rapid messages
      const messageCount = 50;
      const startTime = Date.now();

      for (let i = 0; i < messageCount; i++) {
        sendMessage(ws, {
          type: 'chat:message',
          data: { message: `Burst message ${i}` }
        });
      }

      // Verify all messages are received
      const receivedMessages = [];
      for (let i = 0; i < messageCount; i++) {
        const message = await waitForMessage(ws);
        receivedMessages.push(message);
      }

      const endTime = Date.now();
      const totalTime = endTime - startTime;

      expect(receivedMessages).toHaveLength(messageCount);
      console.log(`🚀 Processed ${messageCount} messages in ${totalTime}ms`);

      // Should handle burst efficiently
      expect(totalTime).toBeLessThan(5000); // 5 seconds for 50 messages

      ws.close();
    });
  });
});
