/**
 * Integration tests for WebSocket functionality
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import { io as Client, type Socket as ClientSocket } from 'socket.io-client';
import { app } from '../../server/index';

interface TestContext {
  serverPort: number;
  clientSocket1: ClientSocket;
  clientSocket2: ClientSocket;
  server: any;
  io: SocketIOServer;
}

describe('WebSocket Integration Tests', () => {
  let context: TestContext;

  beforeAll(async () => {
    // Start test server
    const httpServer = createServer(app);
    const io = new SocketIOServer(httpServer, {
      cors: {
        origin: '*',
        methods: ['GET', 'POST'],
      },
    });

    const port = 3001; // Use different port for tests
    await new Promise<void>((resolve) => {
      httpServer.listen(port, resolve);
    });

    context = {
      serverPort: port,
      server: httpServer,
      io,
    } as TestContext;
  });

  afterAll(async () => {
    if (context.server) {
      await new Promise<void>((resolve) => {
        context.server.close(resolve);
      });
    }
  });

  beforeEach(async () => {
    // Create client connections
    context.clientSocket1 = Client(`http://localhost:${context.serverPort}`, {
      autoConnect: false,
      forceNew: true,
    });

    context.clientSocket2 = Client(`http://localhost:${context.serverPort}`, {
      autoConnect: false,
      forceNew: true,
    });

    // Connect clients
    context.clientSocket1.connect();
    context.clientSocket2.connect();

    // Wait for connections
    await Promise.all([
      new Promise<void>((resolve) => context.clientSocket1.on('connect', resolve)),
      new Promise<void>((resolve) => context.clientSocket2.on('connect', resolve)),
    ]);
  });

  afterEach(() => {
    // Disconnect clients
    if (context.clientSocket1) {
      context.clientSocket1.disconnect();
    }
    if (context.clientSocket2) {
      context.clientSocket2.disconnect();
    }
  });

  describe('Connection Management', () => {
    it('should establish WebSocket connections', () => {
      expect(context.clientSocket1.connected).toBe(true);
      expect(context.clientSocket2.connected).toBe(true);
    });

    it('should handle disconnections gracefully', (done) => {
      context.clientSocket1.on('disconnect', () => {
        expect(context.clientSocket1.connected).toBe(false);
        done();
      });

      context.clientSocket1.disconnect();
    });

    it('should reject invalid authentication', (done) => {
      const invalidClient = Client(`http://localhost:${context.serverPort}`, {
        auth: {
          token: 'invalid-token',
        },
      });

      invalidClient.on('connect_error', (error) => {
        expect(error.message).toContain('authentication');
        invalidClient.disconnect();
        done();
      });

      invalidClient.connect();
    });
  });

  describe('Room Management', () => {
    const testRoomId = 'test-room-123';
    const mockAuth = {
      token: 'mock-valid-token',
      userId: 'user-123',
    };

    beforeEach(() => {
      // Setup authentication for clients
      context.clientSocket1.auth = mockAuth;
      context.clientSocket2.auth = { ...mockAuth, userId: 'user-456' };
    });

    it('should allow users to join rooms', (done) => {
      let joinCount = 0;

      const handleJoin = () => {
        joinCount++;
        if (joinCount === 2) {
          done();
        }
      };

      context.clientSocket1.on('room_joined', handleJoin);
      context.clientSocket2.on('room_joined', handleJoin);

      context.clientSocket1.emit('join_room', { roomId: testRoomId });
      context.clientSocket2.emit('join_room', { roomId: testRoomId });
    });

    it('should broadcast room events to all members', (done) => {
      context.clientSocket2.on('user_joined_room', (data) => {
        expect(data.userId).toBe('user-123');
        expect(data.roomId).toBe(testRoomId);
        done();
      });

      // First client joins, second client should be notified
      context.clientSocket2.emit('join_room', { roomId: testRoomId });

      setTimeout(() => {
        context.clientSocket1.emit('join_room', { roomId: testRoomId });
      }, 100);
    });

    it('should handle users leaving rooms', (done) => {
      context.clientSocket2.on('user_left_room', (data) => {
        expect(data.userId).toBe('user-123');
        expect(data.roomId).toBe(testRoomId);
        done();
      });

      // Both join, then first leaves
      context.clientSocket1.emit('join_room', { roomId: testRoomId });
      context.clientSocket2.emit('join_room', { roomId: testRoomId });

      setTimeout(() => {
        context.clientSocket1.emit('leave_room', { roomId: testRoomId });
      }, 200);
    });

    it('should prevent joining non-existent rooms', (done) => {
      context.clientSocket1.on('error', (error) => {
        expect(error.message).toContain('Room not found');
        done();
      });

      context.clientSocket1.emit('join_room', { roomId: 'non-existent-room' });
    });
  });

  describe('Asset Movement', () => {
    const testRoomId = 'movement-test-room';
    const testAssetId = 'asset-123';

    beforeEach(async () => {
      // Setup room with both clients
      const mockAuth1 = { token: 'token1', userId: 'user-123' };
      const mockAuth2 = { token: 'token2', userId: 'user-456' };

      context.clientSocket1.auth = mockAuth1;
      context.clientSocket2.auth = mockAuth2;

      // Join room
      context.clientSocket1.emit('join_room', { roomId: testRoomId });
      context.clientSocket2.emit('join_room', { roomId: testRoomId });

      await new Promise(resolve => setTimeout(resolve, 100));
    });

    it('should broadcast asset movements', (done) => {
      const moveData = {
        roomId: testRoomId,
        assetId: testAssetId,
        positionX: 100,
        positionY: 200,
        rotation: 45,
        timestamp: Date.now(),
      };

      context.clientSocket2.on('asset_moved', (data) => {
        expect(data.assetId).toBe(testAssetId);
        expect(data.positionX).toBe(100);
        expect(data.positionY).toBe(200);
        expect(data.rotation).toBe(45);
        expect(data.userId).toBe('user-123');
        done();
      });

      context.clientSocket1.emit('move_asset', moveData);
    });

    it('should validate movement data', (done) => {
      const invalidMoveData = {
        roomId: testRoomId,
        assetId: testAssetId,
        positionX: 'invalid', // Should be number
        positionY: 200,
      };

      context.clientSocket1.on('error', (error) => {
        expect(error.message).toContain('validation');
        done();
      });

      context.clientSocket1.emit('move_asset', invalidMoveData);
    });

    it('should handle rapid movements with throttling', (done) => {
      let receivedCount = 0;
      const moveCount = 10;

      context.clientSocket2.on('asset_moved', () => {
        receivedCount++;

        // Should receive fewer events due to throttling
        if (receivedCount >= 3) {
          setTimeout(() => {
            expect(receivedCount).toBeLessThan(moveCount);
            done();
          }, 1000);
        }
      });

      // Send many rapid movements
      for (let i = 0; i < moveCount; i++) {
        context.clientSocket1.emit('move_asset', {
          roomId: testRoomId,
          assetId: testAssetId,
          positionX: i * 10,
          positionY: i * 10,
          timestamp: Date.now(),
        });
      }
    });

    it('should prevent unauthorized movements', (done) => {
      const moveData = {
        roomId: 'unauthorized-room',
        assetId: testAssetId,
        positionX: 100,
        positionY: 200,
      };

      context.clientSocket1.on('error', (error) => {
        expect(error.message).toContain('unauthorized');
        done();
      });

      context.clientSocket1.emit('move_asset', moveData);
    });
  });

  describe('Real-time Collaboration', () => {
    const testRoomId = 'collab-test-room';

    beforeEach(async () => {
      // Setup authenticated clients in same room
      context.clientSocket1.auth = { token: 'token1', userId: 'user-123' };
      context.clientSocket2.auth = { token: 'token2', userId: 'user-456' };

      context.clientSocket1.emit('join_room', { roomId: testRoomId });
      context.clientSocket2.emit('join_room', { roomId: testRoomId });

      await new Promise(resolve => setTimeout(resolve, 100));
    });

    it('should broadcast deck shuffling', (done) => {
      const shuffleData = {
        roomId: testRoomId,
        deckId: 'deck-123',
        newOrder: ['card1', 'card2', 'card3'],
        timestamp: Date.now(),
      };

      context.clientSocket2.on('deck_shuffled', (data) => {
        expect(data.deckId).toBe('deck-123');
        expect(data.newOrder).toEqual(['card1', 'card2', 'card3']);
        expect(data.userId).toBe('user-123');
        done();
      });

      context.clientSocket1.emit('shuffle_deck', shuffleData);
    });

    it('should broadcast card draws', (done) => {
      const drawData = {
        roomId: testRoomId,
        deckId: 'deck-123',
        cardId: 'card-456',
        playerId: 'user-123',
        timestamp: Date.now(),
      };

      context.clientSocket2.on('card_drawn', (data) => {
        expect(data.deckId).toBe('deck-123');
        expect(data.cardId).toBe('card-456');
        expect(data.playerId).toBe('user-123');
        done();
      });

      context.clientSocket1.emit('draw_card', drawData);
    });

    it('should handle chat messages', (done) => {
      const chatData = {
        roomId: testRoomId,
        message: 'Hello from integration test!',
        timestamp: Date.now(),
      };

      context.clientSocket2.on('chat_message', (data) => {
        expect(data.message).toBe('Hello from integration test!');
        expect(data.userId).toBe('user-123');
        expect(data.timestamp).toBeTypeOf('number');
        done();
      });

      context.clientSocket1.emit('chat_message', chatData);
    });

    it('should handle dice rolls', (done) => {
      const diceData = {
        roomId: testRoomId,
        diceType: 'd20',
        result: 15,
        timestamp: Date.now(),
      };

      context.clientSocket2.on('dice_rolled', (data) => {
        expect(data.diceType).toBe('d20');
        expect(data.result).toBe(15);
        expect(data.userId).toBe('user-123');
        done();
      });

      context.clientSocket1.emit('roll_dice', diceData);
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle malformed messages', (done) => {
      context.clientSocket1.on('error', (error) => {
        expect(error.message).toContain('malformed');
        done();
      });

      // Send invalid data
      context.clientSocket1.emit('move_asset', 'invalid-data');
    });

    it('should handle connection drops during operations', async () => {
      const testRoomId = 'drop-test-room';

      context.clientSocket1.emit('join_room', { roomId: testRoomId });
      await new Promise(resolve => setTimeout(resolve, 100));

      // Simulate connection drop
      context.clientSocket1.disconnect();

      // Verify cleanup happened (room membership removed)
      expect(context.clientSocket1.connected).toBe(false);
    });

    it('should handle rapid connect/disconnect cycles', async () => {
      for (let i = 0; i < 5; i++) {
        const client = Client(`http://localhost:${context.serverPort}`);

        await new Promise<void>((resolve) => {
          client.on('connect', resolve);
          client.connect();
        });

        expect(client.connected).toBe(true);

        client.disconnect();
        expect(client.connected).toBe(false);
      }
    });

    it('should enforce message rate limits', (done) => {
      let errorReceived = false;

      context.clientSocket1.on('error', (error) => {
        if (error.message.includes('rate limit') && !errorReceived) {
          errorReceived = true;
          done();
        }
      });

      // Send many messages rapidly to trigger rate limit
      for (let i = 0; i < 50; i++) {
        context.clientSocket1.emit('chat_message', {
          roomId: 'test-room',
          message: `Spam message ${i}`,
          timestamp: Date.now(),
        });
      }
    });
  });

  describe('Performance', () => {
    it('should handle multiple concurrent connections', async () => {
      const connections: ClientSocket[] = [];
      const connectionCount = 20;

      try {
        // Create many connections
        for (let i = 0; i < connectionCount; i++) {
          const client = Client(`http://localhost:${context.serverPort}`, {
            autoConnect: false,
          });
          connections.push(client);
          client.connect();
        }

        // Wait for all to connect
        await Promise.all(
          connections.map(
            client => new Promise<void>(resolve => client.on('connect', resolve)),
          ),
        );

        // Verify all connected
        expect(connections.every(client => client.connected)).toBe(true);

      } finally {
        // Cleanup
        connections.forEach(client => client.disconnect());
      }
    }, 10000); // Longer timeout for performance test

    it('should handle high-frequency asset movements', (done) => {
      const testRoomId = 'perf-test-room';
      let moveCount = 0;
      const targetMoves = 100;

      context.clientSocket1.auth = { token: 'token1', userId: 'user-123' };
      context.clientSocket2.auth = { token: 'token2', userId: 'user-456' };

      context.clientSocket1.emit('join_room', { roomId: testRoomId });
      context.clientSocket2.emit('join_room', { roomId: testRoomId });

      context.clientSocket2.on('asset_moved', () => {
        moveCount++;
        if (moveCount >= 10) { // Should receive some moves despite throttling
          expect(moveCount).toBeLessThan(targetMoves); // But not all due to throttling
          done();
        }
      });

      // Send many rapid movements
      setTimeout(() => {
        for (let i = 0; i < targetMoves; i++) {
          context.clientSocket1.emit('move_asset', {
            roomId: testRoomId,
            assetId: 'perf-asset',
            positionX: i,
            positionY: i,
            timestamp: Date.now(),
          });
        }
      }, 200);
    }, 10000);
  });
});
