/**
 * Lightweight WebSocket Connection Tests
 * 
 * Tests WebSocket server functionality without database dependencies.
 * Focused on connection, authentication, and message broadcasting.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { WebSocket } from 'ws';
import express from 'express';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';

describe('WebSocket Connection Tests', () => {
  let httpServer: any;
  let io: SocketIOServer;
  let baseUrl: string;
  let port: number;

  beforeAll(async () => {
    console.log('🚀 [WebSocket Tests] Setting up lightweight test server...');
    
    // Create test server without database dependencies
    const app = express();
    httpServer = createServer(app);
    
    io = new SocketIOServer(httpServer, {
      cors: {
        origin: "*",
        methods: ["GET", "POST"]
      },
      transports: ['websocket', 'polling']
    });

    // Simple WebSocket handlers for testing
    io.on('connection', (socket) => {
      console.log('[Test Server] Client connected:', socket.id);
      
      socket.on('auth:authenticate', (data) => {
        console.log('[Test Server] Auth request from:', socket.id);
        socket.emit('auth:success', { authenticated: true, userId: data?.token });
      });
      
      socket.on('room:join', (data) => {
        if (data?.roomId) {
          socket.join(data.roomId);
          socket.emit('room:joined', { roomId: data.roomId });
          socket.to(data.roomId).emit('room:user_joined', { 
            userId: socket.id,
            roomId: data.roomId
          });
        }
      });
      
      socket.on('asset:moved', (data) => {
        socket.broadcast.emit('asset:moved', data);
      });
      
      socket.on('test:message', (data) => {
        socket.broadcast.emit('test:message', data);
      });

      socket.on('ping', (data) => {
        socket.emit('pong', data);
      });
      
      socket.on('disconnect', () => {
        console.log('[Test Server] Client disconnected:', socket.id);
      });
    });

    // Start server on random port
    port = await new Promise<number>((resolve, reject) => {
      const testPort = Math.floor(Math.random() * 10000) + 30000;
      const serverInstance = (httpServer as any).listen(testPort, () => {
        resolve(testPort);
      });
      serverInstance.on('error', reject);
    });

    baseUrl = `ws://localhost:${port}`;
    console.log(`✅ [WebSocket Tests] Test server ready on port ${port}`);
  });

  afterAll(async () => {
    console.log('🧹 [WebSocket Tests] Cleaning up test server...');
    if (io) {
      io.close();
    }
    if (httpServer) {
      (httpServer as any).close();
    }
    console.log('✅ [WebSocket Tests] Cleanup completed');
  });

  describe('Basic WebSocket functionality', () => {
    it('should establish WebSocket connection', async () => {
      console.log('🔌 [Test] Testing basic WebSocket connection...');
      
      const ws = new WebSocket(`${baseUrl}/`);
      
      try {
        await new Promise((resolve, reject) => {
          ws.on('open', resolve);
          ws.on('error', reject);
          setTimeout(() => reject(new Error('Connection timeout')), 5000);
        });

        console.log('✅ [Test] WebSocket connection established');
        expect(ws.readyState).toBe(WebSocket.OPEN);

      } finally {
        ws.close();
      }
    });

    it('should handle authentication', async () => {
      console.log('🔐 [Test] Testing WebSocket authentication...');
      
      const ws = new WebSocket(`${baseUrl}/`);
      
      try {
        await new Promise(resolve => ws.on('open', resolve));

        // Set up message listener
        const authResponse = await new Promise((resolve) => {
          ws.once('message', (data) => {
            resolve(JSON.parse(data.toString()));
          });

          // Send auth request
          ws.send(JSON.stringify({
            type: 'auth:authenticate',
            data: { token: 'test-token-123' }
          }));
        });

        console.log('📨 [Test] Auth response:', authResponse);
        expect(authResponse).toBeDefined();
        expect((authResponse as any).authenticated).toBe(true);

      } finally {
        ws.close();
      }
    });

    it('should broadcast messages between clients', async () => {
      console.log('📡 [Test] Testing message broadcasting...');
      
      const ws1 = new WebSocket(`${baseUrl}/`);
      const ws2 = new WebSocket(`${baseUrl}/`);

      try {
        // Wait for both connections
        await Promise.all([
          new Promise(resolve => ws1.on('open', resolve)),
          new Promise(resolve => ws2.on('open', resolve))
        ]);

        // Set up message listener on client 2
        const messagePromise = new Promise((resolve) => {
          ws2.once('message', (data) => {
            resolve(JSON.parse(data.toString()));
          });
        });

        // Send message from client 1
        ws1.send(JSON.stringify({
          type: 'test:message',
          data: { text: 'Hello from client 1' }
        }));

        // Wait for broadcast
        const receivedMessage = await Promise.race([
          messagePromise,
          new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Message timeout')), 2000)
          )
        ]);

        console.log('📨 [Test] Received broadcast:', receivedMessage);
        expect(receivedMessage).toBeDefined();
        expect((receivedMessage as any).data?.text).toBe('Hello from client 1');

      } finally {
        ws1.close();
        ws2.close();
      }
    });

    it('should handle room joining', async () => {
      console.log('🏠 [Test] Testing room joining functionality...');
      
      const ws = new WebSocket(`${baseUrl}/`);
      
      try {
        await new Promise(resolve => ws.on('open', resolve));

        const roomResponse = await new Promise((resolve) => {
          ws.once('message', (data) => {
            resolve(JSON.parse(data.toString()));
          });

          ws.send(JSON.stringify({
            type: 'room:join',
            data: { roomId: 'test-room-123' }
          }));
        });

        console.log('🏠 [Test] Room join response:', roomResponse);
        expect(roomResponse).toBeDefined();
        expect((roomResponse as any).roomId).toBe('test-room-123');

      } finally {
        ws.close();
      }
    });

    it('should handle connection resilience', async () => {
      console.log('🔄 [Test] Testing connection resilience...');
      
      const ws1 = new WebSocket(`${baseUrl}/`);
      
      try {
        await new Promise(resolve => ws1.on('open', resolve));
        console.log('✅ [Test] Initial connection established');

        // Force disconnect
        ws1.terminate();

        // Wait a moment
        await new Promise(resolve => setTimeout(resolve, 100));

        // Reconnect
        const ws2 = new WebSocket(`${baseUrl}/`);
        
        try {
          await new Promise((resolve, reject) => {
            ws2.on('open', resolve);
            ws2.on('error', reject);
            setTimeout(() => reject(new Error('Reconnection timeout')), 3000);
          });

          console.log('✅ [Test] Reconnection successful');
          expect(ws2.readyState).toBe(WebSocket.OPEN);

        } finally {
          ws2.close();
        }

      } catch (error) {
        console.error('❌ [Test] Connection resilience test failed:', error);
        throw error;
      }
    });

    it('should handle multiple simultaneous connections', async () => {
      console.log('🚀 [Test] Testing multiple simultaneous connections...');
      
      const connectionCount = 5;
      const connections: WebSocket[] = [];
      
      try {
        // Create multiple connections
        const connectionPromises = Array.from({ length: connectionCount }, async () => {
          const ws = new WebSocket(`${baseUrl}/`);
          connections.push(ws);
          
          await new Promise(resolve => ws.on('open', resolve));
          return ws;
        });

        await Promise.all(connectionPromises);
        
        console.log(`✅ [Test] ${connectionCount} connections established`);

        // Verify all connections are active
        const activeConnections = connections.filter(ws => ws.readyState === WebSocket.OPEN);
        expect(activeConnections.length).toBe(connectionCount);

        console.log(`📊 [Test] ${activeConnections.length}/${connectionCount} connections active`);

      } finally {
        // Clean up all connections
        connections.forEach(ws => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.close();
          }
        });
      }
    });

    it('should handle ping-pong for keepalive', async () => {
      console.log('🏓 [Test] Testing ping-pong keepalive...');
      
      const ws = new WebSocket(`${baseUrl}/`);
      
      try {
        await new Promise(resolve => ws.on('open', resolve));

        const pongResponse = await new Promise((resolve) => {
          ws.once('message', (data) => {
            resolve(JSON.parse(data.toString()));
          });

          ws.send(JSON.stringify({
            type: 'ping',
            data: { timestamp: Date.now() }
          }));
        });

        console.log('🏓 [Test] Pong response:', (pongResponse as any).type);
        expect(pongResponse).toBeDefined();

      } finally {
        ws.close();
      }
    });
  });
});
