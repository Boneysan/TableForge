/**
 * Fixed WebSocket Connection Tests
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import express from 'express';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import { io as ioClient } from 'socket.io-client';

describe('WebSocket Connection Tests', () => {
  let httpServer: any;
  let io: SocketIOServer;
  let baseUrl: string;
  let port: number;

  beforeAll(async () => {
    console.log('🚀 [WebSocket Tests] Setting up test server...');
    
    const app = express();
    httpServer = createServer(app);
    
    io = new SocketIOServer(httpServer, {
      cors: {
        origin: "*",
        methods: ["GET", "POST"]
      }
    });

    // Simple handlers for testing
    io.on('connection', (socket) => {
      console.log('[Test Server] Client connected:', socket.id);
      
      socket.on('auth:authenticate', (data) => {
        socket.emit('auth:success', { authenticated: true, userId: data?.token });
      });
      
      socket.on('test:message', (data) => {
        socket.broadcast.emit('test:message', data);
      });

      socket.on('ping', (data) => {
        socket.emit('pong', data);
      });
    });

    // Start server
    port = await new Promise<number>((resolve) => {
      const testPort = Math.floor(Math.random() * 10000) + 30000;
      httpServer.listen(testPort, () => {
        resolve(testPort);
      });
    });

    baseUrl = `http://localhost:${port}`;
    console.log(`✅ [WebSocket Tests] Server ready on port ${port}`);
  });

  afterAll(async () => {
    console.log('🧹 [WebSocket Tests] Cleaning up...');
    if (io) {
      io.close();
    }
    if (httpServer) {
      httpServer.close();
    }
  });

  describe('Basic functionality', () => {
    it('should establish connection', async () => {
      console.log('🔌 [Test] Testing connection...');
      
      const client = ioClient(baseUrl);
      
      try {
        await new Promise((resolve, reject) => {
          client.on('connect', () => resolve(undefined));
          client.on('connect_error', reject);
          setTimeout(() => reject(new Error('Timeout')), 5000);
        });

        expect(client.connected).toBe(true);
        console.log('✅ [Test] Connection successful');
      } finally {
        client.disconnect();
      }
    });

    it('should handle authentication', async () => {
      console.log('🔐 [Test] Testing auth...');
      
      const client = ioClient(baseUrl);
      
      try {
        await new Promise<void>((resolve) => {
          client.on('connect', () => resolve());
        });

        const authResult = await new Promise((resolve) => {
          client.once('auth:success', resolve);
          client.emit('auth:authenticate', { token: 'test-token' });
        });

        expect(authResult).toEqual({ authenticated: true, userId: 'test-token' });
        console.log('✅ [Test] Auth successful');
      } finally {
        client.disconnect();
      }
    });

    it('should broadcast messages', async () => {
      console.log('📡 [Test] Testing broadcast...');
      
      const client1 = ioClient(baseUrl);
      const client2 = ioClient(baseUrl);
      
      try {
        await Promise.all([
          new Promise<void>(resolve => client1.on('connect', () => resolve())),
          new Promise<void>(resolve => client2.on('connect', () => resolve()))
        ]);

        const messageReceived = new Promise((resolve) => {
          client2.once('test:message', resolve);
        });

        client1.emit('test:message', { content: 'Hello!' });
        
        const received = await messageReceived;
        expect(received).toEqual({ content: 'Hello!' });
        console.log('✅ [Test] Broadcast successful');
      } finally {
        client1.disconnect();
        client2.disconnect();
      }
    });

    it('should handle ping-pong', async () => {
      console.log('🏓 [Test] Testing ping-pong...');
      
      const client = ioClient(baseUrl);
      
      try {
        await new Promise<void>(resolve => client.on('connect', () => resolve()));

        const pongReceived = new Promise((resolve) => {
          client.once('pong', resolve);
        });

        client.emit('ping', { timestamp: Date.now() });
        
        const pongData = await pongReceived;
        expect(pongData).toHaveProperty('timestamp');
        console.log('✅ [Test] Ping-pong successful');
      } finally {
        client.disconnect();
      }
    });
  });
});
