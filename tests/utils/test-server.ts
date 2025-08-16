import express from 'express';
import { createServer } from 'http';
import type { Server } from 'http';
import { Server as SocketIOServer } from 'socket.io';

export interface TestServer {
  port: number;
  server: Server;
  io: SocketIOServer;
  close: () => Promise<void>;
}

/**
 * Creates a test server instance for WebSocket integration testing
 */
export async function createTestServer(): Promise<TestServer> {
  const app = express();
  const httpServer = createServer(app);
  
  // Initialize Socket.IO
  const io = new SocketIOServer(httpServer, {
    cors: {
      origin: "*",
      methods: ["GET", "POST"]
    },
    transports: ['websocket', 'polling']
  });

  // Configure WebSocket handlers
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
    
    socket.on('card:draw', (data) => {
      socket.emit('card:drawn', { 
        ...data,
        cards: [{ id: 'test-card-' + Date.now(), name: 'Test Card' }]
      });
    });
    
    socket.on('dice:rolled', (data) => {
      socket.broadcast.emit('dice:rolled', data);
    });
    
    socket.on('test:broadcast', (data) => {
      socket.broadcast.emit('test:broadcast', data);
    });

    socket.on('ping', (data) => {
      socket.emit('pong', data);
    });
    
    socket.on('disconnect', () => {
      console.log('[Test Server] Client disconnected:', socket.id);
    });
  });

  // Find available port
  const port = await new Promise<number>((resolve, reject) => {
    const testPort = Math.floor(Math.random() * 10000) + 30000;
    const serverInstance = (httpServer as any).listen(testPort, () => {
      resolve(testPort);
    });
    serverInstance.on('error', reject);
  });

  console.log(`[Test Server] Started on port ${port}`);

  return {
    port,
    server: httpServer,
    io,
    close: async () => {
      return new Promise<void>((resolve) => {
        io.close();
        (httpServer as any).close(() => {
          console.log(`[Test Server] Closed port ${port}`);
          resolve();
        });
      });
    }
  };
}
