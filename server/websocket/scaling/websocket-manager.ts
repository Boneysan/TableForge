// server/websocket/scaling/websocket-manager.ts
// Enhanced WebSocket Manager with Horizontal Scaling Support
import { WebSocketServer, WebSocket } from 'ws';
import { IncomingMessage } from 'http';
import { WebSocketScalingManager } from './redis-pubsub';
import { wsLogger as logger } from '../../utils/logger';
import { randomUUID } from 'crypto';

// Enhanced WebSocket interface with scaling properties
export interface ScalableWebSocket extends WebSocket {
  socketId: string;
  user?: {
    uid: string;
    email?: string;
    displayName?: string;
  };
  currentRoom?: string;
  joinedAt: Date;
  lastActivity: Date;
  instanceId: string;
}

export interface WebSocketMessage {
  type: string;
  data?: any;
  timestamp?: number;
  messageId?: string;
}

export interface RoomJoinData {
  roomId: string;
  userId: string;
  userInfo?: any;
}

export interface RoomLeaveData {
  roomId: string;
  userId: string;
}

export class ScalableWebSocketManager {
  private wss: WebSocketServer;
  private scalingManager: WebSocketScalingManager;
  private connections = new Map<string, ScalableWebSocket>();
  private userSockets = new Map<string, Set<string>>(); // userId -> socketIds
  private cleanupInterval?: NodeJS.Timeout;

  constructor(server: any) {
    this.wss = new WebSocketServer({ 
      server,
      path: '/ws',
      perMessageDeflate: {
        zlibDeflateOptions: {
          threshold: 1024,
        },
      }
    });

    this.scalingManager = new WebSocketScalingManager(this.wss);
    this.setupWebSocketServer();
    this.setupCleanupInterval();
    
    logger.info('Scalable WebSocket manager initialized');
  }

  private setupWebSocketServer(): void {
    this.wss.on('connection', (ws: ScalableWebSocket, request: IncomingMessage) => {
      this.handleConnection(ws, request);
    });

    this.wss.on('error', (error) => {
      logger.error({ error: error.message }, 'WebSocket server error');
    });

    this.wss.on('close', () => {
      logger.info('WebSocket server closed');
    });
  }

  private setupCleanupInterval(): void {
    // Clean up inactive connections every 30 seconds
    this.cleanupInterval = setInterval(() => {
      this.cleanupInactiveConnections();
    }, 30000);
  }

  private handleConnection(ws: ScalableWebSocket, request: IncomingMessage): void {
    // Initialize socket properties
    ws.socketId = randomUUID();
    ws.joinedAt = new Date();
    ws.lastActivity = new Date();
    ws.instanceId = this.scalingManager['instanceId'];

    // Store connection
    this.connections.set(ws.socketId, ws);

    logger.debug({ 
      socketId: ws.socketId,
      userAgent: request.headers['user-agent'],
      ip: request.socket.remoteAddress
    }, 'New WebSocket connection');

    // Setup event handlers
    ws.on('message', (data) => {
      this.handleMessage(ws, data);
    });

    ws.on('close', (code, reason) => {
      this.handleDisconnection(ws, code, reason);
    });

    ws.on('error', (error) => {
      logger.error({ 
        socketId: ws.socketId,
        error: error.message 
      }, 'WebSocket connection error');
    });

    ws.on('pong', () => {
      ws.lastActivity = new Date();
    });

    // Send welcome message
    this.sendMessage(ws, {
      type: 'connection_established',
      data: {
        socketId: ws.socketId,
        instanceId: ws.instanceId,
        timestamp: Date.now()
      }
    });
  }

  private async handleMessage(ws: ScalableWebSocket, data: any): Promise<void> {
    try {
      ws.lastActivity = new Date();
      
      const message: WebSocketMessage = JSON.parse(data.toString());
      message.messageId = message.messageId || randomUUID();
      message.timestamp = message.timestamp || Date.now();

      logger.debug({ 
        socketId: ws.socketId,
        messageType: message.type,
        messageId: message.messageId
      }, 'Received WebSocket message');

      await this.processMessage(ws, message);

    } catch (error) {
      logger.error({ 
        socketId: ws.socketId,
        error: error instanceof Error ? error.message : String(error)
      }, 'Error handling WebSocket message');
      
      this.sendMessage(ws, {
        type: 'error',
        data: {
          message: 'Invalid message format',
          timestamp: Date.now()
        }
      });
    }
  }

  private async processMessage(ws: ScalableWebSocket, message: WebSocketMessage): Promise<void> {
    switch (message.type) {
      case 'authenticate':
        await this.handleAuthentication(ws, message.data);
        break;
        
      case 'join_room':
        await this.handleJoinRoom(ws, message.data);
        break;
        
      case 'leave_room':
        await this.handleLeaveRoom(ws, message.data);
        break;
        
      case 'room_message':
        await this.handleRoomMessage(ws, message);
        break;
        
      case 'ping':
        this.handlePing(ws, message);
        break;
        
      case 'user_message':
        await this.handleUserMessage(ws, message);
        break;
        
      default:
        logger.warn({ 
          socketId: ws.socketId,
          messageType: message.type 
        }, 'Unknown message type');
        
        this.sendMessage(ws, {
          type: 'error',
          data: {
            message: `Unknown message type: ${message.type}`,
            timestamp: Date.now()
          }
        });
    }
  }

  private async handleAuthentication(ws: ScalableWebSocket, data: any): Promise<void> {
    try {
      // Validate authentication data
      if (!data || !data.userId) {
        throw new Error('Invalid authentication data');
      }

      ws.user = {
        uid: data.userId,
        email: data.email,
        displayName: data.displayName
      };

      // Track user socket
      if (!this.userSockets.has(data.userId)) {
        this.userSockets.set(data.userId, new Set());
      }
      this.userSockets.get(data.userId)!.add(ws.socketId);

      this.sendMessage(ws, {
        type: 'authentication_success',
        data: {
          userId: data.userId,
          socketId: ws.socketId,
          timestamp: Date.now()
        }
      });

      logger.info({ 
        socketId: ws.socketId,
        userId: data.userId 
      }, 'WebSocket authentication successful');

    } catch (error) {
      logger.error({ 
        socketId: ws.socketId,
        error: error instanceof Error ? error.message : String(error)
      }, 'WebSocket authentication failed');
      
      this.sendMessage(ws, {
        type: 'authentication_failed',
        data: {
          message: error instanceof Error ? error.message : 'Authentication failed',
          timestamp: Date.now()
        }
      });
    }
  }

  private async handleJoinRoom(ws: ScalableWebSocket, data: RoomJoinData): Promise<void> {
    try {
      if (!ws.user) {
        throw new Error('User not authenticated');
      }

      if (!data.roomId) {
        throw new Error('Room ID required');
      }

      // Leave current room if any
      if (ws.currentRoom) {
        await this.scalingManager.leaveRoom(ws.socketId, ws.currentRoom);
      }

      // Join new room
      await this.scalingManager.joinRoom(ws.socketId, data.roomId);
      ws.currentRoom = data.roomId;

      this.sendMessage(ws, {
        type: 'room_joined',
        data: {
          roomId: data.roomId,
          socketId: ws.socketId,
          timestamp: Date.now()
        }
      });

      // Notify other room members
      await this.scalingManager.broadcastToRoom(data.roomId, {
        type: 'user_joined_room',
        data: {
          userId: ws.user.uid,
          userInfo: data.userInfo || ws.user,
          socketId: ws.socketId,
          timestamp: Date.now()
        }
      }, ws.socketId);

      logger.info({ 
        socketId: ws.socketId,
        userId: ws.user.uid,
        roomId: data.roomId 
      }, 'User joined room');

    } catch (error) {
      logger.error({ 
        socketId: ws.socketId,
        roomId: data.roomId,
        error: error instanceof Error ? error.message : String(error)
      }, 'Failed to join room');
      
      this.sendMessage(ws, {
        type: 'room_join_failed',
        data: {
          roomId: data.roomId,
          message: error instanceof Error ? error.message : 'Failed to join room',
          timestamp: Date.now()
        }
      });
    }
  }

  private async handleLeaveRoom(ws: ScalableWebSocket, data: RoomLeaveData): Promise<void> {
    try {
      if (!ws.user) {
        throw new Error('User not authenticated');
      }

      const roomId = data.roomId || ws.currentRoom;
      if (!roomId) {
        throw new Error('No room to leave');
      }

      // Notify other room members before leaving
      await this.scalingManager.broadcastToRoom(roomId, {
        type: 'user_left_room',
        data: {
          userId: ws.user.uid,
          socketId: ws.socketId,
          timestamp: Date.now()
        }
      }, ws.socketId);

      // Leave room
      await this.scalingManager.leaveRoom(ws.socketId, roomId);
      
      if (ws.currentRoom === roomId) {
        ws.currentRoom = undefined;
      }

      this.sendMessage(ws, {
        type: 'room_left',
        data: {
          roomId,
          socketId: ws.socketId,
          timestamp: Date.now()
        }
      });

      logger.info({ 
        socketId: ws.socketId,
        userId: ws.user.uid,
        roomId 
      }, 'User left room');

    } catch (error) {
      logger.error({ 
        socketId: ws.socketId,
        roomId: data.roomId,
        error: error instanceof Error ? error.message : String(error)
      }, 'Failed to leave room');
      
      this.sendMessage(ws, {
        type: 'room_leave_failed',
        data: {
          roomId: data.roomId,
          message: error instanceof Error ? error.message : 'Failed to leave room',
          timestamp: Date.now()
        }
      });
    }
  }

  private async handleRoomMessage(ws: ScalableWebSocket, message: WebSocketMessage): Promise<void> {
    try {
      if (!ws.user || !ws.currentRoom) {
        throw new Error('User not authenticated or not in a room');
      }

      // Add sender information
      const roomMessage = {
        ...message,
        data: {
          ...message.data,
          senderId: ws.user.uid,
          senderSocketId: ws.socketId,
          timestamp: Date.now()
        }
      };

      // Broadcast to room (excluding sender)
      await this.scalingManager.broadcastToRoom(
        ws.currentRoom, 
        roomMessage, 
        ws.socketId
      );

      logger.debug({ 
        socketId: ws.socketId,
        userId: ws.user.uid,
        roomId: ws.currentRoom,
        messageType: message.type
      }, 'Room message broadcasted');

    } catch (error) {
      logger.error({ 
        socketId: ws.socketId,
        messageType: message.type,
        error: error instanceof Error ? error.message : String(error)
      }, 'Failed to handle room message');
      
      this.sendMessage(ws, {
        type: 'message_failed',
        data: {
          originalMessageId: message.messageId,
          message: error instanceof Error ? error.message : 'Failed to send message',
          timestamp: Date.now()
        }
      });
    }
  }

  private async handleUserMessage(ws: ScalableWebSocket, message: WebSocketMessage): Promise<void> {
    try {
      if (!ws.user) {
        throw new Error('User not authenticated');
      }

      if (!message.data?.targetUserId) {
        throw new Error('Target user ID required');
      }

      // Add sender information
      const userMessage = {
        ...message,
        data: {
          ...message.data,
          senderId: ws.user.uid,
          senderSocketId: ws.socketId,
          timestamp: Date.now()
        }
      };

      // Send to specific user across all instances
      await this.scalingManager.sendToUser(message.data.targetUserId, userMessage);

      logger.debug({ 
        socketId: ws.socketId,
        senderId: ws.user.uid,
        targetUserId: message.data.targetUserId
      }, 'User message sent');

    } catch (error) {
      logger.error({ 
        socketId: ws.socketId,
        error: error instanceof Error ? error.message : String(error)
      }, 'Failed to handle user message');
      
      this.sendMessage(ws, {
        type: 'message_failed',
        data: {
          originalMessageId: message.messageId,
          message: error instanceof Error ? error.message : 'Failed to send message',
          timestamp: Date.now()
        }
      });
    }
  }

  private handlePing(ws: ScalableWebSocket, message: WebSocketMessage): void {
    this.sendMessage(ws, {
      type: 'pong',
      data: {
        originalMessageId: message.messageId,
        timestamp: Date.now()
      }
    });
  }

  private async handleDisconnection(ws: ScalableWebSocket, code: number, reason: Buffer): Promise<void> {
    try {
      logger.info({ 
        socketId: ws.socketId,
        userId: ws.user?.uid,
        code,
        reason: reason.toString()
      }, 'WebSocket disconnection');

      // Leave current room if in one
      if (ws.currentRoom) {
        await this.scalingManager.leaveRoom(ws.socketId, ws.currentRoom);
        
        // Notify room members
        if (ws.user) {
          await this.scalingManager.broadcastToRoom(ws.currentRoom, {
            type: 'user_disconnected',
            data: {
              userId: ws.user.uid,
              socketId: ws.socketId,
              timestamp: Date.now()
            }
          }, ws.socketId);
        }
      }

      // Remove from user socket tracking
      if (ws.user) {
        const userSockets = this.userSockets.get(ws.user.uid);
        if (userSockets) {
          userSockets.delete(ws.socketId);
          if (userSockets.size === 0) {
            this.userSockets.delete(ws.user.uid);
          }
        }
      }

      // Remove from connections
      this.connections.delete(ws.socketId);

    } catch (error) {
      logger.error({ 
        socketId: ws.socketId,
        error: error instanceof Error ? error.message : String(error)
      }, 'Error handling disconnection');
    }
  }

  private sendMessage(ws: ScalableWebSocket, message: WebSocketMessage): void {
    try {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(message));
      }
    } catch (error) {
      logger.error({ 
        socketId: ws.socketId,
        messageType: message.type,
        error: error instanceof Error ? error.message : String(error)
      }, 'Failed to send message to WebSocket');
    }
  }

  private cleanupInactiveConnections(): void {
    const now = Date.now();
    const timeout = 60000; // 1 minute timeout
    let cleanedCount = 0;

    this.connections.forEach((ws, socketId) => {
      if (now - ws.lastActivity.getTime() > timeout) {
        logger.debug({ socketId }, 'Cleaning up inactive connection');
        ws.close(1001, 'Connection timeout');
        cleanedCount++;
      }
    });

    if (cleanedCount > 0) {
      logger.info({ cleanedCount }, 'Cleaned up inactive connections');
    }
  }

  // Public methods for external use
  async broadcastToAll(message: WebSocketMessage): Promise<void> {
    await this.scalingManager.broadcastToAll(message);
  }

  async broadcastToRoom(roomId: string, message: WebSocketMessage, excludeSocketId?: string): Promise<void> {
    await this.scalingManager.broadcastToRoom(roomId, message, excludeSocketId);
  }

  async sendToUser(userId: string, message: WebSocketMessage): Promise<void> {
    await this.scalingManager.sendToUser(userId, message);
  }

  async getRoomMemberCount(roomId: string): Promise<number> {
    return await this.scalingManager.getRoomMemberCount(roomId);
  }

  async getInstanceStats(): Promise<any> {
    return await this.scalingManager.getInstanceStats();
  }

  async getRoomDistribution(): Promise<any[]> {
    return await this.scalingManager.getRoomDistribution();
  }

  async healthCheck(): Promise<any> {
    return await this.scalingManager.healthCheck();
  }

  getLocalConnections(): number {
    return this.connections.size;
  }

  getLocalUserCount(): number {
    return this.userSockets.size;
  }

  async shutdown(): Promise<void> {
    logger.info('Shutting down scalable WebSocket manager');
    
    try {
      // Clear cleanup interval
      if (this.cleanupInterval) {
        clearInterval(this.cleanupInterval);
      }

      // Close all connections
      this.connections.forEach((ws) => {
        ws.close(1001, 'Server shutdown');
      });

      // Close WebSocket server
      this.wss.close();

      // Cleanup scaling manager
      await this.scalingManager.cleanup();

      logger.info('Scalable WebSocket manager shutdown complete');
    } catch (error) {
      logger.error({ 
        error: error instanceof Error ? error.message : String(error) 
      }, 'Error during WebSocket manager shutdown');
      throw error;
    }
  }
}
