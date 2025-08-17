// server/websocket/scaling/redis-pubsub.ts
// Phase 3 WebSocket Scaling Manager - Redis Pub/Sub for Horizontal Scaling
import { Redis } from 'ioredis';
import { WebSocketServer } from 'ws';
import { wsLogger as logger } from '../../utils/logger';

// Mock metrics for development (replace with actual metrics implementation)
const metrics = {
  wsRoomMembers: {
    inc: (labels: any) => console.log('Metric: wsRoomMembers.inc', labels),
    dec: (labels: any) => console.log('Metric: wsRoomMembers.dec', labels)
  },
  wsBroadcasts: {
    inc: (labels: any) => console.log('Metric: wsBroadcasts.inc', labels)
  },
  wsMessageDeliveries: {
    inc: (labels: any, value?: number) => console.log('Metric: wsMessageDeliveries.inc', labels, value)
  },
  wsRemoteRoomJoins: {
    inc: (labels: any) => console.log('Metric: wsRemoteRoomJoins.inc', labels)
  },
  wsRemoteRoomLeaves: {
    inc: (labels: any) => console.log('Metric: wsRemoteRoomLeaves.inc', labels)
  }
};

export class WebSocketScalingManager {
  private publisher: Redis;
  private subscriber: Redis;
  private instanceId: string;
  private wss: WebSocketServer;
  private roomSubscriptions = new Map<string, Set<string>>(); // roomId -> socketIds
  private heartbeatInterval?: NodeJS.Timeout | undefined;

  constructor(wss: WebSocketServer) {
    this.wss = wss;
    this.instanceId = process.env['INSTANCE_ID'] || `instance-${Date.now()}`;
    
    const redisOptions = {
      host: process.env['REDIS_HOST'] || 'localhost',
      port: parseInt(process.env['REDIS_PORT'] || '6379'),
      ...(process.env['REDIS_PASSWORD'] && { password: process.env['REDIS_PASSWORD'] }),
      db: 1, // Separate database for pub/sub
      maxRetriesPerRequest: 3,
      lazyConnect: true,
      family: 4,
      connectTimeout: 10000,
      commandTimeout: 5000
    };

    this.publisher = new Redis(redisOptions);

    this.subscriber = new Redis(redisOptions);

    this.setupEventHandlers();
    this.setupSubscriptions();
    this.setupHeartbeat();
  }

  private setupEventHandlers(): void {
    this.publisher.on('connect', () => {
      logger.info({ instanceId: this.instanceId }, 'WebSocket scaling publisher connected');
    });

    this.subscriber.on('connect', () => {
      logger.info({ instanceId: this.instanceId }, 'WebSocket scaling subscriber connected');
    });

    this.publisher.on('error', (error: Error) => {
      logger.error({ instanceId: this.instanceId, error: error.message }, 'WebSocket scaling publisher error');
    });

    this.subscriber.on('error', (error: Error) => {
      logger.error({ instanceId: this.instanceId, error: error.message }, 'WebSocket scaling subscriber error');
    });

    this.publisher.on('ready', () => {
      logger.info({ instanceId: this.instanceId }, 'WebSocket scaling publisher ready');
    });

    this.subscriber.on('ready', () => {
      logger.info({ instanceId: this.instanceId }, 'WebSocket scaling subscriber ready');
    });
  }

  private setupSubscriptions(): void {
    // Subscribe to room events
    this.subscriber.psubscribe('room:*');
    
    // Subscribe to broadcast events
    this.subscriber.subscribe('broadcast:all');
    
    // Subscribe to instance-specific messages
    this.subscriber.subscribe(`instance:${this.instanceId}`);

    this.subscriber.on('pmessage', (_pattern: string, channel: string, message: string) => {
      this.handleRoomMessage(channel, message);
    });

    this.subscriber.on('message', (channel: string, message: string) => {
      if (channel === 'broadcast:all') {
        this.handleBroadcastMessage(message);
      } else if (channel.startsWith('instance:')) {
        this.handleInstanceMessage(message);
      }
    });

    logger.info({ instanceId: this.instanceId }, 'WebSocket scaling manager initialized');
  }

  private setupHeartbeat(): void {
    // Register this instance
    this.heartbeatInterval = setInterval(async () => {
      try {
        await this.publisher.setex(
          `instance:${this.instanceId}:heartbeat`,
          30, // 30 second TTL
          JSON.stringify({
            timestamp: Date.now(),
            connections: this.wss.clients.size,
            rooms: this.roomSubscriptions.size
          })
        );
      } catch (error) {
        logger.error({ 
          instanceId: this.instanceId, 
          error: error instanceof Error ? error.message : String(error) 
        }, 'Failed to send heartbeat');
      }
    }, 10000); // Every 10 seconds

    logger.debug({ instanceId: this.instanceId }, 'WebSocket scaling heartbeat setup complete');
  }

  // Room management
  async joinRoom(socketId: string, roomId: string): Promise<void> {
    try {
      // Add socket to local room tracking
      if (!this.roomSubscriptions.has(roomId)) {
        this.roomSubscriptions.set(roomId, new Set());
      }
      this.roomSubscriptions.get(roomId)!.add(socketId);

      // Notify other instances about the join
      await this.publisher.publish(`room:${roomId}:join`, JSON.stringify({
        socketId,
        instanceId: this.instanceId,
        timestamp: Date.now()
      }));

      // Update room member count
      await this.publisher.hincrby(`room:${roomId}:members`, this.instanceId, 1);

      metrics.wsRoomMembers.inc({ room_id: roomId });
      
      logger.debug({ 
        socketId, 
        roomId, 
        instanceId: this.instanceId 
      }, 'Socket joined room');
    } catch (error) {
      logger.error({ 
        socketId, 
        roomId, 
        instanceId: this.instanceId, 
        error: error instanceof Error ? error.message : String(error) 
      }, 'Failed to join room');
      throw error;
    }
  }

  async leaveRoom(socketId: string, roomId: string): Promise<void> {
    try {
      // Remove from local tracking
      const roomSockets = this.roomSubscriptions.get(roomId);
      if (roomSockets) {
        roomSockets.delete(socketId);
        if (roomSockets.size === 0) {
          this.roomSubscriptions.delete(roomId);
        }
      }

      // Notify other instances
      await this.publisher.publish(`room:${roomId}:leave`, JSON.stringify({
        socketId,
        instanceId: this.instanceId,
        timestamp: Date.now()
      }));

      // Update room member count
      await this.publisher.hincrby(`room:${roomId}:members`, this.instanceId, -1);

      metrics.wsRoomMembers.dec({ room_id: roomId });
      
      logger.debug({ 
        socketId, 
        roomId, 
        instanceId: this.instanceId 
      }, 'Socket left room');
    } catch (error) {
      logger.error({ 
        socketId, 
        roomId, 
        instanceId: this.instanceId, 
        error: error instanceof Error ? error.message : String(error) 
      }, 'Failed to leave room');
      throw error;
    }
  }

  // Message broadcasting
  async broadcastToRoom(roomId: string, message: any, excludeSocketId?: string): Promise<void> {
    try {
      const messageData = {
        type: 'room_broadcast',
        roomId,
        message,
        excludeSocketId,
        sourceInstance: this.instanceId,
        timestamp: Date.now()
      };

      await this.publisher.publish(`room:${roomId}:broadcast`, JSON.stringify(messageData));
      
      metrics.wsBroadcasts.inc({ type: 'room', room_id: roomId });

      logger.debug({ 
        roomId, 
        instanceId: this.instanceId,
        excludeSocketId,
        messageType: message?.type || 'unknown'
      }, 'Broadcast message to room');
    } catch (error) {
      logger.error({ 
        roomId, 
        instanceId: this.instanceId, 
        error: error instanceof Error ? error.message : String(error) 
      }, 'Failed to broadcast to room');
      throw error;
    }
  }

  async broadcastToAll(message: any): Promise<void> {
    try {
      const messageData = {
        type: 'global_broadcast',
        message,
        sourceInstance: this.instanceId,
        timestamp: Date.now()
      };

      await this.publisher.publish('broadcast:all', JSON.stringify(messageData));
      
      metrics.wsBroadcasts.inc({ type: 'global' });

      logger.debug({ 
        instanceId: this.instanceId,
        messageType: message?.type || 'unknown'
      }, 'Global broadcast message');
    } catch (error) {
      logger.error({ 
        instanceId: this.instanceId, 
        error: error instanceof Error ? error.message : String(error) 
      }, 'Failed to broadcast globally');
      throw error;
    }
  }

  async sendToUser(userId: string, message: any): Promise<void> {
    try {
      // Find which instance has the user's socket
      const instances = await this.getActiveInstances();
      
      for (const instanceId of instances) {
        if (instanceId !== this.instanceId) {
          const messageData = {
            type: 'user_message',
            userId,
            message,
            sourceInstance: this.instanceId,
            timestamp: Date.now()
          };

          await this.publisher.publish(`instance:${instanceId}`, JSON.stringify(messageData));
        }
      }

      // Also check local sockets
      this.deliverToLocalUser(userId, message);

      logger.debug({ 
        userId, 
        instanceId: this.instanceId,
        messageType: message?.type || 'unknown'
      }, 'Message sent to user');
    } catch (error) {
      logger.error({ 
        userId, 
        instanceId: this.instanceId, 
        error: error instanceof Error ? error.message : String(error) 
      }, 'Failed to send message to user');
      throw error;
    }
  }

  // Message handlers
  private handleRoomMessage(channel: string, message: string): void {
    try {
      const data = JSON.parse(message);
      const channelParts = channel.split(':');
      const roomId = channelParts[1];
      const eventType = channelParts[2];

      if (!roomId) {
        logger.warn({ channel }, 'Invalid room channel format - missing roomId');
        return;
      }

      // Don't process messages from this instance
      if (data.sourceInstance === this.instanceId) {
        return;
      }

      switch (eventType) {
        case 'broadcast':
          this.deliverToLocalRoom(roomId, data.message, data.excludeSocketId);
          break;
        case 'join':
          this.handleRemoteRoomJoin(roomId, data);
          break;
        case 'leave':
          this.handleRemoteRoomLeave(roomId, data);
          break;
        default:
          logger.warn({ channel, eventType }, 'Unknown room event type');
      }
    } catch (error) {
      logger.error({ 
        channel, 
        error: error instanceof Error ? error.message : String(error) 
      }, 'Error handling room message');
    }
  }

  private handleBroadcastMessage(message: string): void {
    try {
      const data = JSON.parse(message);
      
      if (data.sourceInstance === this.instanceId) {
        return;
      }

      this.deliverToAllLocalSockets(data.message);
      
      logger.debug({ 
        sourceInstance: data.sourceInstance,
        messageType: data.message?.type || 'unknown'
      }, 'Handled broadcast message');
    } catch (error) {
      logger.error({ 
        error: error instanceof Error ? error.message : String(error) 
      }, 'Error handling broadcast message');
    }
  }

  private handleInstanceMessage(message: string): void {
    try {
      const data = JSON.parse(message);

      switch (data.type) {
        case 'user_message':
          this.deliverToLocalUser(data.userId, data.message);
          break;
        case 'admin_command':
          this.handleAdminCommand(data);
          break;
        default:
          logger.warn({ messageType: data.type }, 'Unknown instance message type');
      }
    } catch (error) {
      logger.error({ 
        error: error instanceof Error ? error.message : String(error) 
      }, 'Error handling instance message');
    }
  }

  // Local delivery methods
  private deliverToLocalRoom(roomId: string, message: any, excludeSocketId?: string): void {
    const roomSockets = this.roomSubscriptions.get(roomId);
    if (!roomSockets) return;

    let deliveredCount = 0;
    
    this.wss.clients.forEach((socket: any) => {
      if (socket.socketId && 
          roomSockets.has(socket.socketId) && 
          socket.socketId !== excludeSocketId &&
          socket.readyState === socket.OPEN) {
        
        try {
          socket.send(JSON.stringify(message));
          deliveredCount++;
        } catch (error) {
          logger.error({ 
            socketId: socket.socketId, 
            roomId,
            error: error instanceof Error ? error.message : String(error) 
          }, 'Failed to deliver message to socket');
        }
      }
    });

    metrics.wsMessageDeliveries.inc({ 
      type: 'room', 
      room_id: roomId 
    }, deliveredCount);

    logger.debug({ 
      roomId, 
      deliveredCount, 
      totalSockets: roomSockets.size 
    }, 'Delivered message to local room');
  }

  private deliverToAllLocalSockets(message: any): void {
    let deliveredCount = 0;
    
    this.wss.clients.forEach((socket: any) => {
      if (socket.readyState === socket.OPEN) {
        try {
          socket.send(JSON.stringify(message));
          deliveredCount++;
        } catch (error) {
          logger.error({ 
            socketId: socket.socketId,
            error: error instanceof Error ? error.message : String(error) 
          }, 'Failed to deliver broadcast message to socket');
        }
      }
    });

    metrics.wsMessageDeliveries.inc({ type: 'broadcast' }, deliveredCount);

    logger.debug({ deliveredCount }, 'Delivered broadcast message to all local sockets');
  }

  private deliverToLocalUser(userId: string, message: any): void {
    let deliveredCount = 0;
    
    this.wss.clients.forEach((socket: any) => {
      if (socket.user?.uid === userId && socket.readyState === socket.OPEN) {
        try {
          socket.send(JSON.stringify(message));
          deliveredCount++;
          metrics.wsMessageDeliveries.inc({ type: 'user' });
        } catch (error) {
          logger.error({ 
            userId, 
            socketId: socket.socketId,
            error: error instanceof Error ? error.message : String(error) 
          }, 'Failed to deliver user message to socket');
        }
      }
    });

    logger.debug({ userId, deliveredCount }, 'Delivered message to local user');
  }

  // Remote event handlers
  private handleRemoteRoomJoin(roomId: string, data: any): void {
    logger.debug({ 
      roomId, 
      remoteInstance: data.instanceId,
      socketId: data.socketId
    }, 'Remote socket joined room');
    
    // Update metrics for remote joins
    metrics.wsRemoteRoomJoins.inc({ room_id: roomId });
  }

  private handleRemoteRoomLeave(roomId: string, data: any): void {
    logger.debug({ 
      roomId, 
      remoteInstance: data.instanceId,
      socketId: data.socketId
    }, 'Remote socket left room');
    
    metrics.wsRemoteRoomLeaves.inc({ room_id: roomId });
  }

  private handleAdminCommand(data: any): void {
    logger.info({ command: data.command, requestId: data.requestId }, 'Handling admin command');
    
    switch (data.command) {
      case 'get_stats':
        this.sendInstanceStats(data.requestId);
        break;
      case 'close_connections':
        this.closeAllConnections();
        break;
      case 'restart_instance':
        this.restartInstance();
        break;
      default:
        logger.warn({ command: data.command }, 'Unknown admin command');
    }
  }

  // Administrative methods
  async getActiveInstances(): Promise<string[]> {
    try {
      const pattern = 'instance:*:heartbeat';
      const keys = await this.publisher.keys(pattern);
      
      return keys.map((key: string) => key.split(':')[1]).filter((id): id is string => Boolean(id));
    } catch (error) {
      logger.error({ 
        error: error instanceof Error ? error.message : String(error) 
      }, 'Failed to get active instances');
      return [];
    }
  }

  async getRoomDistribution(): Promise<RoomDistribution[]> {
    try {
      const instances = await this.getActiveInstances();
      const distribution: RoomDistribution[] = [];

      for (const instanceId of instances) {
        const heartbeat = await this.publisher.get(`instance:${instanceId}:heartbeat`);
        if (heartbeat) {
          const data = JSON.parse(heartbeat);
          distribution.push({
            instanceId,
            connections: data.connections,
            rooms: data.rooms,
            lastHeartbeat: new Date(data.timestamp)
          });
        }
      }

      return distribution;
    } catch (error) {
      logger.error({ 
        error: error instanceof Error ? error.message : String(error) 
      }, 'Failed to get room distribution');
      return [];
    }
  }

  async getRoomMemberCount(roomId: string): Promise<number> {
    try {
      const members = await this.publisher.hgetall(`room:${roomId}:members`);
      
      return Object.values(members).reduce((total: number, count: unknown) => {
        return total + parseInt(String(count || '0'));
      }, 0);
    } catch (error) {
      logger.error({ 
        roomId,
        error: error instanceof Error ? error.message : String(error) 
      }, 'Failed to get room member count');
      return 0;
    }
  }

  async getInstanceStats(): Promise<InstanceStats> {
    try {
      const [roomDistribution, totalInstances] = await Promise.all([
        this.getRoomDistribution(),
        this.getActiveInstances()
      ]);

      return {
        instanceId: this.instanceId,
        connections: this.wss.clients.size,
        rooms: this.roomSubscriptions.size,
        totalInstances: totalInstances.length,
        roomDistribution,
        memory: process.memoryUsage(),
        uptime: process.uptime(),
        timestamp: Date.now()
      };
    } catch (error) {
      logger.error({ 
        error: error instanceof Error ? error.message : String(error) 
      }, 'Failed to get instance stats');
      throw error;
    }
  }

  private async sendInstanceStats(requestId: string): Promise<void> {
    try {
      const stats = await this.getInstanceStats();
      const response = {
        requestId,
        ...stats
      };

      await this.publisher.publish('admin:stats', JSON.stringify(response));
      
      logger.debug({ requestId, instanceId: this.instanceId }, 'Instance stats sent');
    } catch (error) {
      logger.error({ 
        requestId,
        error: error instanceof Error ? error.message : String(error) 
      }, 'Failed to send instance stats');
    }
  }

  private closeAllConnections(): void {
    let closedCount = 0;
    
    this.wss.clients.forEach((socket: any) => {
      try {
        socket.close(1001, 'Server shutdown');
        closedCount++;
      } catch (error) {
        logger.error({ 
          socketId: socket.socketId,
          error: error instanceof Error ? error.message : String(error) 
        }, 'Failed to close socket');
      }
    });

    logger.info({ closedCount, instanceId: this.instanceId }, 'Closed all connections');
  }

  private restartInstance(): void {
    logger.warn({ instanceId: this.instanceId }, 'Instance restart requested');
    
    // Graceful shutdown sequence
    this.cleanup().then(() => {
      process.exit(0);
    }).catch((error) => {
      logger.error({ 
        error: error instanceof Error ? error.message : String(error) 
      }, 'Error during restart cleanup');
      process.exit(1);
    });
  }

  // Health check and monitoring
  async healthCheck(): Promise<ScalingHealthStatus> {
    try {
      const [publisherPing, subscriberPing] = await Promise.all([
        this.publisher.ping(),
        this.subscriber.ping()
      ]);

      const instances = await this.getActiveInstances();
      
      return {
        status: 'healthy',
        instanceId: this.instanceId,
        publisherConnected: publisherPing === 'PONG',
        subscriberConnected: subscriberPing === 'PONG',
        activeInstances: instances.length,
        localConnections: this.wss.clients.size,
        localRooms: this.roomSubscriptions.size
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        instanceId: this.instanceId,
        publisherConnected: false,
        subscriberConnected: false,
        activeInstances: 0,
        localConnections: this.wss.clients.size,
        localRooms: this.roomSubscriptions.size,
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  async cleanup(): Promise<void> {
    try {
      logger.info({ instanceId: this.instanceId }, 'Starting WebSocket scaling manager cleanup');

      // Clear heartbeat interval
      if (this.heartbeatInterval) {
        clearInterval(this.heartbeatInterval);
        this.heartbeatInterval = undefined;
      }

      // Remove instance heartbeat
      await this.publisher.del(`instance:${this.instanceId}:heartbeat`);
      
      // Clean up room memberships
      for (const roomId of this.roomSubscriptions.keys()) {
        await this.publisher.hdel(`room:${roomId}:members`, this.instanceId);
      }

      // Close Redis connections
      await Promise.all([
        this.publisher.quit(),
        this.subscriber.quit()
      ]);

      // Clear local state
      this.roomSubscriptions.clear();
      
      logger.info({ instanceId: this.instanceId }, 'WebSocket scaling manager cleaned up');
    } catch (error) {
      logger.error({ 
        instanceId: this.instanceId,
        error: error instanceof Error ? error.message : String(error) 
      }, 'Error during WebSocket scaling manager cleanup');
      throw error;
    }
  }
}

// Type definitions
export interface RoomDistribution {
  instanceId: string;
  connections: number;
  rooms: number;
  lastHeartbeat: Date;
}

export interface InstanceStats {
  instanceId: string;
  connections: number;
  rooms: number;
  totalInstances: number;
  roomDistribution: RoomDistribution[];
  memory: NodeJS.MemoryUsage;
  uptime: number;
  timestamp: number;
}

export interface ScalingHealthStatus {
  status: 'healthy' | 'unhealthy';
  instanceId: string;
  publisherConnected: boolean;
  subscriberConnected: boolean;
  activeInstances: number;
  localConnections: number;
  localRooms: number;
  error?: string;
}
