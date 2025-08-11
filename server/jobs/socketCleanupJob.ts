import { logger } from '../utils/logger';
import { WebSocketServer, WebSocket } from 'ws';

/**
 * Socket Cleanup Job - Handles inactive WebSocket connection cleanup
 * 
 * Features:
 * - Closes inactive/stale WebSocket connections
 * - Removes disconnected clients from room tracking
 * - Monitors connection health and activity
 * - Prevents resource leaks from abandoned connections
 */
export class SocketCleanupJob {
  private wss: WebSocketServer;
  private connectionTracking: Map<WebSocket, {
    lastActivity: number;
    roomId?: string;
    userId?: string;
    clientId: string;
  }>;
  
  // TTL configurations (in milliseconds)
  private static readonly INACTIVE_CONNECTION_TTL = 30 * 60 * 1000; // 30 minutes
  private static readonly STALE_CONNECTION_TTL = 2 * 60 * 60 * 1000; // 2 hours
  private static readonly PING_INTERVAL = 30 * 1000; // 30 seconds
  
  constructor(wss: WebSocketServer) {
    this.wss = wss;
    this.connectionTracking = new Map();
    this.setupConnectionTracking();
    this.startPingInterval();
  }

  /**
   * Main socket cleanup execution method
   */
  async execute(): Promise<{
    inactiveConnections: number;
    staleConnections: number;
    totalClosed: number;
    activeConnections: number;
    errors: string[];
  }> {
    const correlationId = `socket_cleanup_${Date.now()}`;
    const startTime = Date.now();
    
    logger.info('🔌 [Socket Cleanup] Starting socket cleanup', {
      correlationId,
      timestamp: new Date().toISOString(),
      totalConnections: this.connectionTracking.size
    } as any);

    const results = {
      inactiveConnections: 0,
      staleConnections: 0,
      totalClosed: 0,
      activeConnections: 0,
      errors: [] as string[]
    };

    try {
      const now = Date.now();
      const inactiveThreshold = now - SocketCleanupJob.INACTIVE_CONNECTION_TTL;
      const staleThreshold = now - SocketCleanupJob.STALE_CONNECTION_TTL;

      const connectionsToClose: Array<{
        socket: WebSocket;
        reason: 'inactive' | 'stale';
        info: any;
      }> = [];

      // Analyze all tracked connections
      for (const [socket, info] of this.connectionTracking.entries()) {
        if (socket.readyState !== WebSocket.OPEN) {
          // Connection already closed, remove from tracking
          this.connectionTracking.delete(socket);
          continue;
        }

        if (info.lastActivity < staleThreshold) {
          connectionsToClose.push({
            socket,
            reason: 'stale',
            info
          });
          results.staleConnections++;
        } else if (info.lastActivity < inactiveThreshold) {
          connectionsToClose.push({
            socket,
            reason: 'inactive',
            info
          });
          results.inactiveConnections++;
        }
      }

      // Close identified connections
      for (const { socket, reason, info } of connectionsToClose) {
        try {
          await this.closeConnection(socket, reason, info, correlationId);
          results.totalClosed++;
        } catch (error) {
          results.errors.push(`Failed to close ${reason} connection: ${(error as Error).message}`);
        }
      }

      results.activeConnections = this.connectionTracking.size;

      const duration = Date.now() - startTime;
      logger.info('✅ [Socket Cleanup] Socket cleanup completed successfully', {
        correlationId,
        duration,
        results
      } as any);

    } catch (error) {
      const errorMessage = (error as Error).message;
      results.errors.push(errorMessage);
      
      logger.error('❌ [Socket Cleanup] Socket cleanup failed', {
        correlationId,
        error: errorMessage,
        duration: Date.now() - startTime
      } as any);
    }

    return results;
  }

  /**
   * Setup connection tracking for new WebSocket connections
   */
  private setupConnectionTracking(): void {
    this.wss.on('connection', (socket: WebSocket, request) => {
      const clientId = this.generateClientId();
      
      this.connectionTracking.set(socket, {
        lastActivity: Date.now(),
        clientId
      });

      logger.info('🔌 [Socket Cleanup] New connection tracked', {
        clientId,
        totalConnections: this.connectionTracking.size
      } as any);

      // Track activity on this socket
      socket.on('message', () => {
        this.updateLastActivity(socket);
      });

      socket.on('pong', () => {
        this.updateLastActivity(socket);
      });

      socket.on('close', () => {
        this.connectionTracking.delete(socket);
        logger.info('🔌 [Socket Cleanup] Connection removed from tracking', {
          clientId,
          totalConnections: this.connectionTracking.size
        } as any);
      });

      socket.on('error', (error) => {
        logger.error('🔌 [Socket Cleanup] Connection error', {
          clientId,
          error: error.message
        } as any);
        this.connectionTracking.delete(socket);
      });
    });
  }

  /**
   * Start ping interval to detect dead connections
   */
  private startPingInterval(): void {
    setInterval(() => {
      this.pingAllConnections();
    }, SocketCleanupJob.PING_INTERVAL);
  }

  /**
   * Ping all connections to check their health
   */
  private pingAllConnections(): void {
    const now = Date.now();
    let pingsSent = 0;
    
    for (const [socket, info] of this.connectionTracking.entries()) {
      if (socket.readyState === WebSocket.OPEN) {
        try {
          socket.ping();
          pingsSent++;
        } catch (error) {
          logger.error('🔌 [Socket Cleanup] Failed to ping connection', {
            clientId: info.clientId,
            error: (error as Error).message
          } as any);
          
          // Remove failed connections
          this.connectionTracking.delete(socket);
        }
      } else {
        // Remove closed connections
        this.connectionTracking.delete(socket);
      }
    }

    if (pingsSent > 0) {
      logger.debug('🔌 [Socket Cleanup] Sent pings to connections', {
        pingsSent,
        totalTracked: this.connectionTracking.size
      } as any);
    }
  }

  /**
   * Update last activity timestamp for a connection
   */
  public updateLastActivity(socket: WebSocket, roomId?: string, userId?: string): void {
    const info = this.connectionTracking.get(socket);
    if (info) {
      info.lastActivity = Date.now();
      if (roomId) info.roomId = roomId;
      if (userId) info.userId = userId;
    }
  }

  /**
   * Close a specific connection with cleanup
   */
  private async closeConnection(
    socket: WebSocket, 
    reason: 'inactive' | 'stale',
    info: any,
    correlationId: string
  ): Promise<void> {
    try {
      logger.info('🔌 [Socket Cleanup] Closing connection', {
        correlationId,
        clientId: info.clientId,
        roomId: info.roomId,
        userId: info.userId,
        reason,
        inactiveTime: Date.now() - info.lastActivity
      } as any);

      // Send close frame if connection is still open
      if (socket.readyState === WebSocket.OPEN) {
        socket.close(1001, `Connection closed due to ${reason} timeout`);
      }

      // Remove from tracking
      this.connectionTracking.delete(socket);

      // Additional cleanup could be added here:
      // - Remove from room player lists
      // - Notify other room members
      // - Clean up any pending operations

    } catch (error) {
      logger.error('❌ [Socket Cleanup] Error closing connection', {
        correlationId,
        clientId: info.clientId,
        error: (error as Error).message
      } as any);
      throw error;
    }
  }

  /**
   * Generate a unique client ID for connection tracking
   */
  private generateClientId(): string {
    return `client_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Get socket cleanup statistics for monitoring
   */
  getSocketStats(): {
    totalConnections: number;
    connectionsByState: Record<string, number>;
    averageConnectionAge: number;
    connectionsEligibleForCleanup: {
      inactive: number;
      stale: number;
    };
  } {
    const now = Date.now();
    const inactiveThreshold = now - SocketCleanupJob.INACTIVE_CONNECTION_TTL;
    const staleThreshold = now - SocketCleanupJob.STALE_CONNECTION_TTL;
    
    const connectionsByState: Record<string, number> = {
      CONNECTING: 0,
      OPEN: 0,
      CLOSING: 0,
      CLOSED: 0
    };
    
    let totalAge = 0;
    let eligibleInactive = 0;
    let eligibleStale = 0;

    for (const [socket, info] of this.connectionTracking.entries()) {
      // Count by state
      switch (socket.readyState) {
        case WebSocket.CONNECTING:
          connectionsByState.CONNECTING++;
          break;
        case WebSocket.OPEN:
          connectionsByState.OPEN++;
          break;
        case WebSocket.CLOSING:
          connectionsByState.CLOSING++;
          break;
        case WebSocket.CLOSED:
          connectionsByState.CLOSED++;
          break;
      }

      // Calculate age and eligibility
      const age = now - info.lastActivity;
      totalAge += age;

      if (info.lastActivity < staleThreshold) {
        eligibleStale++;
      } else if (info.lastActivity < inactiveThreshold) {
        eligibleInactive++;
      }
    }

    const totalConnections = this.connectionTracking.size;
    const averageConnectionAge = totalConnections > 0 ? totalAge / totalConnections : 0;

    return {
      totalConnections,
      connectionsByState,
      averageConnectionAge,
      connectionsEligibleForCleanup: {
        inactive: eligibleInactive,
        stale: eligibleStale
      }
    };
  }

  /**
   * Force close all connections (used during server shutdown)
   */
  async closeAllConnections(reason: string = 'Server shutdown'): Promise<void> {
    const correlationId = `shutdown_${Date.now()}`;
    
    logger.info('🔌 [Socket Cleanup] Closing all connections', {
      correlationId,
      totalConnections: this.connectionTracking.size,
      reason
    } as any);

    const closePromises: Promise<void>[] = [];

    for (const [socket, info] of this.connectionTracking.entries()) {
      closePromises.push(
        this.closeConnection(socket, 'stale', info, correlationId)
      );
    }

    await Promise.allSettled(closePromises);
    
    logger.info('✅ [Socket Cleanup] All connections closed', {
      correlationId,
      reason
    } as any);
  }
}