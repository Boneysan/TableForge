import type { WebSocket } from 'ws';
import type { IncomingMessage } from 'http';
import { validateFirebaseToken, extractTokenFromWebSocket, validateTokenFreshness, type ValidatedUser } from '../auth/tokenValidator';
import { roomAuthManager, type RoomClaims } from '../auth/roomAuth';

// Interface for authenticated socket connection
export interface AuthenticatedSocket extends WebSocket {
  user?: ValidatedUser;
  roomId?: string;
  roomClaims?: RoomClaims;
  isAuthenticated: boolean;
  lastHeartbeat: number;
}

// WebSocket authentication events
export interface SocketAuthEvents {
  'auth:required': { message: string };
  'auth:success': { user: ValidatedUser };
  'auth:failed': { error: string };
  'room:joined': { roomId: string; role: string };
  'room:unauthorized': { roomId: string; reason: string };
  'token:expired': { message: string };
}

/**
 * WebSocket authentication manager
 */
export class SocketAuthManager {
  private authenticatedSockets = new Map<string, AuthenticatedSocket>();
  private heartbeatInterval: NodeJS.Timeout;

  constructor() {
    // Start heartbeat to check token expiry
    this.heartbeatInterval = setInterval(() => {
      this.validateActiveConnections();
    }, 30000); // Check every 30 seconds
  }

  /**
   * Authenticate WebSocket connection on initial connect
   */
  async authenticateConnection(socket: AuthenticatedSocket, request: IncomingMessage): Promise<boolean> {
    try {
      console.log('🔌 [Socket Auth] Authenticating WebSocket connection');

      const token = extractTokenFromWebSocket(request);
      if (!token) {
        this.sendAuthError(socket, 'Authentication token required');
        return false;
      }

      const user = await validateFirebaseToken(token);

      if (!validateTokenFreshness(user)) {
        this.sendAuthError(socket, 'Authentication token has expired');
        return false;
      }

      // Attach user to socket
      socket.user = user;
      socket.isAuthenticated = true;
      socket.lastHeartbeat = Date.now();

      // Store authenticated socket
      this.authenticatedSockets.set(user.uid, socket);

      console.log('✅ [Socket Auth] WebSocket authenticated:', {
        uid: user.uid,
        email: user.email,
        socketId: this.getSocketId(socket),
      });

      // Send success message
      this.sendMessage(socket, 'auth:success', { user });

      return true;
    } catch (error) {
      console.error('❌ [Socket Auth] WebSocket authentication failed:', error);
      this.sendAuthError(socket, 'Authentication failed');
      return false;
    }
  }

  /**
   * Re-authenticate WebSocket with new token (for token refresh)
   */
  async reauthenticate(socket: AuthenticatedSocket, token: string): Promise<boolean> {
    try {
      console.log('🔄 [Socket Auth] Re-authenticating WebSocket');

      const user = await validateFirebaseToken(token);

      if (!validateTokenFreshness(user)) {
        this.sendAuthError(socket, 'New token has expired');
        return false;
      }

      // Update socket user
      socket.user = user;
      socket.lastHeartbeat = Date.now();

      console.log('✅ [Socket Auth] WebSocket re-authenticated:', user.uid);
      this.sendMessage(socket, 'auth:success', { user });

      return true;
    } catch (error) {
      console.error('❌ [Socket Auth] Re-authentication failed:', error);
      this.sendAuthError(socket, 'Re-authentication failed');
      return false;
    }
  }

  /**
   * Authorize socket to join a room
   */
  async authorizeRoomJoin(socket: AuthenticatedSocket, roomId: string): Promise<boolean> {
    if (!socket.user || !socket.isAuthenticated) {
      this.sendMessage(socket, 'room:unauthorized', {
        roomId,
        reason: 'Socket not authenticated',
      });
      return false;
    }

    try {
      console.log('🏠 [Socket Auth] Authorizing room join:', {
        userId: socket.user.uid,
        roomId,
      });

      const claims = await roomAuthManager.validateRoomMembership(socket.user, roomId);
      if (!claims) {
        this.sendMessage(socket, 'room:unauthorized', {
          roomId,
          reason: 'Not a member of this room',
        });
        return false;
      }

      // Attach room claims to socket
      socket.roomId = roomId;
      socket.roomClaims = claims;

      console.log('✅ [Socket Auth] Room join authorized:', {
        userId: socket.user.uid,
        roomId,
        role: claims.role,
      });

      this.sendMessage(socket, 'room:joined', {
        roomId,
        role: claims.role,
      });

      return true;
    } catch (error) {
      console.error('❌ [Socket Auth] Room authorization error:', error);
      this.sendMessage(socket, 'room:unauthorized', {
        roomId,
        reason: 'Authorization error',
      });
      return false;
    }
  }

  /**
   * Validate socket action in room
   */
  async validateRoomAction(
    socket: AuthenticatedSocket,
    action: string,
    requiredPermission: string,
  ): Promise<{ allowed: boolean; reason?: string }> {

    if (!socket.user || !socket.isAuthenticated) {
      return { allowed: false, reason: 'Socket not authenticated' };
    }

    if (!socket.roomId || !socket.roomClaims) {
      return { allowed: false, reason: 'Not joined to any room' };
    }

    const result = await roomAuthManager.validateRoomAction(
      socket.user,
      socket.roomId,
      action,
      requiredPermission,
    );

    if (!result.allowed) {
      console.log('❌ [Socket Auth] Room action denied:', {
        userId: socket.user.uid,
        roomId: socket.roomId,
        action,
        reason: result.reason,
      });
    }

    return result;
  }

  /**
   * Handle socket disconnection cleanup
   */
  handleDisconnection(socket: AuthenticatedSocket): void {
    if (socket.user) {
      console.log('👋 [Socket Auth] Socket disconnected:', {
        userId: socket.user.uid,
        roomId: socket.roomId,
      });

      this.authenticatedSockets.delete(socket.user.uid);
    }
  }

  /**
   * Validate active connections for token expiry
   */
  private validateActiveConnections(): void {
    const now = Date.now();
    const expiredSockets: AuthenticatedSocket[] = [];

    for (const [userId, socket] of this.authenticatedSockets) {
      if (socket.user && !validateTokenFreshness(socket.user)) {
        console.log('⏰ [Socket Auth] Token expired for socket:', userId);
        expiredSockets.push(socket);
      }
    }

    // Disconnect expired sockets
    for (const socket of expiredSockets) {
      this.sendMessage(socket, 'token:expired', {
        message: 'Authentication token expired, please reconnect',
      });
      socket.terminate();
    }
  }

  /**
   * Send authentication error to socket
   */
  private sendAuthError(socket: WebSocket, message: string): void {
    this.sendMessage(socket, 'auth:failed', { error: message });
  }

  /**
   * Send message to socket
   */
  private sendMessage(socket: WebSocket, event: keyof SocketAuthEvents, data: any): void {
    if (socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ event, data }));
    }
  }

  /**
   * Get socket identifier for logging
   */
  private getSocketId(socket: WebSocket): string {
    return `socket_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Cleanup resources
   */
  destroy(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
    }
  }
}

// Singleton instance
export const socketAuthManager = new SocketAuthManager();
