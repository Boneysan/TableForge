/**
 * WebSocket Card Move Handler
 *
 * Handles real-time card movement operations with concurrency control:
 * - Processes card move WebSocket messages
 * - Integrates with CardMoveManager for conflict resolution
 * - Broadcasts move results to room participants
 * - Provides late-joiner reconciliation
 */

import { CardMoveManager } from '../concurrency/cardMoveManager';
import type { CardMoveRequest, CardMoveResult } from '../concurrency/cardMoveManager';
import type { AuthenticatedSocket } from '../auth/socketAuth';
import { logger } from '../utils/logger';

// WebSocket message types for card moves
export interface CardMoveMessage {
  type: 'card_move';
  payload: {
    moveId: string;
    moveType: 'card_to_pile' | 'pile_to_pile' | 'card_draw' | 'card_discard' | 'shuffle' | 'pile_reorder';
    sourceType: 'deck' | 'pile' | 'hand' | 'board';
    sourceId?: string;
    targetType: 'deck' | 'pile' | 'hand' | 'board';
    targetId?: string;
    cardAssetIds: string[];
    sourcePosition?: number;
    targetPosition?: number;
    expectedSourceVersion?: number;
    expectedTargetVersion?: number;
    metadata?: Record<string, any>;
  };
}

export interface CardMoveResultMessage {
  type: 'card_move_result';
  payload: {
    moveId: string;
    success: boolean;
    sequenceNumber?: number;
    newSourceVersion?: number;
    newTargetVersion?: number;
    conflictResolution?: string;
    error?: string;
    rollbackRequired?: boolean;
  };
}

export interface CardMoveConflictMessage {
  type: 'card_move_conflict';
  payload: {
    moveId: string;
    conflictType: 'version_mismatch' | 'entity_not_found' | 'permission_denied';
    conflictDetails: string;
    suggestedResolution?: 'retry' | 'refresh_state' | 'abort';
    currentState?: any;
  };
}

export interface ReconciliationRequestMessage {
  type: 'reconciliation_request';
  payload: {
    lastKnownSequence?: number;
  };
}

export interface ReconciliationResponseMessage {
  type: 'reconciliation_response';
  payload: {
    currentSequence: number;
    missedMoves: any[];
    fullStateSnapshot?: any;
  };
}

export class CardMoveHandler {
  private cardMoveManager: CardMoveManager;
  private roomConnections: Map<string, Set<AuthenticatedSocket>>;

  constructor(roomConnections: Map<string, Set<AuthenticatedSocket>>) {
    this.cardMoveManager = CardMoveManager.getInstance();
    this.roomConnections = roomConnections;
  }

  /**
   * Handle card move WebSocket message
   */
  async handleCardMove(ws: AuthenticatedSocket, message: CardMoveMessage): Promise<void> {
    const { payload } = message;
    const roomId = ws.roomId;
    const playerId = ws.user?.uid;

    if (!roomId || !playerId) {
      logger.warn('🎴 [Card Move WS] Invalid connection state', {
        roomId,
        playerId,
        moveId: payload.moveId,
      });

      this.sendError(ws, payload.moveId, 'Invalid connection state');
      return;
    }

    const correlationId = `ws_move_${payload.moveId}_${Date.now()}`;

    logger.info('🎴 [Card Move WS] Processing card move request', {
      correlationId,
      roomId,
      playerId,
      moveId: payload.moveId,
      moveType: payload.moveType,
    });

    try {
      // Create move request
      const moveRequest: CardMoveRequest = {
        moveId: payload.moveId,
        clientId: ws.clientId || `client_${playerId}`, // Use client ID if available
        playerId,
        roomId,
        moveType: payload.moveType,
        sourceType: payload.sourceType,
        sourceId: payload.sourceId,
        targetType: payload.targetType,
        targetId: payload.targetId,
        cardAssetIds: payload.cardAssetIds,
        sourcePosition: payload.sourcePosition,
        targetPosition: payload.targetPosition,
        expectedSourceVersion: payload.expectedSourceVersion,
        expectedTargetVersion: payload.expectedTargetVersion,
        metadata: {
          ...payload.metadata,
          clientTimestamp: Date.now(),
          userAgent: ws.userAgent,
        },
      };

      // Execute move with concurrency control
      const result = await this.cardMoveManager.executeMove(moveRequest);

      // Send result to requesting client
      this.sendMoveResult(ws, result);

      // Broadcast successful moves to other clients in room
      if (result.success) {
        this.broadcastMoveToRoom(roomId, payload, result, ws);
      } else {
        // Handle conflicts
        this.handleMoveConflict(ws, payload, result);
      }

      logger.info('🎴 [Card Move WS] Card move processing completed', {
        correlationId,
        success: result.success,
        sequenceNumber: result.sequenceNumber,
      });

    } catch (error) {
      logger.error('🎴 [Card Move WS] Error processing card move', {
        correlationId,
        moveId: payload.moveId,
        error: error.message,
        stack: error.stack,
      });

      this.sendError(ws, payload.moveId, `Move processing failed: ${error.message}`);
    }
  }

  /**
   * Handle reconciliation request from client
   */
  async handleReconciliationRequest(
    ws: AuthenticatedSocket,
    message: ReconciliationRequestMessage,
  ): Promise<void> {

    const roomId = ws.roomId;
    const { lastKnownSequence } = message.payload;

    if (!roomId) {
      logger.warn('🎴 [Card Move WS] Reconciliation request without room ID', {
        playerId: ws.user?.uid,
      });
      return;
    }

    const correlationId = `reconcile_${roomId}_${Date.now()}`;

    logger.info('🎴 [Card Move WS] Processing reconciliation request', {
      correlationId,
      roomId,
      playerId: ws.user?.uid,
      lastKnownSequence,
    });

    try {
      // Get reconciliation data from move manager
      const reconciliation = await this.cardMoveManager.reconcileClientState(roomId, lastKnownSequence);

      // Send reconciliation response
      const response: ReconciliationResponseMessage = {
        type: 'reconciliation_response',
        payload: reconciliation,
      };

      ws.send(JSON.stringify(response));

      logger.info('🎴 [Card Move WS] Reconciliation response sent', {
        correlationId,
        currentSequence: reconciliation.currentSequence,
        missedMovesCount: reconciliation.missedMoves.length,
      });

    } catch (error) {
      logger.error('🎴 [Card Move WS] Error processing reconciliation', {
        correlationId,
        roomId,
        error: error.message,
      });

      this.sendError(ws, 'reconciliation', `Reconciliation failed: ${error.message}`);
    }
  }

  /**
   * Send move result to client
   */
  private sendMoveResult(ws: AuthenticatedSocket, result: CardMoveResult): void {
    const response: CardMoveResultMessage = {
      type: 'card_move_result',
      payload: {
        moveId: result.moveId,
        success: result.success,
        sequenceNumber: result.sequenceNumber,
        newSourceVersion: result.newSourceVersion,
        newTargetVersion: result.newTargetVersion,
        conflictResolution: result.conflictResolution,
        error: result.error,
        rollbackRequired: result.rollbackRequired,
      },
    };

    ws.send(JSON.stringify(response));
  }

  /**
   * Broadcast successful move to other clients in room
   */
  private broadcastMoveToRoom(
    roomId: string,
    originalPayload: CardMoveMessage['payload'],
    result: CardMoveResult,
    excludeSocket: AuthenticatedSocket,
  ): void {

    const roomSockets = this.roomConnections.get(roomId);
    if (!roomSockets) return;

    const broadcast = {
      type: 'card_move_broadcast',
      payload: {
        ...originalPayload,
        sequenceNumber: result.sequenceNumber,
        newSourceVersion: result.newSourceVersion,
        newTargetVersion: result.newTargetVersion,
        timestamp: Date.now(),
      },
    };

    const message = JSON.stringify(broadcast);

    roomSockets.forEach(socket => {
      if (socket !== excludeSocket && socket.readyState === 1) { // WebSocket.OPEN
        try {
          socket.send(message);
        } catch (error) {
          logger.warn('🎴 [Card Move WS] Error broadcasting to socket', {
            roomId,
            error: error.message,
          });
        }
      }
    });

    logger.debug('🎴 [Card Move WS] Move broadcasted to room', {
      roomId,
      broadcastCount: roomSockets.size - 1,
      moveId: originalPayload.moveId,
    });
  }

  /**
   * Handle move conflicts
   */
  private handleMoveConflict(
    ws: AuthenticatedSocket,
    payload: CardMoveMessage['payload'],
    result: CardMoveResult,
  ): void {

    let conflictType: 'version_mismatch' | 'entity_not_found' | 'permission_denied' = 'version_mismatch';
    let suggestedResolution: 'retry' | 'refresh_state' | 'abort' = 'retry';

    // Determine conflict type and resolution strategy
    if (result.error?.includes('not found')) {
      conflictType = 'entity_not_found';
      suggestedResolution = 'refresh_state';
    } else if (result.error?.includes('version')) {
      conflictType = 'version_mismatch';
      suggestedResolution = 'retry';
    } else if (result.error?.includes('permission')) {
      conflictType = 'permission_denied';
      suggestedResolution = 'abort';
    }

    const conflictMessage: CardMoveConflictMessage = {
      type: 'card_move_conflict',
      payload: {
        moveId: payload.moveId,
        conflictType,
        conflictDetails: result.error || 'Unknown conflict',
        suggestedResolution,
      },
    };

    ws.send(JSON.stringify(conflictMessage));

    logger.info('🎴 [Card Move WS] Conflict message sent', {
      roomId: ws.roomId,
      moveId: payload.moveId,
      conflictType,
      suggestedResolution,
    });
  }

  /**
   * Send error message to client
   */
  private sendError(ws: AuthenticatedSocket, moveId: string, error: string): void {
    const errorMessage = {
      type: 'card_move_error',
      payload: {
        moveId,
        error,
      },
    };

    ws.send(JSON.stringify(errorMessage));
  }

  /**
   * Handle client reconnection - send current state
   */
  async handleClientReconnection(ws: AuthenticatedSocket): Promise<void> {
    const roomId = ws.roomId;

    if (!roomId) return;

    logger.info('🎴 [Card Move WS] Handling client reconnection', {
      roomId,
      playerId: ws.user?.uid,
    });

    try {
      // Automatically trigger reconciliation for reconnected client
      const reconciliation = await this.cardMoveManager.reconcileClientState(roomId);

      if (reconciliation.missedMoves.length > 0) {
        const response: ReconciliationResponseMessage = {
          type: 'reconciliation_response',
          payload: reconciliation,
        };

        ws.send(JSON.stringify(response));

        logger.info('🎴 [Card Move WS] Reconnection reconciliation sent', {
          roomId,
          missedMovesCount: reconciliation.missedMoves.length,
        });
      }

    } catch (error) {
      logger.error('🎴 [Card Move WS] Error handling client reconnection', {
        roomId,
        error: error.message,
      });
    }
  }
}
