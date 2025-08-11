import { validateWebSocketMessage } from '../middleware/validation';
import { 
  wsEventSchema,
  wsJoinRoomSchema,
  wsAssetMovedSchema,
  wsAssetFlippedSchema,
  wsDiceRolledSchema,
  wsChatMessageSchema,
  wsPlayerScoreUpdatedSchema,
  wsTokenRefreshSchema,
  wsBoardResizeSchema,
  wsCardActionSchema,
  createValidationError,
  createAuthError,
  createAuthorizationError
} from '@shared/validators';
import type { WSEvent, ValidationError } from '@shared/validators';
import type { AuthenticatedSocket } from './socketAuth';

// WebSocket event validation mapping
const eventValidators: Record<string, any> = {
  'join_room': wsJoinRoomSchema,
  'asset_moved': wsAssetMovedSchema,
  'asset_flipped': wsAssetFlippedSchema,
  'dice_rolled': wsDiceRolledSchema,
  'chat_message': wsChatMessageSchema,
  'player_score_updated': wsPlayerScoreUpdatedSchema,
  'auth:token_refresh': wsTokenRefreshSchema,
  'board_resize': wsBoardResizeSchema,
  'card_action': wsCardActionSchema,
};

export function validateSocketEvent(socket: AuthenticatedSocket, rawData: any): { success: true; data: any } | { success: false; error: ValidationError } {
  console.log(`🔍 [Socket Validation] Validating socket event from user ${socket.user?.uid}`);
  console.log(`🔍 [Socket Validation] Raw data:`, rawData);

  // First, validate the basic structure
  const baseResult = validateWebSocketMessage(wsEventSchema, rawData);
  if (!baseResult.success) {
    console.log(`❌ [Socket Validation] Base validation failed`);
    return baseResult;
  }

  const eventType = rawData.type;
  console.log(`🔍 [Socket Validation] Event type: ${eventType}`);

  // Validate specific event type if validator exists
  const specificValidator = eventValidators[eventType as keyof typeof eventValidators];
  if (specificValidator) {
    const specificResult = validateWebSocketMessage(specificValidator, rawData);
    if (!specificResult.success) {
      console.log(`❌ [Socket Validation] Specific event validation failed for ${eventType}`);
      return specificResult;
    }
    console.log(`✅ [Socket Validation] Event validation passed for ${eventType}`);
    return { success: true, data: specificResult.data };
  }

  // If no specific validator, use the base validation result
  console.log(`⚠️ [Socket Validation] No specific validator for ${eventType}, using base validation`);
  return { success: true, data: baseResult.data };
}

export function sendSocketError(socket: AuthenticatedSocket, error: ValidationError | any): void {
  console.log(`❌ [Socket Error] Sending error to socket:`, error);
  
  let errorResponse;
  if (error.error) {
    // Already a formatted error
    errorResponse = error;
  } else if (error instanceof Error) {
    // Convert Error to ValidationError
    errorResponse = createValidationError(error.message);
  } else {
    // Generic error
    errorResponse = createValidationError('Invalid request format');
  }

  socket.emit('error', errorResponse);
}

export function requireAuth(socket: AuthenticatedSocket): boolean {
  if (!socket.user || !socket.user.uid) {
    console.log(`❌ [Socket Auth] Socket not authenticated`);
    sendSocketError(socket, createAuthError('Authentication required'));
    return false;
  }
  return true;
}

export function requireRoomMembership(socket: AuthenticatedSocket, roomId: string): boolean {
  if (!(socket as any).roomMemberships || !(socket as any).roomMemberships.has(roomId)) {
    console.log(`❌ [Socket Auth] User ${socket.user?.uid} not a member of room ${roomId}`);
    sendSocketError(socket, createAuthorizationError('Room membership required'));
    return false;
  }
  return true;
}

// Validation middleware wrapper for socket events
export function validateSocketEventMiddleware(
  eventHandler: (socket: AuthenticatedSocket, data: any) => void | Promise<void>
) {
  return async (socket: AuthenticatedSocket, rawData: any) => {
    console.log(`🔍 [Socket Middleware] Processing event from user ${socket.user?.uid}`);

    // Require authentication for all events
    if (!requireAuth(socket)) {
      return;
    }

    // Validate event structure
    const validationResult = validateSocketEvent(socket, rawData);
    if (!validationResult.success) {
      sendSocketError(socket, validationResult.error);
      return;
    }

    const data = validationResult.data;
    console.log(`✅ [Socket Middleware] Event validation passed, calling handler`);

    // For room-specific events, check room membership
    if (data.roomId && !requireRoomMembership(socket, data.roomId)) {
      return;
    }

    try {
      // Call the actual event handler
      await eventHandler(socket, data);
      console.log(`✅ [Socket Middleware] Event handler completed successfully`);
    } catch (error) {
      console.error(`❌ [Socket Middleware] Event handler error:`, error);
      sendSocketError(socket, error instanceof Error ? error : createValidationError('Internal server error'));
    }
  };
}