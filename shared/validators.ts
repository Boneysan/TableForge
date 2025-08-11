import { z } from 'zod';
import { 
  insertGameRoomSchema, 
  insertGameAssetSchema, 
  insertBoardAssetSchema,
  insertDiceRollSchema,
  insertChatMessageSchema,
  insertGameTemplateSchema,
  insertGameSystemSchema,
  insertCardDeckSchema,
  insertCardPileSchema
} from './schema';

// Base validation schemas
export const idSchema = z.string().min(1, 'ID is required');
export const roomIdSchema = z.string().min(1, 'Room ID is required');
export const userIdSchema = z.string().min(1, 'User ID is required');
export const emailSchema = z.string().email('Invalid email format');
export const urlSchema = z.string().url('Invalid URL format');

// Pagination schemas
export const paginationSchema = z.object({
  limit: z.coerce.number().min(1).max(100).default(10),
  offset: z.coerce.number().min(0).default(0),
});

export const limitSchema = z.object({
  limit: z.coerce.number().min(1).max(100).default(10),
});

// HTTP Route Validation Schemas
export const createRoomRequestSchema = insertGameRoomSchema;

export const updateRoomRequestSchema = insertGameRoomSchema.partial().extend({
  boardWidth: z.number().min(100).max(5000).optional(),
  boardHeight: z.number().min(100).max(5000).optional(),
});

export const createAssetRequestSchema = insertGameAssetSchema.extend({
  roomId: roomIdSchema.optional(), // Make room ID validation explicit
});

export const createBoardAssetRequestSchema = insertBoardAssetSchema.extend({
  roomId: roomIdSchema,
  positionX: z.number().min(0),
  positionY: z.number().min(0),
  rotation: z.number().min(0).max(360).default(0),
  scale: z.number().min(0.1).max(5).default(1),
});

export const updateBoardAssetRequestSchema = z.object({
  positionX: z.number().min(0).optional(),
  positionY: z.number().min(0).optional(),
  rotation: z.number().min(0).max(360).optional(),
  scale: z.number().min(0.1).max(5).optional(),
  isFlipped: z.boolean().optional(),
  zIndex: z.number().min(0).optional(),
  isLocked: z.boolean().optional(),
});

export const createDiceRollRequestSchema = insertDiceRollSchema.extend({
  roomId: roomIdSchema,
  diceType: z.enum(['d4', 'd6', 'd8', 'd10', 'd12', 'd20', 'd100']),
  diceCount: z.number().min(1).max(20),
  results: z.array(z.number().min(1)),
  total: z.number().min(1),
});

export const createChatMessageRequestSchema = insertChatMessageSchema.extend({
  roomId: roomIdSchema,
  message: z.string().min(1).max(1000, 'Message too long'),
  messageType: z.enum(['chat', 'system', 'whisper']).default('chat'),
  targetPlayerId: userIdSchema.optional(),
});

export const createGameTemplateRequestSchema = insertGameTemplateSchema;

export const createGameSystemRequestSchema = insertGameSystemSchema.extend({
  name: z.string().min(1).max(100, 'Name too long'),
  description: z.string().max(1000, 'Description too long').optional(),
  version: z.string().max(20, 'Version too long').default('1.0.0'),
});

export const createCardDeckRequestSchema = insertCardDeckSchema.extend({
  roomId: roomIdSchema,
  name: z.string().min(1).max(100, 'Deck name too long'),
  cardIds: z.array(idSchema).min(1, 'Deck must contain at least one card'),
});

export const createCardPileRequestSchema = insertCardPileSchema.extend({
  roomId: roomIdSchema,
  name: z.string().min(1).max(100, 'Pile name too long'),
  positionX: z.number().min(0),
  positionY: z.number().min(0),
  pileType: z.enum(['deck', 'hand', 'discard', 'custom']),
  cardOrder: z.array(idSchema).default([]),
});

export const joinRoomRequestSchema = z.object({
  roomId: roomIdSchema,
});

export const updateUserRequestSchema = z.object({
  firstName: z.string().min(1).max(50).optional(),
  lastName: z.string().min(1).max(50).optional(),
  profileImageUrl: urlSchema.optional(),
});

export const uploadRequestSchema = z.object({
  fileName: z.string().min(1, 'File name is required'),
  fileType: z.string().min(1, 'File type is required'),
  fileSize: z.number().min(1).max(50 * 1024 * 1024, 'File too large (max 50MB)'),
});

// WebSocket Event Validation Schemas
export const wsBaseSchema = z.object({
  type: z.string(),
  roomId: roomIdSchema.optional(),
  payload: z.record(z.any()).optional(),
});

export const wsJoinRoomSchema = wsBaseSchema.extend({
  type: z.literal('join_room'),
  roomId: roomIdSchema,
  payload: z.object({
    player: z.object({
      id: userIdSchema,
      name: z.string().min(1),
      role: z.enum(['admin', 'player']).default('player'),
    }),
  }),
});

export const wsAssetMovedSchema = wsBaseSchema.extend({
  type: z.literal('asset_moved'),
  roomId: roomIdSchema,
  payload: z.object({
    assetId: idSchema,
    positionX: z.number().min(0),
    positionY: z.number().min(0),
    rotation: z.number().min(0).max(360).default(0),
    scale: z.number().min(0.1).max(5).default(1),
  }),
});

export const wsAssetFlippedSchema = wsBaseSchema.extend({
  type: z.literal('asset_flipped'),
  roomId: roomIdSchema,
  payload: z.object({
    assetId: idSchema,
    isFlipped: z.boolean(),
  }),
});

export const wsDiceRolledSchema = wsBaseSchema.extend({
  type: z.literal('dice_rolled'),
  roomId: roomIdSchema,
  payload: z.object({
    playerId: userIdSchema,
    diceType: z.enum(['d4', 'd6', 'd8', 'd10', 'd12', 'd20', 'd100']),
    diceCount: z.number().min(1).max(20),
    results: z.array(z.number().min(1)),
    total: z.number().min(1),
  }),
});

export const wsChatMessageSchema = wsBaseSchema.extend({
  type: z.literal('chat_message'),
  roomId: roomIdSchema,
  payload: z.object({
    playerId: userIdSchema,
    message: z.string().min(1).max(1000, 'Message too long'),
    messageType: z.enum(['chat', 'system', 'whisper']).default('chat'),
    targetPlayerId: userIdSchema.optional(),
  }),
});

export const wsPlayerScoreUpdatedSchema = wsBaseSchema.extend({
  type: z.literal('player_score_updated'),
  roomId: roomIdSchema,
  payload: z.object({
    playerId: userIdSchema,
    score: z.number(),
  }),
});

export const wsTokenRefreshSchema = wsBaseSchema.extend({
  type: z.literal('auth:token_refresh'),
  payload: z.object({
    token: z.string().min(1, 'Token is required'),
  }),
});

export const wsBoardResizeSchema = wsBaseSchema.extend({
  type: z.literal('board_resize'),
  roomId: roomIdSchema,
  payload: z.object({
    width: z.number().min(100).max(5000),
    height: z.number().min(100).max(5000),
  }),
});

export const wsCardActionSchema = wsBaseSchema.extend({
  type: z.literal('card_action'),
  roomId: roomIdSchema,
  payload: z.object({
    action: z.enum(['draw', 'discard', 'shuffle', 'deal', 'flip']),
    cardId: idSchema.optional(),
    pileId: idSchema,
    targetPileId: idSchema.optional(),
    playerId: userIdSchema.optional(),
  }),
});

// Union schema for all WebSocket events
export const wsEventSchema = z.discriminatedUnion('type', [
  wsJoinRoomSchema,
  wsAssetMovedSchema,
  wsAssetFlippedSchema,
  wsDiceRolledSchema,
  wsChatMessageSchema,
  wsPlayerScoreUpdatedSchema,
  wsTokenRefreshSchema,
  wsBoardResizeSchema,
  wsCardActionSchema,
]);

// Error response schemas
export const validationErrorSchema = z.object({
  error: z.literal('validation_error'),
  message: z.string(),
  details: z.array(z.object({
    field: z.string(),
    message: z.string(),
  })).optional(),
});

export const authErrorSchema = z.object({
  error: z.literal('authentication_error'),
  message: z.string(),
});

export const authorizationErrorSchema = z.object({
  error: z.literal('authorization_error'),
  message: z.string(),
  requiredRole: z.string().optional(),
});

export const notFoundErrorSchema = z.object({
  error: z.literal('not_found'),
  message: z.string(),
  resource: z.string().optional(),
});

export const serverErrorSchema = z.object({
  error: z.literal('server_error'),
  message: z.string(),
});

// Type exports
export type ValidationError = z.infer<typeof validationErrorSchema>;
export type AuthError = z.infer<typeof authErrorSchema>;
export type AuthorizationError = z.infer<typeof authorizationErrorSchema>;
export type NotFoundError = z.infer<typeof notFoundErrorSchema>;
export type ServerError = z.infer<typeof serverErrorSchema>;

export type WSEvent = z.infer<typeof wsEventSchema>;
export type WSJoinRoom = z.infer<typeof wsJoinRoomSchema>;
export type WSAssetMoved = z.infer<typeof wsAssetMovedSchema>;
export type WSAssetFlipped = z.infer<typeof wsAssetFlippedSchema>;
export type WSDiceRolled = z.infer<typeof wsDiceRolledSchema>;
export type WSChatMessage = z.infer<typeof wsChatMessageSchema>;
export type WSPlayerScoreUpdated = z.infer<typeof wsPlayerScoreUpdatedSchema>;
export type WSTokenRefresh = z.infer<typeof wsTokenRefreshSchema>;
export type WSBoardResize = z.infer<typeof wsBoardResizeSchema>;
export type WSCardAction = z.infer<typeof wsCardActionSchema>;

// Pre-built validation middleware for common patterns
export const validateRoomId = z.object({
  roomId: roomIdSchema,
});

export const validateAssetId = z.object({
  id: idSchema,
});

export const validateUserId = z.object({
  userId: userIdSchema,
});

// Validation utility functions
export function createValidationError(message: string, details?: Array<{ field: string; message: string }>): ValidationError {
  return { error: 'validation_error', message, details };
}

export function createAuthError(message: string): AuthError {
  return { error: 'authentication_error', message };
}

export function createAuthorizationError(message: string, requiredRole?: string): AuthorizationError {
  return { error: 'authorization_error', message, requiredRole };
}

export function createNotFoundError(message: string, resource?: string): NotFoundError {
  return { error: 'not_found', message, resource };
}

export function createServerError(message: string): ServerError {
  return { error: 'server_error', message };
}

// Common pagination validators
export const validatePagination = z.object({
  page: z.number().int().positive().default(1),
  pageSize: z.number().int().positive().max(100).default(20)
});

export const validateLimit = z.number().int().positive().max(100).default(20);

// Validation middleware helper
export function validateSchema<T>(schema: z.ZodSchema<T>, data: unknown): { success: true; data: T } | { success: false; error: ValidationError } {
  try {
    const result = schema.parse(data);
    return { success: true, data: result };
  } catch (error) {
    if (error instanceof z.ZodError) {
      const details = error.errors.map(err => ({
        field: err.path.join('.'),
        message: err.message,
      }));
      return { 
        success: false, 
        error: createValidationError('Validation failed', details) 
      };
    }
    return { 
      success: false, 
      error: createValidationError('Invalid data format') 
    };
  }
}