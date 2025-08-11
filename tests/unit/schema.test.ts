/**
 * Unit tests for database schemas and validators
 */

import { describe, it, expect } from 'vitest';
import {
  createInsertGameRoomSchema,
  createInsertAssetSchema,
  createInsertDeckSchema,
  createInsertCardSchema,
} from '@shared/schema';

describe('Schema Validation', () => {
  describe('Game Room Schema', () => {
    const gameRoomSchema = createInsertGameRoomSchema;

    it('should validate a valid game room', () => {
      const validRoom = {
        name: 'Test Room',
        description: 'A test game room',
        gameSystemId: 'system-123',
        hostUserId: 'user-123',
        isPublic: true,
        maxPlayers: 6,
        boardWidth: 1920,
        boardHeight: 1080,
        gridSize: 50,
      };

      const result = gameRoomSchema.safeParse(validRoom);
      expect(result.success).toBe(true);
    });

    it('should reject room with invalid name', () => {
      const invalidRoom = {
        name: '', // Empty name
        gameSystemId: 'system-123',
        hostUserId: 'user-123',
      };

      const result = gameRoomSchema.safeParse(invalidRoom);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].path).toContain('name');
      }
    });

    it('should reject room with negative max players', () => {
      const invalidRoom = {
        name: 'Test Room',
        gameSystemId: 'system-123',
        hostUserId: 'user-123',
        maxPlayers: -1,
      };

      const result = gameRoomSchema.safeParse(invalidRoom);
      expect(result.success).toBe(false);
    });

    it('should reject room with invalid board dimensions', () => {
      const invalidRoom = {
        name: 'Test Room',
        gameSystemId: 'system-123',
        hostUserId: 'user-123',
        boardWidth: 0,
        boardHeight: -100,
      };

      const result = gameRoomSchema.safeParse(invalidRoom);
      expect(result.success).toBe(false);
    });
  });

  describe('Asset Schema', () => {
    const assetSchema = createInsertAssetSchema;

    it('should validate a valid asset', () => {
      const validAsset = {
        name: 'Test Asset',
        type: 'token' as const,
        imageUrl: 'https://example.com/image.png',
        width: 100,
        height: 100,
        gameSystemId: 'system-123',
        uploadedBy: 'user-123',
        category: 'characters',
        tags: ['hero', 'warrior'],
      };

      const result = assetSchema.safeParse(validAsset);
      expect(result.success).toBe(true);
    });

    it('should reject asset with invalid type', () => {
      const invalidAsset = {
        name: 'Test Asset',
        type: 'invalid-type',
        imageUrl: 'https://example.com/image.png',
        gameSystemId: 'system-123',
        uploadedBy: 'user-123',
      };

      const result = assetSchema.safeParse(invalidAsset);
      expect(result.success).toBe(false);
    });

    it('should reject asset with invalid dimensions', () => {
      const invalidAsset = {
        name: 'Test Asset',
        type: 'token' as const,
        imageUrl: 'https://example.com/image.png',
        width: -50,
        height: 0,
        gameSystemId: 'system-123',
        uploadedBy: 'user-123',
      };

      const result = assetSchema.safeParse(invalidAsset);
      expect(result.success).toBe(false);
    });
  });

  describe('Deck Schema', () => {
    const deckSchema = createInsertDeckSchema;

    it('should validate a valid deck', () => {
      const validDeck = {
        name: 'Test Deck',
        description: 'A test deck',
        gameSystemId: 'system-123',
        createdBy: 'user-123',
        cardBackUrl: 'https://example.com/back.png',
        isShuffled: false,
        isPublic: true,
      };

      const result = deckSchema.safeParse(validDeck);
      expect(result.success).toBe(true);
    });

    it('should allow deck without optional fields', () => {
      const minimalDeck = {
        name: 'Minimal Deck',
        gameSystemId: 'system-123',
        createdBy: 'user-123',
      };

      const result = deckSchema.safeParse(minimalDeck);
      expect(result.success).toBe(true);
    });

    it('should reject deck with empty name', () => {
      const invalidDeck = {
        name: '',
        gameSystemId: 'system-123',
        createdBy: 'user-123',
      };

      const result = deckSchema.safeParse(invalidDeck);
      expect(result.success).toBe(false);
    });
  });

  describe('Card Schema', () => {
    const cardSchema = createInsertCardSchema;

    it('should validate a valid card', () => {
      const validCard = {
        name: 'Test Card',
        frontImageUrl: 'https://example.com/front.png',
        deckId: 'deck-123',
        orderInDeck: 5,
        metadata: {
          cost: 3,
          attack: 2,
          health: 4,
        },
      };

      const result = cardSchema.safeParse(validCard);
      expect(result.success).toBe(true);
    });

    it('should allow card without optional fields', () => {
      const minimalCard = {
        name: 'Minimal Card',
        frontImageUrl: 'https://example.com/front.png',
        deckId: 'deck-123',
        orderInDeck: 1,
      };

      const result = cardSchema.safeParse(minimalCard);
      expect(result.success).toBe(true);
    });

    it('should reject card with negative order', () => {
      const invalidCard = {
        name: 'Test Card',
        frontImageUrl: 'https://example.com/front.png',
        deckId: 'deck-123',
        orderInDeck: -1,
      };

      const result = cardSchema.safeParse(invalidCard);
      expect(result.success).toBe(false);
    });

    it('should validate complex metadata', () => {
      const cardWithMetadata = {
        name: 'Complex Card',
        frontImageUrl: 'https://example.com/front.png',
        deckId: 'deck-123',
        orderInDeck: 1,
        metadata: {
          type: 'Creature',
          rarity: 'Legendary',
          cost: 8,
          attack: 8,
          health: 8,
          abilities: ['Flying', 'Trample'],
          flavor: 'A mighty dragon soars above the battlefield.',
        },
      };

      const result = cardSchema.safeParse(cardWithMetadata);
      expect(result.success).toBe(true);
    });
  });

  describe('Schema Edge Cases', () => {
    it('should handle null and undefined values properly', () => {
      const gameRoomSchema = createInsertGameRoomSchema;

      const roomWithNulls = {
        name: 'Test Room',
        description: null,
        gameSystemId: 'system-123',
        hostUserId: 'user-123',
        backgroundImageUrl: undefined,
      };

      const result = gameRoomSchema.safeParse(roomWithNulls);
      expect(result.success).toBe(true);
    });

    it('should validate array fields properly', () => {
      const assetSchema = createInsertAssetSchema;

      const assetWithTags = {
        name: 'Tagged Asset',
        type: 'token' as const,
        imageUrl: 'https://example.com/image.png',
        gameSystemId: 'system-123',
        uploadedBy: 'user-123',
        tags: ['tag1', 'tag2', 'tag3'],
      };

      const result = assetSchema.safeParse(assetWithTags);
      expect(result.success).toBe(true);
    });

    it('should reject invalid array elements', () => {
      const assetSchema = createInsertAssetSchema;

      const assetWithInvalidTags = {
        name: 'Invalid Tags',
        type: 'token' as const,
        imageUrl: 'https://example.com/image.png',
        gameSystemId: 'system-123',
        uploadedBy: 'user-123',
        tags: ['valid-tag', '', null, 123], // Mixed invalid types
      };

      const result = assetSchema.safeParse(assetWithInvalidTags);
      expect(result.success).toBe(false);
    });
  });
});
