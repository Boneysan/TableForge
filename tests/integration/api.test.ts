/**
 * Integration tests for API endpoints using Supertest
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import request from 'supertest';
import { app } from '../../server/index';
import { db } from '../../server/db';
import { gameRooms, users, assets, decks } from '../../shared/schema';

describe('API Integration Tests', () => {
  let testUserId: string;
  let testRoomId: string;
  let authToken: string;

  beforeAll(async () => {
    // Setup test database
    // In a real app, you'd use a test database
    console.log('Setting up integration tests...');
  });

  afterAll(async () => {
    // Cleanup test database
    console.log('Cleaning up integration tests...');
  });

  beforeEach(async () => {
    // Reset test data before each test
    // Create test user and get auth token
    testUserId = 'test-user-id';
    authToken = 'mock-auth-token'; // In real tests, generate proper token
  });

  describe('Authentication', () => {
    it('should reject requests without auth token', async () => {
      const response = await request(app)
        .get('/api/user/test-user/rooms')
        .expect(401);

      expect(response.body.message).toContain('Unauthorized');
    });

    it('should accept requests with valid auth token', async () => {
      const response = await request(app)
        .get('/api/user/test-user/rooms')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should validate malformed auth tokens', async () => {
      const response = await request(app)
        .get('/api/user/test-user/rooms')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);

      expect(response.body.message).toContain('Unauthorized');
    });
  });

  describe('Game Rooms API', () => {
    describe('POST /api/rooms', () => {
      it('should create a new game room', async () => {
        const roomData = {
          name: 'Test Room',
          description: 'A test game room',
          gameSystemId: 'test-system',
          isPublic: true,
          maxPlayers: 6,
          boardWidth: 1920,
          boardHeight: 1080,
          gridSize: 50,
        };

        const response = await request(app)
          .post('/api/rooms')
          .set('Authorization', `Bearer ${authToken}`)
          .send(roomData)
          .expect(201);

        expect(response.body).toMatchObject({
          name: roomData.name,
          description: roomData.description,
          hostUserId: testUserId,
          isPublic: true,
          maxPlayers: 6,
        });

        testRoomId = response.body.id;
      });

      it('should validate required fields', async () => {
        const invalidRoomData = {
          description: 'Missing name',
        };

        const response = await request(app)
          .post('/api/rooms')
          .set('Authorization', `Bearer ${authToken}`)
          .send(invalidRoomData)
          .expect(400);

        expect(response.body.errors).toBeDefined();
        expect(response.body.errors.some((e: any) => e.path.includes('name'))).toBe(true);
      });

      it('should set host as current user', async () => {
        const roomData = {
          name: 'Host Test Room',
          gameSystemId: 'test-system',
        };

        const response = await request(app)
          .post('/api/rooms')
          .set('Authorization', `Bearer ${authToken}`)
          .send(roomData)
          .expect(201);

        expect(response.body.hostUserId).toBe(testUserId);
      });
    });

    describe('GET /api/rooms/:id', () => {
      beforeEach(async () => {
        // Create test room
        const roomData = {
          name: 'Get Test Room',
          gameSystemId: 'test-system',
        };

        const response = await request(app)
          .post('/api/rooms')
          .set('Authorization', `Bearer ${authToken}`)
          .send(roomData);

        testRoomId = response.body.id;
      });

      it('should get room by ID', async () => {
        const response = await request(app)
          .get(`/api/rooms/${testRoomId}`)
          .set('Authorization', `Bearer ${authToken}`)
          .expect(200);

        expect(response.body.id).toBe(testRoomId);
        expect(response.body.name).toBe('Get Test Room');
      });

      it('should return 404 for non-existent room', async () => {
        await request(app)
          .get('/api/rooms/non-existent-id')
          .set('Authorization', `Bearer ${authToken}`)
          .expect(404);
      });
    });

    describe('PUT /api/rooms/:id', () => {
      beforeEach(async () => {
        const roomData = {
          name: 'Update Test Room',
          gameSystemId: 'test-system',
        };

        const response = await request(app)
          .post('/api/rooms')
          .set('Authorization', `Bearer ${authToken}`)
          .send(roomData);

        testRoomId = response.body.id;
      });

      it('should update room data', async () => {
        const updateData = {
          name: 'Updated Room Name',
          description: 'Updated description',
          maxPlayers: 8,
        };

        const response = await request(app)
          .put(`/api/rooms/${testRoomId}`)
          .set('Authorization', `Bearer ${authToken}`)
          .send(updateData)
          .expect(200);

        expect(response.body.name).toBe('Updated Room Name');
        expect(response.body.description).toBe('Updated description');
        expect(response.body.maxPlayers).toBe(8);
      });

      it('should only allow host to update room', async () => {
        const otherUserToken = 'other-user-token';

        await request(app)
          .put(`/api/rooms/${testRoomId}`)
          .set('Authorization', `Bearer ${otherUserToken}`)
          .send({ name: 'Unauthorized Update' })
          .expect(403);
      });
    });

    describe('DELETE /api/rooms/:id', () => {
      it('should delete room', async () => {
        const roomData = {
          name: 'Delete Test Room',
          gameSystemId: 'test-system',
        };

        const createResponse = await request(app)
          .post('/api/rooms')
          .set('Authorization', `Bearer ${authToken}`)
          .send(roomData);

        const roomId = createResponse.body.id;

        await request(app)
          .delete(`/api/rooms/${roomId}`)
          .set('Authorization', `Bearer ${authToken}`)
          .expect(204);

        // Verify room is deleted
        await request(app)
          .get(`/api/rooms/${roomId}`)
          .set('Authorization', `Bearer ${authToken}`)
          .expect(404);
      });

      it('should only allow host to delete room', async () => {
        const roomData = {
          name: 'Delete Test Room',
          gameSystemId: 'test-system',
        };

        const createResponse = await request(app)
          .post('/api/rooms')
          .set('Authorization', `Bearer ${authToken}`)
          .send(roomData);

        const roomId = createResponse.body.id;
        const otherUserToken = 'other-user-token';

        await request(app)
          .delete(`/api/rooms/${roomId}`)
          .set('Authorization', `Bearer ${otherUserToken}`)
          .expect(403);
      });
    });
  });

  describe('Assets API', () => {
    let testAssetId: string;

    describe('POST /api/assets', () => {
      it('should create a new asset', async () => {
        const assetData = {
          name: 'Test Asset',
          type: 'token',
          imageUrl: 'https://example.com/image.png',
          width: 100,
          height: 100,
          gameSystemId: 'test-system',
          category: 'characters',
          tags: ['hero', 'warrior'],
        };

        const response = await request(app)
          .post('/api/assets')
          .set('Authorization', `Bearer ${authToken}`)
          .send(assetData)
          .expect(201);

        expect(response.body).toMatchObject({
          name: assetData.name,
          type: assetData.type,
          imageUrl: assetData.imageUrl,
          category: assetData.category,
          uploadedBy: testUserId,
        });

        testAssetId = response.body.id;
      });

      it('should validate asset type', async () => {
        const invalidAssetData = {
          name: 'Invalid Asset',
          type: 'invalid-type',
          imageUrl: 'https://example.com/image.png',
          gameSystemId: 'test-system',
        };

        const response = await request(app)
          .post('/api/assets')
          .set('Authorization', `Bearer ${authToken}`)
          .send(invalidAssetData)
          .expect(400);

        expect(response.body.errors).toBeDefined();
      });
    });

    describe('GET /api/assets', () => {
      beforeEach(async () => {
        // Create test assets
        const assetData = {
          name: 'Query Test Asset',
          type: 'token',
          imageUrl: 'https://example.com/image.png',
          gameSystemId: 'test-system',
          category: 'test-category',
        };

        const response = await request(app)
          .post('/api/assets')
          .set('Authorization', `Bearer ${authToken}`)
          .send(assetData);

        testAssetId = response.body.id;
      });

      it('should get all assets', async () => {
        const response = await request(app)
          .get('/api/assets')
          .set('Authorization', `Bearer ${authToken}`)
          .expect(200);

        expect(Array.isArray(response.body.assets)).toBe(true);
        expect(response.body.assets.some((a: any) => a.id === testAssetId)).toBe(true);
      });

      it('should filter assets by category', async () => {
        const response = await request(app)
          .get('/api/assets?category=test-category')
          .set('Authorization', `Bearer ${authToken}`)
          .expect(200);

        expect(response.body.assets.every((a: any) => a.category === 'test-category')).toBe(true);
      });

      it('should search assets by name', async () => {
        const response = await request(app)
          .get('/api/assets?search=Query Test')
          .set('Authorization', `Bearer ${authToken}`)
          .expect(200);

        expect(response.body.assets.some((a: any) => a.name.includes('Query Test'))).toBe(true);
      });

      it('should paginate results', async () => {
        const response = await request(app)
          .get('/api/assets?page=1&limit=5')
          .set('Authorization', `Bearer ${authToken}`)
          .expect(200);

        expect(response.body.assets.length).toBeLessThanOrEqual(5);
        expect(response.body.pagination).toBeDefined();
        expect(typeof response.body.pagination.total).toBe('number');
      });
    });
  });

  describe('Decks API', () => {
    let testDeckId: string;

    describe('POST /api/decks', () => {
      it('should create a new deck', async () => {
        const deckData = {
          name: 'Test Deck',
          description: 'A test deck for API testing',
          gameSystemId: 'test-system',
          cardBackUrl: 'https://example.com/back.png',
        };

        const response = await request(app)
          .post('/api/decks')
          .set('Authorization', `Bearer ${authToken}`)
          .send(deckData)
          .expect(201);

        expect(response.body).toMatchObject({
          name: deckData.name,
          description: deckData.description,
          createdBy: testUserId,
        });

        testDeckId = response.body.id;
      });
    });

    describe('POST /api/decks/:id/cards', () => {
      beforeEach(async () => {
        const deckData = {
          name: 'Card Test Deck',
          gameSystemId: 'test-system',
        };

        const response = await request(app)
          .post('/api/decks')
          .set('Authorization', `Bearer ${authToken}`)
          .send(deckData);

        testDeckId = response.body.id;
      });

      it('should add cards to deck', async () => {
        const cardsData = [
          {
            name: 'Card 1',
            frontImageUrl: 'https://example.com/card1.png',
            orderInDeck: 0,
          },
          {
            name: 'Card 2',
            frontImageUrl: 'https://example.com/card2.png',
            orderInDeck: 1,
          },
        ];

        const response = await request(app)
          .post(`/api/decks/${testDeckId}/cards`)
          .set('Authorization', `Bearer ${authToken}`)
          .send({ cards: cardsData })
          .expect(201);

        expect(response.body.cards).toHaveLength(2);
        expect(response.body.cards[0].deckId).toBe(testDeckId);
      });
    });

    describe('POST /api/decks/:id/shuffle', () => {
      it('should shuffle deck', async () => {
        const deckData = {
          name: 'Shuffle Test Deck',
          gameSystemId: 'test-system',
        };

        const deckResponse = await request(app)
          .post('/api/decks')
          .set('Authorization', `Bearer ${authToken}`)
          .send(deckData);

        const deckId = deckResponse.body.id;

        // Add cards first
        const cardsData = [
          { name: 'Card 1', frontImageUrl: 'https://example.com/1.png', orderInDeck: 0 },
          { name: 'Card 2', frontImageUrl: 'https://example.com/2.png', orderInDeck: 1 },
          { name: 'Card 3', frontImageUrl: 'https://example.com/3.png', orderInDeck: 2 },
        ];

        await request(app)
          .post(`/api/decks/${deckId}/cards`)
          .set('Authorization', `Bearer ${authToken}`)
          .send({ cards: cardsData });

        // Shuffle deck
        const response = await request(app)
          .post(`/api/decks/${deckId}/shuffle`)
          .set('Authorization', `Bearer ${authToken}`)
          .expect(200);

        expect(response.body.message).toContain('shuffled');
      });
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid JSON', async () => {
      const response = await request(app)
        .post('/api/rooms')
        .set('Authorization', `Bearer ${authToken}`)
        .set('Content-Type', 'application/json')
        .send('{"invalid": json}')
        .expect(400);

      expect(response.body.message).toContain('Invalid JSON');
    });

    it('should handle missing Content-Type', async () => {
      await request(app)
        .post('/api/rooms')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ name: 'Test' })
        .expect(201); // Should still work
    });

    it('should handle very large payloads', async () => {
      const largeData = {
        name: 'Test Room',
        gameSystemId: 'test-system',
        description: 'x'.repeat(10000), // Very long description
      };

      const response = await request(app)
        .post('/api/rooms')
        .set('Authorization', `Bearer ${authToken}`)
        .send(largeData);

      // Should either succeed or fail with payload too large error
      expect([201, 413, 400]).toContain(response.status);
    });
  });

  describe('Rate Limiting', () => {
    it('should enforce rate limits', async () => {
      // Make many requests quickly
      const requests = Array.from({ length: 20 }, () =>
        request(app)
          .get('/api/rooms')
          .set('Authorization', `Bearer ${authToken}`)
      );

      const responses = await Promise.all(requests);
      
      // Some requests should be rate limited
      const rateLimitedResponses = responses.filter(r => r.status === 429);
      expect(rateLimitedResponses.length).toBeGreaterThan(0);
    });
  });
});