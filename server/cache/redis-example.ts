// server/cache/redis-example.ts
import { RedisCacheService } from './redis-cache';
import { UserSession, GameRoomState, AssetMetadata, GameSystemTemplate, RoomPlayer } from './types';

/**
 * Redis Cache Service Usage Examples
 * 
 * This demonstrates the enhanced Redis implementation from Phase 3
 * Performance & Scalability specifications, including domain-specific
 * caching methods, compression support, and batch operations.
 */

// Initialize Redis cache service
const redisCache = new RedisCacheService();

// Example domain objects
const exampleUserSession: UserSession = {
  userId: 'user_123',
  sessionId: 'sess_abc456',
  email: 'player@example.com',
  firstName: 'John',
  lastName: 'Doe',
  profileImageUrl: 'https://example.com/avatar.jpg',
  roles: ['player', 'user'],
  permissions: ['read', 'write'],
  lastActivity: Date.now(),
  expiresAt: Date.now() + (24 * 60 * 60 * 1000) // 24 hours
};

const exampleRoomState: GameRoomState = {
  id: 'room_789',
  name: 'Epic Fantasy Adventure',
  gameSystemId: 'system_456',
  ownerId: 'user_123',
  isActive: true,
  maxPlayers: 6,
  currentPlayers: 2,
  boardConfig: {
    width: 1920,
    height: 1080,
    backgroundImage: 'fantasy_map.jpg',
    backgroundColor: '#2D4A3E',
    gridEnabled: true,
    gridSize: 50,
    gridColor: '#FFFFFF20',
    snapToGrid: true,
    layers: []
  },
  assets: [],
  boardAssets: [],
  players: [
    { 
      id: 'player_1', 
      roomId: 'room_789', 
      playerId: 'user_123', 
      role: 'player', 
      isOnline: true, 
      joinedAt: Date.now(),
      lastActivity: Date.now(),
      firstName: 'John',
      lastName: 'Doe',
      profileImageUrl: 'https://example.com/avatar1.jpg'
    },
    { 
      id: 'player_2', 
      roomId: 'room_789', 
      playerId: 'user_456', 
      role: 'player', 
      isOnline: true, 
      joinedAt: Date.now(),
      lastActivity: Date.now(),
      firstName: 'Jane',
      lastName: 'Smith',
      profileImageUrl: 'https://example.com/avatar2.jpg'
    }
  ] as RoomPlayer[],
  gameState: {
    round: 5,
    currentTurn: 'user_123',
    score: { user_123: 100, user_456: 85 }
  },
  lastModified: Date.now()
};

const exampleAssetMetadata: AssetMetadata = {
  id: 'asset_321',
  name: 'Character Token',
  type: 'token',
  filePath: '/assets/tokens/character_token.png',
  fileName: 'character_token.png',
  fileSize: 2048576,
  mimeType: 'image/png',
  width: 256,
  height: 256,
  gameSystemId: 'system_456',
  roomId: 'room_789',
  uploadedBy: 'user_123',
  uploadedAt: Date.now(),
  isPublic: true,
  tags: ['character', 'token', 'fantasy'],
  metadata: {
    character: 'warrior',
    rarity: 'common'
  }
};

const exampleGameSystem: GameSystemTemplate = {
  id: 'system_456',
  name: 'Fantasy Adventure RPG',
  description: 'A classic fantasy role-playing game system',
  category: 'RPG',
  complexity: 'intermediate',
  playerCount: {
    min: 2,
    max: 6,
    recommended: 4
  },
  playTime: {
    min: 120,
    max: 240,
    average: 180
  },
  rules: 'Complete rulebook with character creation, combat system, and spell mechanics',
  setupInstructions: 'Each player creates a character, GM sets up the adventure scenario, distribute starting equipment',
  assets: [] as AssetMetadata[],
  isOfficial: false,
  isPublic: true,
  rating: 4.5,
  downloadCount: 1250,
  createdBy: 'user_123',
  createdAt: Date.now(),
  updatedAt: Date.now(),
  version: '2.1.0'
};

async function demonstrateUserSessionCaching() {
  console.log('=== User Session Caching ===');
  
  // Cache user session
  const setCached = await redisCache.setUserSession('user_123', exampleUserSession, 3600);
  console.log('User session cached:', setCached);
  
  // Retrieve user session
  const retrievedSession = await redisCache.getUserSession('user_123');
  console.log('Retrieved session:', retrievedSession);
  
  // Cache miss example
  const missedSession = await redisCache.getUserSession('nonexistent_user');
  console.log('Cache miss result:', missedSession);
}

async function demonstrateRoomStateCaching() {
  console.log('\n=== Room State Caching (with compression) ===');
  
  // Cache room state (uses compression for large objects)
  const setCached = await redisCache.setRoomState('room_789', exampleRoomState, 1800);
  console.log('Room state cached:', setCached);
  
  // Retrieve room state
  const retrievedState = await redisCache.getRoomState('room_789');
  console.log('Retrieved room state:', retrievedState);
}

async function demonstrateAssetMetadataCaching() {
  console.log('\n=== Asset Metadata Caching ===');
  
  // Cache asset metadata (longer TTL for static assets)
  const setCached = await redisCache.setAssetMetadata('asset_321', exampleAssetMetadata);
  console.log('Asset metadata cached:', setCached);
  
  // Retrieve asset metadata
  const retrievedMetadata = await redisCache.getAssetMetadata('asset_321');
  console.log('Retrieved metadata:', retrievedMetadata);
}

async function demonstrateGameSystemCaching() {
  console.log('\n=== Game System Template Caching ===');
  
  // Cache game system template (very long TTL for rarely changing data)
  const setCached = await redisCache.setGameSystemTemplate('system_456', exampleGameSystem);
  console.log('Game system cached:', setCached);
  
  // Retrieve game system template
  const retrievedSystem = await redisCache.getGameSystemTemplate('system_456');
  console.log('Retrieved game system:', retrievedSystem);
}

async function demonstrateBatchOperations() {
  console.log('\n=== Batch Operations ===');
  
  // Batch set multiple assets
  const batchItems = [
    { key: 'asset:meta:asset_1', value: { ...exampleAssetMetadata, assetId: 'asset_1' }, ttl: 3600 },
    { key: 'asset:meta:asset_2', value: { ...exampleAssetMetadata, assetId: 'asset_2' }, ttl: 3600 },
    { key: 'asset:meta:asset_3', value: { ...exampleAssetMetadata, assetId: 'asset_3' }, ttl: 3600 }
  ];
  
  const batchSet = await redisCache.mset(batchItems, 'asset_metadata');
  console.log('Batch set result:', batchSet);
  
  // Batch get multiple assets
  const assetKeys = ['asset:meta:asset_1', 'asset:meta:asset_2', 'asset:meta:asset_3'];
  const batchGet = await redisCache.mget<AssetMetadata>(assetKeys, 'asset_metadata');
  console.log('Batch get results:', batchGet);
}

async function demonstrateCachedQueries() {
  console.log('\n=== Cached Query Operations ===');
  
  // Simulate expensive database query with caching
  const expensiveQuery = async (): Promise<{ users: string[], count: number }> => {
    console.log('Executing expensive query...');
    // Simulate delay
    await new Promise(resolve => setTimeout(resolve, 100));
    return {
      users: ['user_123', 'user_456', 'user_789'],
      count: 3
    };
  };
  
  // First call executes query
  console.time('First query');
  const result1 = await redisCache.getCachedQuery('active_users_list', expensiveQuery, 300);
  console.timeEnd('First query');
  console.log('First result:', result1);
  
  // Second call returns cached result
  console.time('Cached query');
  const result2 = await redisCache.getCachedQuery('active_users_list', expensiveQuery, 300);
  console.timeEnd('Cached query');
  console.log('Cached result:', result2);
}

async function demonstrateInvalidation() {
  console.log('\n=== Cache Invalidation ===');
  
  // Set up some test data
  await redisCache.setUserSession('user_123', exampleUserSession);
  await redisCache.setRoomState('room_789', exampleRoomState);
  
  // Invalidate user-specific data
  console.log('Invalidating user data...');
  await redisCache.invalidateUserData('user_123');
  
  // Verify invalidation
  const invalidatedSession = await redisCache.getUserSession('user_123');
  console.log('Session after invalidation:', invalidatedSession);
  
  // Invalidate room-specific data
  console.log('Invalidating room data...');
  await redisCache.invalidateRoomData('room_789');
  
  // Verify invalidation
  const invalidatedRoom = await redisCache.getRoomState('room_789');
  console.log('Room state after invalidation:', invalidatedRoom);
}

async function demonstrateHealthAndStats() {
  console.log('\n=== Health Check and Statistics ===');
  
  // Health check
  const health = await redisCache.healthCheck();
  console.log('Cache health:', health);
  
  // Get cache statistics
  const stats = await redisCache.getStats();
  console.log('Cache stats:', stats);
}

// Main demonstration function
async function runRedisExamples() {
  try {
    console.log('Redis Cache Service Examples');
    console.log('============================');
    
    await demonstrateUserSessionCaching();
    await demonstrateRoomStateCaching();
    await demonstrateAssetMetadataCaching();
    await demonstrateGameSystemCaching();
    await demonstrateBatchOperations();
    await demonstrateCachedQueries();
    await demonstrateInvalidation();
    await demonstrateHealthAndStats();
    
    console.log('\n=== All Examples Completed ===');
    
  } catch (error) {
    console.error('Error running Redis examples:', error);
  } finally {
    // Clean up
    await redisCache.close();
  }
}

// Export for use in other modules
export {
  runRedisExamples,
  demonstrateUserSessionCaching,
  demonstrateRoomStateCaching,
  demonstrateAssetMetadataCaching,
  demonstrateGameSystemCaching,
  demonstrateBatchOperations,
  demonstrateCachedQueries,
  demonstrateInvalidation,
  demonstrateHealthAndStats
};

// Run examples if this file is executed directly
if (require.main === module) {
  runRedisExamples();
}
