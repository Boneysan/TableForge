// server/cache/phase3-integration-example.ts
import { createCacheManager } from './cache-manager';
import { RedisCacheService } from './redis-cache';
import { UserSession, GameRoomState } from './types';
import { createApplicationCache } from './application-cache';
import { createDistributedCache } from './distributed-cache';
import { createEdgeCache } from './edge-cache';

/**
 * Phase 3 Integration Example
 * 
 * This demonstrates how to integrate the enhanced RedisCacheService
 * with the existing multi-level cache architecture for maximum
 * performance in production environments.
 */

// Helper function to create complete cache system
function createMultiLevelCache() {
  const applicationCache = createApplicationCache();
  const distributedCache = createDistributedCache();
  const edgeCache = createEdgeCache();
  return createCacheManager(applicationCache, distributedCache, edgeCache);
}

// Example: Enhanced cache service integration
async function demonstratePhase3Integration() {
  console.log('=== Phase 3 Cache Integration Example ===\n');

  // 1. Initialize enhanced Redis cache service
  const enhancedRedis = new RedisCacheService();
  
  // 2. Initialize multi-level cache manager (using existing infrastructure)
  const cacheManager = createMultiLevelCache();

  // 3. Example user session caching workflow
  console.log('1. User Session Cache Workflow:');
  
  const userSession: UserSession = {
    userId: 'user_123',
    sessionId: 'sess_abc456',
    email: 'player@example.com',
    firstName: 'John',
    lastName: 'Doe',
    roles: ['player'],
    permissions: ['read', 'write'],
    lastActivity: Date.now(),
    expiresAt: Date.now() + (24 * 60 * 60 * 1000)
  };

  // Use enhanced Redis for user sessions
  await enhancedRedis.setUserSession('user_123', userSession, 3600);
  const session = await enhancedRedis.getUserSession('user_123');
  console.log('   ✓ Enhanced Redis user session cached and retrieved:', !!session);

  // Use multi-level cache for general data
  const result = await cacheManager.getOrSet(
    'user_profile:user_123',
    'user_profile',
    async () => ({ ...userSession, profileData: 'extended' }),
    1800
  );
  console.log('   ✓ Multi-level cache fallback working:', !!result);

  // 4. Example room state caching with compression
  console.log('\n2. Room State Cache with Compression:');
  
  const roomState: GameRoomState = {
    id: 'room_789',
    name: 'Epic Adventure',
    gameSystemId: 'system_456',
    ownerId: 'user_123',
    isActive: true,
    maxPlayers: 6,
    currentPlayers: 2,
    boardConfig: {
      width: 1920,
      height: 1080,
      gridEnabled: true,
      gridSize: 50,
      gridColor: '#FFFFFF20',
      snapToGrid: true,
      layers: []
    },
    assets: [],
    boardAssets: [],
    players: [],
    gameState: { largeData: 'This would be a large object in production' },
    lastModified: Date.now()
  };

  // Enhanced Redis automatically compresses large room states
  await enhancedRedis.setRoomState('room_789', roomState, 1800);
  const room = await enhancedRedis.getRoomState('room_789');
  console.log('   ✓ Room state cached with compression:', !!room);

  // 5. Batch operations for performance
  console.log('\n3. Batch Operations Performance:');
  
  const batchAssets = [
    { key: 'asset:meta:asset_1', value: { id: 'asset_1', name: 'Token 1' }, ttl: 3600 },
    { key: 'asset:meta:asset_2', value: { id: 'asset_2', name: 'Token 2' }, ttl: 3600 },
    { key: 'asset:meta:asset_3', value: { id: 'asset_3', name: 'Token 3' }, ttl: 3600 }
  ];

  console.time('Batch set operation');
  await enhancedRedis.mset(batchAssets, 'asset_metadata');
  console.timeEnd('Batch set operation');

  console.time('Batch get operation');
  const batchResults = await enhancedRedis.mget(['asset:meta:asset_1', 'asset:meta:asset_2'], 'asset_metadata');
  console.timeEnd('Batch get operation');
  console.log('   ✓ Batch operations completed efficiently:', batchResults.length);

  // 6. Cached query pattern for expensive operations
  console.log('\n4. Cached Query Pattern:');
  
  const expensiveQuery = async () => {
    console.log('   → Executing expensive query...');
    await new Promise(resolve => setTimeout(resolve, 50)); // Simulate delay
    return { result: 'expensive data', computedAt: Date.now() };
  };

  console.time('First query (cache miss)');
  const queryResult1 = await enhancedRedis.getCachedQuery('expensive_operation', expensiveQuery, 300);
  console.timeEnd('First query (cache miss)');

  console.time('Second query (cache hit)');
  const queryResult2 = await enhancedRedis.getCachedQuery('expensive_operation', expensiveQuery, 300);
  console.timeEnd('Second query (cache hit)');
  console.log('   ✓ Cached query pattern working efficiently:', !!queryResult1 && !!queryResult2);

  // 7. Smart invalidation patterns
  console.log('\n5. Smart Invalidation:');
  
  // Invalidate all user-related data
  await enhancedRedis.invalidateUserData('user_123');
  console.log('   ✓ User data invalidated across all patterns');

  // Invalidate room-specific data
  await enhancedRedis.invalidateRoomData('room_789');
  console.log('   ✓ Room data invalidated across all patterns');

  // 8. Health monitoring
  console.log('\n6. Health Monitoring:');
  
  const health = await enhancedRedis.healthCheck();
  const stats = await enhancedRedis.getStats();
  console.log('   ✓ Cache health:', health.status);
  console.log('   ✓ Cache stats:', stats.connected ? 'Connected' : 'Disconnected');

  // 9. Integration benefits summary
  console.log('\n=== Phase 3 Integration Benefits ===');
  console.log('✓ Domain-specific cache methods for optimized performance');
  console.log('✓ Automatic compression for large objects (room states, game systems)');
  console.log('✓ Batch operations for improved throughput');
  console.log('✓ Smart invalidation patterns for data consistency');
  console.log('✓ Cached query pattern for expensive operations');
  console.log('✓ Production-ready health monitoring and statistics');
  console.log('✓ Seamless integration with existing multi-level cache architecture');

  // Cleanup
  await enhancedRedis.close();
  console.log('\n✓ Integration example completed successfully');
}

// Production integration factory
function createEnhancedCacheSystem() {
  return {
    // Enhanced Redis for domain-specific high-performance caching
    redis: new RedisCacheService(),
    
    // Multi-level cache manager for general caching with fallbacks
    multiLevel: createMultiLevelCache(),
    
    // Recommended usage patterns
    patterns: {
      // Use enhanced Redis for:
      userSessions: 'redisCache.setUserSession/getUserSession',
      roomStates: 'redisCache.setRoomState/getRoomState (with compression)',
      assetMetadata: 'redisCache.setAssetMetadata/getAssetMetadata',
      gameSystemTemplates: 'redisCache.setGameSystemTemplate/getGameSystemTemplate',
      expensiveQueries: 'redisCache.getCachedQuery',
      batchOperations: 'redisCache.mset/mget',
      
      // Use multi-level cache for:
      generalData: 'cacheManager.getOrSet with L1/L2/L3 fallback',
      temporaryData: 'cacheManager.set with TTL',
      patternInvalidation: 'cacheManager.invalidatePattern',
      healthChecks: 'cacheManager.getStats for all levels'
    }
  };
}

// Performance comparison helper
async function comparePhase3Performance() {
  console.log('=== Phase 3 Performance Comparison ===\n');
  
  const enhancedRedis = new RedisCacheService();
  const basicCacheManager = createMultiLevelCache();
  
  const testData = { id: 'test', data: 'large'.repeat(1000) }; // Simulate large object
  
  // Test enhanced Redis performance (using public methods)
  console.time('Enhanced Redis setUserSession');
  const userTestData: UserSession = {
    userId: 'test_user',
    sessionId: 'test_session',
    email: 'test@example.com',
    firstName: 'Test',
    lastName: 'User',
    roles: ['player'],
    permissions: ['read'],
    lastActivity: Date.now(),
    expiresAt: Date.now() + 3600000
  };
  await enhancedRedis.setUserSession('test_user', userTestData, 300);
  console.timeEnd('Enhanced Redis setUserSession');
  
  console.time('Enhanced Redis getUserSession');
  await enhancedRedis.getUserSession('test_user');
  console.timeEnd('Enhanced Redis getUserSession');
  
  // Test basic cache performance
  console.time('Basic cache set');
  await basicCacheManager.set('test:basic', testData, 'performance_test', 300);
  console.timeEnd('Basic cache set');
  
  console.time('Basic cache get');
  await basicCacheManager.get('test:basic', 'performance_test');
  console.timeEnd('Basic cache get');
  
  console.log('\n✓ Performance comparison completed');
  
  await enhancedRedis.close();
}

// Export for testing and integration
export {
  demonstratePhase3Integration,
  createEnhancedCacheSystem,
  comparePhase3Performance
};

// Run demonstration if executed directly
if (require.main === module) {
  demonstratePhase3Integration()
    .then(() => comparePhase3Performance())
    .catch(console.error);
}
