// server/cache/examples.ts
import { createMultiLevelCache, UserSession, GameRoomState, AssetMetadata } from './index';

// Initialize the cache system
const cache = createMultiLevelCache();

// Example 1: User Session Management
export async function getUserSession(userId: string): Promise<UserSession | null> {
  const result = await cache.getOrSet(
    userId,
    'user-session',
    async () => {
      // Simulate database lookup
      console.log(`Loading user session from database: ${userId}`);
      return {
        userId,
        authProvider: 'firebase' as const,
        permissions: ['read', 'write'],
        expiresAt: Date.now() + (24 * 60 * 60 * 1000) // 24 hours
      };
    },
    3600 // 1 hour cache TTL
  );
  
  return result.success ? result.data || null : null;
}

// Example 2: Game Room State Caching
export async function getRoomState(roomId: string): Promise<GameRoomState | null> {
  return await cache.getOrSet(
    roomId,
    'room-state',
    async () => {
      console.log(`Loading room state from database: ${roomId}`);
      return {
        roomId,
        boardConfig: { width: 1200, height: 800 },
        assets: [],
        connectedUsers: [],
        lastModified: Date.now()
      };
    },
    1800 // 30 minute cache TTL
  ).then(result => result.success ? result.data : null);
}

// Example 3: Asset Metadata Caching
export async function getAssetMetadata(assetId: string): Promise<AssetMetadata | null> {
  return await cache.getOrSet(
    assetId,
    'asset-metadata',
    async () => {
      console.log(`Loading asset metadata from database: ${assetId}`);
      return {
        assetId,
        fileName: 'example.png',
        mimeType: 'image/png',
        sizeBytes: 1024000,
        uploaderId: 'user-123',
        roomId: 'room-abc'
      };
    },
    7200 // 2 hour cache TTL
  ).then(result => result.success ? result.data : null);
}

// Example 4: Batch Operations
export async function batchLoadUsers(userIds: string[]): Promise<UserSession[]> {
  const results = await Promise.allSettled(
    userIds.map(userId => getUserSession(userId))
  );
  
  return results
    .filter(result => result.status === 'fulfilled' && result.value !== null)
    .map(result => (result as PromiseFulfilledResult<UserSession>).value);
}

// Example 5: Cache Invalidation Patterns
export async function userLogout(userId: string): Promise<void> {
  // Invalidate user-specific cache entries
  await cache.invalidateUserData(userId);
  console.log(`Invalidated cache for user: ${userId}`);
}

export async function roomClosed(roomId: string): Promise<void> {
  // Invalidate room-specific cache entries
  await cache.invalidateRoomData(roomId);
  console.log(`Invalidated cache for room: ${roomId}`);
}

// Example 6: Performance Monitoring
export async function getCachePerformanceStats(): Promise<void> {
  const stats = await cache.getComprehensiveStats();
  
  console.log('Cache Performance Statistics:');
  console.log(`Overall Hit Rate: ${(stats.hitRate * 100).toFixed(2)}%`);
  console.log(`Total Operations: ${stats.performance.totalOperations}`);
  
  stats.levels.forEach((level, index) => {
    const levelName = ['L1 (Application)', 'L2 (Distributed)', 'L3 (Edge)'][index];
    console.log(`${levelName}:`);
    console.log(`  Size: ${level.stats.size || 'N/A'}`);
    console.log(`  Memory: ${level.stats.memoryUsage || 0} bytes`);
  });
}

// Example 7: Health Check Integration
export async function checkCacheHealth(): Promise<boolean> {
  const health = await cache.healthCheck();
  
  console.log(`Cache System Status: ${health.overall}`);
  
  health.levels.forEach(level => {
    console.log(`${level.level}: ${level.status}`);
    if (level.info) {
      console.log(`  Info:`, level.info);
    }
  });
  
  return health.overall === 'healthy';
}

// Example 8: WebSocket Integration Pattern
export async function handleWebSocketMessage(userId: string, roomId: string, messageType: string, _data: any): Promise<void> {
  // Cache user session for permission checking
  const userSession = await getUserSession(userId);
  if (!userSession) {
    throw new Error('Invalid user session');
  }
  
  // Cache room state for message processing
  const roomState = await getRoomState(roomId);
  if (!roomState) {
    throw new Error('Room not found');
  }
  
  // Process message based on type
  switch (messageType) {
    case 'move_asset':
      // Update cached room state
      roomState.lastModified = Date.now();
      await cache.set(roomId, roomState, 'room-state', 1800);
      break;
      
    case 'user_join':
      // Add user to room's players
      const existingPlayer = roomState.players.find(p => p.userId === userId);
      if (!existingPlayer) {
        roomState.players.push({
          userId,
          role: 'player',
          isReady: false,
          joinedAt: Date.now()
        });
        roomState.currentPlayers++;
        await cache.set(roomId, roomState, 'room-state', 1800);
      }
      break;
      
    case 'user_leave':
      // Remove user from room's players
      roomState.players = roomState.players.filter((p: any) => p.userId !== userId);
      roomState.currentPlayers = Math.max(0, roomState.currentPlayers - 1);
      await cache.set(roomId, roomState, 'room-state', 1800);
      break;
  }
  
  console.log(`Processed ${messageType} for user ${userId} in room ${roomId}`);
}

// Example 9: API Response Caching
export async function getPublicGameTemplates(): Promise<any[]> {
  return await cache.getOrSet(
    'all-public-templates',
    'game-templates',
    async () => {
      console.log('Loading public game templates from database');
      // Simulate expensive database query
      return [
        { id: 'template-1', name: 'Chess Board', category: 'board' },
        { id: 'template-2', name: 'Poker Deck', category: 'card' },
        { id: 'template-3', name: 'D20 Dice Set', category: 'dice' }
      ];
    },
    3600 // 1 hour cache
  ).then(result => result.success ? result.data : []);
}

// Example 10: Edge Cache for Static Assets
export async function cacheStaticAsset(assetId: string, assetData: Buffer, contentType: string): Promise<boolean> {
  return await cache.edgeCache.cacheAsset(assetId, assetData, contentType);
}

export async function getStaticAsset(assetId: string, contentType: string): Promise<Buffer | null> {
  return await cache.edgeCache.getCachedAsset(assetId, contentType);
}

// Example 11: Demonstration Function
export async function demonstrateCacheSystem(): Promise<void> {
  console.log('=== Multi-Level Cache System Demonstration ===\n');
  
  // 1. User Session Caching
  console.log('1. User Session Caching:');
  const user1 = await getUserSession('user-123');
  console.log('First call (cache miss):', user1);
  
  const user2 = await getUserSession('user-123');
  console.log('Second call (cache hit):', user2);
  console.log();
  
  // 2. Room State Caching
  console.log('2. Room State Caching:');
  const room1 = await getRoomState('room-abc');
  console.log('First call (cache miss):', room1);
  
  const room2 = await getRoomState('room-abc');
  console.log('Second call (cache hit):', room2);
  console.log();
  
  // 3. Performance Statistics
  console.log('3. Performance Statistics:');
  await getCachePerformanceStats();
  console.log();
  
  // 4. Health Check
  console.log('4. Health Check:');
  await checkCacheHealth();
  console.log();
  
  // 5. Cache Invalidation
  console.log('5. Cache Invalidation:');
  await userLogout('user-123');
  await roomClosed('room-abc');
  console.log();
  
  // 6. Final Statistics
  console.log('6. Final Performance Statistics:');
  await getCachePerformanceStats();
  
  console.log('\n=== Demonstration Complete ===');
}

// Export demonstration function for testing
if (require.main === module) {
  demonstrateCacheSystem().catch(console.error);
}
