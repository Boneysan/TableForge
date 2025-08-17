// server/cache/index.ts
export type { 
  CacheStrategy, 
  ApplicationCache, 
  DistributedCache, 
  EdgeCache,
  CacheItem,
  CacheConfig,
  CacheOperationResult,
  CacheStats,
  UserSession,
  GameRoomState,
  AssetMetadata,
  GameSystemTemplate
} from './types';

export { CacheConfigService, cacheConfig } from './config';

export { 
  MultiLevelCacheManager, 
  createCacheManager 
} from './cache-manager';

export { 
  MemoryApplicationCache, 
  createApplicationCache 
} from './application-cache';

export { 
  RedisDistributedCache, 
  createDistributedCache 
} from './distributed-cache';

export { 
  CDNEdgeCache, 
  createEdgeCache 
} from './edge-cache';

import { createApplicationCache } from './application-cache';
import { createDistributedCache } from './distributed-cache';
import { createEdgeCache } from './edge-cache';
import { createCacheManager, MultiLevelCacheManager } from './cache-manager';

// Convenience factory function to create a complete cache system
export function createMultiLevelCache(): MultiLevelCacheManager {
  const applicationCache = createApplicationCache();
  const distributedCache = createDistributedCache();
  const edgeCache = createEdgeCache();
  
  return createCacheManager(applicationCache, distributedCache, edgeCache);
}

// Pre-configured cache managers for different environments
export function createDevelopmentCache(): MultiLevelCacheManager {
  // Development uses mock implementations for all levels
  return createMultiLevelCache();
}

export function createProductionCache(redisClient?: any, edgeProvider?: any): MultiLevelCacheManager {
  const applicationCache = createApplicationCache();
  const distributedCache = createDistributedCache(redisClient);
  const edgeCache = createEdgeCache(edgeProvider);
  
  return createCacheManager(applicationCache, distributedCache, edgeCache);
}
