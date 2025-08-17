// server/cache/cache-manager.ts
import { ApplicationCache, DistributedCache, EdgeCache, CacheStrategy, CacheOperationResult } from './types';
import { cacheConfig } from './config';
import { createUserLogger } from '../utils/logger';

// Cache-specific logger
const cacheLogger = createUserLogger('cache-system');

export class MultiLevelCacheManager implements CacheStrategy {
  public applicationCache: ApplicationCache;
  public distributedCache: DistributedCache;
  public edgeCache: EdgeCache;

  private readonly hitRateWindow = 1000;
  private hitRateHistory: boolean[] = [];

  constructor(
    applicationCache: ApplicationCache,
    distributedCache: DistributedCache,
    edgeCache: EdgeCache
  ) {
    this.applicationCache = applicationCache;
    this.distributedCache = distributedCache;
    this.edgeCache = edgeCache;
  }

  // Primary cache operations with cascading fallback
  async get<T>(key: string, cacheType: string): Promise<CacheOperationResult<T>> {
    const startTime = Date.now();

    try {
      // L1: Application cache (fastest)
      const l1Result = this.applicationCache.get<T>(key, cacheType);
      if (l1Result !== null) {
        const duration = Date.now() - startTime;
        this.recordHit();
        
        return {
          success: true,
          data: l1Result,
          fromCache: true,
          cacheLevel: 'L1',
          duration
        };
      }

      // L2: Distributed cache (Redis)
      const l2Result = await this.distributedCache.get<T>(key);
      if (l2Result !== null) {
        const duration = Date.now() - startTime;
        
        // Populate L1 cache for next time
        this.applicationCache.set(key, l2Result, cacheType, 
          cacheConfig.getApplicationCacheConfig().defaultTTL);
        
        this.recordHit();
        
        return {
          success: true,
          data: l2Result,
          fromCache: true,
          cacheLevel: 'L2',
          duration
        };
      }

      // L3: Edge cache (CDN)
      const l3Result = await this.edgeCache.get<T>(key);
      if (l3Result !== null) {
        const duration = Date.now() - startTime;
        
        // Populate L1 and L2 caches
        this.applicationCache.set(key, l3Result, cacheType,
          cacheConfig.getApplicationCacheConfig().defaultTTL);
        await this.distributedCache.set(key, l3Result,
          cacheConfig.getDistributedCacheConfig().defaultTTL);
        
        this.recordHit();
        
        return {
          success: true,
          data: l3Result,
          fromCache: true,
          cacheLevel: 'L3',
          duration
        };
      }

      // Cache miss across all levels
      const duration = Date.now() - startTime;
      this.recordMiss();
      
      return {
        success: false,
        fromCache: false,
        duration,
        error: 'Cache miss across all levels'
      };

    } catch (error) {
      const duration = Date.now() - startTime;
      
      cacheLogger.error('Multi-level cache get error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        cacheType,
        operation: 'get',
        duration
      });

      return {
        success: false,
        fromCache: false,
        duration,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  // Set data across cache levels with TTL propagation
  async set<T>(
    key: string, 
    value: T, 
    cacheType: string, 
    ttl?: number
  ): Promise<CacheOperationResult<boolean>> {
    const startTime = Date.now();

    try {
      const l1TTL = ttl || cacheConfig.getApplicationCacheConfig().defaultTTL;
      const l2TTL = ttl || cacheConfig.getDistributedCacheConfig().defaultTTL;
      const l3TTL = ttl || cacheConfig.getEdgeCacheConfig().defaultTTL;

      // Set in all cache levels (parallel for L2 and L3)
      const [l1Success, l2Success, l3Success] = await Promise.allSettled([
        Promise.resolve(this.applicationCache.set(key, value, cacheType, l1TTL)),
        this.distributedCache.set(key, value, l2TTL),
        this.edgeCache.set(key, value, l3TTL)
      ]);

      const results = [
        { level: 'L1', success: l1Success.status === 'fulfilled' ? l1Success.value : false },
        { level: 'L2', success: l2Success.status === 'fulfilled' ? l2Success.value : false },
        { level: 'L3', success: l3Success.status === 'fulfilled' ? l3Success.value : false }
      ];

      const duration = Date.now() - startTime;
      const successCount = results.filter(r => r.success).length;
      const allSuccess = successCount === 3;

      if (!allSuccess) {
        cacheLogger.warn('Partial cache set failure', {
          successCount,
          totalLevels: 3,
          cacheType,
          operation: 'set',
          results
        });
      }

      return {
        success: allSuccess,
        data: allSuccess,
        fromCache: false,
        duration
      };

    } catch (error) {
      const duration = Date.now() - startTime;
      
      cacheLogger.error('Multi-level cache set error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        cacheType,
        operation: 'set',
        duration
      });
      
      return {
        success: false,
        data: false,
        fromCache: false,
        duration,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  // Cache with data loader pattern
  async getOrSet<T>(
    key: string,
    cacheType: string,
    dataLoader: () => Promise<T>,
    ttl?: number
  ): Promise<CacheOperationResult<T>> {
    // Try to get from cache first
    const cacheResult = await this.get<T>(key, cacheType);
    
    if (cacheResult.success && cacheResult.data !== undefined) {
      return cacheResult;
    }

    // Load data and set in cache
    const startTime = Date.now();
    
    try {
      const data = await dataLoader();
      await this.set(key, data, cacheType, ttl);
      
      const duration = Date.now() - startTime;
      
      return {
        success: true,
        data,
        fromCache: false,
        duration
      };
    } catch (error) {
      const duration = Date.now() - startTime;
      
      cacheLogger.error('Data loader failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        cacheType,
        key,
        duration
      });
      
      return {
        success: false,
        fromCache: false,
        duration,
        error: error instanceof Error ? error.message : 'Data loader failed'
      };
    }
  }

  // Invalidation across all cache levels
  async invalidate(pattern: string): Promise<{ level: string; count: number }[]> {
    const startTime = Date.now();
    
    try {
      const [l1Count, l2Count, l3Count] = await Promise.allSettled([
        Promise.resolve(this.applicationCache.invalidate(pattern)),
        this.distributedCache.invalidatePattern(pattern),
        this.edgeCache.invalidate(pattern)
      ]);

      const results = [
        { level: 'L1', count: l1Count.status === 'fulfilled' ? l1Count.value : 0 },
        { level: 'L2', count: l2Count.status === 'fulfilled' ? l2Count.value : 0 },
        { level: 'L3', count: l3Count.status === 'fulfilled' ? l3Count.value : 0 }
      ];

      const duration = Date.now() - startTime;
      const totalInvalidated = results.reduce((sum, r) => sum + r.count, 0);
      
      cacheLogger.debug('Cache invalidation completed', {
        pattern,
        duration,
        totalInvalidated,
        results
      });

      return results;
    } catch (error) {
      cacheLogger.error('Cache invalidation error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        pattern
      });
      
      throw error;
    }
  }

  // Specialized invalidation methods
  async invalidateUserData(userId: string): Promise<void> {
    await Promise.all([
      this.invalidate(`user:*:${userId}*`),
      this.distributedCache.invalidatePattern(`user:*:${userId}*`)
    ]);
    
    cacheLogger.info('User data invalidated', { userId });
  }

  async invalidateRoomData(roomId: string): Promise<void> {
    await Promise.all([
      this.invalidate(`room:*:${roomId}*`),
      this.distributedCache.invalidatePattern(`room:*:${roomId}*`)
    ]);
    
    cacheLogger.info('Room data invalidated', { roomId });
  }

  // Health check across all cache levels
  async healthCheck(): Promise<{
    overall: 'healthy' | 'degraded' | 'unhealthy';
    levels: Array<{ level: string; status: string; info?: any }>;
  }> {
    try {
      const [l1Stats, l2Health, l3Stats] = await Promise.allSettled([
        Promise.resolve(this.applicationCache.getStats()),
        this.distributedCache.healthCheck(),
        this.edgeCache.getStats()
      ]);

      const levels = [
        {
          level: 'L1',
          status: l1Stats.status === 'fulfilled' ? 'healthy' : 'unhealthy',
          info: l1Stats.status === 'fulfilled' ? l1Stats.value : undefined
        },
        {
          level: 'L2',
          status: l2Health.status === 'fulfilled' ? l2Health.value.status : 'unhealthy',
          info: l2Health.status === 'fulfilled' ? l2Health.value : undefined
        },
        {
          level: 'L3',
          status: l3Stats.status === 'fulfilled' ? 'healthy' : 'unhealthy',
          info: l3Stats.status === 'fulfilled' ? l3Stats.value : undefined
        }
      ];

      const healthyCount = levels.filter(l => l.status === 'healthy').length;
      let overall: 'healthy' | 'degraded' | 'unhealthy';

      if (healthyCount === 3) {
        overall = 'healthy';
      } else if (healthyCount >= 1) {
        overall = 'degraded';
      } else {
        overall = 'unhealthy';
      }

      return { overall, levels };
    } catch (error) {
      cacheLogger.error('Cache health check failed', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      
      return {
        overall: 'unhealthy',
        levels: [
          { level: 'L1', status: 'unknown' },
          { level: 'L2', status: 'unknown' },
          { level: 'L3', status: 'unknown' }
        ]
      };
    }
  }

  // Performance monitoring and statistics
  async getComprehensiveStats(): Promise<{
    hitRate: number;
    levels: Array<{ level: string; stats: any }>;
    performance: {
      totalOperations: number;
    };
  }> {
    try {
      const [l1Stats, l2Stats, l3Stats] = await Promise.allSettled([
        Promise.resolve(this.applicationCache.getStats()),
        this.distributedCache.getStats(),
        this.edgeCache.getStats()
      ]);

      const levels = [
        {
          level: 'L1',
          stats: l1Stats.status === 'fulfilled' ? l1Stats.value : { error: 'Failed to get stats' }
        },
        {
          level: 'L2',
          stats: l2Stats.status === 'fulfilled' ? l2Stats.value : { error: 'Failed to get stats' }
        },
        {
          level: 'L3',
          stats: l3Stats.status === 'fulfilled' ? l3Stats.value : { error: 'Failed to get stats' }
        }
      ];

      return {
        hitRate: this.calculateCurrentHitRate(),
        levels,
        performance: {
          totalOperations: this.hitRateHistory.length
        }
      };
    } catch (error) {
      cacheLogger.error('Failed to get comprehensive cache stats', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      
      throw error;
    }
  }

  // Cleanup and shutdown
  async shutdown(): Promise<void> {
    try {
      await this.distributedCache.close();
      cacheLogger.info('Multi-level cache manager shutdown completed');
    } catch (error) {
      cacheLogger.error('Error during cache manager shutdown', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      
      throw error;
    }
  }

  // Private utility methods
  private recordHit(): void {
    this.hitRateHistory.push(true);
    if (this.hitRateHistory.length > this.hitRateWindow) {
      this.hitRateHistory.shift();
    }
    
    const hitRate = this.calculateCurrentHitRate();
    
    // Warn if hit rate drops below threshold
    if (hitRate < 0.5 && this.hitRateHistory.length >= 100) {
      cacheLogger.warn('Cache hit rate below threshold', {
        hitRate,
        threshold: 0.5,
        recentOperations: this.hitRateHistory.length
      });
    }
  }

  private recordMiss(): void {
    this.hitRateHistory.push(false);
    if (this.hitRateHistory.length > this.hitRateWindow) {
      this.hitRateHistory.shift();
    }
  }

  private calculateCurrentHitRate(): number {
    if (this.hitRateHistory.length === 0) return 0;
    
    const hits = this.hitRateHistory.filter(Boolean).length;
    return hits / this.hitRateHistory.length;
  }
}

// Factory function for creating cache manager
export function createCacheManager(
  applicationCache: ApplicationCache,
  distributedCache: DistributedCache,
  edgeCache: EdgeCache
): MultiLevelCacheManager {
  return new MultiLevelCacheManager(applicationCache, distributedCache, edgeCache);
}
