// server/cache/cache-manager-phase3.ts
// Phase 3 Unified cache manager integrating all caching components

import { CacheConfig, CacheStats, CacheStrategy, ApplicationCache, DistributedCache } from './types';
import { createUserLogger } from '../utils/logger';
import { metrics } from '../observability/metrics';
import RedisCacheService from './redis-cache-phase3';
import { CacheInvalidationManager, InvalidationEvent } from './cache-invalidation-strategies';
import CacheMonitoringService, { CacheMonitoringConfig, defaultMonitoringConfig } from './cache-monitoring';

const logger = createUserLogger('cache-manager');

export interface CacheManagerConfig {
  applicationCache: CacheConfig;
  distributedCache: CacheConfig;
  monitoring: CacheMonitoringConfig;
  invalidation: {
    enabled: boolean;
    batchSize: number;
    processingInterval: number;
  };
}

export class CacheManagerPhase3 implements CacheStrategy {
  private appCacheInstance: ApplicationCache;
  private distCacheInstance: DistributedCache;
  private invalidationManager: CacheInvalidationManager;
  private monitoringService: CacheMonitoringService;
  private config: CacheManagerConfig;
  private initialized = false;

  constructor(config: CacheManagerConfig) {
    this.config = config;
    
    // Initialize cache instances
    this.initializeCaches();
    
    // Initialize monitoring
    this.monitoringService = new CacheMonitoringService(config.monitoring);
    
    // Initialize invalidation manager
    this.invalidationManager = new CacheInvalidationManager(
      this.appCacheInstance as any, // TODO: Fix type compatibility
      this.distCacheInstance as RedisCacheService
    );

    logger.info('Cache manager phase 3 initialized', {
      applicationCache: config.applicationCache.maxSize,
      distributedCache: config.distributedCache.defaultTTL,
      monitoring: config.monitoring.enabled,
      invalidation: config.invalidation.enabled
    });
  }

  get applicationCache(): ApplicationCache {
    return this.appCacheInstance;
  }

  get distributedCache(): DistributedCache {
    return this.distCacheInstance;
  }

  get edgeCache() {
    return undefined; // Future implementation
  }

  // Initialize cache instances
  private initializeCaches(): void {
    try {
      // Import and initialize application cache
      const ApplicationCachePhase3 = require('./application-cache-phase3-impl').default;
      this.appCacheInstance = new ApplicationCachePhase3(this.config.applicationCache);

      // Initialize distributed cache
      this.distCacheInstance = new RedisCacheService(this.config.distributedCache);

      this.initialized = true;
      logger.info('Cache instances initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize cache instances', { error });
      throw error;
    }
  }

  // Unified cache operations with L1/L2 fallback
  async get<T>(key: string, options?: { 
    cacheType?: string;
    skipL1?: boolean;
    skipL2?: boolean;
  }): Promise<T | null> {
    const cacheType = options?.cacheType || 'unified';
    const startTime = Date.now();

    try {
      // L1 Cache (Application) - fastest
      if (!options?.skipL1) {
        const l1Result = this.appCacheInstance.get<T>(key, cacheType);
        if (l1Result !== null) {
          this.recordCacheHit('L1', cacheType, Date.now() - startTime);
          return l1Result;
        }
      }

      // L2 Cache (Redis) - distributed
      if (!options?.skipL2) {
        const l2Result = await this.distCacheInstance.get<T>(key);
        if (l2Result !== null) {
          // Populate L1 cache for faster future access
          if (!options?.skipL1) {
            this.appCacheInstance.set(key, l2Result, cacheType);
          }
          
          this.recordCacheHit('L2', cacheType, Date.now() - startTime);
          return l2Result;
        }
      }

      // Cache miss
      this.recordCacheMiss(cacheType, Date.now() - startTime);
      return null;

    } catch (error) {
      this.recordCacheError('get', cacheType, error, Date.now() - startTime);
      logger.error('Cache get operation failed', { key, cacheType, error });
      return null;
    }
  }

  async set<T>(key: string, value: T, options?: {
    cacheType?: string;
    ttl?: number;
    skipL1?: boolean;
    skipL2?: boolean;
  }): Promise<boolean> {
    const cacheType = options?.cacheType || 'unified';
    const startTime = Date.now();

    try {
      let l1Success = true;
      let l2Success = true;

      // Set in L1 Cache (Application)
      if (!options?.skipL1) {
        l1Success = this.appCacheInstance.set(key, value, cacheType, options?.ttl);
      }

      // Set in L2 Cache (Redis)
      if (!options?.skipL2) {
        l2Success = await this.distCacheInstance.set(key, value, options?.ttl);
      }

      const success = l1Success && l2Success;
      const duration = Date.now() - startTime;

      if (success) {
        this.recordCacheSet(cacheType, duration);
      } else {
        this.recordCacheError('set', cacheType, new Error('Partial cache set failure'), duration);
      }

      return success;

    } catch (error) {
      this.recordCacheError('set', cacheType, error, Date.now() - startTime);
      logger.error('Cache set operation failed', { key, cacheType, error });
      return false;
    }
  }

  async delete(key: string, options?: {
    cacheType?: string;
    skipL1?: boolean;
    skipL2?: boolean;
  }): Promise<boolean> {
    const cacheType = options?.cacheType || 'unified';
    const startTime = Date.now();

    try {
      let l1Success = true;
      let l2Success = true;

      // Delete from L1 Cache
      if (!options?.skipL1) {
        // Note: ApplicationCache interface doesn't have delete method, using invalidate
        this.appCacheInstance.invalidate(key);
      }

      // Delete from L2 Cache
      if (!options?.skipL2) {
        l2Success = await this.distCacheInstance.delete(key);
      }

      const duration = Date.now() - startTime;
      this.recordCacheDelete(cacheType, duration);

      return l1Success && l2Success;

    } catch (error) {
      this.recordCacheError('delete', cacheType, error, Date.now() - startTime);
      logger.error('Cache delete operation failed', { key, cacheType, error });
      return false;
    }
  }

  // Batch operations
  async mget<T>(keys: string[], options?: {
    cacheType?: string;
    skipL1?: boolean;
    skipL2?: boolean;
  }): Promise<Array<T | null>> {
    const cacheType = options?.cacheType || 'unified';
    const startTime = Date.now();

    try {
      const results: Array<T | null> = new Array(keys.length).fill(null);
      const missingKeys: string[] = [];
      const missingIndices: number[] = [];

      // Check L1 Cache first
      if (!options?.skipL1) {
        for (let i = 0; i < keys.length; i++) {
          const key = keys[i];
          if (key) {
            const result = this.appCacheInstance.get<T>(key, cacheType);
            if (result !== null) {
              results[i] = result;
            } else {
              missingKeys.push(key);
              missingIndices.push(i);
            }
          }
        }
      } else {
        missingKeys.push(...keys.filter(k => k !== undefined));
        missingIndices.push(...keys.map((_, i) => i).filter(i => keys[i] !== undefined));
      }

      // Check L2 Cache for missing keys
      if (missingKeys.length > 0 && !options?.skipL2) {
        const l2Results = await this.distCacheInstance.mget<T>(missingKeys);
        
        for (let i = 0; i < l2Results.length; i++) {
          const result = l2Results[i];
          const originalIndex = missingIndices[i];
          const missingKey = missingKeys[i];
          
          if (result !== null && originalIndex !== undefined && missingKey) {
            results[originalIndex] = result as T;
            
            // Populate L1 cache
            if (!options?.skipL1) {
              this.appCacheInstance.set(missingKey, result, cacheType);
            }
          }
        }
      }

      const duration = Date.now() - startTime;
      const hits = results.filter(r => r !== null).length;
      const misses = results.length - hits;

      this.recordBatchOperation('mget', cacheType, duration, hits, misses);

      return results;

    } catch (error) {
      this.recordCacheError('mget', cacheType, error, Date.now() - startTime);
      logger.error('Cache mget operation failed', { keyCount: keys.length, cacheType, error });
      return keys.map(() => null);
    }
  }

  async mset(items: Array<{ key: string; value: any; ttl?: number }>, options?: {
    cacheType?: string;
    skipL1?: boolean;
    skipL2?: boolean;
  }): Promise<boolean> {
    const cacheType = options?.cacheType || 'unified';
    const startTime = Date.now();

    try {
      let l1Success = true;
      let l2Success = true;

      // Set in L1 Cache
      if (!options?.skipL1) {
        for (const item of items) {
          if (!this.appCacheInstance.set(item.key, item.value, cacheType, item.ttl)) {
            l1Success = false;
          }
        }
      }

      // Set in L2 Cache
      if (!options?.skipL2) {
        l2Success = await this.distCacheInstance.mset(items);
      }

      const success = l1Success && l2Success;
      const duration = Date.now() - startTime;

      this.recordBatchOperation('mset', cacheType, duration, items.length, 0);

      return success;

    } catch (error) {
      this.recordCacheError('mset', cacheType, error, Date.now() - startTime);
      logger.error('Cache mset operation failed', { itemCount: items.length, cacheType, error });
      return false;
    }
  }

  // Cache invalidation
  async invalidate(pattern: string, options?: {
    reason?: string;
    source?: string;
  }): Promise<number> {
    const startTime = Date.now();

    try {
      const event: InvalidationEvent = {
        type: 'pattern',
        target: pattern,
        pattern,
        reason: options?.reason || 'Manual invalidation',
        source: options?.source || 'cache-manager',
        timestamp: Date.now()
      };

      await this.invalidationManager.invalidate(event);

      const duration = Date.now() - startTime;
      this.recordCacheInvalidation(pattern, duration);

      return 1; // Simplified return value

    } catch (error) {
      logger.error('Cache invalidation failed', { pattern, error });
      return 0;
    }
  }

  // Domain-specific convenience methods
  async invalidateUser(userId: string, reason: string = 'User data updated'): Promise<void> {
    await this.invalidationManager.invalidateUser(userId, reason, 'cache-manager');
  }

  async invalidateRoom(roomId: string, reason: string = 'Room data updated'): Promise<void> {
    await this.invalidationManager.invalidateRoom(roomId, reason, 'cache-manager');
  }

  async invalidateAsset(assetId: string, reason: string = 'Asset data updated'): Promise<void> {
    await this.invalidationManager.invalidateAsset(assetId, reason, 'cache-manager');
  }

  // Health checks and monitoring
  async healthCheck(): Promise<{
    status: string;
    components: any;
    overall: boolean;
  }> {
    try {
      const [l1Health, l2Health] = await Promise.all([
        this.getL1Health(),
        this.distCacheInstance.healthCheck()
      ]);

      const monitoringHealth = this.monitoringService.healthCheck();
      const invalidationHealth = this.invalidationManager.getStats();

      const components = {
        l1Cache: l1Health,
        l2Cache: l2Health,
        monitoring: monitoringHealth,
        invalidation: invalidationHealth
      };

      const overall = l1Health.status === 'healthy' && 
                     l2Health.status === 'healthy' &&
                     monitoringHealth.status === 'active';

      return {
        status: overall ? 'healthy' : 'degraded',
        components,
        overall
      };

    } catch (error) {
      logger.error('Health check failed', { error });
      return {
        status: 'unhealthy',
        components: {},
        overall: false
      };
    }
  }

  async getStats(): Promise<{
    l1Cache: CacheStats;
    l2Cache: CacheStats;
    combined: CacheStats;
  }> {
    try {
      const [l1Stats, l2Stats] = await Promise.all([
        Promise.resolve(this.appCacheInstance.getStats()),
        this.distCacheInstance.getStats()
      ]);

      // Calculate combined stats
      const combined: CacheStats = {
        hitRate: (l1Stats.hitRate + l2Stats.hitRate) / 2,
        missRate: (l1Stats.missRate + l2Stats.missRate) / 2,
        totalHits: l1Stats.totalHits + l2Stats.totalHits,
        totalMisses: l1Stats.totalMisses + l2Stats.totalMisses,
        totalOperations: l1Stats.totalOperations + l2Stats.totalOperations,
        itemCount: l1Stats.itemCount + l2Stats.itemCount,
        connected: l1Stats.connected && l2Stats.connected
      };

      return {
        l1Cache: l1Stats,
        l2Cache: l2Stats,
        combined
      };

    } catch (error) {
      logger.error('Failed to get cache stats', { error });
      throw error;
    }
  }

  // Performance analysis
  getPerformanceReport(timeRangeMs?: number): any {
    return this.monitoringService.getPerformanceReport(timeRangeMs);
  }

  getActiveAlerts(): any[] {
    return this.monitoringService.getActiveAlerts();
  }

  // Cleanup and shutdown
  async shutdown(): Promise<void> {
    try {
      logger.info('Shutting down cache manager');

      // Stop monitoring
      this.monitoringService.stopMonitoring();

      // Close distributed cache connection
      await this.distCacheInstance.close();

      // Clear application cache
      this.appCacheInstance.clear();

      logger.info('Cache manager shutdown completed');

    } catch (error) {
      logger.error('Cache manager shutdown failed', { error });
      throw error;
    }
  }

  // Private helper methods
  private getL1Health(): { status: string; itemCount: number } {
    try {
      const stats = this.appCacheInstance.getStats();
      return {
        status: 'healthy',
        itemCount: stats.itemCount
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        itemCount: 0
      };
    }
  }

  private recordCacheHit(level: string, cacheType: string, duration: number): void {
    metrics.cacheHits?.inc({ cache_type: `${level}_${cacheType}` });
    this.monitoringService.recordOperation(cacheType, 'get', duration, true);
  }

  private recordCacheMiss(cacheType: string, duration: number): void {
    metrics.cacheMisses?.inc({ cache_type: cacheType });
    this.monitoringService.recordOperation(cacheType, 'get', duration, true);
  }

  private recordCacheSet(cacheType: string, duration: number): void {
    this.monitoringService.recordOperation(cacheType, 'set', duration, true);
  }

  private recordCacheDelete(cacheType: string, duration: number): void {
    this.monitoringService.recordOperation(cacheType, 'delete', duration, true);
  }

  private recordCacheError(operation: string, cacheType: string, _error: any, duration: number): void {
    metrics.cacheErrors?.inc({ type: operation, cache_type: cacheType });
    this.monitoringService.recordOperation(cacheType, operation, duration, false);
  }

  private recordBatchOperation(operation: string, cacheType: string, duration: number, hits: number, misses: number): void {
    this.monitoringService.recordOperation(cacheType, operation, duration, true);
    if (hits > 0) {
      metrics.cacheHits?.inc({ cache_type: cacheType }, hits);
    }
    if (misses > 0) {
      metrics.cacheMisses?.inc({ cache_type: cacheType }, misses);
    }
  }

  private recordCacheInvalidation(pattern: string, duration: number): void {
    metrics.cacheInvalidations?.inc({ pattern });
    this.monitoringService.recordOperation('unified', 'invalidate', duration, true);
  }
}

// Default configuration for Phase 3 cache manager
export const defaultCacheManagerConfig: CacheManagerConfig = {
  applicationCache: {
    defaultTTL: 300, // 5 minutes
    maxSize: 10000,
    evictionPolicy: 'lru',
    compressionEnabled: false,
    serializationMethod: 'json',
    namespace: 'tableforge'
  },
  distributedCache: {
    defaultTTL: 3600, // 1 hour
    maxSize: 100000,
    evictionPolicy: 'lru',
    compressionEnabled: true,
    serializationMethod: 'json',
    namespace: 'tableforge'
  },
  monitoring: defaultMonitoringConfig,
  invalidation: {
    enabled: true,
    batchSize: 100,
    processingInterval: 1000
  }
};

export default CacheManagerPhase3;
