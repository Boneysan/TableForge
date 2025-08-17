// server/cache/application-cache-phase3.ts
// Phase 3 Enhanced application-level cache with LRU eviction and performance tracking

import { ApplicationCache, CacheConfig, CacheStats } from './types';
import { createUserLogger } from '../utils/logger';
import { metrics } from '../observability/metrics';

const logger = createUserLogger('application-cache');

interface CacheItem<T> {
  value: T;
  expiresAt: number;
  accessedAt: number;
  createdAt: number;
  accessCount: number;
  size: number;
}

interface CacheMetrics {
  hits: number;
  misses: number;
  sets: number;
  evictions: number;
  totalSize: number;
  operationTimes: number[];
}
  cacheMisses: { inc: (_labels: any) => {} },
  cacheInvalidations: { inc: (_labels: any, _count?: number) => {} }
};

export class EnhancedApplicationCache implements ApplicationCache {
  private cache: MockLRU<string, CacheItem>;
  private config: CacheConfig;
  private readonly logger = createUserLogger('enhanced-app-cache');

  constructor(config?: CacheConfig) {
    this.config = config || cacheConfig.getApplicationCacheConfig();
    this.cache = new MockLRU({
      max: this.config.maxSize,
      ttl: this.config.defaultTTL * 1000, // Convert to milliseconds
      updateAgeOnGet: true,
      allowStale: false
    });

    this.logger.info('Enhanced application cache initialized', {
      maxSize: this.config.maxSize,
      defaultTTL: this.config.defaultTTL
    });
  }

  get<T>(key: string, cacheType: string): T | null {
    const startTime = Date.now();
    const item = this.cache.get(key);
    
    metrics.cacheOperationDuration.observe(
      { operation: 'get', cache_type: `app_${cacheType}` },
      Date.now() - startTime
    );

    if (item) {
      // Check if expired
      if (Date.now() > item.expiresAt) {
        this.cache.delete(key);
        metrics.cacheMisses.inc({ cache_type: `app_${cacheType}` });
        return null;
      }

      metrics.cacheHits.inc({ cache_type: `app_${cacheType}` });
      item.lastAccessed = Date.now();
      item.hitCount++;
      return item.value as T;
    }

    metrics.cacheMisses.inc({ cache_type: `app_${cacheType}` });
    return null;
  }

  set<T>(key: string, value: T, cacheType: string, ttl?: number): boolean {
    const startTime = Date.now();
    
    const item: CacheItem<T> = {
      key,
      value,
      ttl: ttl || this.config.defaultTTL,
      createdAt: Date.now(),
      lastAccessed: Date.now(),
      hitCount: 0,
      expiresAt: Date.now() + ((ttl || this.config.defaultTTL) * 1000)
    };

    this.cache.set(key, item, { ttl: (ttl || this.config.defaultTTL) * 1000 });
    
    metrics.cacheOperationDuration.observe(
      { operation: 'set', cache_type: `app_${cacheType}` },
      Date.now() - startTime
    );

    return true;
  }

  invalidate(pattern: string): number {
    let deletedCount = 0;
    const regex = new RegExp(pattern.replace(/\*/g, '.*'));
    
    for (const key of this.cache.keys()) {
      if (regex.test(key)) {
        this.cache.delete(key);
        deletedCount++;
      }
    }

    metrics.cacheInvalidations.inc({ pattern }, deletedCount);
    return deletedCount;
  }

  clear(): void {
    this.cache.clear();
  }

  getStats(): { size: number; maxSize: number; hitRate: number } {
    return {
      size: this.cache.size,
      maxSize: this.config.maxSize,
      hitRate: this.calculateHitRate()
    };
  }

  private calculateHitRate(): number {
    // Calculate hit rate from stored metrics
    // This would integrate with actual metrics system
    return 0; // Placeholder
  }

  // Additional methods for compatibility with ApplicationCache interface
  has(key: string, cacheType: string): boolean {
    const item = this.cache.get(key);
    if (!item) {
      return false;
    }
    
    // Check if expired
    if (Date.now() > item.expiresAt) {
      this.cache.delete(key);
      return false;
    }
    
    return true;
  }

  delete(key: string, cacheType?: string): boolean {
    return this.cache.delete(key);
  }
}

// Maintain backward compatibility with existing implementation
export class MemoryApplicationCache extends EnhancedApplicationCache {
  constructor() {
    super(); // Use enhanced implementation with default config
  }
}

// Factory function for creating application cache instances
export function createApplicationCache(config?: CacheConfig): ApplicationCache {
  return new EnhancedApplicationCache(config);
}

// Export the Phase 3 compliant implementation as default
export { EnhancedApplicationCache as ApplicationCache } from './application-cache';
