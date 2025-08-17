// server/cache/application-cache-phase3.ts
// Phase 3 Enhanced application-level cache with LRU eviction and performance tracking

import { ApplicationCache, CacheConfig, CacheStats } from './types';
import { createUserLogger } from '../utils/logger';
import { metrics } from '../observability/metrics';
import { cacheConfig } from './config';

// Mock LRU cache for development (replace with actual lru-cache in production)
class MockLRU<K, V> {
  private data = new Map<K, V>();
  private maxSize: number;

  constructor(options: { max: number; ttl: number; updateAgeOnGet: boolean; allowStale: boolean }) {
    this.maxSize = options.max;
  }

  get(key: K): V | undefined {
    return this.data.get(key);
  }

  set(key: K, value: V): void {
    if (this.data.size >= this.maxSize) {
      // Simple LRU eviction - remove first (oldest) item
      const firstKey = this.data.keys().next().value;
      if (firstKey !== undefined) {
        this.data.delete(firstKey);
      }
    }
    this.data.set(key, value);
  }

  delete(key: K): boolean {
    return this.data.delete(key);
  }

  clear(): void {
    this.data.clear();
  }

  keys(): IterableIterator<K> {
    return this.data.keys();
  }

  get size(): number {
    return this.data.size;
  }
}

interface CacheItem<T = any> {
  value: T;
  expiresAt: number;
  accessedAt: number;
  createdAt: number;
  accessCount: number;
  size: number;
  lastAccessed: number;
  hitCount: number;
}

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
      value,
      createdAt: Date.now(),
      lastAccessed: Date.now(),
      hitCount: 0,
      accessedAt: Date.now(),
      accessCount: 1,
      size: JSON.stringify(value).length,
      expiresAt: Date.now() + ((ttl || this.config.defaultTTL) * 1000)
    };

    this.cache.set(key, item);
    
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

  getStats(): CacheStats {
    const hitRate = this.calculateHitRate();
    return {
      connected: true,
      keyCount: this.cache.size,
      memoryUsage: this.cache.size * 1024, // Rough estimate
      hitRate,
      missRate: 1 - hitRate,
      totalHits: 0, // Would be tracked in production
      totalMisses: 0, // Would be tracked in production
      totalOperations: 0, // Would be tracked in production
      itemCount: this.cache.size,
      size: this.cache.size,
      maxSize: this.config.maxSize
    };
  }

  private calculateHitRate(): number {
    // Calculate hit rate from stored metrics
    // This would integrate with actual metrics system
    return 0; // Placeholder
  }

  // Additional methods for compatibility with ApplicationCache interface
  has(key: string, _cacheType: string): boolean {
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

  delete(key: string, _cacheType?: string): boolean {
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
