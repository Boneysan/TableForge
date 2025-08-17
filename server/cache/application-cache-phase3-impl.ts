// server/cache/application-cache-phase3-impl.ts
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

export default class ApplicationCachePhase3 implements ApplicationCache {
  private cache = new Map<string, CacheItem<any>>();
  private accessOrder = new Map<string, number>(); // For LRU tracking
  private sizesByType = new Map<string, number>();
  private metricsByType = new Map<string, CacheMetrics>();
  private config: CacheConfig;
  private currentSize = 0;
  private accessCounter = 0;
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor(config: CacheConfig) {
    this.config = {
      ...config,
      defaultTTL: config.defaultTTL || 300, // 5 minutes default
      maxSize: config.maxSize || 10000,
      evictionPolicy: config.evictionPolicy || 'lru',
      compressionEnabled: config.compressionEnabled || false,
      serializationMethod: config.serializationMethod || 'json',
      namespace: config.namespace || 'tableforge'
    };

    // Start periodic cleanup
    this.startCleanupTask();

    logger.info('Application cache phase 3 initialized', {
      maxSize: this.config.maxSize,
      defaultTTL: this.config.defaultTTL,
      evictionPolicy: this.config.evictionPolicy
    });
  }

  get<T>(key: string, cacheType: string = 'default'): T | null {
    const startTime = Date.now();
    const fullKey = this.makeKey(key, cacheType);

    try {
      const item = this.cache.get(fullKey);
      
      if (!item) {
        this.recordMiss(cacheType, Date.now() - startTime);
        return null;
      }

      // Check expiration
      if (Date.now() > item.expiresAt) {
        this.cache.delete(fullKey);
        this.accessOrder.delete(fullKey);
        this.recordMiss(cacheType, Date.now() - startTime);
        return null;
      }

      // Update access tracking for LRU
      item.accessedAt = Date.now();
      item.accessCount++;
      this.accessOrder.set(fullKey, ++this.accessCounter);

      this.recordHit(cacheType, Date.now() - startTime);
      
      return item.value as T;

    } catch (error) {
      logger.error('Cache get operation failed', { key: fullKey, error });
      this.recordMiss(cacheType, Date.now() - startTime);
      return null;
    }
  }

  set<T>(key: string, value: T, cacheType: string = 'default', ttl?: number): boolean {
    const startTime = Date.now();
    const fullKey = this.makeKey(key, cacheType);
    const effectiveTTL = ttl || this.config.defaultTTL!;

    try {
      // Calculate item size
      const itemSize = this.calculateSize(value);
      
      // Check if we need to evict items
      if (this.currentSize + itemSize > this.config.maxSize!) {
        this.evictItems(itemSize);
      }

      // Create cache item
      const item: CacheItem<T> = {
        value,
        expiresAt: Date.now() + (effectiveTTL * 1000),
        accessedAt: Date.now(),
        createdAt: Date.now(),
        accessCount: 1,
        size: itemSize
      };

      // Remove old item if exists
      const existingItem = this.cache.get(fullKey);
      if (existingItem) {
        this.currentSize -= existingItem.size;
      }

      // Set new item
      this.cache.set(fullKey, item);
      this.accessOrder.set(fullKey, ++this.accessCounter);
      this.currentSize += itemSize;

      // Update size tracking by type
      const currentTypeSize = this.sizesByType.get(cacheType) || 0;
      this.sizesByType.set(cacheType, currentTypeSize + itemSize - (existingItem?.size || 0));

      this.recordSet(cacheType, Date.now() - startTime);

      return true;

    } catch (error) {
      logger.error('Cache set operation failed', { key: fullKey, error });
      return false;
    }
  }

  has(key: string, cacheType: string = 'default'): boolean {
    const fullKey = this.makeKey(key, cacheType);
    const item = this.cache.get(fullKey);
    
    if (!item) {
      return false;
    }

    // Check expiration
    if (Date.now() > item.expiresAt) {
      this.cache.delete(fullKey);
      this.accessOrder.delete(fullKey);
      return false;
    }

    return true;
  }

  invalidate(pattern: string): number {
    const startTime = Date.now();
    let invalidated = 0;

    try {
      // Convert pattern to regex
      const regex = new RegExp(pattern.replace(/\*/g, '.*'));
      
      for (const [key, item] of this.cache.entries()) {
        if (regex.test(key)) {
          this.cache.delete(key);
          this.accessOrder.delete(key);
          this.currentSize -= item.size;
          invalidated++;
        }
      }

      // Update size tracking
      this.recalculateSizesByType();

      const duration = Date.now() - startTime;
      logger.debug('Cache invalidation completed', { 
        pattern, 
        invalidated, 
        duration 
      });

      // Record metrics
      metrics.cacheInvalidations?.inc({ pattern: 'application' });

      return invalidated;

    } catch (error) {
      logger.error('Cache invalidation failed', { pattern, error });
      return 0;
    }
  }

  clear(): void {
    const itemCount = this.cache.size;
    
    this.cache.clear();
    this.accessOrder.clear();
    this.sizesByType.clear();
    this.metricsByType.clear();
    this.currentSize = 0;
    this.accessCounter = 0;

    logger.info('Application cache cleared', { itemCount });
  }

  getStats(): CacheStats {
    const totalMetrics = this.calculateTotalMetrics();
    const connected = true; // Application cache is always "connected"

    return {
      hitRate: totalMetrics.hits > 0 ? totalMetrics.hits / (totalMetrics.hits + totalMetrics.misses) : 0,
      missRate: totalMetrics.misses > 0 ? totalMetrics.misses / (totalMetrics.hits + totalMetrics.misses) : 0,
      totalHits: totalMetrics.hits,
      totalMisses: totalMetrics.misses,
      totalOperations: totalMetrics.hits + totalMetrics.misses + totalMetrics.sets,
      itemCount: this.cache.size,
      connected,
      keyCount: this.cache.size,
      memoryUsage: this.currentSize,
      size: this.cache.size,
      maxSize: this.config.maxSize,
      averageLatency: this.calculateAverageResponseTime()
    };
  }

  // Private helper methods
  private makeKey(key: string, cacheType: string): string {
    return `${this.config.namespace}:${cacheType}:${key}`;
  }

  private calculateSize(value: any): number {
    try {
      if (typeof value === 'string') {
        return value.length * 2; // Rough estimate for Unicode strings
      }
      
      if (typeof value === 'number') {
        return 8;
      }
      
      if (typeof value === 'boolean') {
        return 4;
      }
      
      if (value === null || value === undefined) {
        return 4;
      }
      
      // For objects, use JSON serialization size as estimate
      return JSON.stringify(value).length * 2;
    } catch {
      return 1024; // Default size for non-serializable objects
    }
  }

  private evictItems(neededSpace: number): void {
    const startTime = Date.now();
    let freedSpace = 0;
    let evicted = 0;

    if (this.config.evictionPolicy === 'lru') {
      // Sort by access order (oldest first)
      const sortedByAccess = Array.from(this.accessOrder.entries())
        .sort((a, b) => a[1] - b[1]);

      for (const [key] of sortedByAccess) {
        const item = this.cache.get(key);
        if (item) {
          this.cache.delete(key);
          this.accessOrder.delete(key);
          freedSpace += item.size;
          this.currentSize -= item.size;
          evicted++;

          // Record eviction metrics
          const cacheType = this.extractCacheType(key);
          this.recordEviction(cacheType);

          if (freedSpace >= neededSpace || this.cache.size === 0) {
            break;
          }
        }
      }
    }

    // Update size tracking
    this.recalculateSizesByType();

    const duration = Date.now() - startTime;
    logger.debug('Cache eviction completed', {
      evicted,
      freedSpace,
      neededSpace,
      duration,
      remainingItems: this.cache.size
    });

    // Record metrics
    if (metrics.cacheInvalidations) {
      metrics.cacheInvalidations.inc({ pattern: 'application' });
    }
  }

  private extractCacheType(fullKey: string): string {
    const parts = fullKey.split(':');
    return parts.length >= 2 && parts[1] ? parts[1] : 'default';
  }

  private recalculateSizesByType(): void {
    this.sizesByType.clear();
    
    for (const [key, item] of this.cache.entries()) {
      const cacheType = this.extractCacheType(key);
      const currentSize = this.sizesByType.get(cacheType) || 0;
      this.sizesByType.set(cacheType, currentSize + item.size);
    }
  }

  private startCleanupTask(): void {
    // Run cleanup every 5 minutes
    this.cleanupInterval = setInterval(() => {
      this.cleanupExpiredItems();
    }, 5 * 60 * 1000);
  }

  private cleanupExpiredItems(): void {
    const startTime = Date.now();
    let cleaned = 0;

    for (const [key, item] of this.cache.entries()) {
      if (Date.now() > item.expiresAt) {
        this.cache.delete(key);
        this.accessOrder.delete(key);
        this.currentSize -= item.size;
        cleaned++;
      }
    }

    if (cleaned > 0) {
      this.recalculateSizesByType();
      
      const duration = Date.now() - startTime;
      logger.debug('Expired items cleanup completed', {
        cleaned,
        duration,
        remainingItems: this.cache.size
      });
    }
  }

  private calculateTotalMetrics(): CacheMetrics {
    let totalHits = 0;
    let totalMisses = 0;
    let totalSets = 0;
    let totalEvictions = 0;
    let totalOperationTimes: number[] = [];

    for (const cacheMetrics of this.metricsByType.values()) {
      totalHits += cacheMetrics.hits;
      totalMisses += cacheMetrics.misses;
      totalSets += cacheMetrics.sets;
      totalEvictions += cacheMetrics.evictions;
      totalOperationTimes.push(...cacheMetrics.operationTimes);
    }

    return {
      hits: totalHits,
      misses: totalMisses,
      sets: totalSets,
      evictions: totalEvictions,
      totalSize: this.currentSize,
      operationTimes: totalOperationTimes
    };
  }

  private calculateAverageResponseTime(): number {
    const totalMetrics = this.calculateTotalMetrics();
    const times = totalMetrics.operationTimes;
    
    if (times.length === 0) return 0;
    
    const sum = times.reduce((a, b) => a + b, 0);
    return sum / times.length;
  }

  private getMetrics(cacheType: string): CacheMetrics {
    if (!this.metricsByType.has(cacheType)) {
      this.metricsByType.set(cacheType, {
        hits: 0,
        misses: 0,
        sets: 0,
        evictions: 0,
        totalSize: 0,
        operationTimes: []
      });
    }
    return this.metricsByType.get(cacheType)!;
  }

  private recordHit(cacheType: string, duration: number): void {
    const cacheMetrics = this.getMetrics(cacheType);
    cacheMetrics.hits++;
    cacheMetrics.operationTimes.push(duration);
    
    // Keep only last 1000 operation times
    if (cacheMetrics.operationTimes.length > 1000) {
      cacheMetrics.operationTimes = cacheMetrics.operationTimes.slice(-1000);
    }

    // Record global metrics
    metrics.cacheHits?.inc({ cache_type: `application_${cacheType}` });
  }

  private recordMiss(cacheType: string, duration: number): void {
    const cacheMetrics = this.getMetrics(cacheType);
    cacheMetrics.misses++;
    cacheMetrics.operationTimes.push(duration);
    
    if (cacheMetrics.operationTimes.length > 1000) {
      cacheMetrics.operationTimes = cacheMetrics.operationTimes.slice(-1000);
    }

    metrics.cacheMisses?.inc({ cache_type: `application_${cacheType}` });
  }

  private recordSet(cacheType: string, duration: number): void {
    const cacheMetrics = this.getMetrics(cacheType);
    cacheMetrics.sets++;
    cacheMetrics.operationTimes.push(duration);
    
    if (cacheMetrics.operationTimes.length > 1000) {
      cacheMetrics.operationTimes = cacheMetrics.operationTimes.slice(-1000);
    }
  }

  private recordEviction(cacheType: string): void {
    const cacheMetrics = this.getMetrics(cacheType);
    cacheMetrics.evictions++;
  }

  // Cleanup on destruction
  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    
    this.clear();
    logger.info('Application cache destroyed');
  }
}
