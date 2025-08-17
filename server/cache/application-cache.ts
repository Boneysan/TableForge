// server/cache/application-cache.ts
import { ApplicationCache, CacheItem } from './types';
import { cacheConfig } from './config';
import { createUserLogger } from '../utils/logger';

// Application cache using in-memory Map with TTL support
export class MemoryApplicationCache implements ApplicationCache {
  private cache = new Map<string, CacheItem>();
  private timers = new Map<string, NodeJS.Timeout>();
  private readonly logger = createUserLogger('app-cache');

  get<T>(key: string, cacheType: string): T | null {
    const fullKey = `${cacheType}:${key}`;
    const item = this.cache.get(fullKey);
    
    if (!item) {
      return null;
    }

    // Check if expired
    if (Date.now() > item.expiresAt) {
      this.delete(fullKey);
      return null;
    }

    // Update access time for LRU tracking
    item.lastAccessed = Date.now();
    this.cache.set(fullKey, item);

    return item.value as T;
  }

  set<T>(key: string, value: T, cacheType: string, ttl: number): boolean {
    try {
      const fullKey = `${cacheType}:${key}`;
      const config = cacheConfig.getApplicationCacheConfig();
      const now = Date.now();
      
      // Check size limits
      if (this.cache.size >= config.maxSize) {
        this.evictLRU();
      }

      // Clear existing timer if present
      const existingTimer = this.timers.get(fullKey);
      if (existingTimer) {
        clearTimeout(existingTimer);
      }

      // Create cache item
      const item: CacheItem = {
        value,
        createdAt: now,
        expiresAt: now + (ttl * 1000),
        lastAccessed: now,
        size: this.estimateSize(value)
      };

      this.cache.set(fullKey, item);

      // Set expiration timer
      const timer = setTimeout(() => {
        this.delete(fullKey);
      }, ttl * 1000);

      this.timers.set(fullKey, timer);

      return true;
    } catch (error) {
      this.logger.error('Application cache set error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        key: `${cacheType}:${key}`
      });
      return false;
    }
  }

  has(key: string, cacheType: string): boolean {
    const fullKey = `${cacheType}:${key}`;
    const item = this.cache.get(fullKey);
    
    if (!item) {
      return false;
    }

    // Check if expired
    if (Date.now() > item.expiresAt) {
      this.delete(fullKey);
      return false;
    }

    return true;
  }

  delete(key: string, cacheType?: string): boolean {
    const fullKey = cacheType ? `${cacheType}:${key}` : key;
    
    // Clear timer
    const timer = this.timers.get(fullKey);
    if (timer) {
      clearTimeout(timer);
      this.timers.delete(fullKey);
    }

    return this.cache.delete(fullKey);
  }

  clear(): void {
    // Clear all timers
    for (const timer of this.timers.values()) {
      clearTimeout(timer);
    }
    
    this.timers.clear();
    this.cache.clear();
  }

  invalidate(pattern: string): number {
    let count = 0;
    const regex = new RegExp(pattern.replace(/\*/g, '.*'));

    for (const key of this.cache.keys()) {
      if (regex.test(key)) {
        this.delete(key);
        count++;
      }
    }

    return count;
  }

  size(): number {
    return this.cache.size;
  }

  getStats(): {
    size: number;
    maxSize: number;
    hitRate?: number;
    memoryUsage: number;
    oldestEntry?: number;
    newestEntry?: number;
  } {
    const config = cacheConfig.getApplicationCacheConfig();
    let totalSize = 0;
    let oldestTime = Infinity;
    let newestTime = 0;

    for (const item of this.cache.values()) {
      totalSize += item.size || 0;
      oldestTime = Math.min(oldestTime, item.createdAt);
      newestTime = Math.max(newestTime, item.createdAt);
    }

    const stats: {
      size: number;
      maxSize: number;
      hitRate?: number;
      memoryUsage: number;
      oldestEntry?: number;
      newestEntry?: number;
    } = {
      size: this.cache.size,
      maxSize: config.maxSize,
      memoryUsage: totalSize
    };

    if (oldestTime !== Infinity) {
      stats.oldestEntry = oldestTime;
    }

    if (newestTime !== 0) {
      stats.newestEntry = newestTime;
    }

    return stats;
  }

  // Private helper methods
  private evictLRU(): void {
    let oldestKey: string | null = null;
    let oldestTime = Infinity;

    for (const [key, item] of this.cache.entries()) {
      if (item.lastAccessed < oldestTime) {
        oldestTime = item.lastAccessed;
        oldestKey = key;
      }
    }

    if (oldestKey) {
      this.delete(oldestKey);
      this.logger.debug('LRU eviction performed', { 
        evictedKey: oldestKey,
        currentSize: this.cache.size 
      });
    }
  }

  private estimateSize(value: any): number {
    try {
      return JSON.stringify(value).length * 2; // Rough estimate (UTF-16)
    } catch {
      return 1024; // Default estimate for non-serializable objects
    }
  }

  // Maintenance methods
  cleanup(): void {
    const now = Date.now();
    const expiredKeys: string[] = [];

    for (const [key, item] of this.cache.entries()) {
      if (now > item.expiresAt) {
        expiredKeys.push(key);
      }
    }

    for (const key of expiredKeys) {
      this.delete(key);
    }

    if (expiredKeys.length > 0) {
      this.logger.debug('Expired entries cleaned up', { 
        count: expiredKeys.length,
        remainingSize: this.cache.size 
      });
    }
  }

  // Export cache state for persistence or debugging
  export(): Array<{ key: string; item: CacheItem }> {
    const entries: Array<{ key: string; item: CacheItem }> = [];
    
    for (const [key, item] of this.cache.entries()) {
      entries.push({ key, item });
    }

    return entries;
  }
}

// Factory function
export function createApplicationCache(): ApplicationCache {
  return new MemoryApplicationCache();
}
