// server/cache/distributed-cache.ts
import { DistributedCache, CacheStats } from './types';
import { cacheConfig } from './config';
import { createUserLogger } from '../utils/logger';

// Redis client interface (to be replaced with actual Redis implementation)
interface RedisClient {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, options?: { EX: number }): Promise<string | null>;
  mget(keys: string[]): Promise<Array<string | null>>;
  mset(keyValues: string[]): Promise<string | null>;
  del(keys: string[]): Promise<number>;
  keys(pattern: string): Promise<string[]>;
  ping(): Promise<string>;
  flushall(): Promise<string>;
  quit(): Promise<string>;
  info(section?: string): Promise<string>;
}

// Mock Redis client for development/testing
class MockRedisClient implements RedisClient {
  private data = new Map<string, { value: string; expires: number }>();

  async get(key: string): Promise<string | null> {
    const item = this.data.get(key);
    if (!item) return null;
    
    if (Date.now() > item.expires) {
      this.data.delete(key);
      return null;
    }
    
    return item.value;
  }

  async set(key: string, value: string, options?: { EX: number }): Promise<string | null> {
    const expires = options?.EX ? Date.now() + (options.EX * 1000) : Date.now() + (3600 * 1000);
    this.data.set(key, { value, expires });
    return 'OK';
  }

  async mget(keys: string[]): Promise<Array<string | null>> {
    const results: Array<string | null> = [];
    for (const key of keys) {
      results.push(await this.get(key));
    }
    return results;
  }

  async mset(keyValues: string[]): Promise<string | null> {
    for (let i = 0; i < keyValues.length; i += 2) {
      const key = keyValues[i];
      const value = keyValues[i + 1];
      if (key && value) {
        await this.set(key, value);
      }
    }
    return 'OK';
  }

  async del(keys: string[]): Promise<number> {
    let count = 0;
    for (const key of keys) {
      if (this.data.delete(key)) {
        count++;
      }
    }
    return count;
  }

  async keys(pattern: string): Promise<string[]> {
    const regex = new RegExp(pattern.replace(/\*/g, '.*'));
    const matchedKeys: string[] = [];
    
    for (const key of this.data.keys()) {
      if (regex.test(key)) {
        matchedKeys.push(key);
      }
    }
    
    return matchedKeys;
  }

  async ping(): Promise<string> {
    return 'PONG';
  }

  async flushall(): Promise<string> {
    this.data.clear();
    return 'OK';
  }

  async quit(): Promise<string> {
    this.data.clear();
    return 'OK';
  }

  async info(_section?: string): Promise<string> {
    return `# Memory\nused_memory:${this.data.size * 1024}\n# Stats\ntotal_connections_received:1\n`;
  }
}

export class RedisDistributedCache implements DistributedCache {
  private client: RedisClient;
  private readonly logger = createUserLogger('redis-cache');

  constructor(client?: RedisClient) {
    this.client = client || new MockRedisClient();
  }

  async get<T>(key: string, cacheType: string): Promise<T | null> {
    try {
      const fullKey = `${cacheType}:${key}`;
      const value = await this.client.get(fullKey);
      
      if (!value) {
        return null;
      }

      return JSON.parse(value) as T;
    } catch (error) {
      this.logger.error('Redis get error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        key: `${cacheType}:${key}`
      });
      return null;
    }
  }

  async set<T>(key: string, value: T, cacheType: string, ttl?: number): Promise<boolean> {
    try {
      const fullKey = `${cacheType}:${key}`;
      const config = cacheConfig.getDistributedCacheConfig();
      const serialized = JSON.stringify(value);
      const actualTTL = ttl || config.defaultTTL;

      const result = await this.client.set(fullKey, serialized, { EX: actualTTL });
      return result === 'OK';
    } catch (error) {
      this.logger.error('Redis set error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        key: `${cacheType}:${key}`
      });
      return false;
    }
  }

  async mget<T>(keys: string[], cacheType: string): Promise<Array<T | null>> {
    try {
      const fullKeys = keys.map(key => `${cacheType}:${key}`);
      const values = await this.client.mget(fullKeys);
      
      return values.map(value => {
        if (!value) return null;
        try {
          return JSON.parse(value) as T;
        } catch {
          return null;
        }
      });
    } catch (error) {
      this.logger.error('Redis mget error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        keyCount: keys.length,
        cacheType
      });
      return new Array(keys.length).fill(null);
    }
  }

  async mset(items: Array<{ key: string; value: any; ttl?: number }>, cacheType: string): Promise<boolean> {
    try {
      const keyValues: string[] = [];
      
      for (const item of items) {
        const fullKey = `${cacheType}:${item.key}`;
        const serialized = JSON.stringify(item.value);
        keyValues.push(fullKey, serialized);
      }

      const result = await this.client.mset(keyValues);
      
      // Handle TTL for each key individually (Redis MSET doesn't support TTL)
      for (const item of items) {
        if (item.ttl) {
          const fullKey = `${cacheType}:${item.key}`;
          await this.client.set(fullKey, JSON.stringify(item.value), { EX: item.ttl });
        }
      }

      return result === 'OK';
    } catch (error) {
      this.logger.error('Redis mset error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        itemCount: items.length,
        cacheType
      });
      return false;
    }
  }

  async invalidate(pattern: string): Promise<number> {
    try {
      const keys = await this.client.keys(pattern);
      if (keys.length === 0) {
        return 0;
      }

      const deletedCount = await this.client.del(keys);
      
      this.logger.debug('Redis invalidation completed', {
        pattern,
        deletedCount,
        totalKeys: keys.length
      });

      return deletedCount;
    } catch (error) {
      this.logger.error('Redis invalidation error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        pattern
      });
      return 0;
    }
  }

  async invalidateUserData(userId: string): Promise<void> {
    const patterns = [
      `user:session:${userId}*`,
      `user:profile:${userId}*`,
      `user:preferences:${userId}*`,
      `user:auth:${userId}*`
    ];

    const deletePromises = patterns.map(pattern => this.invalidate(pattern));
    const results = await Promise.allSettled(deletePromises);
    
    const totalDeleted = results.reduce((sum, result) => {
      return sum + (result.status === 'fulfilled' ? result.value : 0);
    }, 0);

    this.logger.info('User data invalidated from Redis', {
      userId,
      patterns: patterns.length,
      deletedKeys: totalDeleted
    });
  }

  async invalidateRoomData(roomId: string): Promise<void> {
    const patterns = [
      `room:state:${roomId}*`,
      `room:assets:${roomId}*`,
      `room:board:${roomId}*`,
      `room:templates:${roomId}*`,
      `room:history:${roomId}*`
    ];

    const deletePromises = patterns.map(pattern => this.invalidate(pattern));
    const results = await Promise.allSettled(deletePromises);
    
    const totalDeleted = results.reduce((sum, result) => {
      return sum + (result.status === 'fulfilled' ? result.value : 0);
    }, 0);

    this.logger.info('Room data invalidated from Redis', {
      roomId,
      patterns: patterns.length,
      deletedKeys: totalDeleted
    });
  }

  async healthCheck(): Promise<{ status: string; info?: any }> {
    try {
      const pingResult = await this.client.ping();
      const info = await this.client.info('memory');
      
      return {
        status: pingResult === 'PONG' ? 'healthy' : 'unhealthy',
        info: {
          ping: pingResult,
          memory: info
        }
      };
    } catch (error) {
      this.logger.error('Redis health check failed', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      
      return {
        status: 'unhealthy',
        info: {
          error: error instanceof Error ? error.message : 'Unknown error'
        }
      };
    }
  }

  async getStats(): Promise<CacheStats> {
    try {
      const info = await this.client.info();
      const memoryMatch = info.match(/used_memory:(\d+)/);
      
      return {
        size: 0, // Would need separate tracking or Redis key count
        maxSize: 0, // Redis doesn't have built-in size limits
        memoryUsage: memoryMatch && memoryMatch[1] ? parseInt(memoryMatch[1], 10) : 0
      };
    } catch (error) {
      this.logger.error('Failed to get Redis stats', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      
      return {
        size: 0,
        maxSize: 0,
        memoryUsage: 0
      };
    }
  }

  async close(): Promise<void> {
    try {
      await this.client.quit();
      this.logger.info('Redis connection closed successfully');
    } catch (error) {
      this.logger.error('Error closing Redis connection', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  // Utility methods for development
  async flush(): Promise<void> {
    try {
      await this.client.flushall();
      this.logger.warn('Redis cache flushed - all data cleared');
    } catch (error) {
      this.logger.error('Failed to flush Redis cache', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  // Advanced operations for complex data patterns
  async incrementCounter(key: string, cacheType: string, increment = 1): Promise<number> {
    try {
      const fullKey = `${cacheType}:counter:${key}`;
      const current = await this.get<number>(fullKey, 'counter') || 0;
      const newValue = current + increment;
      await this.set(fullKey, newValue, 'counter');
      return newValue;
    } catch (error) {
      this.logger.error('Redis counter increment error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        key: `${cacheType}:counter:${key}`
      });
      return 0;
    }
  }

  async atomicUpdate<T>(
    key: string, 
    cacheType: string, 
    updateFn: (current: T | null) => T
  ): Promise<boolean> {
    try {
      const current = await this.get<T>(key, cacheType);
      const updated = updateFn(current);
      return await this.set(key, updated, cacheType);
    } catch (error) {
      this.logger.error('Redis atomic update error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        key: `${cacheType}:${key}`
      });
      return false;
    }
  }
}

// Factory function
export function createDistributedCache(redisClient?: RedisClient): DistributedCache {
  return new RedisDistributedCache(redisClient);
}
