// server/cache/edge-cache.ts
import { EdgeCache } from './types';
import { cacheConfig } from './config';
import { createUserLogger } from '../utils/logger';

// CDN/Edge Cache interface (could integrate with CloudFlare, AWS CloudFront, etc.)
interface EdgeCacheProvider {
  get(key: string): Promise<any | null>;
  set(key: string, value: any, ttl: number): Promise<boolean>;
  invalidate(pattern: string): Promise<number>;
  getStats(): Promise<any>;
}

// Mock Edge Cache for development/testing
class MockEdgeCacheProvider implements EdgeCacheProvider {
  private cache = new Map<string, { value: any; expires: number }>();

  async get(key: string): Promise<any | null> {
    const item = this.cache.get(key);
    if (!item) return null;
    
    if (Date.now() > item.expires) {
      this.cache.delete(key);
      return null;
    }
    
    return item.value;
  }

  async set(key: string, value: any, ttl: number): Promise<boolean> {
    try {
      const expires = Date.now() + (ttl * 1000);
      this.cache.set(key, { value, expires });
      return true;
    } catch {
      return false;
    }
  }

  async invalidate(pattern: string): Promise<number> {
    const regex = new RegExp(pattern.replace(/\*/g, '.*'));
    let count = 0;

    for (const key of this.cache.keys()) {
      if (regex.test(key)) {
        this.cache.delete(key);
        count++;
      }
    }

    return count;
  }

  async getStats(): Promise<any> {
    return {
      size: this.cache.size,
      memoryUsage: this.cache.size * 1024 // Rough estimate
    };
  }
}

export class CDNEdgeCache implements EdgeCache {
  private provider: EdgeCacheProvider;
  private readonly logger = createUserLogger('edge-cache');

  constructor(provider?: EdgeCacheProvider) {
    this.provider = provider || new MockEdgeCacheProvider();
  }

  async get<T>(key: string): Promise<T | null> {
    try {
      const value = await this.provider.get(key);
      return value as T | null;
    } catch (error) {
      this.logger.error('Edge cache get error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        key
      });
      return null;
    }
  }

  async set<T>(key: string, value: T, ttl?: number): Promise<boolean> {
    try {
      const config = cacheConfig.getEdgeCacheConfig();
      const actualTTL = ttl || config.defaultTTL;
      
      return await this.provider.set(key, value, actualTTL);
    } catch (error) {
      this.logger.error('Edge cache set error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        key
      });
      return false;
    }
  }

  async invalidate(pattern: string): Promise<number> {
    try {
      const count = await this.provider.invalidate(pattern);
      
      this.logger.debug('Edge cache invalidation completed', {
        pattern,
        deletedCount: count
      });

      return count;
    } catch (error) {
      this.logger.error('Edge cache invalidation error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        pattern
      });
      return 0;
    }
  }

  async getStats(): Promise<{
    size: number;
    memoryUsage: number;
    hitRate?: number;
  }> {
    try {
      const stats = await this.provider.getStats();
      return {
        size: stats.size || 0,
        memoryUsage: stats.memoryUsage || 0,
        hitRate: stats.hitRate
      };
    } catch (error) {
      this.logger.error('Failed to get edge cache stats', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      
      return {
        size: 0,
        memoryUsage: 0
      };
    }
  }

  // Edge cache specific methods for asset caching
  async cacheAsset(assetId: string, assetData: any, contentType: string): Promise<boolean> {
    try {
      const key = `asset:${contentType}:${assetId}`;
      const config = cacheConfig.getEdgeCacheConfig();
      
      // Assets get longer TTL on edge cache
      const assetTTL = config.defaultTTL * 24; // 24x longer for static assets
      
      return await this.set(key, assetData, assetTTL);
    } catch (error) {
      this.logger.error('Asset cache error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        assetId,
        contentType
      });
      return false;
    }
  }

  async getCachedAsset(assetId: string, contentType: string): Promise<any | null> {
    try {
      const key = `asset:${contentType}:${assetId}`;
      return await this.get(key);
    } catch (error) {
      this.logger.error('Asset retrieval error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        assetId,
        contentType
      });
      return null;
    }
  }

  // Template caching for game boards and card designs
  async cacheTemplate(templateId: string, templateData: any, templateType: 'board' | 'card' | 'deck'): Promise<boolean> {
    try {
      const key = `template:${templateType}:${templateId}`;
      const config = cacheConfig.getEdgeCacheConfig();
      
      // Templates are somewhat static but may change
      const templateTTL = config.defaultTTL * 12; // 12x longer for templates
      
      return await this.set(key, templateData, templateTTL);
    } catch (error) {
      this.logger.error('Template cache error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        templateId,
        templateType
      });
      return false;
    }
  }

  async getCachedTemplate(templateId: string, templateType: 'board' | 'card' | 'deck'): Promise<any | null> {
    try {
      const key = `template:${templateType}:${templateId}`;
      return await this.get(key);
    } catch (error) {
      this.logger.error('Template retrieval error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        templateId,
        templateType
      });
      return null;
    }
  }

  // Public game configuration caching
  async cachePublicGameConfig(gameId: string, config: any): Promise<boolean> {
    try {
      const key = `public:game:${gameId}`;
      const configData = cacheConfig.getEdgeCacheConfig();
      
      // Public configs can be cached for a long time
      const publicTTL = configData.defaultTTL * 48; // 48x longer for public configs
      
      return await this.set(key, config, publicTTL);
    } catch (error) {
      this.logger.error('Public game config cache error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        gameId
      });
      return false;
    }
  }

  // Batch operations for efficiency
  async batchInvalidateAssets(assetIds: string[]): Promise<number> {
    let totalInvalidated = 0;
    
    try {
      const invalidationPromises = assetIds.map(assetId => 
        this.invalidate(`asset:*:${assetId}`)
      );
      
      const results = await Promise.allSettled(invalidationPromises);
      
      totalInvalidated = results.reduce((sum, result) => {
        return sum + (result.status === 'fulfilled' ? result.value : 0);
      }, 0);

      this.logger.info('Batch asset invalidation completed', {
        assetCount: assetIds.length,
        totalInvalidated
      });
    } catch (error) {
      this.logger.error('Batch asset invalidation error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        assetCount: assetIds.length
      });
    }

    return totalInvalidated;
  }

  // Warming methods for preloading commonly used data
  async warmCache(items: Array<{ key: string; value: any; ttl?: number }>): Promise<number> {
    let successCount = 0;
    
    try {
      const warmingPromises = items.map(async item => {
        const success = await this.set(item.key, item.value, item.ttl);
        return success ? 1 : 0;
      });
      
      const results = await Promise.allSettled(warmingPromises);
      
      successCount = results.reduce((sum, result) => {
        return sum + (result.status === 'fulfilled' ? result.value : 0);
      }, 0);

      this.logger.info('Cache warming completed', {
        itemCount: items.length,
        successCount,
        failureCount: items.length - successCount
      });
    } catch (error) {
      this.logger.error('Cache warming error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        itemCount: items.length
      });
    }

    return successCount;
  }

  // Health check specific to edge cache
  async healthCheck(): Promise<{ status: 'healthy' | 'degraded' | 'unhealthy'; details: any }> {
    try {
      // Test basic operations
      const testKey = 'health-check-test';
      const testValue = { timestamp: Date.now() };
      
      const setSuccess = await this.set(testKey, testValue, 10); // 10 second TTL
      const getValue = await this.get(testKey);
      const deleteSuccess = await this.invalidate(testKey);

      const isHealthy = setSuccess && getValue !== null && deleteSuccess > 0;
      
      return {
        status: isHealthy ? 'healthy' : 'degraded',
        details: {
          canSet: setSuccess,
          canGet: getValue !== null,
          canDelete: deleteSuccess > 0,
          timestamp: Date.now()
        }
      };
    } catch (error) {
      this.logger.error('Edge cache health check failed', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      
      return {
        status: 'unhealthy',
        details: {
          error: error instanceof Error ? error.message : 'Unknown error',
          timestamp: Date.now()
        }
      };
    }
  }
}

// Factory function
export function createEdgeCache(provider?: EdgeCacheProvider): EdgeCache {
  return new CDNEdgeCache(provider);
}
