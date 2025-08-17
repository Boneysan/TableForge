// server/cache/redis-cache-phase3.ts
// Phase 3 Redis cache implementation with full performance optimization
// import Redis from 'ioredis'; // TODO: Add ioredis dependency for production
import { CacheConfig, CacheStats, CacheMetrics, DistributedCache } from './types';
import { 
  UserSession, 
  GameRoomState, 
  AssetMetadata, 
  GameSystemTemplate,
  CacheKeyPatterns,
  CacheTTL 
} from './types';
import { createUserLogger } from '../utils/logger';
import { metrics } from '../observability/metrics';

const logger = createUserLogger('redis-cache');

// Mock Redis interface for development (replace with actual ioredis in production)
interface Redis {
  get(key: string): Promise<string | null>;
  setex(key: string, seconds: number, value: string): Promise<string>;
  del(...keys: string[]): Promise<number>;
  mget(...keys: string[]): Promise<Array<string | null>>;
  pipeline(): RedisPipeline;
  keys(pattern: string): Promise<string[]>;
  ping(): Promise<string>;
  info(section?: string): Promise<string>;
  dbsize(): Promise<number>;
  quit(): Promise<string>;
  on(event: string, callback: (error?: Error) => void): void;
  connect(): Promise<void>;
}

interface RedisPipeline {
  setex(key: string, seconds: number, value: string): RedisPipeline;
  exec(): Promise<any>;
}

// Mock Redis implementation for development
class MockRedis implements Redis {
  private data = new Map<string, { value: string; expires: number }>();
  private callbacks: { [event: string]: Function[] } = {};
  private connected = false;

  async connect(): Promise<void> {
    this.connected = true;
    this.emit('connect');
    this.emit('ready');
  }

  async get(key: string): Promise<string | null> {
    const item = this.data.get(key);
    if (!item || Date.now() > item.expires) {
      this.data.delete(key);
      return null;
    }
    return item.value;
  }

  async setex(key: string, seconds: number, value: string): Promise<string> {
    const expires = Date.now() + (seconds * 1000);
    this.data.set(key, { value, expires });
    return 'OK';
  }

  async del(...keys: string[]): Promise<number> {
    let deleted = 0;
    for (const key of keys) {
      if (this.data.delete(key)) {
        deleted++;
      }
    }
    return deleted;
  }

  async mget(...keys: string[]): Promise<Array<string | null>> {
    const results: Array<string | null> = [];
    for (const key of keys) {
      results.push(await this.get(key));
    }
    return results;
  }

  pipeline(): RedisPipeline {
    return new MockRedisPipeline(this);
  }

  async keys(pattern: string): Promise<string[]> {
    const regex = new RegExp(pattern.replace(/\*/g, '.*'));
    return Array.from(this.data.keys()).filter(key => regex.test(key));
  }

  async ping(): Promise<string> {
    return 'PONG';
  }

  async info(section?: string): Promise<string> {
    return 'used_memory:1048576\r\n';
  }

  async dbsize(): Promise<number> {
    return this.data.size;
  }

  async quit(): Promise<string> {
    this.connected = false;
    this.emit('close');
    return 'OK';
  }

  on(event: string, callback: (error?: Error) => void): void {
    if (!this.callbacks[event]) {
      this.callbacks[event] = [];
    }
    this.callbacks[event].push(callback);
  }

  private emit(event: string, ...args: any[]): void {
    if (this.callbacks[event]) {
      this.callbacks[event].forEach(callback => callback(...args));
    }
  }
}

class MockRedisPipeline implements RedisPipeline {
  private commands: Array<{ method: string; args: any[] }> = [];

  constructor(private redis: MockRedis) {}

  setex(key: string, seconds: number, value: string): RedisPipeline {
    this.commands.push({ method: 'setex', args: [key, seconds, value] });
    return this;
  }

  async exec(): Promise<any> {
    const results = [];
    for (const command of this.commands) {
      if (command.method === 'setex') {
        results.push(await (this.redis as any)[command.method](...command.args));
      }
    }
    return results;
  }
}

export class RedisCacheService implements DistributedCache {
  private client: Redis;
  private config: CacheConfig;
  private readonly keyPrefix: string;
  private metricsData: CacheMetrics;
  private isConnected = false;

  constructor(config: CacheConfig) {
    this.config = config;
    this.keyPrefix = config.namespace ? `${config.namespace}:` : 'tableforge:';
    this.metricsData = this.initializeMetrics();
    
    // Redis client configuration for production performance
    this.client = new MockRedis(); // Use MockRedis for development
    // In production, use: this.client = new Redis({ ... });

    this.setupEventHandlers();
    this.initializeConnection();
  }

  private initializeMetrics(): CacheMetrics {
    return {
      hits: 0,
      misses: 0,
      sets: 0,
      deletes: 0,
      errors: 0,
      totalOperationTime: 0,
      operationCount: 0
    };
  }

  private setupEventHandlers(): void {
    this.client.on('connect', () => {
      logger.info('Redis cache connected successfully');
      this.isConnected = true;
      metrics.cacheConnections?.inc({ status: 'connected', cache_type: 'redis' });
    });

    this.client.on('ready', () => {
      logger.info('Redis cache ready for operations');
    });

    this.client.on('error', (error?: Error) => {
      logger.error('Redis cache error', { error: error?.message || 'Unknown error' });
      this.isConnected = false;
      this.metricsData.errors++;
      metrics.cacheErrors?.inc({ type: 'connection', cache_type: 'redis' });
    });

    this.client.on('close', () => {
      logger.warn('Redis cache connection closed');
      this.isConnected = false;
      metrics.cacheConnections?.dec({ status: 'connected', cache_type: 'redis' });
    });

    this.client.on('reconnecting', () => {
      logger.info('Redis cache reconnecting...');
    });
  }

  private async initializeConnection(): Promise<void> {
    try {
      await this.client.connect();
      logger.info('Redis cache initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize Redis cache', { error });
      throw error;
    }
  }

  // Core cache operations
  async get<T>(key: string): Promise<T | null> {
    const fullKey = this.buildKey(key);
    const startTime = Date.now();
    
    try {
      const cached = await this.client.get(fullKey);
      const duration = Date.now() - startTime;
      
      this.updateMetrics('get', duration);
      
      if (cached) {
        this.metricsData.hits++;
        metrics.cacheHits?.inc({ cache_type: 'redis' });
        return this.deserialize<T>(cached);
      }

      this.metricsData.misses++;
      metrics.cacheMisses?.inc({ cache_type: 'redis' });
      return null;
    } catch (error) {
      this.handleError('get', error, { key: fullKey });
      return null;
    }
  }

  async set<T>(key: string, value: T, ttl?: number): Promise<boolean> {
    const fullKey = this.buildKey(key);
    const cacheTTL = ttl || this.config.defaultTTL;
    const startTime = Date.now();

    try {
      const serialized = this.serialize(value);
      const compressed = this.config.compressionEnabled 
        ? await this.compress(serialized)
        : serialized;

      await this.client.setex(fullKey, cacheTTL, compressed);
      
      const duration = Date.now() - startTime;
      this.updateMetrics('set', duration);
      this.metricsData.sets++;
      
      return true;
    } catch (error) {
      this.handleError('set', error, { key: fullKey });
      return false;
    }
  }

  async delete(key: string): Promise<boolean> {
    const fullKey = this.buildKey(key);
    const startTime = Date.now();

    try {
      const deleted = await this.client.del(fullKey);
      const duration = Date.now() - startTime;
      
      this.updateMetrics('delete', duration);
      this.metricsData.deletes++;
      
      return deleted > 0;
    } catch (error) {
      this.handleError('delete', error, { key: fullKey });
      return false;
    }
  }

  // Batch operations for performance
  async mget<T>(keys: string[]): Promise<Array<T | null>> {
    const fullKeys = keys.map(key => this.buildKey(key));
    const startTime = Date.now();

    try {
      const results = await this.client.mget(...fullKeys);
      const duration = Date.now() - startTime;
      
      this.updateMetrics('mget', duration);

      return results.map(result => {
        if (result) {
          this.metricsData.hits++;
          return this.deserialize<T>(result);
        } else {
          this.metricsData.misses++;
          return null;
        }
      });
    } catch (error) {
      this.handleError('mget', error, { keyCount: keys.length });
      return keys.map(() => null);
    }
  }

  async mset(items: Array<{ key: string; value: any; ttl?: number }>): Promise<boolean> {
    const pipeline = this.client.pipeline();
    const startTime = Date.now();

    try {
      for (const item of items) {
        const fullKey = this.buildKey(item.key);
        const ttl = item.ttl || this.config.defaultTTL;
        const serialized = this.serialize(item.value);
        const compressed = this.config.compressionEnabled 
          ? await this.compress(serialized)
          : serialized;
        
        pipeline.setex(fullKey, ttl, compressed);
      }

      await pipeline.exec();
      
      const duration = Date.now() - startTime;
      this.updateMetrics('mset', duration);
      this.metricsData.sets += items.length;
      
      return true;
    } catch (error) {
      this.handleError('mset', error, { itemCount: items.length });
      return false;
    }
  }

  // Domain-specific cache methods
  async getUserSession(userId: string): Promise<UserSession | null> {
    const key = this.interpolateKey(CacheKeyPatterns.USER_SESSION, { userId });
    return this.get<UserSession>(key);
  }

  async setUserSession(userId: string, session: UserSession, ttl?: number): Promise<boolean> {
    const key = this.interpolateKey(CacheKeyPatterns.USER_SESSION, { userId });
    return this.set(key, session, ttl || CacheTTL.USER_SESSION);
  }

  async getRoomState(roomId: string): Promise<GameRoomState | null> {
    const key = this.interpolateKey(CacheKeyPatterns.ROOM_STATE, { roomId });
    return this.get<GameRoomState>(key);
  }

  async setRoomState(roomId: string, state: GameRoomState, ttl?: number): Promise<boolean> {
    const key = this.interpolateKey(CacheKeyPatterns.ROOM_STATE, { roomId });
    return this.set(key, state, ttl || CacheTTL.ROOM_STATE);
  }

  async getAssetMetadata(assetId: string): Promise<AssetMetadata | null> {
    const key = this.interpolateKey(CacheKeyPatterns.ASSET_METADATA, { assetId });
    return this.get<AssetMetadata>(key);
  }

  async setAssetMetadata(assetId: string, metadata: AssetMetadata): Promise<boolean> {
    const key = this.interpolateKey(CacheKeyPatterns.ASSET_METADATA, { assetId });
    return this.set(key, metadata, CacheTTL.ASSET_METADATA);
  }

  async getGameSystemTemplate(systemId: string): Promise<GameSystemTemplate | null> {
    const key = this.interpolateKey(CacheKeyPatterns.GAME_SYSTEM, { systemId });
    return this.get<GameSystemTemplate>(key);
  }

  async setGameSystemTemplate(systemId: string, template: GameSystemTemplate): Promise<boolean> {
    const key = this.interpolateKey(CacheKeyPatterns.GAME_SYSTEM, { systemId });
    return this.set(key, template, CacheTTL.GAME_SYSTEM);
  }

  // Query result caching with automatic key generation
  async getCachedQuery<T>(queryKey: string, queryFn: () => Promise<T>, ttl?: number): Promise<T> {
    const key = this.interpolateKey(CacheKeyPatterns.QUERY_RESULT, { queryHash: queryKey });
    const cached = await this.get<T>(key);

    if (cached !== null) {
      logger.debug('Query cache hit', { queryKey });
      return cached;
    }

    logger.debug('Query cache miss, executing query', { queryKey });
    const startTime = Date.now();
    
    try {
      const result = await queryFn();
      const queryDuration = Date.now() - startTime;
      
      // Cache the result
      await this.set(key, result, ttl || CacheTTL.QUERY_RESULT);
      
      logger.debug('Query executed and cached', { 
        queryKey, 
        duration: queryDuration 
      });
      
      return result;
    } catch (error) {
      logger.error('Query execution failed', { queryKey, error });
      throw error;
    }
  }

  // Cache invalidation methods
  async invalidatePattern(pattern: string): Promise<number> {
    const fullPattern = this.keyPrefix + pattern;
    
    try {
      const keys = await this.client.keys(fullPattern);
      
      if (keys.length === 0) {
        return 0;
      }

      const deleted = await this.client.del(...keys);
      
      logger.debug('Cache pattern invalidated', { 
        pattern: fullPattern, 
        deletedCount: deleted 
      });
      
      metrics.cacheInvalidations?.inc({ pattern }, deleted);
      
      return deleted;
    } catch (error) {
      this.handleError('invalidatePattern', error, { pattern: fullPattern });
      return 0;
    }
  }

  async invalidateUserData(userId: string): Promise<void> {
    const patterns = [
      this.interpolateKey(CacheKeyPatterns.USER_SESSION, { userId }),
      this.interpolateKey(CacheKeyPatterns.USER_PROFILE, { userId }),
      this.interpolateKey(CacheKeyPatterns.USER_ROOMS, { userId }),
      `query:user:${userId}:*`
    ];

    await Promise.all(patterns.map(pattern => this.invalidatePattern(pattern)));
    
    logger.debug('User cache data invalidated', { userId });
  }

  async invalidateRoomData(roomId: string): Promise<void> {
    const patterns = [
      this.interpolateKey(CacheKeyPatterns.ROOM_STATE, { roomId }),
      this.interpolateKey(CacheKeyPatterns.ROOM_PLAYERS, { roomId }),
      this.interpolateKey(CacheKeyPatterns.ROOM_CHAT, { roomId }) + ':*',
      `query:room:${roomId}:*`
    ];

    await Promise.all(patterns.map(pattern => this.invalidatePattern(pattern)));
    
    logger.debug('Room cache data invalidated', { roomId });
  }

  // Health check and monitoring
  async healthCheck(): Promise<{ status: string; latency?: number; info?: any }> {
    const startTime = Date.now();
    
    try {
      await this.client.ping();
      const latency = Date.now() - startTime;
      
      return { 
        status: 'healthy', 
        latency,
        info: {
          connected: this.isConnected,
          keyPrefix: this.keyPrefix
        }
      };
    } catch (error) {
      return { 
        status: 'unhealthy', 
        info: { 
          error: error instanceof Error ? error.message : String(error) 
        } 
      };
    }
  }

  async getStats(): Promise<CacheStats> {
    try {
      const info = await this.client.info('memory');
      const keyCount = await this.client.dbsize();
      
      const hitRate = this.metricsData.hits + this.metricsData.misses > 0
        ? this.metricsData.hits / (this.metricsData.hits + this.metricsData.misses)
        : 0;

      const averageLatency = this.metricsData.operationCount > 0
        ? this.metricsData.totalOperationTime / this.metricsData.operationCount
        : 0;
      
      return {
        hitRate,
        missRate: 1 - hitRate,
        totalHits: this.metricsData.hits,
        totalMisses: this.metricsData.misses,
        totalOperations: this.metricsData.operationCount,
        itemCount: keyCount,
        memoryUsage: this.parseMemoryInfo(info),
        connected: this.isConnected,
        averageLatency
      };
    } catch (error) {
      return {
        hitRate: 0,
        missRate: 1,
        totalHits: 0,
        totalMisses: 0,
        totalOperations: 0,
        itemCount: 0,
        connected: false,
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  // Utility methods
  private buildKey(key: string): string {
    return this.keyPrefix + key;
  }

  private interpolateKey(template: string, variables: Record<string, string>): string {
    let result = template;
    for (const [key, value] of Object.entries(variables)) {
      result = result.replace(`{{${key}}}`, value);
    }
    return result;
  }

  private serialize<T>(value: T): string {
    try {
      switch (this.config.serializationMethod) {
        case 'json':
        default:
          return JSON.stringify(value);
        // Add msgpack and protobuf support later
      }
    } catch (error) {
      logger.error('Serialization failed', { error });
      throw error;
    }
  }

  private deserialize<T>(data: string): T {
    try {
      switch (this.config.serializationMethod) {
        case 'json':
        default:
          return JSON.parse(data);
        // Add msgpack and protobuf support later
      }
    } catch (error) {
      logger.error('Deserialization failed', { error });
      throw error;
    }
  }

  private async compress(data: string): Promise<string> {
    // TODO: Implement compression based on config.compressionEnabled
    // For now, return data as-is
    return data;
  }

  private async decompress(data: string): Promise<string> {
    // TODO: Implement decompression based on config.compressionEnabled
    // For now, return data as-is
    return data;
  }

  private updateMetrics(operation: string, duration: number): void {
    this.metricsData.operationCount++;
    this.metricsData.totalOperationTime += duration;
    
    metrics.cacheOperationDuration?.observe(
      { operation, cache_type: 'redis' },
      duration
    );
  }

  private handleError(operation: string, error: any, context: any): void {
    this.metricsData.errors++;
    
    logger.error(`Redis cache ${operation} operation failed`, {
      error: error instanceof Error ? error.message : String(error),
      context
    });
    
    metrics.cacheErrors?.inc({ type: operation, cache_type: 'redis' });
  }

  private parseMemoryInfo(info: string): number {
    // Parse Redis memory info to extract used memory
    const lines = info.split('\r\n');
    for (const line of lines) {
      if (line.startsWith('used_memory:')) {
        const memoryStr = line.split(':')[1];
        return memoryStr ? parseInt(memoryStr) : 0;
      }
    }
    return 0;
  }

  async close(): Promise<void> {
    try {
      await this.client.quit();
      logger.info('Redis cache connection closed');
    } catch (error) {
      logger.error('Error closing Redis cache connection', { error });
    }
  }
}

export default RedisCacheService;
