# Phase 3 Implementation Guide: Performance & Scalability

## Overview
Comprehensive performance optimization and scalability enhancements to support 10x current user load with sub-100ms response times.

## 1. Caching Strategy Architecture

### 1.1 Multi-Level Caching Design
```typescript
// server/cache/types.ts
export interface CacheStrategy {
  // L1: In-memory application cache (Redis-like interface)
  applicationCache: ApplicationCache;
  
  // L2: Redis distributed cache
  distributedCache: DistributedCache;
  
  // L3: CDN edge cache
  edgeCache: EdgeCache;
}

export interface CacheItem<T = any> {
  key: string;
  value: T;
  ttl: number;
  createdAt: number;
  lastAccessed: number;
  hitCount: number;
}

export interface CacheConfig {
  defaultTTL: number;
  maxSize: number;
  evictionPolicy: 'lru' | 'lfu' | 'ttl';
  compressionEnabled: boolean;
  serializationMethod: 'json' | 'msgpack' | 'protobuf';
}
```

### 1.2 Redis Implementation
```typescript
// server/cache/redis-cache.ts
import Redis from 'ioredis';
import { CacheConfig, CacheItem } from './types';
import { logger } from '../utils/logger';
import { metrics } from '../observability/metrics';

export class RedisCacheService {
  private client: Redis;
  private config: CacheConfig;
  private readonly keyPrefix = 'tableforge:';

  constructor(config: CacheConfig) {
    this.config = config;
    this.client = new Redis({
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT || '6379'),
      password: process.env.REDIS_PASSWORD,
      db: parseInt(process.env.REDIS_DB || '0'),
      retryDelayOnFailover: 100,
      maxRetriesPerRequest: 3,
      lazyConnect: true,
      // Connection pooling
      family: 4,
      keepAlive: 30000,
      connectTimeout: 10000,
      commandTimeout: 5000
    });

    this.setupEventHandlers();
  }

  private setupEventHandlers(): void {
    this.client.on('connect', () => {
      logger.info('Redis cache connected');
      metrics.cacheConnections.inc({ status: 'connected' });
    });

    this.client.on('error', (error) => {
      logger.error('Redis cache error', { error });
      metrics.cacheErrors.inc({ type: 'connection' });
    });

    this.client.on('ready', () => {
      logger.info('Redis cache ready');
    });
  }

  // User session caching
  async getUserSession(userId: string): Promise<UserSession | null> {
    const key = this.buildKey('user:session', userId);
    const startTime = Date.now();
    
    try {
      const cached = await this.client.get(key);
      const duration = Date.now() - startTime;
      
      metrics.cacheOperationDuration.observe(
        { operation: 'get', cache_type: 'user_session' },
        duration
      );

      if (cached) {
        metrics.cacheHits.inc({ cache_type: 'user_session' });
        return JSON.parse(cached);
      }

      metrics.cacheMisses.inc({ cache_type: 'user_session' });
      return null;
    } catch (error) {
      logger.error('Cache get error', { key, error });
      metrics.cacheErrors.inc({ type: 'get' });
      return null;
    }
  }

  async setUserSession(userId: string, session: UserSession, ttl?: number): Promise<boolean> {
    const key = this.buildKey('user:session', userId);
    const sessionTTL = ttl || this.config.defaultTTL;
    const startTime = Date.now();

    try {
      await this.client.setex(key, sessionTTL, JSON.stringify(session));
      const duration = Date.now() - startTime;
      
      metrics.cacheOperationDuration.observe(
        { operation: 'set', cache_type: 'user_session' },
        duration
      );

      return true;
    } catch (error) {
      logger.error('Cache set error', { key, error });
      metrics.cacheErrors.inc({ type: 'set' });
      return false;
    }
  }

  // Room state caching
  async getRoomState(roomId: string): Promise<GameRoomState | null> {
    const key = this.buildKey('room:state', roomId);
    return this.getCompressed(key, 'room_state');
  }

  async setRoomState(roomId: string, state: GameRoomState, ttl?: number): Promise<boolean> {
    const key = this.buildKey('room:state', roomId);
    return this.setCompressed(key, state, 'room_state', ttl);
  }

  // Asset metadata caching
  async getAssetMetadata(assetId: string): Promise<AssetMetadata | null> {
    const key = this.buildKey('asset:meta', assetId);
    return this.get(key, 'asset_metadata');
  }

  async setAssetMetadata(assetId: string, metadata: AssetMetadata): Promise<boolean> {
    const key = this.buildKey('asset:meta', assetId);
    // Assets don't change often, longer TTL
    return this.set(key, metadata, 'asset_metadata', 3600);
  }

  // Game system templates caching
  async getGameSystemTemplate(systemId: string): Promise<GameSystemTemplate | null> {
    const key = this.buildKey('system:template', systemId);
    return this.getCompressed(key, 'game_system');
  }

  async setGameSystemTemplate(systemId: string, template: GameSystemTemplate): Promise<boolean> {
    const key = this.buildKey('system:template', systemId);
    // Game systems change rarely, very long TTL
    return this.setCompressed(key, template, 'game_system', 7200);
  }

  // Query result caching for expensive operations
  async getCachedQuery<T>(queryKey: string, queryFn: () => Promise<T>, ttl?: number): Promise<T> {
    const key = this.buildKey('query', queryKey);
    const cached = await this.get<T>(key, 'query_result');

    if (cached !== null) {
      return cached;
    }

    // Execute query and cache result
    const result = await queryFn();
    await this.set(key, result, 'query_result', ttl);
    return result;
  }

  // Batch operations for efficiency
  async mget<T>(keys: string[], cacheType: string): Promise<Array<T | null>> {
    const prefixedKeys = keys.map(key => this.keyPrefix + key);
    const startTime = Date.now();

    try {
      const results = await this.client.mget(...prefixedKeys);
      const duration = Date.now() - startTime;

      metrics.cacheOperationDuration.observe(
        { operation: 'mget', cache_type: cacheType },
        duration
      );

      return results.map(result => result ? JSON.parse(result) : null);
    } catch (error) {
      logger.error('Cache mget error', { keys, error });
      return keys.map(() => null);
    }
  }

  async mset(items: Array<{ key: string; value: any; ttl?: number }>, cacheType: string): Promise<boolean> {
    const pipeline = this.client.pipeline();
    const startTime = Date.now();

    for (const item of items) {
      const key = this.keyPrefix + item.key;
      const ttl = item.ttl || this.config.defaultTTL;
      pipeline.setex(key, ttl, JSON.stringify(item.value));
    }

    try {
      await pipeline.exec();
      const duration = Date.now() - startTime;

      metrics.cacheOperationDuration.observe(
        { operation: 'mset', cache_type: cacheType },
        duration
      );

      return true;
    } catch (error) {
      logger.error('Cache mset error', { itemCount: items.length, error });
      return false;
    }
  }

  // Cache invalidation patterns
  async invalidatePattern(pattern: string): Promise<number> {
    const fullPattern = this.keyPrefix + pattern;
    const keys = await this.client.keys(fullPattern);
    
    if (keys.length === 0) {
      return 0;
    }

    const deleted = await this.client.del(...keys);
    metrics.cacheInvalidations.inc({ pattern }, deleted);
    
    return deleted;
  }

  async invalidateUserData(userId: string): Promise<void> {
    await Promise.all([
      this.invalidatePattern(`user:session:${userId}`),
      this.invalidatePattern(`user:*:${userId}`),
      this.invalidatePattern(`query:user:${userId}:*`)
    ]);
  }

  async invalidateRoomData(roomId: string): Promise<void> {
    await Promise.all([
      this.invalidatePattern(`room:state:${roomId}`),
      this.invalidatePattern(`room:*:${roomId}`),
      this.invalidatePattern(`query:room:${roomId}:*`)
    ]);
  }

  // Helper methods
  private async get<T>(key: string, cacheType: string): Promise<T | null> {
    const startTime = Date.now();
    
    try {
      const cached = await this.client.get(key);
      const duration = Date.now() - startTime;
      
      metrics.cacheOperationDuration.observe(
        { operation: 'get', cache_type: cacheType },
        duration
      );

      if (cached) {
        metrics.cacheHits.inc({ cache_type: cacheType });
        return JSON.parse(cached);
      }

      metrics.cacheMisses.inc({ cache_type: cacheType });
      return null;
    } catch (error) {
      logger.error('Cache get error', { key, error });
      return null;
    }
  }

  private async set<T>(key: string, value: T, cacheType: string, ttl?: number): Promise<boolean> {
    const cacheTTL = ttl || this.config.defaultTTL;
    const startTime = Date.now();

    try {
      await this.client.setex(key, cacheTTL, JSON.stringify(value));
      const duration = Date.now() - startTime;
      
      metrics.cacheOperationDuration.observe(
        { operation: 'set', cache_type: cacheType },
        duration
      );

      return true;
    } catch (error) {
      logger.error('Cache set error', { key, error });
      return false;
    }
  }

  private async getCompressed<T>(key: string, cacheType: string): Promise<T | null> {
    const startTime = Date.now();
    
    try {
      const compressed = await this.client.get(key);
      if (!compressed) {
        metrics.cacheMisses.inc({ cache_type: cacheType });
        return null;
      }

      // Decompress if needed
      const decompressed = this.config.compressionEnabled 
        ? await this.decompress(compressed)
        : compressed;

      const duration = Date.now() - startTime;
      metrics.cacheOperationDuration.observe(
        { operation: 'get_compressed', cache_type: cacheType },
        duration
      );

      metrics.cacheHits.inc({ cache_type: cacheType });
      return JSON.parse(decompressed);
    } catch (error) {
      logger.error('Cache get compressed error', { key, error });
      return null;
    }
  }

  private async setCompressed<T>(
    key: string, 
    value: T, 
    cacheType: string, 
    ttl?: number
  ): Promise<boolean> {
    const cacheTTL = ttl || this.config.defaultTTL;
    const startTime = Date.now();

    try {
      let serialized = JSON.stringify(value);
      
      if (this.config.compressionEnabled) {
        serialized = await this.compress(serialized);
      }

      await this.client.setex(key, cacheTTL, serialized);
      const duration = Date.now() - startTime;
      
      metrics.cacheOperationDuration.observe(
        { operation: 'set_compressed', cache_type: cacheType },
        duration
      );

      return true;
    } catch (error) {
      logger.error('Cache set compressed error', { key, error });
      return false;
    }
  }

  private buildKey(...parts: string[]): string {
    return this.keyPrefix + parts.join(':');
  }

  private async compress(data: string): Promise<string> {
    // Implementation depends on chosen compression library
    // For example, using zlib or lz4
    return data; // Placeholder
  }

  private async decompress(data: string): Promise<string> {
    // Implementation depends on chosen compression library
    return data; // Placeholder
  }

  // Health check and monitoring
  async healthCheck(): Promise<{ status: string; info?: any }> {
    try {
      await this.client.ping();
      return { status: 'healthy' };
    } catch (error) {
      return { status: 'unhealthy', info: error.message };
    }
  }

  async getStats(): Promise<CacheStats> {
    try {
      const info = await this.client.info('memory');
      const keyCount = await this.client.dbsize();
      
      return {
        connected: true,
        keyCount,
        memoryUsage: this.parseMemoryInfo(info),
        hitRate: this.calculateHitRate()
      };
    } catch (error) {
      return {
        connected: false,
        error: error.message
      };
    }
  }

  private parseMemoryInfo(info: string): any {
    // Parse Redis memory info
    return {}; // Placeholder
  }

  private calculateHitRate(): number {
    // Calculate cache hit rate from metrics
    return 0; // Placeholder
  }

  async close(): Promise<void> {
    await this.client.quit();
  }
}

interface CacheStats {
  connected: boolean;
  keyCount?: number;
  memoryUsage?: any;
  hitRate?: number;
  error?: string;
}
```

### 1.3 Application-Level Cache
```typescript
// server/cache/application-cache.ts
import LRU from 'lru-cache';
import { CacheConfig, CacheItem } from './types';
import { metrics } from '../observability/metrics';

export class ApplicationCache {
  private cache: LRU<string, CacheItem>;
  private config: CacheConfig;

  constructor(config: CacheConfig) {
    this.config = config;
    this.cache = new LRU({
      max: config.maxSize,
      ttl: config.defaultTTL * 1000, // Convert to milliseconds
      updateAgeOnGet: true,
      allowStale: false
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
      hitCount: 0
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
    return 0; // Placeholder
  }
}
```

## 2. Database Optimization

### 2.1 Connection Pool Optimization
```typescript
// server/database/connection-pool.ts
import { Pool, PoolConfig } from 'pg';
import { drizzle } from 'drizzle-orm/node-postgres';
import { logger } from '../utils/logger';
import { metrics } from '../observability/metrics';

export class DatabaseConnectionPool {
  private pool: Pool;
  private drizzleDb: any;

  constructor() {
    const poolConfig: PoolConfig = {
      host: process.env.DATABASE_HOST,
      port: parseInt(process.env.DATABASE_PORT || '5432'),
      database: process.env.DATABASE_NAME,
      user: process.env.DATABASE_USER,
      password: process.env.DATABASE_PASSWORD,
      
      // Connection pool settings
      min: parseInt(process.env.DB_POOL_MIN || '5'),
      max: parseInt(process.env.DB_POOL_MAX || '20'),
      idleTimeoutMillis: parseInt(process.env.DB_IDLE_TIMEOUT || '30000'),
      connectionTimeoutMillis: parseInt(process.env.DB_CONNECTION_TIMEOUT || '10000'),
      
      // Performance settings
      statement_timeout: parseInt(process.env.DB_STATEMENT_TIMEOUT || '30000'),
      query_timeout: parseInt(process.env.DB_QUERY_TIMEOUT || '30000'),
      
      // SSL settings
      ssl: process.env.NODE_ENV === 'production' ? {
        rejectUnauthorized: false
      } : false
    };

    this.pool = new Pool(poolConfig);
    this.drizzleDb = drizzle(this.pool);
    
    this.setupMonitoring();
  }

  private setupMonitoring(): void {
    this.pool.on('connect', (client) => {
      logger.debug('Database client connected');
      metrics.dbConnections.inc({ status: 'connected' });
    });

    this.pool.on('remove', (client) => {
      logger.debug('Database client removed');
      metrics.dbConnections.dec({ status: 'connected' });
    });

    this.pool.on('error', (error, client) => {
      logger.error('Database pool error', { error });
      metrics.dbErrors.inc({ type: 'pool_error' });
    });

    // Monitor pool statistics periodically
    setInterval(() => {
      metrics.dbPoolSize.set(this.pool.totalCount);
      metrics.dbPoolIdle.set(this.pool.idleCount);
      metrics.dbPoolWaiting.set(this.pool.waitingCount);
    }, 10000);
  }

  getDb() {
    return this.drizzleDb;
  }

  async query<T>(text: string, params?: any[]): Promise<T> {
    const client = await this.pool.connect();
    const startTime = Date.now();
    
    try {
      const result = await client.query(text, params);
      const duration = Date.now() - startTime;
      
      metrics.dbQueryDuration.observe(
        { query_type: this.getQueryType(text) },
        duration
      );

      logger.debug('Database query executed', {
        query: text.substring(0, 100),
        duration,
        rowCount: result.rowCount
      });

      return result.rows as T;
    } catch (error) {
      metrics.dbErrors.inc({ type: 'query_error' });
      logger.error('Database query failed', {
        query: text.substring(0, 100),
        error: error.message
      });
      throw error;
    } finally {
      client.release();
    }
  }

  async transaction<T>(callback: (tx: any) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    const startTime = Date.now();

    try {
      await client.query('BEGIN');
      const result = await callback(client);
      await client.query('COMMIT');
      
      const duration = Date.now() - startTime;
      metrics.dbTransactionDuration.observe(duration);
      
      logger.debug('Database transaction completed', { duration });
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      metrics.dbErrors.inc({ type: 'transaction_error' });
      logger.error('Database transaction failed', { error: error.message });
      throw error;
    } finally {
      client.release();
    }
  }

  private getQueryType(query: string): string {
    const normalized = query.trim().toLowerCase();
    if (normalized.startsWith('select')) return 'select';
    if (normalized.startsWith('insert')) return 'insert';
    if (normalized.startsWith('update')) return 'update';
    if (normalized.startsWith('delete')) return 'delete';
    return 'other';
  }

  async getPoolStats(): Promise<PoolStats> {
    return {
      totalCount: this.pool.totalCount,
      idleCount: this.pool.idleCount,
      waitingCount: this.pool.waitingCount,
      config: {
        min: this.pool.options.min || 0,
        max: this.pool.options.max || 0
      }
    };
  }

  async healthCheck(): Promise<{ status: string; latency?: number }> {
    const startTime = Date.now();
    
    try {
      await this.query('SELECT 1');
      const latency = Date.now() - startTime;
      return { status: 'healthy', latency };
    } catch (error) {
      return { status: 'unhealthy' };
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

interface PoolStats {
  totalCount: number;
  idleCount: number;
  waitingCount: number;
  config: {
    min: number;
    max: number;
  };
}
```

### 2.2 Query Optimization Service
```typescript
// server/database/query-optimizer.ts
import { DatabaseConnectionPool } from './connection-pool';
import { RedisCacheService } from '../cache/redis-cache';
import { metrics } from '../observability/metrics';
import { logger } from '../utils/logger';

export class QueryOptimizer {
  constructor(
    private db: DatabaseConnectionPool,
    private cache: RedisCacheService
  ) {}

  // Optimized room queries with caching
  async getRoomWithAssets(roomId: string): Promise<RoomWithAssets | null> {
    const cacheKey = `room:with_assets:${roomId}`;
    
    return this.cache.getCachedQuery(cacheKey, async () => {
      const startTime = Date.now();
      
      // Optimized query using joins instead of separate queries
      const query = `
        SELECT 
          r.*,
          json_agg(
            json_build_object(
              'id', a.id,
              'name', a.name,
              'type', a.type,
              'filePath', a.file_path,
              'width', a.width,
              'height', a.height
            )
          ) FILTER (WHERE a.id IS NOT NULL) as assets,
          json_agg(
            json_build_object(
              'id', ba.id,
              'assetId', ba.asset_id,
              'positionX', ba.position_x,
              'positionY', ba.position_y,
              'rotation', ba.rotation,
              'scale', ba.scale,
              'zIndex', ba.z_index
            )
          ) FILTER (WHERE ba.id IS NOT NULL) as board_assets
        FROM game_rooms r
        LEFT JOIN game_assets a ON a.room_id = r.id
        LEFT JOIN board_assets ba ON ba.room_id = r.id
        WHERE r.id = $1 AND r.is_active = true
        GROUP BY r.id
      `;

      const result = await this.db.query<RoomWithAssets[]>(query, [roomId]);
      const duration = Date.now() - startTime;
      
      metrics.dbQueryDuration.observe(
        { query_type: 'complex_room_query' },
        duration
      );

      logger.debug('Complex room query executed', {
        roomId,
        duration,
        hasResult: result.length > 0
      });

      return result[0] || null;
    }, 300); // 5 minute cache
  }

  // Optimized player queries
  async getActivePlayersInRoom(roomId: string): Promise<RoomPlayer[]> {
    const cacheKey = `room:active_players:${roomId}`;
    
    return this.cache.getCachedQuery(cacheKey, async () => {
      const query = `
        SELECT 
          rp.*,
          u.first_name,
          u.last_name,
          u.profile_image_url
        FROM room_players rp
        JOIN users u ON u.id = rp.player_id
        WHERE rp.room_id = $1 AND rp.is_online = true
        ORDER BY rp.joined_at ASC
      `;

      return this.db.query<RoomPlayer[]>(query, [roomId]);
    }, 60); // 1 minute cache
  }

  // Batch asset loading
  async getAssetsBatch(assetIds: string[]): Promise<GameAsset[]> {
    if (assetIds.length === 0) return [];

    // Try to get from cache first
    const cacheKeys = assetIds.map(id => `asset:${id}`);
    const cached = await this.cache.mget<GameAsset>(cacheKeys, 'asset');
    
    const missingIndices: number[] = [];
    const missingIds: string[] = [];
    
    cached.forEach((item, index) => {
      if (item === null) {
        missingIndices.push(index);
        missingIds.push(assetIds[index]);
      }
    });

    // Fetch missing assets from database
    if (missingIds.length > 0) {
      const placeholders = missingIds.map((_, i) => `$${i + 1}`).join(',');
      const query = `
        SELECT * FROM game_assets 
        WHERE id IN (${placeholders})
      `;

      const dbResults = await this.db.query<GameAsset[]>(query, missingIds);
      
      // Cache the fetched assets
      const cacheItems = dbResults.map(asset => ({
        key: `asset:${asset.id}`,
        value: asset,
        ttl: 3600 // 1 hour
      }));
      
      await this.cache.mset(cacheItems, 'asset');

      // Merge cached and db results
      dbResults.forEach((asset, dbIndex) => {
        const originalIndex = missingIndices[dbIndex];
        cached[originalIndex] = asset;
      });
    }

    return cached.filter(Boolean) as GameAsset[];
  }

  // Optimized search queries
  async searchGameSystems(
    filters: GameSystemFilters,
    pagination: { page: number; limit: number }
  ): Promise<{ systems: GameSystem[]; total: number }> {
    const cacheKey = `search:systems:${JSON.stringify({ filters, pagination })}`;
    
    return this.cache.getCachedQuery(cacheKey, async () => {
      const conditions: string[] = ['is_public = true'];
      const params: any[] = [];
      let paramIndex = 1;

      // Build dynamic query based on filters
      if (filters.category) {
        conditions.push(`category = $${paramIndex++}`);
        params.push(filters.category);
      }

      if (filters.complexity) {
        conditions.push(`complexity = $${paramIndex++}`);
        params.push(filters.complexity);
      }

      if (filters.search) {
        conditions.push(`(name ILIKE $${paramIndex} OR description ILIKE $${paramIndex})`);
        params.push(`%${filters.search}%`);
        paramIndex++;
      }

      const whereClause = conditions.join(' AND ');
      const offset = (pagination.page - 1) * pagination.limit;

      // Count query
      const countQuery = `
        SELECT COUNT(*) as total
        FROM game_systems 
        WHERE ${whereClause}
      `;

      // Data query with pagination
      const dataQuery = `
        SELECT 
          *,
          (SELECT COUNT(*) FROM game_rooms WHERE game_system_id = game_systems.id) as usage_count
        FROM game_systems 
        WHERE ${whereClause}
        ORDER BY 
          CASE WHEN is_official THEN 0 ELSE 1 END,
          download_count DESC,
          rating DESC,
          created_at DESC
        LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
      `;

      const [countResult, dataResult] = await Promise.all([
        this.db.query<[{ total: string }]>(countQuery, params),
        this.db.query<GameSystem[]>(dataQuery, [...params, pagination.limit, offset])
      ]);

      return {
        systems: dataResult,
        total: parseInt(countResult[0].total)
      };
    }, 180); // 3 minute cache
  }

  // Database analytics and performance monitoring
  async getSlowQueries(): Promise<SlowQuery[]> {
    const query = `
      SELECT 
        query,
        calls,
        total_time,
        mean_time,
        max_time,
        stddev_time
      FROM pg_stat_statements 
      WHERE mean_time > 100
      ORDER BY mean_time DESC
      LIMIT 20
    `;

    return this.db.query<SlowQuery[]>(query);
  }

  async getTableStats(): Promise<TableStats[]> {
    const query = `
      SELECT 
        schemaname,
        tablename,
        n_tup_ins as inserts,
        n_tup_upd as updates,
        n_tup_del as deletes,
        n_live_tup as live_tuples,
        n_dead_tup as dead_tuples,
        last_vacuum,
        last_autovacuum,
        last_analyze,
        last_autoanalyze
      FROM pg_stat_user_tables
      ORDER BY n_live_tup DESC
    `;

    return this.db.query<TableStats[]>(query);
  }

  async optimizeQueries(): Promise<OptimizationResult> {
    const results: OptimizationResult = {
      analyzedTables: 0,
      updatedIndexes: 0,
      vacuumedTables: 0,
      recommendations: []
    };

    try {
      // Update table statistics
      const tables = ['game_rooms', 'game_assets', 'board_assets', 'room_players'];
      
      for (const table of tables) {
        await this.db.query(`ANALYZE ${table}`);
        results.analyzedTables++;
      }

      // Check for missing indexes
      const missingIndexes = await this.checkMissingIndexes();
      results.recommendations.push(...missingIndexes);

      // Vacuum if needed
      const tableStats = await this.getTableStats();
      for (const stat of tableStats) {
        const deadTupleRatio = stat.dead_tuples / (stat.live_tuples + stat.dead_tuples);
        if (deadTupleRatio > 0.1) { // More than 10% dead tuples
          await this.db.query(`VACUUM ANALYZE ${stat.tablename}`);
          results.vacuumedTables++;
        }
      }

      logger.info('Database optimization completed', results);
      return results;
    } catch (error) {
      logger.error('Database optimization failed', { error });
      throw error;
    }
  }

  private async checkMissingIndexes(): Promise<string[]> {
    // Check for frequently queried columns without indexes
    const recommendations: string[] = [];
    
    // This would analyze query patterns and suggest indexes
    // Implementation depends on specific query patterns observed
    
    return recommendations;
  }
}

interface RoomWithAssets {
  id: string;
  name: string;
  assets: GameAsset[];
  board_assets: BoardAsset[];
}

interface GameSystemFilters {
  category?: string;
  complexity?: string;
  search?: string;
}

interface SlowQuery {
  query: string;
  calls: number;
  total_time: number;
  mean_time: number;
  max_time: number;
  stddev_time: number;
}

interface TableStats {
  schemaname: string;
  tablename: string;
  inserts: number;
  updates: number;
  deletes: number;
  live_tuples: number;
  dead_tuples: number;
  last_vacuum: Date;
  last_autovacuum: Date;
  last_analyze: Date;
  last_autoanalyze: Date;
}

interface OptimizationResult {
  analyzedTables: number;
  updatedIndexes: number;
  vacuumedTables: number;
  recommendations: string[];
}
```

## 3. WebSocket Scaling Implementation

### 3.1 Redis Pub/Sub for Horizontal Scaling
```typescript
// server/websocket/scaling/redis-pubsub.ts
import Redis from 'ioredis';
import { WebSocketServer } from 'ws';
import { logger } from '../../utils/logger';
import { metrics } from '../../observability/metrics';

export class WebSocketScalingManager {
  private publisher: Redis;
  private subscriber: Redis;
  private instanceId: string;
  private wss: WebSocketServer;
  private roomSubscriptions = new Map<string, Set<string>>(); // roomId -> socketIds

  constructor(wss: WebSocketServer) {
    this.wss = wss;
    this.instanceId = process.env.INSTANCE_ID || `instance-${Date.now()}`;
    
    this.publisher = new Redis({
      host: process.env.REDIS_HOST,
      port: parseInt(process.env.REDIS_PORT || '6379'),
      password: process.env.REDIS_PASSWORD,
      db: 1 // Separate database for pub/sub
    });

    this.subscriber = new Redis({
      host: process.env.REDIS_HOST,
      port: parseInt(process.env.REDIS_PORT || '6379'),
      password: process.env.REDIS_PASSWORD,
      db: 1
    });

    this.setupSubscriptions();
    this.setupHeartbeat();
  }

  private setupSubscriptions(): void {
    // Subscribe to room events
    this.subscriber.psubscribe('room:*');
    
    // Subscribe to broadcast events
    this.subscriber.subscribe('broadcast:all');
    
    // Subscribe to instance-specific messages
    this.subscriber.subscribe(`instance:${this.instanceId}`);

    this.subscriber.on('pmessage', (pattern, channel, message) => {
      this.handleRoomMessage(channel, message);
    });

    this.subscriber.on('message', (channel, message) => {
      if (channel === 'broadcast:all') {
        this.handleBroadcastMessage(message);
      } else if (channel.startsWith('instance:')) {
        this.handleInstanceMessage(message);
      }
    });

    logger.info('WebSocket scaling manager initialized', {
      instanceId: this.instanceId
    });
  }

  private setupHeartbeat(): void {
    // Register this instance
    setInterval(async () => {
      await this.publisher.setex(
        `instance:${this.instanceId}:heartbeat`,
        30, // 30 second TTL
        JSON.stringify({
          timestamp: Date.now(),
          connections: this.wss.clients.size,
          rooms: this.roomSubscriptions.size
        })
      );
    }, 10000); // Every 10 seconds
  }

  // Room management
  async joinRoom(socketId: string, roomId: string): Promise<void> {
    // Add socket to local room tracking
    if (!this.roomSubscriptions.has(roomId)) {
      this.roomSubscriptions.set(roomId, new Set());
    }
    this.roomSubscriptions.get(roomId)!.add(socketId);

    // Notify other instances about the join
    await this.publisher.publish(`room:${roomId}:join`, JSON.stringify({
      socketId,
      instanceId: this.instanceId,
      timestamp: Date.now()
    }));

    // Update room member count
    await this.publisher.hincrby(`room:${roomId}:members`, this.instanceId, 1);

    metrics.wsRoomMembers.inc({ room_id: roomId });
    
    logger.debug('Socket joined room', { socketId, roomId, instanceId: this.instanceId });
  }

  async leaveRoom(socketId: string, roomId: string): Promise<void> {
    // Remove from local tracking
    const roomSockets = this.roomSubscriptions.get(roomId);
    if (roomSockets) {
      roomSockets.delete(socketId);
      if (roomSockets.size === 0) {
        this.roomSubscriptions.delete(roomId);
      }
    }

    // Notify other instances
    await this.publisher.publish(`room:${roomId}:leave`, JSON.stringify({
      socketId,
      instanceId: this.instanceId,
      timestamp: Date.now()
    }));

    // Update room member count
    await this.publisher.hincrby(`room:${roomId}:members`, this.instanceId, -1);

    metrics.wsRoomMembers.dec({ room_id: roomId });
    
    logger.debug('Socket left room', { socketId, roomId, instanceId: this.instanceId });
  }

  // Message broadcasting
  async broadcastToRoom(roomId: string, message: any, excludeSocketId?: string): Promise<void> {
    const messageData = {
      type: 'room_broadcast',
      roomId,
      message,
      excludeSocketId,
      sourceInstance: this.instanceId,
      timestamp: Date.now()
    };

    await this.publisher.publish(`room:${roomId}:broadcast`, JSON.stringify(messageData));
    
    metrics.wsBroadcasts.inc({ type: 'room', room_id: roomId });
  }

  async broadcastToAll(message: any): Promise<void> {
    const messageData = {
      type: 'global_broadcast',
      message,
      sourceInstance: this.instanceId,
      timestamp: Date.now()
    };

    await this.publisher.publish('broadcast:all', JSON.stringify(messageData));
    
    metrics.wsBroadcasts.inc({ type: 'global' });
  }

  async sendToUser(userId: string, message: any): Promise<void> {
    // Find which instance has the user's socket
    const instances = await this.getActiveInstances();
    
    for (const instanceId of instances) {
      if (instanceId !== this.instanceId) {
        const messageData = {
          type: 'user_message',
          userId,
          message,
          sourceInstance: this.instanceId,
          timestamp: Date.now()
        };

        await this.publisher.publish(`instance:${instanceId}`, JSON.stringify(messageData));
      }
    }

    // Also check local sockets
    this.deliverToLocalUser(userId, message);
  }

  // Message handlers
  private handleRoomMessage(channel: string, message: string): void {
    try {
      const data = JSON.parse(message);
      const roomId = channel.split(':')[1];
      const eventType = channel.split(':')[2];

      // Don't process messages from this instance
      if (data.sourceInstance === this.instanceId) {
        return;
      }

      switch (eventType) {
        case 'broadcast':
          this.deliverToLocalRoom(roomId, data.message, data.excludeSocketId);
          break;
        case 'join':
          this.handleRemoteRoomJoin(roomId, data);
          break;
        case 'leave':
          this.handleRemoteRoomLeave(roomId, data);
          break;
      }
    } catch (error) {
      logger.error('Error handling room message', { channel, error });
    }
  }

  private handleBroadcastMessage(message: string): void {
    try {
      const data = JSON.parse(message);
      
      if (data.sourceInstance === this.instanceId) {
        return;
      }

      this.deliverToAllLocalSockets(data.message);
    } catch (error) {
      logger.error('Error handling broadcast message', { error });
    }
  }

  private handleInstanceMessage(message: string): void {
    try {
      const data = JSON.parse(message);

      switch (data.type) {
        case 'user_message':
          this.deliverToLocalUser(data.userId, data.message);
          break;
        case 'admin_command':
          this.handleAdminCommand(data);
          break;
      }
    } catch (error) {
      logger.error('Error handling instance message', { error });
    }
  }

  // Local delivery methods
  private deliverToLocalRoom(roomId: string, message: any, excludeSocketId?: string): void {
    const roomSockets = this.roomSubscriptions.get(roomId);
    if (!roomSockets) return;

    let deliveredCount = 0;
    
    this.wss.clients.forEach((socket: any) => {
      if (socket.socketId && 
          roomSockets.has(socket.socketId) && 
          socket.socketId !== excludeSocketId &&
          socket.readyState === socket.OPEN) {
        
        socket.send(JSON.stringify(message));
        deliveredCount++;
      }
    });

    metrics.wsMessageDeliveries.inc({ 
      type: 'room', 
      room_id: roomId 
    }, deliveredCount);
  }

  private deliverToAllLocalSockets(message: any): void {
    let deliveredCount = 0;
    
    this.wss.clients.forEach((socket: any) => {
      if (socket.readyState === socket.OPEN) {
        socket.send(JSON.stringify(message));
        deliveredCount++;
      }
    });

    metrics.wsMessageDeliveries.inc({ type: 'broadcast' }, deliveredCount);
  }

  private deliverToLocalUser(userId: string, message: any): void {
    this.wss.clients.forEach((socket: any) => {
      if (socket.user?.uid === userId && socket.readyState === socket.OPEN) {
        socket.send(JSON.stringify(message));
        metrics.wsMessageDeliveries.inc({ type: 'user' });
      }
    });
  }

  // Remote event handlers
  private handleRemoteRoomJoin(roomId: string, data: any): void {
    logger.debug('Remote socket joined room', { 
      roomId, 
      remoteInstance: data.instanceId 
    });
    
    // Update metrics for remote joins
    metrics.wsRemoteRoomJoins.inc({ room_id: roomId });
  }

  private handleRemoteRoomLeave(roomId: string, data: any): void {
    logger.debug('Remote socket left room', { 
      roomId, 
      remoteInstance: data.instanceId 
    });
    
    metrics.wsRemoteRoomLeaves.inc({ room_id: roomId });
  }

  private handleAdminCommand(data: any): void {
    switch (data.command) {
      case 'get_stats':
        this.sendInstanceStats(data.requestId);
        break;
      case 'close_connections':
        this.closeAllConnections();
        break;
    }
  }

  // Administrative methods
  async getActiveInstances(): Promise<string[]> {
    const pattern = 'instance:*:heartbeat';
    const keys = await this.publisher.keys(pattern);
    
    return keys.map(key => key.split(':')[1]);
  }

  async getRoomDistribution(): Promise<RoomDistribution[]> {
    const instances = await this.getActiveInstances();
    const distribution: RoomDistribution[] = [];

    for (const instanceId of instances) {
      const heartbeat = await this.publisher.get(`instance:${instanceId}:heartbeat`);
      if (heartbeat) {
        const data = JSON.parse(heartbeat);
        distribution.push({
          instanceId,
          connections: data.connections,
          rooms: data.rooms,
          lastHeartbeat: new Date(data.timestamp)
        });
      }
    }

    return distribution;
  }

  async getRoomMemberCount(roomId: string): Promise<number> {
    const members = await this.publisher.hgetall(`room:${roomId}:members`);
    
    return Object.values(members).reduce((total, count) => {
      return total + parseInt(count || '0');
    }, 0);
  }

  private async sendInstanceStats(requestId: string): Promise<void> {
    const stats = {
      requestId,
      instanceId: this.instanceId,
      connections: this.wss.clients.size,
      rooms: this.roomSubscriptions.size,
      memory: process.memoryUsage(),
      uptime: process.uptime(),
      timestamp: Date.now()
    };

    await this.publisher.publish('admin:stats', JSON.stringify(stats));
  }

  private closeAllConnections(): void {
    this.wss.clients.forEach((socket: any) => {
      socket.close(1001, 'Server shutdown');
    });
  }

  async cleanup(): Promise<void> {
    // Remove instance heartbeat
    await this.publisher.del(`instance:${this.instanceId}:heartbeat`);
    
    // Clean up room memberships
    for (const roomId of this.roomSubscriptions.keys()) {
      await this.publisher.hdel(`room:${roomId}:members`, this.instanceId);
    }

    await this.publisher.quit();
    await this.subscriber.quit();
    
    logger.info('WebSocket scaling manager cleaned up', {
      instanceId: this.instanceId
    });
  }
}

interface RoomDistribution {
  instanceId: string;
  connections: number;
  rooms: number;
  lastHeartbeat: Date;
}
```

## 4. Implementation Timeline

### Week 1-2: Cache Implementation
- [ ] Set up Redis infrastructure
- [ ] Implement Redis cache service
- [ ] Add application-level caching
- [ ] Create cache invalidation strategies
- [ ] Add cache monitoring and metrics

### Week 3-4: Database Optimization
- [ ] Optimize connection pooling
- [ ] Implement query optimizer service
- [ ] Add batch loading capabilities
- [ ] Create database monitoring tools
- [ ] Implement automated optimization routines

### Week 5-6: WebSocket Scaling
- [ ] Implement Redis pub/sub system
- [ ] Add horizontal scaling support
- [ ] Create load balancing strategies
- [ ] Add scaling monitoring and metrics
- [ ] Test multi-instance scenarios

### Week 7-8: Integration & Testing
- [ ] Performance testing with caching
- [ ] Load testing with scaling
- [ ] Optimization fine-tuning
- [ ] Documentation and monitoring setup
- [ ] Production deployment preparation

## 5. Performance Targets

### Response Time Targets
- **API Endpoints**: <50ms (95th percentile)
- **Database Queries**: <25ms (95th percentile)
- **Cache Operations**: <5ms (95th percentile)
- **WebSocket Messages**: <10ms delivery time

### Scalability Targets
- **Concurrent Users**: 1000+ per instance
- **Database Connections**: 20 connections supporting 1000+ users
- **Cache Hit Rate**: >90% for frequently accessed data
- **Horizontal Scaling**: Support 10+ instances seamlessly

### Resource Usage Targets
- **Memory Usage**: <512MB per 1000 concurrent users
- **CPU Usage**: <70% under peak load
- **Database CPU**: <50% under normal load
- **Network Bandwidth**: Optimized WebSocket messages

---

**Implementation Priority**: Medium-High  
**Estimated Effort**: 8 weeks  
**Dependencies**: Phase 1 and 2 completion  
**Risk Level**: Medium
