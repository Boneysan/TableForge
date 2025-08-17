// server/cache/config.ts
import { CacheConfig, CacheWarmingConfig, CompressionConfig, CacheMonitoringConfig } from './types';

export class CacheConfigService {
  private static instance: CacheConfigService;
  
  private constructor() {}

  static getInstance(): CacheConfigService {
    if (!CacheConfigService.instance) {
      CacheConfigService.instance = new CacheConfigService();
    }
    return CacheConfigService.instance;
  }

  // Default cache configurations for different cache types
  getDefaultConfig(): CacheConfig {
    return {
      defaultTTL: parseInt(process.env['CACHE_DEFAULT_TTL'] || '300'), // 5 minutes
      maxSize: parseInt(process.env['CACHE_MAX_SIZE'] || '10000'), // 10k items
      evictionPolicy: (process.env['CACHE_EVICTION_POLICY'] as any) || 'lru',
      compressionEnabled: process.env['CACHE_COMPRESSION_ENABLED'] === 'true',
      serializationMethod: (process.env['CACHE_SERIALIZATION'] as any) || 'json'
    };
  }

  // Application cache (L1) configuration
  getApplicationCacheConfig(): CacheConfig {
    return {
      defaultTTL: parseInt(process.env['L1_CACHE_TTL'] || '60'), // 1 minute
      maxSize: parseInt(process.env['L1_CACHE_MAX_SIZE'] || '1000'), // 1k items
      evictionPolicy: 'lru',
      compressionEnabled: false, // No compression for L1 (speed priority)
      serializationMethod: 'json'
    };
  }

  // Redis cache (L2) configuration
  getDistributedCacheConfig(): CacheConfig {
    return {
      defaultTTL: parseInt(process.env['L2_CACHE_TTL'] || '900'), // 15 minutes
      maxSize: parseInt(process.env['L2_CACHE_MAX_SIZE'] || '100000'), // 100k items
      evictionPolicy: 'lru',
      compressionEnabled: process.env['L2_CACHE_COMPRESSION'] === 'true',
      serializationMethod: (process.env['L2_CACHE_SERIALIZATION'] as any) || 'json'
    };
  }

  // Edge cache (L3) configuration
  getEdgeCacheConfig(): CacheConfig {
    return {
      defaultTTL: parseInt(process.env['L3_CACHE_TTL'] || '3600'), // 1 hour
      maxSize: parseInt(process.env['L3_CACHE_MAX_SIZE'] || '1000000'), // 1M items
      evictionPolicy: 'lru',
      compressionEnabled: true, // Always compress for edge cache
      serializationMethod: 'msgpack' // More efficient for edge
    };
  }

  // Domain-specific TTL configurations
  getUserSessionTTL(): number {
    return parseInt(process.env['USER_SESSION_TTL'] || '1800'); // 30 minutes
  }

  getRoomStateTTL(): number {
    return parseInt(process.env['ROOM_STATE_TTL'] || '300'); // 5 minutes
  }

  getAssetMetadataTTL(): number {
    return parseInt(process.env['ASSET_METADATA_TTL'] || '3600'); // 1 hour
  }

  getGameSystemTemplateTTL(): number {
    return parseInt(process.env['GAME_SYSTEM_TTL'] || '7200'); // 2 hours
  }

  getQueryResultTTL(): number {
    return parseInt(process.env['QUERY_RESULT_TTL'] || '600'); // 10 minutes
  }

  // Cache warming configuration
  getCacheWarmingConfig(): CacheWarmingConfig {
    return {
      enabled: process.env['CACHE_WARMING_ENABLED'] === 'true',
      strategies: this.parseCacheWarmingStrategies(),
      warmupInterval: parseInt(process.env['CACHE_WARMUP_INTERVAL'] || '300000'), // 5 minutes
      batchSize: parseInt(process.env['CACHE_WARMUP_BATCH_SIZE'] || '100'),
      priority: (process.env['CACHE_WARMUP_PRIORITY'] as any) || 'medium'
    };
  }

  // Compression configuration
  getCompressionConfig(): CompressionConfig {
    return {
      enabled: process.env['CACHE_COMPRESSION_ENABLED'] === 'true',
      algorithm: (process.env['CACHE_COMPRESSION_ALGORITHM'] as any) || 'gzip',
      level: parseInt(process.env['CACHE_COMPRESSION_LEVEL'] || '6'),
      minSize: parseInt(process.env['CACHE_COMPRESSION_MIN_SIZE'] || '1024') // 1KB
    };
  }

  // Monitoring configuration
  getMonitoringConfig(): CacheMonitoringConfig {
    return {
      enabled: process.env['CACHE_MONITORING_ENABLED'] === 'true',
      metricsInterval: parseInt(process.env['CACHE_METRICS_INTERVAL'] || '60000'), // 1 minute
      alertThresholds: {
        hitRateBelow: parseFloat(process.env['CACHE_ALERT_HIT_RATE'] || '0.8'), // 80%
        errorRateAbove: parseFloat(process.env['CACHE_ALERT_ERROR_RATE'] || '0.05'), // 5%
        latencyAbove: parseInt(process.env['CACHE_ALERT_LATENCY'] || '100'), // 100ms
        memoryUsageAbove: parseFloat(process.env['CACHE_ALERT_MEMORY'] || '0.9') // 90%
      },
      alerts: {
        email: this.parseEmailList(process.env['CACHE_ALERT_EMAILS'] || ''),
        ...(process.env['CACHE_ALERT_WEBHOOK'] && { webhook: process.env['CACHE_ALERT_WEBHOOK'] })
      }
    };
  }

  // Redis connection configuration
  getRedisConfig() {
    return {
      host: process.env['REDIS_HOST'] || 'localhost',
      port: parseInt(process.env['REDIS_PORT'] || '6379'),
      password: process.env['REDIS_PASSWORD'],
      db: parseInt(process.env['REDIS_DB'] || '0'),
      keyPrefix: process.env['REDIS_KEY_PREFIX'] || 'tableforge:',
      connectTimeout: parseInt(process.env['REDIS_CONNECT_TIMEOUT'] || '10000'),
      lazyConnect: true,
      retryDelayOnFailover: 100,
      maxRetriesPerRequest: 3,
      family: 4,
      keepAlive: 30000,
      commandTimeout: parseInt(process.env['REDIS_COMMAND_TIMEOUT'] || '5000'),
      // Connection pool settings
      maxClients: parseInt(process.env['REDIS_MAX_CLIENTS'] || '10'),
      acquireTimeout: parseInt(process.env['REDIS_ACQUIRE_TIMEOUT'] || '10000'),
      fifo: true
    };
  }

  // Cache key patterns
  getCacheKeyPatterns() {
    return {
      userSession: 'user:session:{userId}',
      userPermissions: 'user:permissions:{userId}',
      roomState: 'room:state:{roomId}',
      roomPlayers: 'room:players:{roomId}',
      roomAssets: 'room:assets:{roomId}',
      assetMetadata: 'asset:meta:{assetId}',
      gameSystemTemplate: 'system:template:{systemId}',
      gameSystemAssets: 'system:assets:{systemId}',
      queryResult: 'query:{queryType}:{hash}',
      userRooms: 'user:rooms:{userId}',
      popularRooms: 'popular:rooms:{timeframe}',
      recentAssets: 'recent:assets:{timeframe}',
      systemStats: 'stats:system:{metric}',
      roomStats: 'stats:room:{roomId}:{metric}'
    };
  }

  // Cache invalidation patterns
  getCacheInvalidationPatterns() {
    return {
      userAll: 'user:*:{userId}*',
      roomAll: 'room:*:{roomId}*',
      assetAll: 'asset:*:{assetId}*',
      systemAll: 'system:*:{systemId}*',
      queryByUser: 'query:*:*{userId}*',
      queryByRoom: 'query:*:*{roomId}*',
      statsAll: 'stats:*',
      popularContent: 'popular:*',
      recentContent: 'recent:*'
    };
  }

  // Performance thresholds
  getPerformanceThresholds() {
    return {
      l1CacheMaxLatency: parseInt(process.env['L1_CACHE_MAX_LATENCY'] || '1'), // 1ms
      l2CacheMaxLatency: parseInt(process.env['L2_CACHE_MAX_LATENCY'] || '10'), // 10ms
      l3CacheMaxLatency: parseInt(process.env['L3_CACHE_MAX_LATENCY'] || '50'), // 50ms
      minHitRate: parseFloat(process.env['CACHE_MIN_HIT_RATE'] || '0.85'), // 85%
      maxMemoryUsage: parseFloat(process.env['CACHE_MAX_MEMORY'] || '0.8'), // 80%
      maxErrorRate: parseFloat(process.env['CACHE_MAX_ERROR_RATE'] || '0.01') // 1%
    };
  }

  // Environment-specific overrides
  isDevelopment(): boolean {
    return process.env['NODE_ENV'] === 'development';
  }

  isProduction(): boolean {
    return process.env['NODE_ENV'] === 'production';
  }

  isTest(): boolean {
    return process.env['NODE_ENV'] === 'test';
  }

  // Development mode adjustments
  getDevelopmentOverrides(): Partial<CacheConfig> {
    if (!this.isDevelopment()) return {};

    return {
      defaultTTL: 30, // Shorter TTL for development
      compressionEnabled: false, // Disable compression for faster debugging
      serializationMethod: 'json' // Use JSON for better debugging
    };
  }

  // Test mode adjustments
  getTestOverrides(): Partial<CacheConfig> {
    if (!this.isTest()) return {};

    return {
      defaultTTL: 10, // Very short TTL for tests
      maxSize: 100, // Small cache size for tests
      compressionEnabled: false,
      serializationMethod: 'json'
    };
  }

  // Utility methods
  private parseCacheWarmingStrategies(): Array<'popular_rooms' | 'active_users' | 'game_systems' | 'recent_assets'> {
    const strategies = process.env['CACHE_WARMING_STRATEGIES'] || 'popular_rooms,active_users';
    return strategies.split(',').map(s => s.trim()) as any[];
  }

  private parseEmailList(emailString: string): string[] {
    if (!emailString) return [];
    return emailString.split(',').map(email => email.trim()).filter(Boolean);
  }

  // Configuration validation
  validateConfig(config: CacheConfig): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (config.defaultTTL < 0) {
      errors.push('defaultTTL must be non-negative');
    }

    if (config.maxSize < 1) {
      errors.push('maxSize must be at least 1');
    }

    if (!['lru', 'lfu', 'ttl'].includes(config.evictionPolicy)) {
      errors.push('evictionPolicy must be one of: lru, lfu, ttl');
    }

    if (!['json', 'msgpack', 'protobuf'].includes(config.serializationMethod)) {
      errors.push('serializationMethod must be one of: json, msgpack, protobuf');
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  // Create environment-specific configuration
  createEnvironmentConfig(): CacheConfig {
    const baseConfig = this.getDefaultConfig();
    
    if (this.isTest()) {
      return { ...baseConfig, ...this.getTestOverrides() };
    }
    
    if (this.isDevelopment()) {
      return { ...baseConfig, ...this.getDevelopmentOverrides() };
    }
    
    return baseConfig;
  }
}

// Export singleton instance
export const cacheConfig = CacheConfigService.getInstance();
