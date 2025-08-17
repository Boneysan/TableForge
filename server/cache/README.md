# Multi-Level Caching System

## Overview

The Vorpal Board multi-level caching system implements a sophisticated L1/L2/L3 cache architecture designed for high-performance real-time gaming applications. This system provides cascading fallback, automatic cache warming, and comprehensive observability.

## Architecture

### Cache Levels

- **L1 (Application Cache)**: In-memory cache using JavaScript Map with TTL support
- **L2 (Distributed Cache)**: Redis-based distributed cache for multi-instance deployments  
- **L3 (Edge Cache)**: CDN/Edge cache for static assets and public game configurations

### Key Features

- **Cascading Fallback**: L1 → L2 → L3 → Data Loader pattern
- **Automatic Cache Population**: Lower levels automatically populate higher levels on cache hits
- **Intelligent Invalidation**: Pattern-based invalidation across all cache levels
- **Performance Monitoring**: Built-in hit rate tracking and performance metrics
- **Type Safety**: Full TypeScript support with generic interfaces

## Enhanced Redis Cache Service (Phase 3)

The `RedisCacheService` provides a sophisticated Redis implementation that aligns with the Phase 3 Performance & Scalability specifications:

### Domain-Specific Caching Methods

#### User Session Management
```typescript
// Cache user sessions with automatic TTL
await redisCache.setUserSession('user_123', userSession, 3600);
const session = await redisCache.getUserSession('user_123');
```

#### Game Room State (with Compression)
```typescript
// Large room states are automatically compressed
await redisCache.setRoomState('room_789', roomState, 1800);
const state = await redisCache.getRoomState('room_789');
```

#### Asset Metadata
```typescript
// Static assets with longer TTL
await redisCache.setAssetMetadata('asset_321', metadata);
const metadata = await redisCache.getAssetMetadata('asset_321');
```

#### Game System Templates
```typescript
// Very long TTL for rarely changing data
await redisCache.setGameSystemTemplate('system_456', template);
const template = await redisCache.getGameSystemTemplate('system_456');
```

### Advanced Features

#### Cached Query Pattern
```typescript
// Cache expensive database queries
const result = await redisCache.getCachedQuery('user_stats', async () => {
  return await expensiveDatabaseQuery();
}, 300);
```

#### Batch Operations
```typescript
// Efficient multi-key operations
const items = [
  { key: 'user:1', value: userData1, ttl: 3600 },
  { key: 'user:2', value: userData2, ttl: 3600 }
];
await redisCache.mset(items, 'user_data');

const keys = ['user:1', 'user:2'];
const results = await redisCache.mget(keys, 'user_data');
```

#### Smart Invalidation
```typescript
// Invalidate user-related data across patterns
await redisCache.invalidateUserData('user_123');

// Invalidate room-related data
await redisCache.invalidateRoomData('room_789');

// Pattern-based invalidation
await redisCache.invalidatePattern('temp:*');
```

### Production Configuration

The service supports both development (MockRedis) and production (real Redis) configurations:

```typescript
// Development with mock Redis (current implementation)
const redisCache = new RedisCacheService();

// Production with real Redis (requires ioredis dependency)
// Uncomment Redis import and constructor when deploying
```

### Performance Characteristics

- **Connection Pooling**: Optimized Redis connection settings
- **Compression**: Automatic compression for large objects (room states, game systems)
- **Batch Operations**: Efficient pipeline operations for multi-key scenarios
- **Smart TTL**: Domain-specific TTL values based on data volatility
- **Health Monitoring**: Built-in health checks and statistics collection

### Integration with Observability

The service integrates with the metrics system to track:
- Cache hit/miss rates
- Operation durations
- Connection health
- Invalidation patterns
- Error rates

See `redis-example.ts` for comprehensive usage examples.

## Quick Start

### Basic Usage

```typescript
import { createMultiLevelCache } from '@server/cache';

// Create cache manager with default implementations
const cache = createMultiLevelCache();

// Basic get/set operations
await cache.set('user-123', userData, 'user-session', 3600); // 1 hour TTL
const user = await cache.get<UserSession>('user-123', 'user-session');

// Cache-or-load pattern
const roomState = await cache.getOrSet(
  'room-abc', 
  'room-state',
  async () => {
    // Data loader function - only called on cache miss
    return await database.getRoomState('room-abc');
  },
  1800 // 30 minute TTL
);
```

### Environment-Specific Setup

```typescript
// Development (uses mock implementations)
const devCache = createDevelopmentCache();

// Production (with Redis and CDN)
const prodCache = createProductionCache(redisClient, edgeProvider);
```

## Configuration

### Environment Variables

```bash
# Application Cache (L1)
CACHE_L1_MAX_SIZE=10000
CACHE_L1_DEFAULT_TTL=300

# Distributed Cache (L2) 
CACHE_L2_HOST=localhost
CACHE_L2_PORT=6379
CACHE_L2_DEFAULT_TTL=3600
CACHE_L2_MAX_MEMORY=512mb

# Edge Cache (L3)
CACHE_L3_ENDPOINT=https://cdn.example.com
CACHE_L3_DEFAULT_TTL=86400
CACHE_L3_COMPRESSION=true
```

### Programmatic Configuration

```typescript
import { cacheConfig } from '@server/cache';

// Access current configuration
const l1Config = cacheConfig.getApplicationCacheConfig();
const l2Config = cacheConfig.getDistributedCacheConfig();
const l3Config = cacheConfig.getEdgeCacheConfig();

// All configurations are type-safe and include:
// - defaultTTL: number
// - maxSize: number (L1 only)
// - compressionEnabled: boolean
// - Performance thresholds and monitoring settings
```

## Cache Types

### Domain-Specific Cache Types

```typescript
// User sessions with authentication state
interface UserSession {
  userId: string;
  authProvider: 'firebase' | 'replit' | 'guest';
  permissions: string[];
  expiresAt: number;
}

// Game room state for real-time synchronization
interface GameRoomState {
  roomId: string;
  boardConfig: any;
  assets: AssetMetadata[];
  connectedUsers: string[];
  lastModified: number;
}

// Asset metadata for file management
interface AssetMetadata {
  assetId: string;
  fileName: string;
  mimeType: string;
  sizeBytes: number;
  uploaderId: string;
  roomId?: string;
}

// Game system templates for board configurations
interface GameSystemTemplate {
  templateId: string;
  name: string;
  category: 'board' | 'card' | 'dice' | 'token';
  configuration: any;
  isPublic: boolean;
}
```

## Advanced Operations

### Specialized Invalidation

```typescript
// User-specific data invalidation
await cache.invalidateUserData('user-123');
// Invalidates: user:session:user-123*, user:profile:user-123*, etc.

// Room-specific data invalidation  
await cache.invalidateRoomData('room-abc');
// Invalidates: room:state:room-abc*, room:assets:room-abc*, etc.

// Pattern-based invalidation
await cache.invalidate('user:*:active');
// Invalidates all active user cache entries
```

### Performance Monitoring

```typescript
// Comprehensive statistics
const stats = await cache.getComprehensiveStats();
console.log(`Hit Rate: ${stats.hitRate * 100}%`);
console.log(`L1 Size: ${stats.levels[0].stats.size}`);
console.log(`L2 Memory: ${stats.levels[1].stats.memoryUsage} bytes`);

// Health check across all levels
const health = await cache.healthCheck();
console.log(`Overall Status: ${health.overall}`);
health.levels.forEach(level => {
  console.log(`${level.level}: ${level.status}`);
});
```

### Asset and Template Caching

```typescript
// Edge cache for static assets (L3 specialized methods)
await cache.edgeCache.cacheAsset('image-123', imageData, 'image/png');
const cachedImage = await cache.edgeCache.getCachedAsset('image-123', 'image/png');

// Template caching with extended TTL
await cache.edgeCache.cacheTemplate('board-fantasy', templateData, 'board');
const template = await cache.edgeCache.getCachedTemplate('board-fantasy', 'board');
```

## Integration Examples

### WebSocket Message Caching

```typescript
// Cache frequently accessed room state
app.ws('/room/:roomId', async (ws, req) => {
  const roomId = req.params.roomId;
  
  // Get cached room state with fallback to database
  const roomState = await cache.getOrSet(
    roomId,
    'room-state', 
    () => database.getRoomState(roomId),
    1800 // 30 minutes
  );
  
  ws.send(JSON.stringify({ type: 'room-state', data: roomState.data }));
});
```

### API Response Caching

```typescript
// Cache expensive database queries
app.get('/api/game-templates', async (req, res) => {
  const templates = await cache.getOrSet(
    'all-public-templates',
    'game-templates',
    () => database.getPublicTemplates(),
    3600 // 1 hour
  );
  
  res.json(templates.data);
});
```

### Authentication Data Caching

```typescript
// Cache user sessions across requests
const getUserSession = async (userId: string): Promise<UserSession | null> => {
  return await cache.getOrSet(
    userId,
    'user-session',
    async () => {
      const user = await auth.validateUser(userId);
      return user ? {
        userId: user.uid,
        authProvider: user.provider,
        permissions: user.permissions,
        expiresAt: Date.now() + (24 * 60 * 60 * 1000) // 24 hours
      } : null;
    },
    3600 // 1 hour cache
  );
};
```

## Performance Characteristics

### Cache Hit Rates (Expected)

- **L1 (Application)**: 70-80% for frequently accessed data
- **L2 (Distributed)**: 15-20% for cross-instance shared data  
- **L3 (Edge)**: 5-10% for static assets and public configurations
- **Overall Hit Rate**: 90-95% for optimal performance

### TTL Recommendations

| Data Type | L1 TTL | L2 TTL | L3 TTL | Reasoning |
|-----------|--------|--------|--------|-----------|
| User Sessions | 5 min | 1 hour | N/A | Frequent access, security |
| Room State | 10 min | 30 min | N/A | Real-time updates needed |
| Game Templates | 1 hour | 12 hours | 48 hours | Relatively static |
| Static Assets | N/A | 6 hours | 7 days | Immutable content |
| User Profiles | 15 min | 2 hours | N/A | Moderate update frequency |

### Memory Usage Guidelines

- **L1 Cache**: Target 100MB-500MB per instance
- **L2 Cache**: 1GB-8GB shared across instances
- **L3 Cache**: Managed by CDN provider

## Monitoring and Observability

### Built-in Metrics

The cache system integrates with the existing Vorpal Board observability infrastructure:

```typescript
// Automatic metrics collection for:
// - Cache hit/miss rates by level and type
// - Operation duration (get/set/invalidate)
// - Memory usage across all levels
// - Error rates and failure modes
// - Data loader performance
```

### Health Checks

```typescript
// Automated health monitoring
const healthStatus = await cache.healthCheck();

// Returns status for each cache level:
// - 'healthy': All operations working
// - 'degraded': Some operations failing  
// - 'unhealthy': Level unavailable
```

### Debug and Troubleshooting

```typescript
// Export cache state for debugging
const l1State = cache.applicationCache.export();
console.log('L1 Cache Contents:', l1State);

// Manual cache warming for testing
await cache.edgeCache.warmCache([
  { key: 'test-key', value: 'test-value', ttl: 3600 }
]);

// Force cleanup and maintenance
cache.applicationCache.cleanup(); // Remove expired entries
```

## Best Practices

### Cache Key Design

```typescript
// Use consistent, hierarchical key patterns
const cacheKey = `${domain}:${type}:${identifier}:${version}`;

// Examples:
// user:session:user-123:v1
// room:state:room-abc:current  
// asset:metadata:image-456:v2
// template:board:fantasy-castle:v1
```

### Error Handling

```typescript
// Always handle cache failures gracefully
const getData = async (key: string) => {
  const result = await cache.get(key, 'data');
  
  if (!result.success) {
    // Log error but continue with fallback
    logger.warn('Cache miss, loading from database', { 
      key, 
      error: result.error 
    });
    return await database.getData(key);
  }
  
  return result.data;
};
```

### TTL Management

```typescript
// Use different TTLs based on data volatility
const setUserData = async (userId: string, data: any) => {
  // Short TTL for frequently changing data
  await cache.set(userId, data, 'user-session', 300); // 5 minutes
  
  // Longer TTL for stable data  
  await cache.set(userId, data.profile, 'user-profile', 3600); // 1 hour
};
```

## Production Deployment

### Redis Configuration

```yaml
# docker-compose.yml
redis:
  image: redis:7-alpine
  command: redis-server --maxmemory 1gb --maxmemory-policy allkeys-lru
  ports:
    - "6379:6379"
  volumes:
    - redis_data:/data
```

### Environment Setup

```bash
# Production environment variables
CACHE_L2_HOST=redis.internal
CACHE_L2_PASSWORD=secure-password
CACHE_L2_TLS_ENABLED=true
CACHE_L3_ENDPOINT=https://cdn.vorpalboard.com
CACHE_L3_AUTH_TOKEN=cdn-api-token
```

This multi-level caching system provides enterprise-grade performance and reliability for the Vorpal Board platform, enabling smooth real-time gaming experiences even under high load conditions.
