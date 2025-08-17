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
  key?: string;
  value: T;
  ttl?: number;
  createdAt: number;
  lastAccessed: number;
  hitCount?: number;
  expiresAt: number;
  size?: number;
}

export interface CacheConfig {
  defaultTTL: number;
  maxSize: number;
  evictionPolicy: 'lru' | 'lfu' | 'ttl';
  compressionEnabled: boolean;
  serializationMethod: 'json' | 'msgpack' | 'protobuf';
  namespace?: string; // Cache namespace for multi-tenant support
}

export interface CacheMetrics {
  hits: number;
  misses: number;
  sets: number;
  deletes: number;
  errors: number;
  totalOperationTime: number;
  operationCount: number;
}

// Cache layer interfaces
export interface ApplicationCache {
  get<T>(key: string, cacheType: string): T | null;
  set<T>(key: string, value: T, cacheType: string, ttl?: number): boolean;
  invalidate(pattern: string): number;
  clear(): void;
  getStats(): CacheStats;
}

export interface DistributedCache {
  get<T>(key: string): Promise<T | null>;
  set<T>(key: string, value: T, ttl?: number): Promise<boolean>;
  delete(key: string): Promise<boolean>;
  mget<T>(keys: string[]): Promise<Array<T | null>>;
  mset(items: Array<{ key: string; value: any; ttl?: number }>): Promise<boolean>;
  invalidatePattern(pattern: string): Promise<number>;
  healthCheck(): Promise<{ status: string; latency?: number; info?: any }>;
  getStats(): Promise<CacheStats>;
  close(): Promise<void>;
}

export interface EdgeCache {
  get<T>(key: string): Promise<T | null>;
  set<T>(key: string, value: T, ttl?: number): Promise<boolean>;
  invalidate(pattern: string): Promise<number>;
  getStats(): Promise<CacheStats>;
}

// Cache statistics interface
export interface CacheStats {
  connected?: boolean;
  keyCount?: number;
  memoryUsage?: any;
  hitRate: number;
  missRate: number;
  totalHits: number;
  totalMisses: number;
  totalOperations: number;
  itemCount: number;
  size?: number;
  maxSize?: number;
  error?: string;
  averageLatency?: number;
}

// Domain-specific cache interfaces
export interface UserSession {
  userId: string;
  sessionId: string;
  email: string;
  firstName: string;
  lastName: string;
  profileImageUrl?: string;
  roles: string[];
  permissions: string[];
  lastActivity: number;
  expiresAt: number;
}

export interface GameRoomState {
  id: string;
  name: string;
  gameSystemId: string;
  ownerId: string;
  isActive: boolean;
  maxPlayers: number;
  currentPlayers: number;
  boardConfig: BoardConfig;
  assets: GameAsset[];
  boardAssets: BoardAsset[];
  players: RoomPlayer[];
  gameState: any;
  lastModified: number;
}

export interface AssetMetadata {
  id: string;
  name: string;
  type: 'card' | 'token' | 'board' | 'dice' | 'rule';
  filePath: string;
  fileName: string;
  fileSize: number;
  mimeType: string;
  width?: number;
  height?: number;
  gameSystemId?: string;
  roomId?: string;
  uploadedBy: string;
  uploadedAt: number;
  isPublic: boolean;
  tags: string[];
  metadata: Record<string, any>;
}

export interface GameSystemTemplate {
  id: string;
  name: string;
  description: string;
  category: string;
  complexity: 'beginner' | 'intermediate' | 'advanced' | 'expert';
  playerCount: {
    min: number;
    max: number;
    recommended: number;
  };
  playTime: {
    min: number;
    max: number;
    average: number;
  };
  assets: AssetMetadata[];
  rules: string;
  setupInstructions: string;
  isOfficial: boolean;
  isPublic: boolean;
  rating: number;
  downloadCount: number;
  createdBy: string;
  createdAt: number;
  updatedAt: number;
  version: string;
}

export interface BoardConfig {
  width: number;
  height: number;
  backgroundImage?: string;
  backgroundColor?: string;
  gridEnabled: boolean;
  gridSize: number;
  gridColor: string;
  snapToGrid: boolean;
  layers: BoardLayer[];
}

export interface BoardLayer {
  id: string;
  name: string;
  zIndex: number;
  visible: boolean;
  locked: boolean;
  opacity: number;
}

export interface GameAsset {
  id: string;
  name: string;
  type: string;
  filePath: string;
  width: number;
  height: number;
  gameSystemId?: string;
  roomId?: string;
  uploadedBy: string;
  uploadedAt: number;
  isPublic: boolean;
  metadata: Record<string, any>;
}

export interface BoardAsset {
  id: string;
  assetId: string;
  roomId: string;
  positionX: number;
  positionY: number;
  rotation: number;
  scale: number;
  zIndex: number;
  isLocked: boolean;
  ownerId?: string;
  lastModified: number;
}

export interface RoomPlayer {
  id: string;
  roomId: string;
  playerId: string;
  role: 'player' | 'gm' | 'observer';
  isOnline: boolean;
  joinedAt: number;
  lastActivity: number;
  firstName: string;
  lastName: string;
  profileImageUrl?: string;
}

// Cache operation result types
export interface CacheOperationResult<T = any> {
  success: boolean;
  data?: T;
  fromCache: boolean;
  cacheLevel?: 'L1' | 'L2' | 'L3';
  duration: number;
  error?: string;
}

export interface CacheMissResult {
  key: string;
  cacheType: string;
  missedLevels: Array<'L1' | 'L2' | 'L3'>;
  executionTime: number;
}

// Cache invalidation patterns
export interface CacheInvalidationPattern {
  pattern: string;
  scope: 'user' | 'room' | 'system' | 'global';
  cascading: boolean;
  levels: Array<'L1' | 'L2' | 'L3'>;
}

// Cache warming strategies
export interface CacheWarmingConfig {
  enabled: boolean;
  strategies: Array<'popular_rooms' | 'active_users' | 'game_systems' | 'recent_assets'>;
  warmupInterval: number;
  batchSize: number;
  priority: 'low' | 'medium' | 'high';
}

// Cache compression configuration
export interface CompressionConfig {
  enabled: boolean;
  algorithm: 'gzip' | 'lz4' | 'brotli';
  level: number;
  minSize: number; // Minimum size to compress
}

// Cache monitoring and alerting
export interface CacheMonitoringConfig {
  enabled: boolean;
  metricsInterval: number;
  alertThresholds: {
    hitRateBelow: number;
    errorRateAbove: number;
    latencyAbove: number;
    memoryUsageAbove: number;
  };
  alerts: {
    email: string[];
    webhook?: string;
  };
}

export type CacheLevel = 'L1' | 'L2' | 'L3';
export type CacheOperation = 'get' | 'set' | 'delete' | 'invalidate' | 'clear';
export type EvictionPolicy = 'lru' | 'lfu' | 'ttl' | 'random';
export type SerializationMethod = 'json' | 'msgpack' | 'protobuf' | 'avro';

// Cache key patterns for consistent naming
export const CacheKeyPatterns = {
  USER_SESSION: 'user:session:{{userId}}',
  USER_PROFILE: 'user:profile:{{userId}}',
  ROOM_STATE: 'room:state:{{roomId}}',
  ROOM_PLAYERS: 'room:players:{{roomId}}',
  ASSET_METADATA: 'asset:meta:{{assetId}}',
  GAME_SYSTEM: 'system:template:{{systemId}}',
  QUERY_RESULT: 'query:{{queryHash}}',
  SEARCH_RESULTS: 'search:{{searchHash}}',
  LEADERBOARD: 'leaderboard:{{type}}:{{period}}',
  NOTIFICATION: 'notification:{{userId}}',
  RATE_LIMIT: 'rate:{{userId}}:{{endpoint}}',
  BATCH_ASSETS: 'batch:assets:{{batchId}}',
  USER_ROOMS: 'user:rooms:{{userId}}',
  ROOM_CHAT: 'room:chat:{{roomId}}:{{page}}',
  SYSTEM_CONFIG: 'system:config:{{key}}'
} as const;

// Cache TTL constants (in seconds)
export const CacheTTL = {
  USER_SESSION: 3600, // 1 hour
  USER_PROFILE: 1800, // 30 minutes
  ROOM_STATE: 300, // 5 minutes
  ROOM_PLAYERS: 60, // 1 minute
  ASSET_METADATA: 3600, // 1 hour
  GAME_SYSTEM: 7200, // 2 hours
  QUERY_RESULT: 600, // 10 minutes
  SEARCH_RESULTS: 300, // 5 minutes
  LEADERBOARD: 900, // 15 minutes
  NOTIFICATION: 1800, // 30 minutes
  RATE_LIMIT: 3600, // 1 hour
  BATCH_ASSETS: 3600, // 1 hour
  USER_ROOMS: 300, // 5 minutes
  ROOM_CHAT: 1800, // 30 minutes
  SYSTEM_CONFIG: 86400 // 24 hours
} as const;
