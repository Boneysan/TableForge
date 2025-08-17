import { register, Counter, Histogram, Gauge } from 'prom-client';
import { logger } from '@server/utils/logger';

// Metrics registry and configuration
register.setDefaultLabels({
  app: 'vorpal-board',
  version: '1.0.0',
  environment: process.env['NODE_ENV'] || 'development',
});

// Room Metrics
export const activeRoomsGauge = new Gauge({
  name: 'vorpal_active_rooms_total',
  help: 'Number of currently active game rooms',
  labelNames: ['status'],
});

export const roomCreatedCounter = new Counter({
  name: 'vorpal_rooms_created_total',
  help: 'Total number of rooms created',
  labelNames: ['created_by_type'],
});

export const roomDeletedCounter = new Counter({
  name: 'vorpal_rooms_deleted_total',
  help: 'Total number of rooms deleted',
  labelNames: ['reason'],
});

// WebSocket Connection Metrics
export const websocketConnectionsGauge = new Gauge({
  name: 'vorpal_websocket_connections_active',
  help: 'Number of active WebSocket connections',
  labelNames: ['room_id'],
});

export const websocketConnectCounter = new Counter({
  name: 'vorpal_websocket_connects_total',
  help: 'Total number of WebSocket connections established',
  labelNames: ['auth_status'],
});

export const websocketDisconnectCounter = new Counter({
  name: 'vorpal_websocket_disconnects_total',
  help: 'Total number of WebSocket disconnections',
  labelNames: ['reason'],
});

export const websocketMessageCounter = new Counter({
  name: 'vorpal_websocket_messages_total',
  help: 'Total number of WebSocket messages sent/received',
  labelNames: ['direction', 'event_type', 'room_id'],
});

// Game Move Metrics
export const cardMovesCounter = new Counter({
  name: 'vorpal_card_moves_total',
  help: 'Total number of card moves performed',
  labelNames: ['move_type', 'source_type', 'target_type', 'room_id'],
});

export const movesPerMinuteGauge = new Gauge({
  name: 'vorpal_moves_per_minute',
  help: 'Number of moves per minute across all rooms',
  labelNames: ['room_id'],
});

export const deckOperationsCounter = new Counter({
  name: 'vorpal_deck_operations_total',
  help: 'Total number of deck operations (shuffle, deal, etc.)',
  labelNames: ['operation', 'deck_type', 'room_id'],
});

// Asset Management Metrics
export const assetUploadCounter = new Counter({
  name: 'vorpal_asset_uploads_total',
  help: 'Total number of assets uploaded',
  labelNames: ['asset_type', 'upload_status'],
});

export const assetUploadSizeHistogram = new Histogram({
  name: 'vorpal_asset_upload_size_bytes',
  help: 'Distribution of asset upload sizes in bytes',
  buckets: [1024, 10240, 102400, 1048576, 10485760, 52428800], // 1KB to 50MB
  labelNames: ['asset_type'],
});

export const assetUploadDurationHistogram = new Histogram({
  name: 'vorpal_asset_upload_duration_seconds',
  help: 'Duration of asset uploads in seconds',
  buckets: [0.1, 0.5, 1, 2, 5, 10, 30],
  labelNames: ['asset_type'],
});

// Authentication Metrics
export const authenticationCounter = new Counter({
  name: 'vorpal_authentication_attempts_total',
  help: 'Total number of authentication attempts',
  labelNames: ['provider', 'status'],
});

export const activeUsersGauge = new Gauge({
  name: 'vorpal_active_users_total',
  help: 'Number of currently active users',
  labelNames: ['auth_provider'],
});

// Performance Metrics
export const httpRequestDurationHistogram = new Histogram({
  name: 'vorpal_http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  buckets: [0.01, 0.05, 0.1, 0.5, 1, 2, 5],
  labelNames: ['method', 'route', 'status_code'],
});

export const databaseQueryDurationHistogram = new Histogram({
  name: 'vorpal_database_query_duration_seconds',
  help: 'Duration of database queries in seconds',
  buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1],
  labelNames: ['operation', 'table'],
});

export const databaseConnectionsGauge = new Gauge({
  name: 'vorpal_database_connections_active',
  help: 'Number of active database connections',
});

// Error Metrics
export const errorCounter = new Counter({
  name: 'vorpal_errors_total',
  help: 'Total number of errors by type and severity',
  labelNames: ['error_type', 'severity', 'component'],
});

export const uncaughtExceptionCounter = new Counter({
  name: 'vorpal_uncaught_exceptions_total',
  help: 'Total number of uncaught exceptions',
  labelNames: ['type'],
});

// Game System Metrics
export const gameSystemsGauge = new Gauge({
  name: 'vorpal_game_systems_total',
  help: 'Total number of game systems',
  labelNames: ['visibility', 'category'],
});

export const gameTemplatesGauge = new Gauge({
  name: 'vorpal_game_templates_total',
  help: 'Total number of game templates',
  labelNames: ['visibility', 'category'],
});

// Memory and Resource Metrics
export const memoryUsageGauge = new Gauge({
  name: 'vorpal_memory_usage_bytes',
  help: 'Memory usage in bytes',
  labelNames: ['type'],
});

export const cpuUsageGauge = new Gauge({
  name: 'vorpal_cpu_usage_percent',
  help: 'CPU usage percentage',
});

// Move tracking for real-time metrics
class MoveTracker {
  private moveCountsPerRoom: Map<string, number[]> = new Map();
  private readonly windowSizeMinutes = 5;
  private readonly tickIntervalMs = 10000; // 10 seconds

  constructor() {
    // Update moves per minute every 10 seconds
    setInterval(() => {
      this.updateMovesPerMinute();
    }, this.tickIntervalMs);
  }

  recordMove(roomId: string): void {
    const now = Date.now();
    const minuteBucket = Math.floor(now / 60000); // Current minute

    if (!this.moveCountsPerRoom.has(roomId)) {
      this.moveCountsPerRoom.set(roomId, []);
    }

    const roomMoves = this.moveCountsPerRoom.get(roomId)!;
    
    // Add move to current minute bucket
    const existingBucketIndex = roomMoves.findIndex(
      (_, index) => minuteBucket - this.windowSizeMinutes <= index
    );
    
    if (existingBucketIndex === -1) {
      roomMoves.push(1);
    } else {
      const lastIndex = roomMoves.length - 1;
      if (lastIndex >= 0 && roomMoves[lastIndex] !== undefined) {
        roomMoves[lastIndex]++;
      }
    }

    // Clean old buckets (older than window)
    const cutoff = minuteBucket - this.windowSizeMinutes;
    this.moveCountsPerRoom.set(
      roomId,
      roomMoves.filter((_, index) => minuteBucket - cutoff <= index)
    );
  }

  private updateMovesPerMinute(): void {
    for (const [roomId, moves] of this.moveCountsPerRoom.entries()) {
      const totalMoves = moves.reduce((sum, count) => sum + count, 0);
      const averageMovesPerMinute = totalMoves / this.windowSizeMinutes;
      
      movesPerMinuteGauge.set({ room_id: roomId }, averageMovesPerMinute);
    }
  }

  getMovesPerMinute(roomId: string): number {
    const moves = this.moveCountsPerRoom.get(roomId) || [];
    const totalMoves = moves.reduce((sum, count) => sum + count, 0);
    return totalMoves / this.windowSizeMinutes;
  }
}

export const moveTracker = new MoveTracker();

// Resource monitoring
function updateResourceMetrics(): void {
  const usage = process.memoryUsage();
  
  memoryUsageGauge.set({ type: 'heap_used' }, usage.heapUsed);
  memoryUsageGauge.set({ type: 'heap_total' }, usage.heapTotal);
  memoryUsageGauge.set({ type: 'external' }, usage.external);
  memoryUsageGauge.set({ type: 'rss' }, usage.rss);

  // CPU usage (simplified)
  const cpuUsage = process.cpuUsage();
  const totalCpu = cpuUsage.user + cpuUsage.system;
  cpuUsageGauge.set(totalCpu / 1000000); // Convert to percentage
}

// Start resource monitoring
setInterval(updateResourceMetrics, 30000); // Every 30 seconds

// Helper functions for common metric operations
export function incrementRoomCount(status: 'active' | 'inactive' = 'active'): void {
  activeRoomsGauge.inc({ status });
}

export function decrementRoomCount(status: 'active' | 'inactive' = 'active'): void {
  activeRoomsGauge.dec({ status });
}

export function recordWebSocketConnect(authStatus: 'authenticated' | 'anonymous'): void {
  websocketConnectCounter.inc({ auth_status: authStatus });
}

export function recordWebSocketDisconnect(reason: string): void {
  websocketDisconnectCounter.inc({ reason });
}

export function recordWebSocketMessage(
  direction: 'inbound' | 'outbound',
  eventType: string,
  roomId: string
): void {
  websocketMessageCounter.inc({
    direction,
    event_type: eventType,
    room_id: roomId,
  });
}

export function recordCardMove(
  moveType: string,
  sourceType: string,
  targetType: string,
  roomId: string
): void {
  cardMovesCounter.inc({
    move_type: moveType,
    source_type: sourceType,
    target_type: targetType,
    room_id: roomId,
  });
  
  moveTracker.recordMove(roomId);
}

export function recordDeckOperation(
  operation: string,
  deckType: string,
  roomId: string
): void {
  deckOperationsCounter.inc({
    operation,
    deck_type: deckType,
    room_id: roomId,
  });
}

export function recordAssetUpload(
  assetType: string,
  status: 'success' | 'failure',
  sizeBytes?: number,
  durationSeconds?: number
): void {
  assetUploadCounter.inc({ asset_type: assetType, upload_status: status });
  
  if (sizeBytes) {
    assetUploadSizeHistogram.observe({ asset_type: assetType }, sizeBytes);
  }
  
  if (durationSeconds) {
    assetUploadDurationHistogram.observe({ asset_type: assetType }, durationSeconds);
  }
}

export function recordAuthentication(
  provider: string,
  status: 'success' | 'failure'
): void {
  authenticationCounter.inc({ provider, status });
}

export function recordHttpRequest(
  method: string,
  route: string,
  statusCode: number,
  durationSeconds: number
): void {
  httpRequestDurationHistogram.observe(
    {
      method,
      route,
      status_code: statusCode.toString(),
    },
    durationSeconds
  );
}

export function recordDatabaseQuery(
  operation: string,
  table: string,
  durationSeconds: number
): void {
  databaseQueryDurationHistogram.observe(
    { operation, table },
    durationSeconds
  );
}

export function recordError(
  errorType: string,
  severity: 'low' | 'medium' | 'high' | 'critical',
  component: string
): void {
  errorCounter.inc({
    error_type: errorType,
    severity,
    component,
  });
}

// Cleanup function
export function resetMetrics(): void {
  register.resetMetrics();
  logger.info('Metrics registry reset');
}

// Export metrics endpoint
export async function getMetrics(): Promise<string> {
  return await register.metrics();
}

// Health check for metrics
export async function getMetricsHealth(): Promise<{
  status: 'healthy' | 'unhealthy';
  details: Record<string, any>;
}> {
  try {
    const metricsArray = await register.getMetricsAsJSON();
    return {
      status: 'healthy',
      details: {
        totalMetrics: metricsArray.length,
        lastUpdate: new Date().toISOString(),
        memoryUsage: process.memoryUsage(),
      },
    };
  } catch (error) {
    return {
      status: 'unhealthy',
      details: {
        error: (error as Error).message,
      },
    };
  }
}

// Unified metrics object for easy importing
export const metrics = {
  // Cache metrics
  cacheHits: new Counter({ name: 'cache_hits_total', help: 'Cache hits', labelNames: ['cache_type'] }),
  cacheMisses: new Counter({ name: 'cache_misses_total', help: 'Cache misses', labelNames: ['cache_type'] }),
  cacheErrors: new Counter({ name: 'cache_errors_total', help: 'Cache errors', labelNames: ['type', 'cache_type'] }),
  cacheConnections: new Gauge({ name: 'cache_connections', help: 'Cache connections', labelNames: ['status', 'cache_type'] }),
  cacheOperationDuration: new Histogram({ name: 'cache_operation_duration_seconds', help: 'Cache operation duration', labelNames: ['operation', 'cache_type'] }),
  cacheInvalidations: new Counter({ name: 'cache_invalidations_total', help: 'Cache invalidations', labelNames: ['pattern'] }),
  
  // Database metrics
  dbConnections: databaseConnectionsGauge,
  dbPoolSize: new Gauge({ name: 'db_pool_size', help: 'Database pool size' }),
  dbPoolIdle: new Gauge({ name: 'db_pool_idle', help: 'Database pool idle connections' }),
  dbPoolWaiting: new Gauge({ name: 'db_pool_waiting', help: 'Database pool waiting connections' }),
  dbQueryDuration: databaseQueryDurationHistogram,
  dbTransactionDuration: new Histogram({ name: 'db_transaction_duration_seconds', help: 'Database transaction duration' }),
  dbErrors: new Counter({ name: 'db_errors_total', help: 'Database errors', labelNames: ['type'] }),
  
  // WebSocket metrics
  wsConnections: websocketConnectionsGauge,
  wsRoomMembers: new Gauge({ name: 'ws_room_members', help: 'WebSocket room members', labelNames: ['room_id'] }),
  wsBroadcasts: new Counter({ name: 'ws_broadcasts_total', help: 'WebSocket broadcasts', labelNames: ['type', 'room_id'] }),
  wsMessageDeliveries: new Counter({ name: 'ws_message_deliveries_total', help: 'WebSocket message deliveries', labelNames: ['type'] }),
  wsRemoteRoomJoins: new Counter({ name: 'ws_remote_room_joins_total', help: 'Remote room joins', labelNames: ['room_id'] }),
  wsRemoteRoomLeaves: new Counter({ name: 'ws_remote_room_leaves_total', help: 'Remote room leaves', labelNames: ['room_id'] })
};