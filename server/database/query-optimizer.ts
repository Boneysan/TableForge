// server/database/query-optimizer.ts
import { DatabaseConnectionPool } from './connection-pool';
import { RedisCacheService } from '../cache/redis-cache';
import { dbLogger as logger } from '../utils/logger';

// Note: Metrics import commented out until observability system is implemented
// import { metrics } from '../observability/metrics';

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
      
      // Metrics tracking (commented until observability system is ready)
      // metrics.dbQueryDuration.observe(
      //   { query_type: 'complex_room_query' },
      //   duration
      // );

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

  // Advanced query optimization methods
  async getQueryPlan(query: string, params?: any[]): Promise<QueryPlan[]> {
    const explainQuery = `EXPLAIN (ANALYZE true, BUFFERS true, FORMAT JSON) ${query}`;
    
    try {
      const result = await this.db.query<any[]>(explainQuery, params);
      return result[0]?.['QUERY PLAN'] || [];
    } catch (error) {
      logger.error('Failed to get query plan', { query: query.substring(0, 100), error });
      return [];
    }
  }

  async optimizeTableMaintenance(): Promise<MaintenanceResult> {
    const result: MaintenanceResult = {
      reindexedTables: 0,
      vacuumedTables: 0,
      analyzedTables: 0,
      recommendations: []
    };

    try {
      const tableStats = await this.getTableStats();
      
      for (const stat of tableStats) {
        // Calculate bloat ratios
        const totalTuples = stat.live_tuples + stat.dead_tuples;
        const deadRatio = totalTuples > 0 ? stat.dead_tuples / totalTuples : 0;
        
        // Vacuum if high dead tuple ratio
        if (deadRatio > 0.15) {
          await this.db.query(`VACUUM ANALYZE ${stat.tablename}`);
          result.vacuumedTables++;
        }
        
        // Analyze if statistics are old
        const lastAnalyze = stat.last_analyze || stat.last_autoanalyze;
        if (!lastAnalyze || (Date.now() - lastAnalyze.getTime()) > 24 * 60 * 60 * 1000) {
          await this.db.query(`ANALYZE ${stat.tablename}`);
          result.analyzedTables++;
        }
        
        // Add recommendations for heavily updated tables
        if (stat.updates > stat.live_tuples * 0.5) {
          result.recommendations.push(
            `Table ${stat.tablename} has high update ratio, consider more frequent VACUUM`
          );
        }
      }

      logger.info('Table maintenance completed', result);
      return result;
    } catch (error) {
      logger.error('Table maintenance failed', { error });
      throw error;
    }
  }

  async getCacheEfficiency(): Promise<CacheEfficiencyReport> {
    // Get cache statistics from Redis service
    const cacheStats = await this.cache.getStats();
    
    // Calculate efficiency metrics
    const efficiency: CacheEfficiencyReport = {
      hitRate: cacheStats.hitRate || 0,
      missRate: 1 - (cacheStats.hitRate || 0),
      keyCount: cacheStats.keyCount || 0,
      memoryUsage: cacheStats.memoryUsage || {},
      recommendations: []
    };

    // Add recommendations based on efficiency
    if (efficiency.hitRate < 0.8) {
      efficiency.recommendations.push('Cache hit rate is below 80%, consider increasing TTL for frequently accessed data');
    }
    
    if (efficiency.keyCount > 100000) {
      efficiency.recommendations.push('High number of cache keys, consider implementing key expiration policies');
    }

    return efficiency;
  }

  private async checkMissingIndexes(): Promise<string[]> {
    const recommendations: string[] = [];
    
    try {
      // Check for tables without primary key indexes
      const missingPrimaryKeys = await this.db.query<Array<{ tablename: string }>>(`
        SELECT tablename 
        FROM pg_tables 
        WHERE schemaname = 'public' 
        AND tablename NOT IN (
          SELECT tablename 
          FROM pg_indexes 
          WHERE indexname LIKE '%pkey'
        )
      `);

      for (const table of missingPrimaryKeys) {
        recommendations.push(`Table ${table.tablename} is missing a primary key index`);
      }

      // Check for foreign key columns without indexes
      const missingFKIndexes = await this.db.query<Array<{ column_name: string; table_name: string }>>(`
        SELECT 
          kcu.column_name,
          kcu.table_name
        FROM information_schema.key_column_usage kcu
        JOIN information_schema.table_constraints tc ON kcu.constraint_name = tc.constraint_name
        WHERE tc.constraint_type = 'FOREIGN KEY'
        AND NOT EXISTS (
          SELECT 1 FROM pg_indexes 
          WHERE tablename = kcu.table_name 
          AND indexdef LIKE '%' || kcu.column_name || '%'
        )
      `);

      for (const fk of missingFKIndexes) {
        recommendations.push(`Foreign key column ${fk.table_name}.${fk.column_name} is missing an index`);
      }

      // Recommend indexes for frequently queried columns
      recommendations.push('Consider adding indexes on frequently queried timestamp columns (created_at, updated_at)');
      recommendations.push('Consider adding composite indexes for common WHERE clause combinations');

    } catch (error) {
      logger.error('Failed to check missing indexes', { error });
    }

    return recommendations;
  }

  // Performance monitoring methods
  async getPerformanceMetrics(): Promise<PerformanceMetrics> {
    try {
      const [slowQueries, tableStats, cacheEfficiency] = await Promise.all([
        this.getSlowQueries(),
        this.getTableStats(),
        this.getCacheEfficiency()
      ]);

      return {
        slowQueryCount: slowQueries.length,
        averageQueryTime: slowQueries.length > 0 
          ? slowQueries.reduce((sum, q) => sum + q.mean_time, 0) / slowQueries.length 
          : 0,
        totalTableSize: tableStats.reduce((sum, t) => sum + t.live_tuples, 0),
        cacheHitRate: cacheEfficiency.hitRate,
        recommendations: [
          ...slowQueries.slice(0, 3).map(q => `Slow query detected: ${q.query.substring(0, 50)}... (${q.mean_time.toFixed(2)}ms avg)`),
          ...cacheEfficiency.recommendations.slice(0, 2)
        ]
      };
    } catch (error) {
      logger.error('Failed to get performance metrics', { error });
      throw error;
    }
  }

  // Cleanup and maintenance
  async cleanupOldStatistics(): Promise<void> {
    try {
      // Reset query statistics if they're getting too large
      const statCount = await this.db.query<[{ count: string }]>('SELECT COUNT(*) as count FROM pg_stat_statements');
      
      if (parseInt(statCount[0].count) > 10000) {
        await this.db.query('SELECT pg_stat_statements_reset()');
        logger.info('Query statistics reset due to high count');
      }
    } catch (error) {
      logger.error('Failed to cleanup statistics', { error });
    }
  }
}

// Type definitions
export interface RoomWithAssets {
  id: string;
  name: string;
  game_system_id?: string;
  is_active: boolean;
  created_at: Date;
  assets: GameAsset[];
  board_assets: BoardAsset[];
}

export interface RoomPlayer {
  id: string;
  room_id: string;
  player_id: string;
  is_online: boolean;
  joined_at: Date;
  first_name: string;
  last_name: string;
  profile_image_url?: string;
}

export interface GameAsset {
  id: string;
  name: string;
  type: string;
  file_path: string;
  room_id: string;
  width?: number;
  height?: number;
  created_at: Date;
}

export interface BoardAsset {
  id: string;
  asset_id: string;
  room_id: string;
  position_x: number;
  position_y: number;
  rotation: number;
  scale: number;
  z_index: number;
}

export interface GameSystem {
  id: string;
  name: string;
  description: string;
  category: string;
  complexity: string;
  is_official: boolean;
  is_public: boolean;
  download_count: number;
  rating: number;
  created_at: Date;
  usage_count: number;
}

export interface GameSystemFilters {
  category?: string;
  complexity?: string;
  search?: string;
}

export interface SlowQuery {
  query: string;
  calls: number;
  total_time: number;
  mean_time: number;
  max_time: number;
  stddev_time: number;
}

export interface TableStats {
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

export interface OptimizationResult {
  analyzedTables: number;
  updatedIndexes: number;
  vacuumedTables: number;
  recommendations: string[];
}

export interface QueryPlan {
  [key: string]: any;
}

export interface MaintenanceResult {
  reindexedTables: number;
  vacuumedTables: number;
  analyzedTables: number;
  recommendations: string[];
}

export interface CacheEfficiencyReport {
  hitRate: number;
  missRate: number;
  keyCount: number;
  memoryUsage: any;
  recommendations: string[];
}

export interface PerformanceMetrics {
  slowQueryCount: number;
  averageQueryTime: number;
  totalTableSize: number;
  cacheHitRate: number;
  recommendations: string[];
}
