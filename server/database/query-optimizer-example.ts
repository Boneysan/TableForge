// server/database/query-optimizer-example.ts
// Query Optimizer Usage Examples and Integration Guide

import { DatabaseConnectionPool } from './connection-pool';
import { RedisCacheService } from '../cache/redis-cache';
import { QueryOptimizer } from './query-optimizer';
import { OptimizedDatabaseService } from './optimized-db-service';
import { dbLogger as logger } from '../utils/logger';

/**
 * Example: Setting up the Query Optimizer with existing database components
 */
export async function setupQueryOptimizer(): Promise<OptimizedDatabaseService> {
  // Initialize connection pool (already implemented)
  const connectionPool = new DatabaseConnectionPool();
  
  // Initialize Redis cache service (already implemented)
  const cacheConfig = {
    defaultTTL: 300, // 5 minutes
    maxSize: 10000,
    evictionPolicy: 'lru' as const,
    compressionEnabled: false,
    serializationMethod: 'json' as const
  };
  const cacheService = new RedisCacheService(cacheConfig);
  
  // Create the optimized database service
  const optimizedDb = new OptimizedDatabaseService(connectionPool, cacheService);
  
  logger.info('Query optimizer initialized successfully');
  return optimizedDb;
}

/**
 * Example: Using optimized room queries
 */
export async function roomQueryExamples(optimizedDb: OptimizedDatabaseService) {
  const roomId = 'example-room-id';
  
  try {
    // Get room with all assets in a single optimized query
    const roomWithAssets = await optimizedDb.getRoomWithCompleteData(roomId);
    
    if (roomWithAssets) {
      logger.info({
        roomId,
        assetCount: roomWithAssets.assets.length,
        boardAssetCount: roomWithAssets.board_assets.length
      }, 'Room data retrieved successfully');
      
      // Data is now cached for subsequent requests
      console.log('Room:', roomWithAssets.name);
      console.log('Assets:', roomWithAssets.assets.map(a => a.name));
    }
    
    // Get active players with caching
    const players = await optimizedDb.getActiveRoomPlayers(roomId);
    logger.info({ roomId, playerCount: players.length }, 'Active players retrieved');
    
  } catch (error) {
    logger.error({ roomId, error: error instanceof Error ? error.message : String(error) }, 'Room query failed');
  }
}

/**
 * Example: Batch asset operations
 */
export async function assetBatchExamples(optimizedDb: OptimizedDatabaseService) {
  const assetIds = [
    'asset-1',
    'asset-2', 
    'asset-3',
    'asset-4',
    'asset-5'
  ];
  
  try {
    // Efficiently load multiple assets with cache optimization
    const assets = await optimizedDb.getMultipleAssets(assetIds);
    
    logger.info({
      requestedCount: assetIds.length,
      retrievedCount: assets.length
    }, 'Batch asset loading completed');
    
    // Process assets
    for (const asset of assets) {
      console.log(`Asset: ${asset.name} (${asset.type})`);
    }
    
  } catch (error) {
    logger.error({ assetIds: assetIds.length, error: error instanceof Error ? error.message : String(error) }, 'Batch asset loading failed');
  }
}

/**
 * Example: Advanced search with filtering and pagination
 */
export async function searchExamples(optimizedDb: OptimizedDatabaseService) {
  try {
    // Search with category filter
    const categoryResults = await optimizedDb.searchGameSystems(
      { category: 'RPG' },
      1, // page
      10 // limit
    );
    
    logger.info({
      category: 'RPG',
      totalSystems: categoryResults.total,
      currentPage: categoryResults.page,
      totalPages: categoryResults.totalPages
    }, 'Category search completed');
    
    // Search with text query
    const textResults = await optimizedDb.searchGameSystems(
      { search: 'fantasy' },
      1,
      20
    );
    
    logger.info({
      searchTerm: 'fantasy',
      results: textResults.systems.length
    }, 'Text search completed');
    
    // Complex search with multiple filters
    const complexResults = await optimizedDb.searchGameSystems(
      {
        category: 'RPG',
        complexity: 'Medium',
        search: 'dragon'
      },
      1,
      15
    );
    
    console.log('Complex search results:', complexResults.systems.map(s => s.name));
    
  } catch (error) {
    logger.error({ error: error instanceof Error ? error.message : String(error) }, 'Search examples failed');
  }
}

/**
 * Example: Performance monitoring and optimization
 */
export async function performanceMonitoringExamples(optimizedDb: OptimizedDatabaseService) {
  try {
    // Generate comprehensive performance report
    const performanceReport = await optimizedDb.getPerformanceReport();
    
    logger.info({
      dbStatus: performanceReport.database.status,
      cacheHitRate: performanceReport.cache.hitRate,
      slowQueries: performanceReport.database.slowQueryCount,
      recommendations: performanceReport.recommendations.length
    }, 'Performance report generated');
    
    // Print key metrics
    console.log('Database Performance Report:');
    console.log(`- Database Status: ${performanceReport.database.status}`);
    console.log(`- Average Query Time: ${performanceReport.database.averageQueryTime.toFixed(2)}ms`);
    console.log(`- Cache Hit Rate: ${(performanceReport.cache.hitRate * 100).toFixed(1)}%`);
    console.log(`- Tables Needing Vacuum: ${performanceReport.tables.needsVacuum}`);
    
    if (performanceReport.recommendations.length > 0) {
      console.log('\nRecommendations:');
      performanceReport.recommendations.forEach((rec, idx) => {
        console.log(`${idx + 1}. ${rec}`);
      });
    }
    
  } catch (error) {
    logger.error({ error: error instanceof Error ? error.message : String(error) }, 'Performance monitoring failed');
  }
}

/**
 * Example: Automated database optimization
 */
export async function optimizationExamples(optimizedDb: OptimizedDatabaseService) {
  try {
    logger.info('Starting automated database optimization');
    
    // Run comprehensive optimization
    const optimizationResult = await optimizedDb.runOptimization();
    
    if (optimizationResult.success) {
      logger.info({
        duration: optimizationResult.duration,
        analyzedTables: optimizationResult.queryOptimization.analyzedTables,
        vacuumedTables: optimizationResult.maintenance.vacuumedTables,
        recommendations: optimizationResult.queryOptimization.recommendations.length
      }, 'Database optimization completed successfully');
      
      console.log('Optimization Results:');
      console.log(`- Duration: ${optimizationResult.duration}ms`);
      console.log(`- Tables Analyzed: ${optimizationResult.queryOptimization.analyzedTables}`);
      console.log(`- Tables Vacuumed: ${optimizationResult.maintenance.vacuumedTables}`);
      
      if (optimizationResult.queryOptimization.recommendations.length > 0) {
        console.log('\nOptimization Recommendations:');
        optimizationResult.queryOptimization.recommendations.forEach((rec, idx) => {
          console.log(`${idx + 1}. ${rec}`);
        });
      }
    } else {
      logger.error({ error: optimizationResult.error }, 'Database optimization failed');
    }
    
  } catch (error) {
    logger.error({ error: error instanceof Error ? error.message : String(error) }, 'Optimization examples failed');
  }
}

/**
 * Example: Health monitoring
 */
export async function healthCheckExamples(optimizedDb: OptimizedDatabaseService) {
  try {
    const healthResult = await optimizedDb.performHealthCheck();
    
    logger.info({
      overall: healthResult.overall,
      dbHealthy: healthResult.database.healthy,
      cacheHealthy: healthResult.cache.healthy,
      dbLatency: healthResult.database.latency
    }, 'Health check completed');
    
    console.log('System Health Status:');
    console.log(`- Overall Status: ${healthResult.overall ? '✅ Healthy' : '❌ Unhealthy'}`);
    console.log(`- Database: ${healthResult.database.healthy ? '✅ Healthy' : '❌ Unhealthy'}`);
    console.log(`- Cache: ${healthResult.cache.healthy ? '✅ Healthy' : '❌ Unhealthy'}`);
    console.log(`- DB Latency: ${healthResult.database.latency}ms`);
    console.log(`- Pool Utilization: ${(healthResult.database.poolUtilization * 100).toFixed(1)}%`);
    
    if (!healthResult.overall && healthResult.error) {
      console.log(`- Error: ${healthResult.error}`);
    }
    
  } catch (error) {
    logger.error({ error: error instanceof Error ? error.message : String(error) }, 'Health check failed');
  }
}

/**
 * Example: Using Query Optimizer directly for advanced operations
 */
export async function advancedQueryOptimizerExamples(optimizedDb: OptimizedDatabaseService) {
  const queryOptimizer = optimizedDb.getQueryOptimizer();
  
  try {
    // Analyze slow queries
    const slowQueries = await queryOptimizer.getSlowQueries();
    
    if (slowQueries.length > 0) {
      logger.warn({ slowQueryCount: slowQueries.length }, 'Slow queries detected');
      
      console.log('Slow Queries:');
      slowQueries.slice(0, 5).forEach((query, idx) => {
        console.log(`${idx + 1}. Average Time: ${query.mean_time.toFixed(2)}ms`);
        console.log(`   Query: ${query.query.substring(0, 100)}...`);
        console.log(`   Calls: ${query.calls}`);
      });
    }
    
    // Get table statistics
    const tableStats = await queryOptimizer.getTableStats();
    
    console.log('\nTop Tables by Size:');
    tableStats.slice(0, 10).forEach((table, idx) => {
      console.log(`${idx + 1}. ${table.tablename}: ${table.live_tuples.toLocaleString()} rows`);
    });
    
    // Get cache efficiency report
    const cacheEfficiency = await queryOptimizer.getCacheEfficiency();
    
    console.log('\nCache Efficiency:');
    console.log(`- Hit Rate: ${(cacheEfficiency.hitRate * 100).toFixed(1)}%`);
    console.log(`- Keys: ${cacheEfficiency.keyCount.toLocaleString()}`);
    
    if (cacheEfficiency.recommendations.length > 0) {
      console.log('- Recommendations:');
      cacheEfficiency.recommendations.forEach(rec => {
        console.log(`  • ${rec}`);
      });
    }
    
  } catch (error) {
    logger.error({ error: error instanceof Error ? error.message : String(error) }, 'Advanced query optimizer examples failed');
  }
}

/**
 * Complete example workflow
 */
export async function completeWorkflowExample() {
  try {
    // Setup
    const optimizedDb = await setupQueryOptimizer();
    
    // Perform various operations
    await roomQueryExamples(optimizedDb);
    await assetBatchExamples(optimizedDb);
    await searchExamples(optimizedDb);
    
    // Monitor and optimize
    await performanceMonitoringExamples(optimizedDb);
    await healthCheckExamples(optimizedDb);
    
    // Run optimization if needed
    const healthResult = await optimizedDb.performHealthCheck();
    if (!healthResult.overall || healthResult.database.latency > 100) {
      logger.info('Performance issues detected, running optimization');
      await optimizationExamples(optimizedDb);
    }
    
    // Advanced analysis
    await advancedQueryOptimizerExamples(optimizedDb);
    
    // Cleanup
    await optimizedDb.shutdown();
    
    logger.info('Complete workflow example finished successfully');
    
  } catch (error) {
    logger.error({ error: error instanceof Error ? error.message : String(error) }, 'Complete workflow example failed');
  }
}

// Scheduled optimization example
export function scheduleOptimization(optimizedDb: OptimizedDatabaseService) {
  // Run optimization every 6 hours
  setInterval(async () => {
    try {
      logger.info('Running scheduled database optimization');
      const result = await optimizedDb.runOptimization();
      
      if (result.success) {
        logger.info({
          duration: result.duration,
          optimizations: result.queryOptimization.analyzedTables + result.maintenance.vacuumedTables
        }, 'Scheduled optimization completed');
      } else {
        logger.error({ error: result.error }, 'Scheduled optimization failed');
      }
    } catch (error) {
      logger.error({ error: error instanceof Error ? error.message : String(error) }, 'Scheduled optimization error');
    }
  }, 6 * 60 * 60 * 1000); // 6 hours

  // Health check every 5 minutes
  setInterval(async () => {
    try {
      const health = await optimizedDb.performHealthCheck();
      
      if (!health.overall) {
        logger.warn({
          dbHealthy: health.database.healthy,
          cacheHealthy: health.cache.healthy,
          error: health.error
        }, 'System health check failed');
      }
    } catch (error) {
      logger.error({ error: error instanceof Error ? error.message : String(error) }, 'Health check error');
    }
  }, 5 * 60 * 1000); // 5 minutes
}

export default {
  setupQueryOptimizer,
  roomQueryExamples,
  assetBatchExamples,
  searchExamples,
  performanceMonitoringExamples,
  optimizationExamples,
  healthCheckExamples,
  advancedQueryOptimizerExamples,
  completeWorkflowExample,
  scheduleOptimization
};
