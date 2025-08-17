// server/database/connection-pool-example.ts
// Example usage of the Phase 3 Database Connection Pool

import { getConnectionPool, getEnhancedDb } from './enhanced-db';
import { createUserLogger } from '../utils/logger';

const logger = createUserLogger('db-pool-example');

// Example 1: Basic Database Operations
export async function basicDatabaseExample() {
  console.log('\n=== Basic Database Operations ===');
  
  const db = getEnhancedDb();
  
  try {
    // Health check
    const health = await db.healthCheck();
    console.log('Database health:', health);
    
    // Get pool statistics
    const stats = await db.getStats();
    console.log('Pool statistics:', {
      totalConnections: stats.totalCount,
      idleConnections: stats.idleCount,
      waitingConnections: stats.waitingCount,
      utilization: stats.performance.connectionUtilization.toFixed(2) + '%'
    });
    
    // Simple query example
    const result = await db.query<Array<{ now: string }>>(
      'SELECT NOW() as now'
    );
    console.log('Current time:', result[0]?.now);
    
  } catch (error) {
    console.error('Database operation failed:', error);
  }
}

// Example 2: Transaction Usage
export async function transactionExample() {
  console.log('\n=== Transaction Example ===');
  
  const db = getEnhancedDb();
  
  try {
    const result = await db.transaction(async (client) => {
      // Example transaction operations
      await client.query('BEGIN');
      
      // Multiple operations that should be atomic
      const userResult = await client.query(
        'SELECT COUNT(*) as user_count FROM users'
      );
      
      const roomResult = await client.query(
        'SELECT COUNT(*) as room_count FROM game_rooms'
      );
      
      return {
        users: userResult.rows[0]?.user_count || 0,
        rooms: roomResult.rows[0]?.room_count || 0
      };
    });
    
    console.log('Transaction result:', result);
    
  } catch (error) {
    console.error('Transaction failed:', error);
  }
}

// Example 3: Batch Query Operations
export async function batchQueryExample() {
  console.log('\n=== Batch Query Example ===');
  
  const db = getEnhancedDb();
  
  try {
    const queries = [
      { text: 'SELECT COUNT(*) as count, \'users\' as table_name FROM users' },
      { text: 'SELECT COUNT(*) as count, \'rooms\' as table_name FROM game_rooms' },
      { text: 'SELECT COUNT(*) as count, \'assets\' as table_name FROM game_assets' }
    ];
    
    const results = await db.batchQuery(queries);
    
    console.log('Batch query results:');
    results.forEach((result: any, index) => {
      const row = result[0];
      console.log(`  ${row.table_name}: ${row.count} records`);
    });
    
  } catch (error) {
    console.error('Batch query failed:', error);
  }
}

// Example 4: Performance Monitoring
export async function performanceMonitoringExample() {
  console.log('\n=== Performance Monitoring ===');
  
  const pool = getConnectionPool();
  
  try {
    // Get detailed statistics
    const stats = await pool.getDetailedStats();
    
    console.log('Detailed Pool Statistics:');
    console.log('Connection Pool:');
    console.log(`  Total: ${stats.totalCount}`);
    console.log(`  Idle: ${stats.idleCount}`);
    console.log(`  Waiting: ${stats.waitingCount}`);
    console.log(`  Min/Max: ${stats.config.min}/${stats.config.max}`);
    
    console.log('Performance Metrics:');
    console.log(`  Utilization: ${stats.performance.connectionUtilization.toFixed(2)}%`);
    console.log(`  Queued Requests: ${stats.performance.queuedRequests}`);
    console.log(`  Average Acquire Time: ${stats.performance.averageAcquireTime}ms`);
    
    console.log('Health Status:');
    console.log(`  Healthy: ${stats.health.isHealthy}`);
    console.log(`  Last Check: ${stats.health.lastHealthCheck}`);
    console.log(`  Uptime: ${(stats.health.uptime / 60).toFixed(2)} minutes`);
    
  } catch (error) {
    console.error('Performance monitoring failed:', error);
  }
}

// Example 5: Connection Pool Optimization
export async function optimizationExample() {
  console.log('\n=== Connection Pool Optimization ===');
  
  const pool = getConnectionPool();
  
  try {
    console.log('Running optimization analysis...');
    
    const optimization = await pool.optimizeConnections();
    
    console.log('Optimization Results:');
    console.log('Actions Taken:');
    optimization.actions.forEach(action => {
      console.log(`  - ${action}`);
    });
    
    console.log('Recommendations:');
    optimization.recommendations.forEach(rec => {
      console.log(`  - ${rec}`);
    });
    
    console.log('Before/After Comparison:');
    console.log(`  Connections: ${optimization.beforeStats.totalCount} -> ${optimization.afterStats?.totalCount || 'N/A'}`);
    console.log(`  Utilization: ${optimization.beforeStats.performance.connectionUtilization.toFixed(2)}% -> ${optimization.afterStats?.performance.connectionUtilization.toFixed(2) || 'N/A'}%`);
    
  } catch (error) {
    console.error('Optimization failed:', error);
  }
}

// Example 6: Load Testing Simulation
export async function loadTestingExample() {
  console.log('\n=== Load Testing Simulation ===');
  
  const db = getEnhancedDb();
  const concurrentRequests = 50;
  const requestsPerBatch = 10;
  
  try {
    console.log(`Simulating ${concurrentRequests} concurrent database requests...`);
    
    const startTime = Date.now();
    
    // Create multiple concurrent requests
    const promises = Array.from({ length: concurrentRequests }, async (_, index) => {
      const batchStartTime = Date.now();
      
      try {
        // Simulate different types of queries
        if (index % 3 === 0) {
          // Read operation
          await db.query('SELECT 1 as test_query');
        } else if (index % 3 === 1) {
          // Transaction operation
          await db.transaction(async (client) => {
            await client.query('SELECT NOW()');
            return true;
          });
        } else {
          // Batch operation
          await db.batchQuery([
            { text: 'SELECT 1 as batch_1' },
            { text: 'SELECT 2 as batch_2' }
          ]);
        }
        
        return {
          success: true,
          duration: Date.now() - batchStartTime,
          requestId: index
        };
      } catch (error) {
        return {
          success: false,
          duration: Date.now() - batchStartTime,
          requestId: index,
          error: error
        };
      }
    });
    
    const results = await Promise.all(promises);
    const totalTime = Date.now() - startTime;
    
    const successful = results.filter(r => r.success).length;
    const failed = results.filter(r => !r.success).length;
    const avgDuration = results.reduce((sum, r) => sum + r.duration, 0) / results.length;
    
    console.log('Load Test Results:');
    console.log(`  Total Requests: ${concurrentRequests}`);
    console.log(`  Successful: ${successful}`);
    console.log(`  Failed: ${failed}`);
    console.log(`  Success Rate: ${(successful / concurrentRequests * 100).toFixed(2)}%`);
    console.log(`  Total Time: ${totalTime}ms`);
    console.log(`  Average Request Time: ${avgDuration.toFixed(2)}ms`);
    console.log(`  Requests/Second: ${(concurrentRequests / (totalTime / 1000)).toFixed(2)}`);
    
    // Get pool stats after load test
    const finalStats = await db.getStats();
    console.log(`  Final Pool Utilization: ${finalStats.performance.connectionUtilization.toFixed(2)}%`);
    
  } catch (error) {
    console.error('Load testing failed:', error);
  }
}

// Example 7: Error Handling and Recovery
export async function errorHandlingExample() {
  console.log('\n=== Error Handling Example ===');
  
  const db = getEnhancedDb();
  
  try {
    // Simulate various error scenarios
    console.log('Testing invalid query handling...');
    
    try {
      await db.query('SELECT * FROM non_existent_table');
    } catch (error: any) {
      console.log(`  Handled query error: ${error.message}`);
    }
    
    console.log('Testing transaction rollback...');
    
    try {
      await db.transaction(async (client) => {
        await client.query('SELECT 1');
        throw new Error('Simulated transaction error');
      });
    } catch (error: any) {
      console.log(`  Handled transaction error: ${error.message}`);
    }
    
    // Verify pool is still healthy after errors
    const health = await db.healthCheck();
    console.log(`  Pool health after errors: ${health.status}`);
    
  } catch (error) {
    console.error('Error handling test failed:', error);
  }
}

// Main function to run all examples
export async function runAllDatabaseExamples() {
  console.log('🚀 Running Phase 3 Database Connection Pool Examples\n');
  
  try {
    await basicDatabaseExample();
    await transactionExample();
    await batchQueryExample();
    await performanceMonitoringExample();
    await optimizationExample();
    await loadTestingExample();
    await errorHandlingExample();
    
    console.log('\n✅ All database examples completed successfully!');
  } catch (error) {
    console.error('\n❌ Database examples failed:', error);
  }
}
