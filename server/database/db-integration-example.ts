// server/database/db-integration-example.ts
// Example of how to integrate the Phase 3 connection pool with existing database setup

import { getEnhancedDb } from './enhanced-db';
import { Pool, neonConfig } from '@neondatabase/serverless';
import { drizzle } from 'drizzle-orm/neon-serverless';
import ws from 'ws';
import * as schema from '@shared/schema';

// Configure Neon if needed
neonConfig.webSocketConstructor = ws;

// Example: Migrate from existing setup to Phase 3 connection pool
export class DatabaseMigrationExample {
  
  // OLD WAY (current db.ts setup)
  static createLegacyDatabase() {
    if (!process.env.DATABASE_URL) {
      throw new Error('DATABASE_URL must be set. Did you forget to provision a database?');
    }

    const pool = new Pool({ connectionString: process.env.DATABASE_URL });
    return drizzle({ client: pool, schema });
  }

  // NEW WAY (Phase 3 enhanced setup)
  static createEnhancedDatabase() {
    return getEnhancedDb().getDb();
  }

  // MIGRATION EXAMPLE: Gradual transition
  static async migrateToEnhancedDb() {
    console.log('=== Database Migration Example ===');

    // Step 1: Test both databases work the same way
    const legacyDb = this.createLegacyDatabase();
    const enhancedDb = this.createEnhancedDatabase();

    try {
      // Test basic query on both
      console.log('Testing legacy database...');
      const legacyResult = await legacyDb.execute('SELECT NOW() as timestamp');
      console.log('Legacy result:', legacyResult.rows[0]);

      console.log('Testing enhanced database...');
      const enhancedDbService = getEnhancedDb();
      const enhancedResult = await enhancedDbService.query<Array<{ timestamp: string }>>(
        'SELECT NOW() as timestamp'
      );
      console.log('Enhanced result:', enhancedResult[0]);

      // Step 2: Show enhanced features not available in legacy
      console.log('\nTesting enhanced features...');
      
      // Health check
      const health = await enhancedDbService.healthCheck();
      console.log('Health check:', health);

      // Pool statistics
      const stats = await enhancedDbService.getStats();
      console.log('Pool stats:', {
        connections: stats.totalCount,
        idle: stats.idleCount,
        utilization: stats.performance.connectionUtilization.toFixed(2) + '%'
      });

      // Batch operations
      const batchResults = await enhancedDbService.batchQuery([
        { text: 'SELECT 1 as test1' },
        { text: 'SELECT 2 as test2' },
        { text: 'SELECT 3 as test3' }
      ]);
      console.log('Batch results:', batchResults.map(r => r[0]));

      console.log('\n✅ Migration test successful!');
      
    } catch (error) {
      console.error('❌ Migration test failed:', error);
    }
  }

  // Example: How existing code would change
  static async exampleCodeMigration() {
    console.log('\n=== Code Migration Examples ===');

    // OLD CODE PATTERN
    console.log('OLD: Using legacy database');
    /*
    import { db } from '../db';
    
    const users = await db.select().from(schema.users);
    */

    // NEW CODE PATTERN
    console.log('NEW: Using enhanced database');
    const enhancedDb = getEnhancedDb().getDb();
    
    // Same Drizzle queries work exactly the same
    try {
      const users = await enhancedDb.select().from(schema.users);
      console.log(`Found ${users.length} users`);
    } catch (error) {
      console.log('No users table yet, which is expected');
    }

    // ENHANCED: Now you can also use advanced features
    const dbService = getEnhancedDb();
    
    // Direct SQL with connection pooling
    const directQuery = await dbService.query<Array<{ count: string }>>(
      'SELECT COUNT(*) as count FROM information_schema.tables WHERE table_schema = $1',
      ['public']
    );
    console.log(`Database has ${directQuery[0]?.count || 0} tables`);

    // Transaction with connection pooling
    const transactionResult = await dbService.transaction(async (client) => {
      const result = await client.query('SELECT CURRENT_DATABASE() as db_name');
      return result.rows[0];
    });
    console.log('Transaction result:', transactionResult);
  }

  // Example: Environment-specific configuration
  static showEnvironmentConfig() {
    console.log('\n=== Environment Configuration ===');

    console.log('Environment variables for Phase 3 database:');
    console.log('DATABASE_URL=', process.env.DATABASE_URL ? '***SET***' : 'NOT SET');
    console.log('DATABASE_HOST=', process.env.DATABASE_HOST || 'localhost');
    console.log('DATABASE_PORT=', process.env.DATABASE_PORT || '5432');
    console.log('DATABASE_NAME=', process.env.DATABASE_NAME || 'tableforge');
    console.log('DATABASE_USER=', process.env.DATABASE_USER || 'postgres');
    console.log('DATABASE_PASSWORD=', process.env.DATABASE_PASSWORD ? '***SET***' : 'NOT SET');
    
    console.log('\nConnection pool settings:');
    console.log('DB_POOL_MIN=', process.env.DB_POOL_MIN || '5');
    console.log('DB_POOL_MAX=', process.env.DB_POOL_MAX || '20');
    console.log('DB_IDLE_TIMEOUT=', process.env.DB_IDLE_TIMEOUT || '30000');
    console.log('DB_CONNECTION_TIMEOUT=', process.env.DB_CONNECTION_TIMEOUT || '10000');
    
    console.log('\nRecommended production settings:');
    console.log('DB_POOL_MIN=10');
    console.log('DB_POOL_MAX=50');
    console.log('DB_ENABLE_MONITORING=true');
    console.log('DB_ENABLE_OPTIMIZATION=true');
  }
}

// Example: How to gradually replace the existing db.ts file
export function createBackwardCompatibleDb() {
  // This function provides the same interface as the old db.ts
  // but uses the enhanced connection pool underneath
  
  const enhancedDb = getEnhancedDb();
  
  return {
    // Main database instance (same as before)
    db: enhancedDb.getDb(),
    
    // Raw pool access (same as before) 
    pool: enhancedDb.getPool(),
    
    // NEW: Enhanced features
    enhanced: {
      query: enhancedDb.query.bind(enhancedDb),
      transaction: enhancedDb.transaction.bind(enhancedDb),
      batchQuery: enhancedDb.batchQuery.bind(enhancedDb),
      healthCheck: enhancedDb.healthCheck.bind(enhancedDb),
      getStats: enhancedDb.getStats.bind(enhancedDb),
      optimize: enhancedDb.optimize.bind(enhancedDb)
    }
  };
}

// Example usage function
export async function runDatabaseIntegrationExample() {
  console.log('🔄 Running Database Integration Example\n');
  
  try {
    await DatabaseMigrationExample.migrateToEnhancedDb();
    await DatabaseMigrationExample.exampleCodeMigration();
    DatabaseMigrationExample.showEnvironmentConfig();
    
    console.log('\n🎯 Integration example completed successfully!');
    console.log('\nNext steps:');
    console.log('1. Update imports to use enhanced database');
    console.log('2. Set environment variables for connection pool');
    console.log('3. Test in development environment');
    console.log('4. Deploy to production with pool monitoring');
    
  } catch (error) {
    console.error('\n❌ Integration example failed:', error);
  }
}
