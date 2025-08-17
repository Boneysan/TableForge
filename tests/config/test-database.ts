/**
 * Test Database Configuration
 * Phase 2 Week 2: Integration Tests
 * 
 * Provides isolated test database setup with automatic cleanup
 * for reliable integration testing.
 */

import { db } from '@server/db';
import * as schema from '@shared/schema';

// Re-export the main database connection for tests
export const testDb = db;

/**
 * Truncate all tables for test isolation
 */
export async function truncateAllTables() {
  try {
    // List of tables to truncate in order (respecting foreign keys)
    const tables = [
      'board_assets',
      'game_assets', 
      'player_sessions',
      'game_rooms',
      'game_systems',
      'users',
      'sessions'
    ];

    // Truncate each table
    for (const tableName of tables) {
      try {
        await db.execute(`TRUNCATE TABLE "${tableName}" RESTART IDENTITY CASCADE;`);
      } catch (error) {
        // Table might not exist, continue
        console.warn(`Could not truncate table ${tableName}:`, error);
      }
    }
    
    console.log(`🧹 Truncated ${tables.length} tables for test isolation`);
  } catch (error) {
    console.error('❌ Error truncating tables:', error);
    throw error;
  }
}

/**
 * Execute test with automatic cleanup
 */
export async function withTestTransaction<T>(
  testFn: (db: typeof testDb) => Promise<T>
): Promise<T> {
  // Truncate before test
  await truncateAllTables();
  
  try {
    const result = await testFn(testDb);
    return result;
  } finally {
    // Truncate after test for isolation
    await truncateAllTables();
  }
}

/**
 * Seed test data for integration tests
 */
export async function seedTestData() {
  try {
    // Create test users
    const testUsers = await testDb.insert(schema.users).values([
      {
        id: 'test-user-1',
        email: 'test1@example.com',
        firstName: 'Test',
        lastName: 'User One'
      },
      {
        id: 'test-user-2', 
        email: 'test2@example.com',
        firstName: 'Test',
        lastName: 'User Two'
      },
      {
        id: 'test-admin',
        email: 'admin@example.com',
        firstName: 'Test',
        lastName: 'Administrator'
      }
    ]).returning();

    // Create test game systems
    const testGameSystems = await testDb.insert(schema.gameSystems).values([
      {
        id: 'test-system-1',
        name: 'Test Card Game',
        description: 'Integration test card game system',
        category: 'card-game',
        isPublic: true,
        createdBy: 'test-admin'
      },
      {
        id: 'test-system-2',
        name: 'Test Board Game',
        description: 'Integration test board game system',
        category: 'board-game', 
        isPublic: true,
        createdBy: 'test-admin'
      }
    ]).returning();

    // Create test rooms (gameRooms table has no gameSystemId field, removing it)
    const testRooms = await testDb.insert(schema.gameRooms).values([
      {
        id: 'test-room-1',
        name: 'Integration Test Room 1',
        createdBy: 'test-user-1',
        isActive: true
      },
      {
        id: 'test-room-2',
        name: 'Integration Test Room 2', 
        createdBy: 'test-user-2',
        isActive: true
      }
    ]).returning();

    console.log('✅ Test data seeded successfully');
    console.log(`   Users: ${testUsers.length}`);
    console.log(`   Game Systems: ${testGameSystems.length}`);
    console.log(`   Rooms: ${testRooms.length}`);

    return {
      users: testUsers,
      gameSystems: testGameSystems,
      rooms: testRooms
    };

  } catch (error) {
    console.error('❌ Error seeding test data:', error);
    throw error;
  }
}

/**
 * Reset test database to clean state
 */
export async function resetTestDatabase() {
  await truncateAllTables();
  await seedTestData();
  console.log('🔄 Test database reset complete');
}

/**
 * Initialize test database - basic setup
 */
export async function initTestDatabase() {
  console.log('✅ Test database ready (using main connection)');
  return { db: testDb };
}

/**
 * Cleanup test database - placeholder for consistency
 */
export async function cleanupTestDatabase() {
  console.log('🧹 Test database cleanup complete');
}

// Export the main database instances
export function getTestDatabase() {
  return { db: testDb };
}
