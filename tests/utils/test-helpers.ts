// Test Helper Functions for Integration Tests
import { db } from '../../server/db';
import { gameRooms, users, gameAssets } from '../../shared/schema';
import { sql } from 'drizzle-orm';
import type { ValidatedUser } from '../../server/auth/tokenValidator';

/**
 * Creates a test user for integration tests
 */
export async function createTestUser(overrides: Partial<any> = {}): Promise<any> {
  const userData = {
    uid: `test-user-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    email: `test${Date.now()}@example.com`,
    displayName: `Test User ${Date.now()}`,
    photoURL: null,
    emailVerified: true,
    isActive: true,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  };

  try {
    const [insertedUser] = await db.insert(users).values(userData).returning();
    return insertedUser;
  } catch (error) {
    console.error('Error creating test user:', error);
    throw error;
  }
}

/**
 * Creates a mock authentication token for testing
 */
export async function createAuthToken(uid: string): Promise<string> {
  // For integration tests, we'll use a mock token that our middleware will recognize
  // In a real scenario, this would be a valid Firebase token
  return `test-token-${uid}`;
}

/**
 * Creates a test game room
 */
export async function createTestRoom(createdBy: string, overrides: Partial<any> = {}): Promise<any> {
  const roomData = {
    id: `test-room-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    name: `Test Room ${Date.now()}`,
    gameSystemId: 'test-system-1',
    createdBy,
    isActive: true,
    isPublic: false,
    maxPlayers: 6,
    currentPlayers: 1,
    boardState: {},
    gameSettings: {},
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  };

  try {
    const [insertedRoom] = await db.insert(gameRooms).values(roomData).returning();
    return insertedRoom;
  } catch (error) {
    console.error('Error creating test room:', error);
    throw error;
  }
}

/**
 * Creates a test asset
 */
export async function createTestAsset(roomId: string, uploadedBy: string, overrides: Partial<any> = {}): Promise<any> {
  const assetData = {
    id: `test-asset-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    roomId,
    name: 'Test Asset',
    type: 'card',
    filePath: '/uploads/test-asset.png',
    width: 64,
    height: 96,
    uploadedBy,
    isSystemAsset: false,
    createdAt: new Date(),
    ...overrides,
  };

  try {
    const [insertedAsset] = await db.insert(gameAssets).values(assetData).returning();
    return insertedAsset;
  } catch (error) {
    console.error('Error creating test asset:', error);
    throw error;
  }
}

/**
 * Cleans up test data from database
 */
export async function cleanupDatabase(): Promise<void> {
  try {
    // Delete in order to respect foreign key constraints
    await db.delete(gameAssets).where(sql`${gameAssets.name} LIKE 'Test%'`);
    await db.delete(gameRooms).where(sql`${gameRooms.name} LIKE 'Test Room%'`);
    await db.delete(users).where(sql`${users.email} LIKE 'test%@example.com'`);
    
    console.log('✅ Test database cleanup completed');
  } catch (error) {
    console.error('❌ Error cleaning up test database:', error);
    throw error;
  }
}

/**
 * Creates a validated user mock for testing
 */
export function createMockValidatedUser(overrides: Partial<ValidatedUser> = {}): ValidatedUser {
  return {
    uid: `test-user-${Date.now()}`,
    email: 'test@example.com',
    displayName: 'Test User',
    photoURL: null,
    emailVerified: true,
    source: 'firebase' as const,
    issuedAt: Date.now(),
    expiresAt: Date.now() + 3600000, // 1 hour from now
    ...overrides,
  };
}

/**
 * Wait for async operations
 */
export function waitFor(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Generate unique test identifiers
 */
export function generateTestId(prefix = 'test'): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}
