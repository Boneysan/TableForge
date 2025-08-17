// server/cache/phase3-cache-integration-example.ts
// Complete Phase 3 caching system integration example

import CacheManagerPhase3, { defaultCacheManagerConfig, CacheManagerConfig } from './cache-manager-phase3';
import { createUserLogger } from '../utils/logger';

const logger = createUserLogger('cache-integration');

/**
 * Phase 3 Cache Integration Example
 * 
 * This example demonstrates how to use the complete Phase 3 caching system
 * including:
 * - Redis distributed cache with domain-specific methods
 * - Application-level LRU cache with performance tracking
 * - Cache invalidation strategies with event-driven processing
 * - Cache monitoring with metrics collection and alerting
 */

export class CacheIntegrationExample {
  private cacheManager: CacheManagerPhase3;

  constructor() {
    // Initialize cache manager with custom configuration
    const config: CacheManagerConfig = {
      ...defaultCacheManagerConfig,
      applicationCache: {
        ...defaultCacheManagerConfig.applicationCache,
        maxSize: 50000, // Increased for high-performance workload
        defaultTTL: 600  // 10 minutes for better hit rates
      },
      distributedCache: {
        ...defaultCacheManagerConfig.distributedCache,
        defaultTTL: 7200 // 2 hours for distributed cache
      },
      monitoring: {
        ...defaultCacheManagerConfig.monitoring,
        alerting: {
          enabled: true,
          hitRateThreshold: 0.8,  // Alert if hit rate < 80%
          errorRateThreshold: 0.05, // Alert if error rate > 5%
          responseTimeThreshold: 100 // Alert if avg response > 100ms
        }
      }
    };

    this.cacheManager = new CacheManagerPhase3(config);
  }

  /**
   * Example: Caching user sessions with automatic L1/L2 fallback
   */
  async handleUserSession(userId: string) {
    const sessionKey = `session:${userId}`;
    
    try {
      // Try to get from cache (L1 -> L2 fallback automatically)
      let session = await this.cacheManager.get(sessionKey, {
        cacheType: 'user-session'
      });

      if (!session) {
        // Cache miss - fetch from database
        session = await this.fetchUserSessionFromDatabase(userId);
        
        if (session) {
          // Store in both L1 and L2 cache
          await this.cacheManager.set(sessionKey, session, {
            cacheType: 'user-session',
            ttl: 1800 // 30 minutes
          });
        }
      }

      return session;

    } catch (error) {
      logger.error('Session cache operation failed', { userId, error });
      // Fallback to database on cache failure
      return await this.fetchUserSessionFromDatabase(userId);
    }
  }

  /**
   * Example: Batch caching for room data
   */
  async handleRoomDataBatch(roomIds: string[]) {
    const roomKeys = roomIds.map(id => `room:${id}`);
    
    try {
      // Get all rooms from cache (batch operation)
      const cachedRooms = await this.cacheManager.mget(roomKeys, {
        cacheType: 'room-data'
      });

      // Find rooms that need to be fetched
      const missedIndices: number[] = [];
      const missedRoomIds: string[] = [];

      cachedRooms.forEach((room, index) => {
        if (room === null) {
          missedIndices.push(index);
          missedRoomIds.push(roomIds[index]);
        }
      });

      // Fetch missed rooms from database
      const freshRooms = await this.fetchRoomsFromDatabase(missedRoomIds);

      // Cache the fresh data
      if (freshRooms.length > 0) {
        const cacheItems = freshRooms.map((room, index) => ({
          key: `room:${missedRoomIds[index]}`,
          value: room,
          ttl: 3600 // 1 hour
        }));

        await this.cacheManager.mset(cacheItems, {
          cacheType: 'room-data'
        });

        // Update results array
        freshRooms.forEach((room, index) => {
          const originalIndex = missedIndices[index];
          cachedRooms[originalIndex] = room;
        });
      }

      return cachedRooms.filter(room => room !== null);

    } catch (error) {
      logger.error('Room batch cache operation failed', { roomIds, error });
      return await this.fetchRoomsFromDatabase(roomIds);
    }
  }

  /**
   * Example: Cache invalidation when user updates profile
   */
  async handleUserProfileUpdate(userId: string) {
    try {
      // Update user profile in database
      await this.updateUserProfileInDatabase(userId);

      // Invalidate all user-related cache entries
      await this.cacheManager.invalidateUser(userId, 'Profile updated');

      // Also invalidate any rooms the user is in
      const userRooms = await this.getUserRoomsFromDatabase(userId);
      for (const roomId of userRooms) {
        await this.cacheManager.invalidateRoom(roomId, `User ${userId} profile updated`);
      }

      logger.info('User profile updated and cache invalidated', { userId });

    } catch (error) {
      logger.error('User profile update failed', { userId, error });
      throw error;
    }
  }

  /**
   * Example: Performance monitoring and health checks
   */
  async performHealthCheck() {
    try {
      // Get overall health status
      const health = await this.cacheManager.healthCheck();
      
      // Get detailed performance stats
      const stats = await this.cacheManager.getStats();
      
      // Get performance report
      const performanceReport = this.cacheManager.getPerformanceReport(3600000); // Last hour
      
      // Get active alerts
      const alerts = this.cacheManager.getActiveAlerts();

      const healthReport = {
        status: health.status,
        components: health.components,
        performance: {
          l1Cache: {
            hitRate: stats.l1Cache.hitRate,
            itemCount: stats.l1Cache.itemCount,
            memoryUsage: stats.l1Cache.memoryUsage
          },
          l2Cache: {
            hitRate: stats.l2Cache.hitRate,
            itemCount: stats.l2Cache.itemCount,
            connected: stats.l2Cache.connected
          },
          combined: {
            hitRate: stats.combined.hitRate,
            totalOperations: stats.combined.totalOperations
          }
        },
        report: performanceReport,
        alerts: alerts.length > 0 ? alerts : 'No active alerts'
      };

      // Log critical issues
      if (health.overall === false) {
        logger.error('Cache system health check failed', { healthReport });
      } else if (alerts.length > 0) {
        logger.warn('Cache system has active alerts', { alerts });
      } else {
        logger.info('Cache system healthy', { 
          hitRate: stats.combined.hitRate,
          operations: stats.combined.totalOperations 
        });
      }

      return healthReport;

    } catch (error) {
      logger.error('Health check failed', { error });
      return {
        status: 'error',
        error: error.message
      };
    }
  }

  /**
   * Example: Cleanup and shutdown
   */
  async shutdown() {
    try {
      logger.info('Shutting down cache integration example');
      await this.cacheManager.shutdown();
      logger.info('Cache integration example shutdown completed');
    } catch (error) {
      logger.error('Cache integration example shutdown failed', { error });
      throw error;
    }
  }

  // Mock database methods (replace with actual database calls)
  private async fetchUserSessionFromDatabase(userId: string): Promise<any> {
    // Simulate database fetch
    await new Promise(resolve => setTimeout(resolve, 50));
    return {
      userId,
      sessionId: `session-${Date.now()}`,
      email: `user${userId}@example.com`,
      firstName: 'Test',
      lastName: 'User',
      roles: ['user'],
      permissions: ['read'],
      lastActivity: Date.now(),
      expiresAt: Date.now() + 3600000
    };
  }

  private async fetchRoomsFromDatabase(roomIds: string[]): Promise<any[]> {
    // Simulate database batch fetch
    await new Promise(resolve => setTimeout(resolve, 100));
    return roomIds.map(id => ({
      id,
      name: `Room ${id}`,
      description: `Test room ${id}`,
      createdAt: Date.now(),
      userCount: Math.floor(Math.random() * 10)
    }));
  }

  private async updateUserProfileInDatabase(userId: string): Promise<void> {
    // Simulate database update
    await new Promise(resolve => setTimeout(resolve, 200));
    logger.debug('User profile updated in database', { userId });
  }

  private async getUserRoomsFromDatabase(userId: string): Promise<string[]> {
    // Simulate fetching user's rooms
    await new Promise(resolve => setTimeout(resolve, 50));
    return [`room-${userId}-1`, `room-${userId}-2`];
  }
}

/**
 * Usage example
 */
export async function runCacheIntegrationExample() {
  const example = new CacheIntegrationExample();

  try {
    logger.info('Starting Phase 3 cache integration example');

    // Example 1: User session caching
    const session1 = await example.handleUserSession('user123');
    const session2 = await example.handleUserSession('user123'); // Should hit cache
    logger.info('User session example completed', { 
      firstCall: session1?.sessionId,
      secondCall: session2?.sessionId,
      cacheHit: session1?.sessionId === session2?.sessionId
    });

    // Example 2: Batch room data caching
    const rooms = await example.handleRoomDataBatch(['room1', 'room2', 'room3']);
    logger.info('Room batch example completed', { roomCount: rooms.length });

    // Example 3: Cache invalidation
    await example.handleUserProfileUpdate('user123');

    // Example 4: Health check and monitoring
    const healthReport = await example.performHealthCheck();
    logger.info('Health check completed', { status: healthReport.status });

    logger.info('Phase 3 cache integration example completed successfully');

  } catch (error) {
    logger.error('Cache integration example failed', { error });
  } finally {
    await example.shutdown();
  }
}

export default CacheIntegrationExample;
