import { db } from '../db';
import { gameRooms, roomPlayers, cardDecks, cardPiles, boardAssets } from '@shared/schema';
import { eq, lt, and, isNull, sql } from 'drizzle-orm';
import { logger } from '../utils/logger';
import { ObjectStorageService } from '../objectStorage';

/**
 * Room Cleanup Job - Handles TTL-based room lifecycle management
 *
 * Features:
 * - Removes abandoned rooms based on inactivity
 * - Cleans up associated game data (decks, piles, tokens, sessions)
 * - Preserves system assets while removing room-specific data
 * - Logs cleanup operations for audit trails
 */
export class RoomCleanupJob {
  private objectStorageService: ObjectStorageService;

  // TTL configurations (in milliseconds)
  private static readonly ROOM_TTL_INACTIVE = 24 * 60 * 60 * 1000; // 24 hours
  private static readonly ROOM_TTL_EMPTY = 7 * 24 * 60 * 60 * 1000; // 7 days
  private static readonly ROOM_TTL_ABANDONED = 30 * 24 * 60 * 60 * 1000; // 30 days

  constructor() {
    this.objectStorageService = new ObjectStorageService();
  }

  /**
   * Main cleanup execution method
   */
  async execute(): Promise<{
    abandonedRooms: number;
    emptyRooms: number;
    inactiveRooms: number;
    totalCleaned: number;
    errors: string[];
  }> {
    const correlationId = `cleanup_${Date.now()}`;
    const startTime = Date.now();

    logger.info('🧹 [Room Cleanup] Starting room lifecycle cleanup', {
      correlationId,
      timestamp: new Date().toISOString(),
    } as any);

    const results = {
      abandonedRooms: 0,
      emptyRooms: 0,
      inactiveRooms: 0,
      totalCleaned: 0,
      errors: [] as string[],
    };

    try {
      // Step 1: Clean abandoned rooms (no activity for 30+ days)
      const abandonedCount = await this.cleanAbandonedRooms(correlationId);
      results.abandonedRooms = abandonedCount;

      // Step 2: Clean empty rooms (no players for 7+ days)
      const emptyCount = await this.cleanEmptyRooms(correlationId);
      results.emptyRooms = emptyCount;

      // Step 3: Clean inactive rooms (no recent activity for 24+ hours)
      const inactiveCount = await this.cleanInactiveRooms(correlationId);
      results.inactiveRooms = inactiveCount;

      results.totalCleaned = abandonedCount + emptyCount + inactiveCount;

      const duration = Date.now() - startTime;
      logger.info('✅ [Room Cleanup] Cleanup completed successfully', {
        correlationId,
        duration,
        results,
      } as any);

    } catch (error) {
      const errorMessage = (error as Error).message;
      results.errors.push(errorMessage);

      logger.error('❌ [Room Cleanup] Cleanup failed', {
        correlationId,
        error: errorMessage,
        duration: Date.now() - startTime,
      } as any);
    }

    return results;
  }

  /**
   * Clean rooms that have been completely abandoned (30+ days)
   */
  private async cleanAbandonedRooms(correlationId: string): Promise<number> {
    const cutoffDate = new Date(Date.now() - RoomCleanupJob.ROOM_TTL_ABANDONED);

    logger.info('🧹 [Room Cleanup] Cleaning abandoned rooms', {
      correlationId,
      cutoffDate: cutoffDate.toISOString(),
    } as any);

    try {
      // Find rooms that haven't been updated in 30+ days
      const abandonedRooms = await db
        .select({ id: gameRooms.id, name: gameRooms.name })
        .from(gameRooms)
        .where(
          and(
            lt(gameRooms.updatedAt, cutoffDate),
            isNull(gameRooms.lastActivityAt), // Rooms with no recent activity
          ),
        );

      let cleanedCount = 0;
      for (const room of abandonedRooms) {
        try {
          await this.cleanupSingleRoom(room.id, 'abandoned', correlationId);
          cleanedCount++;

          logger.info('🧹 [Room Cleanup] Abandoned room cleaned', {
            correlationId,
            roomId: room.id,
            roomName: room.name,
          } as any);

        } catch (error) {
          logger.error('❌ [Room Cleanup] Failed to clean abandoned room', {
            correlationId,
            roomId: room.id,
            error: (error as Error).message,
          } as any);
        }
      }

      return cleanedCount;
    } catch (error) {
      logger.error('❌ [Room Cleanup] Error finding abandoned rooms', {
        correlationId,
        error: (error as Error).message,
      } as any);
      return 0;
    }
  }

  /**
   * Clean rooms that have been empty (no players) for 7+ days
   */
  private async cleanEmptyRooms(correlationId: string): Promise<number> {
    const cutoffDate = new Date(Date.now() - RoomCleanupJob.ROOM_TTL_EMPTY);

    logger.info('🧹 [Room Cleanup] Cleaning empty rooms', {
      correlationId,
      cutoffDate: cutoffDate.toISOString(),
    } as any);

    try {
      // Find rooms with no active players for 7+ days
      const emptyRooms = await db
        .select({
          id: gameRooms.id,
          name: gameRooms.name,
          playerCount: sql<number>`(
            SELECT COUNT(*) 
            FROM ${roomPlayers} 
            WHERE ${roomPlayers.roomId} = ${gameRooms.id}
          )`,
        })
        .from(gameRooms)
        .where(
          and(
            lt(gameRooms.updatedAt, cutoffDate),
            sql`(
              SELECT COUNT(*) 
              FROM ${roomPlayers} 
              WHERE ${roomPlayers.roomId} = ${gameRooms.id}
            ) = 0`,
          ),
        );

      let cleanedCount = 0;
      for (const room of emptyRooms) {
        try {
          await this.cleanupSingleRoom(room.id, 'empty', correlationId);
          cleanedCount++;

          logger.info('🧹 [Room Cleanup] Empty room cleaned', {
            correlationId,
            roomId: room.id,
            roomName: room.name,
          } as any);

        } catch (error) {
          logger.error('❌ [Room Cleanup] Failed to clean empty room', {
            correlationId,
            roomId: room.id,
            error: (error as Error).message,
          } as any);
        }
      }

      return cleanedCount;
    } catch (error) {
      logger.error('❌ [Room Cleanup] Error finding empty rooms', {
        correlationId,
        error: (error as Error).message,
      } as any);
      return 0;
    }
  }

  /**
   * Clean rooms that have been inactive for 24+ hours
   */
  private async cleanInactiveRooms(correlationId: string): Promise<number> {
    const cutoffDate = new Date(Date.now() - RoomCleanupJob.ROOM_TTL_INACTIVE);

    logger.info('🧹 [Room Cleanup] Cleaning inactive rooms', {
      correlationId,
      cutoffDate: cutoffDate.toISOString(),
    } as any);

    try {
      // Find rooms that haven't been updated in 24+ hours
      const inactiveRooms = await db
        .select({
          id: gameRooms.id,
          name: gameRooms.name,
          createdAt: gameRooms.createdAt,
        })
        .from(gameRooms)
        .where(
          and(
            lt(gameRooms.createdAt, cutoffDate),
            eq(gameRooms.isActive, true),
          ),
        );

      let cleanedCount = 0;
      for (const room of inactiveRooms) {
        try {
          await this.cleanupSingleRoom(room.id, 'inactive', correlationId);
          cleanedCount++;

          logger.info('🧹 [Room Cleanup] Inactive room cleaned', {
            correlationId,
            roomId: room.id,
            roomName: room.name,
            createdAt: room.createdAt,
          } as any);

        } catch (error) {
          logger.error('❌ [Room Cleanup] Failed to clean inactive room', {
            correlationId,
            roomId: room.id,
            error: (error as Error).message,
          } as any);
        }
      }

      return cleanedCount;
    } catch (error) {
      logger.error('❌ [Room Cleanup] Error finding inactive rooms', {
        correlationId,
        error: (error as Error).message,
      } as any);
      return 0;
    }
  }

  /**
   * Clean up a single room and all its associated data
   */
  private async cleanupSingleRoom(
    roomId: string,
    reason: 'abandoned' | 'empty' | 'inactive',
    correlationId: string,
  ): Promise<void> {

    await db.transaction(async (tx) => {
      logger.info('🧹 [Room Cleanup] Starting single room cleanup', {
        correlationId,
        roomId,
        reason,
      } as any);

      // 1. Delete card decks (preserves system assets)
      await tx.delete(cardDecks)
        .where(eq(cardDecks.roomId, roomId));

      // 2. Delete card piles
      await tx.delete(cardPiles)
        .where(eq(cardPiles.roomId, roomId));

      // 3. Delete board assets
      await tx.delete(boardAssets)
        .where(eq(boardAssets.roomId, roomId));

      // 4. Delete room players
      await tx.delete(roomPlayers)
        .where(eq(roomPlayers.roomId, roomId));

      // 5. Mark room as inactive (no separate sessions table)
      // Room cleanup completed - room will be deleted next

      // 6. Finally delete the room itself
      await tx.delete(gameRooms)
        .where(eq(gameRooms.id, roomId));

      logger.info('✅ [Room Cleanup] Single room cleanup completed', {
        correlationId,
        roomId,
        reason,
      } as any);
    });
  }

  /**
   * Get cleanup statistics for monitoring
   */
  async getCleanupStats(): Promise<{
    roomsEligibleForCleanup: {
      abandoned: number;
      empty: number;
      inactive: number;
    };
    totalRooms: number;
  }> {
    const now = Date.now();
    const abandonedCutoff = new Date(now - RoomCleanupJob.ROOM_TTL_ABANDONED);
    const emptyCutoff = new Date(now - RoomCleanupJob.ROOM_TTL_EMPTY);
    const inactiveCutoff = new Date(now - RoomCleanupJob.ROOM_TTL_INACTIVE);

    const [abandoned, empty, inactive, total] = await Promise.all([
      // Abandoned rooms count
      db.select({ count: sql<number>`COUNT(*)` })
        .from(gameRooms)
        .where(
          and(
            lt(gameRooms.updatedAt, abandonedCutoff),
            isNull(gameRooms.lastActivityAt),
          ),
        ),

      // Empty rooms count
      db.select({ count: sql<number>`COUNT(*)` })
        .from(gameRooms)
        .where(
          and(
            lt(gameRooms.updatedAt, emptyCutoff),
            sql`(
              SELECT COUNT(*) 
              FROM ${roomPlayers} 
              WHERE ${roomPlayers.roomId} = ${gameRooms.id}
            ) = 0`,
          ),
        ),

      // Inactive rooms count
      db.select({ count: sql<number>`COUNT(*)` })
        .from(gameRooms)
        .where(
          and(
            lt(gameRooms.lastActivityAt, inactiveCutoff),
            sql`NOT EXISTS (
              SELECT 1 FROM ${gameSessions} 
              WHERE ${gameSessions.roomId} = ${gameRooms.id} 
              AND ${gameSessions.isActive} = true
            )`,
          ),
        ),

      // Total rooms count
      db.select({ count: sql<number>`COUNT(*)` })
        .from(gameRooms),
    ]);

    return {
      roomsEligibleForCleanup: {
        abandoned: abandoned[0]?.count || 0,
        empty: empty[0]?.count || 0,
        inactive: inactive[0]?.count || 0,
      },
      totalRooms: total[0]?.count || 0,
    };
  }
}
