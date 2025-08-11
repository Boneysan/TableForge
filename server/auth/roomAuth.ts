import { storage } from '../storage';
import type { ValidatedUser, RoomClaims } from './tokenValidator';
import { createRoomClaims, hasPermission } from './tokenValidator';

/**
 * Room authorization and membership management
 */
export class RoomAuthManager {
  // Cache room membership for performance (with TTL)
  private membershipCache = new Map<string, { claims: RoomClaims; expiry: number }>();
  private readonly CACHE_TTL = 5 * 60 * 1000; // 5 minutes

  /**
   * Validates user's membership in a room and returns room-scoped claims
   */
  async validateRoomMembership(user: ValidatedUser, roomId: string): Promise<RoomClaims | null> {
    const cacheKey = `${user.uid}:${roomId}`;
    const cached = this.membershipCache.get(cacheKey);

    // Return cached claims if valid
    if (cached && Date.now() < cached.expiry) {
      console.log('🏠 [Room Auth] Using cached membership for', { userId: user.uid, roomId });
      return cached.claims;
    }

    try {
      console.log('🏠 [Room Auth] Validating room membership', { userId: user.uid, roomId });

      // Get room from database
      const room = await storage.getRoom(roomId);
      if (!room) {
        console.log('❌ [Room Auth] Room not found:', roomId);
        return null;
      }

      // Get room membership
      const membership = await storage.getRoomMembership(user.uid, roomId);
      if (!membership) {
        console.log('❌ [Room Auth] User not a member of room:', { userId: user.uid, roomId });
        return null;
      }

      // Create room claims based on membership
      const claims = createRoomClaims(user.uid, roomId, membership.role as any);

      // Cache the claims
      this.membershipCache.set(cacheKey, {
        claims,
        expiry: Date.now() + this.CACHE_TTL,
      });

      console.log('✅ [Room Auth] Room membership validated', {
        userId: user.uid,
        roomId,
        role: claims.role,
        permissions: claims.permissions.length,
      });

      return claims;
    } catch (error) {
      console.error('❌ [Room Auth] Error validating room membership:', error);
      return null;
    }
  }

  /**
   * Validates user can perform action in room
   */
  async validateRoomAction(
    user: ValidatedUser,
    roomId: string,
    action: string,
    requiredPermission: string,
  ): Promise<{ allowed: boolean; claims?: RoomClaims; reason?: string }> {

    console.log('🔒 [Room Auth] Validating room action', {
      userId: user.uid,
      roomId,
      action,
      requiredPermission,
    });

    // Get room membership
    const claims = await this.validateRoomMembership(user, roomId);
    if (!claims) {
      return {
        allowed: false,
        reason: 'User is not a member of this room',
      };
    }

    // Check permission
    if (!hasPermission(claims, requiredPermission)) {
      console.log('❌ [Room Auth] Permission denied', {
        userId: user.uid,
        roomId,
        action,
        requiredPermission,
        userPermissions: claims.permissions,
      });

      return {
        allowed: false,
        claims,
        reason: `User lacks required permission: ${requiredPermission}`,
      };
    }

    console.log('✅ [Room Auth] Action authorized', {
      userId: user.uid,
      roomId,
      action,
      role: claims.role,
    });

    return {
      allowed: true,
      claims,
    };
  }

  /**
   * Invalidates cached membership for user/room
   */
  invalidateCache(userId: string, roomId?: string): void {
    if (roomId) {
      const key = `${userId}:${roomId}`;
      this.membershipCache.delete(key);
      console.log('🗑️ [Room Auth] Invalidated cache for', { userId, roomId });
    } else {
      // Invalidate all entries for user
      for (const [key] of this.membershipCache) {
        if (key.startsWith(`${userId}:`)) {
          this.membershipCache.delete(key);
        }
      }
      console.log('🗑️ [Room Auth] Invalidated all cache entries for user:', userId);
    }
  }

  /**
   * Clean expired cache entries
   */
  cleanExpiredCache(): void {
    const now = Date.now();
    let cleanedCount = 0;

    for (const [key, { expiry }] of this.membershipCache) {
      if (now >= expiry) {
        this.membershipCache.delete(key);
        cleanedCount++;
      }
    }

    if (cleanedCount > 0) {
      console.log('🧹 [Room Auth] Cleaned expired cache entries:', cleanedCount);
    }
  }
}

// Singleton instance
export const roomAuthManager = new RoomAuthManager();

// Clean cache every 10 minutes
setInterval(() => {
  roomAuthManager.cleanExpiredCache();
}, 10 * 60 * 1000);
