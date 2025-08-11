import admin from 'firebase-admin';
import type { DecodedIdToken } from 'firebase-admin/auth';

// Interface for validated user claims
export interface ValidatedUser {
  uid: string;
  email: string | null;
  displayName: string | null;
  photoURL: string | null;
  emailVerified: boolean;
  source: 'firebase' | 'replit';
  issuedAt: number;
  expiresAt: number;
}

// Interface for room-scoped claims
export interface RoomClaims {
  userId: string;
  roomId: string;
  role: 'owner' | 'gm' | 'player';
  permissions: string[];
  joinedAt: number;
}

/**
 * Validates Firebase ID token and returns user claims
 * This is the primary trust boundary - never trust client-side claims
 */
export async function validateFirebaseToken(idToken: string): Promise<ValidatedUser> {
  try {
    console.log('🔐 [Token Validator] Validating Firebase ID token...');
    
    // Verify the ID token using Firebase Admin SDK
    const decodedToken: DecodedIdToken = await admin.auth().verifyIdToken(idToken, true);
    
    console.log('✅ [Token Validator] Token validated successfully', {
      uid: decodedToken.uid,
      email: decodedToken.email,
      issued: new Date(decodedToken.iat * 1000).toISOString(),
      expires: new Date(decodedToken.exp * 1000).toISOString(),
    });

    return {
      uid: decodedToken.uid,
      email: decodedToken.email || null,
      displayName: decodedToken.name || null,
      photoURL: decodedToken.picture || null,
      emailVerified: decodedToken.email_verified || false,
      source: 'firebase',
      issuedAt: decodedToken.iat,
      expiresAt: decodedToken.exp,
    };
  } catch (error) {
    console.error('❌ [Token Validator] Firebase token validation failed:', error);
    throw new Error('Invalid or expired authentication token');
  }
}

/**
 * Extracts and validates authentication token from request headers
 */
export function extractTokenFromRequest(req: any): string | null {
  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    console.log('⚠️ [Token Validator] No authorization header found');
    return null;
  }

  if (!authHeader.startsWith('Bearer ')) {
    console.log('⚠️ [Token Validator] Invalid authorization header format');
    return null;
  }

  const token = authHeader.substring(7);
  if (!token || token.length < 10) {
    console.log('⚠️ [Token Validator] Token too short or empty');
    return null;
  }

  return token;
}

/**
 * Extracts token from WebSocket handshake
 */
export function extractTokenFromWebSocket(req: any): string | null {
  // Try authorization header first
  let token = extractTokenFromRequest(req);
  if (token) return token;

  // Try query parameter as fallback
  const url = new URL(req.url, 'http://localhost');
  token = url.searchParams.get('token');
  
  if (token && token.length > 10) {
    console.log('🔐 [Token Validator] Token extracted from WebSocket query params');
    return token;
  }

  console.log('⚠️ [Token Validator] No valid token found in WebSocket handshake');
  return null;
}

/**
 * Validates token expiry and freshness
 */
export function validateTokenFreshness(user: ValidatedUser): boolean {
  const now = Math.floor(Date.now() / 1000);
  
  // Check if token is expired
  if (now >= user.expiresAt) {
    console.log('❌ [Token Validator] Token has expired');
    return false;
  }

  // Check if token is too old (> 24 hours)
  const tokenAge = now - user.issuedAt;
  if (tokenAge > 24 * 60 * 60) {
    console.log('⚠️ [Token Validator] Token is older than 24 hours, consider refresh');
  }

  return true;
}

/**
 * Creates room-scoped claims for user authorization
 */
export function createRoomClaims(userId: string, roomId: string, role: 'owner' | 'gm' | 'player'): RoomClaims {
  const basePermissions = ['read_room', 'send_chat'];
  const rolePermissions: Record<string, string[]> = {
    owner: [...basePermissions, 'manage_room', 'manage_players', 'delete_room', 'modify_board', 'manage_assets'],
    gm: [...basePermissions, 'manage_players', 'modify_board', 'manage_game_state', 'manage_assets'],
    player: [...basePermissions, 'move_tokens', 'view_hand', 'roll_dice'],
  };

  return {
    userId,
    roomId,
    role,
    permissions: rolePermissions[role] || basePermissions,
    joinedAt: Math.floor(Date.now() / 1000),
  };
}

/**
 * Validates if user has required permission for room action
 */
export function hasPermission(claims: RoomClaims, permission: string): boolean {
  return claims.permissions.includes(permission);
}

/**
 * Trust boundary documentation
 * 
 * AUTHENTICATION TRUST BOUNDARIES:
 * 
 * 1. CLIENT SIDE (UNTRUSTED):
 *    - Firebase Auth state (user object)
 *    - Client-side ID tokens
 *    - WebSocket connection state
 *    - Room membership claims from client
 * 
 * 2. SERVER SIDE (TRUSTED):
 *    - Firebase Admin SDK token validation
 *    - Database-stored user/room relationships
 *    - Server-generated room claims
 *    - Permission validation on every operation
 * 
 * NEVER TRUST:
 * - Anything sent from the client
 * - Claims about user identity without server validation
 * - Room permissions without database verification
 * 
 * ALWAYS VALIDATE:
 * - ID tokens on every HTTP request
 * - ID tokens on WebSocket connect AND reconnect
 * - Room membership before processing events
 * - User permissions before allowing actions
 */