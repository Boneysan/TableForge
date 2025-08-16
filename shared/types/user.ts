/**
 * User-related type definitions shared across client and server
 */

// Re-export ValidatedUser from server auth for shared usage
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

// Room-specific user claims
export interface RoomClaims {
  userId: string;
  roomId: string;
  role: 'owner' | 'gm' | 'player';
  permissions: string[];
  joinedAt: number;
}

// User roles and permissions
export type UserRole = 'owner' | 'admin' | 'gm' | 'player';
export type AdminLevel = 'super' | 'moderator' | 'support';

export interface UserPermissions {
  rooms: string[];
  admin: string[];
  global: string[];
}

// Session information
export interface UserSession {
  userId: string;
  sessionId: string;
  createdAt: number;
  lastActivity: number;
  expiresAt: number;
  refreshToken?: string;
  metadata: {
    userAgent: string;
    ip: string;
    location?: string;
  };
}

// Public user profile (safe for client consumption)
export interface PublicUserProfile {
  id: string;
  displayName: string;
  photoURL: string | null;
  isOnline: boolean;
  lastSeen?: string;
}

// Full user profile (server-side with sensitive data)
export interface UserProfile extends PublicUserProfile {
  email: string | null;
  emailVerified: boolean;
  createdAt: string;
  updatedAt: string;
  preferences: UserPreferences;
  statistics: UserStatistics;
}

// User preferences
export interface UserPreferences {
  theme: 'light' | 'dark' | 'system';
  language: string;
  timezone: string;
  notifications: {
    email: boolean;
    browser: boolean;
    gameInvites: boolean;
    systemUpdates: boolean;
  };
  privacy: {
    profileVisibility: 'public' | 'friends' | 'private';
    showOnlineStatus: boolean;
    allowGameInvites: boolean;
  };
  gameplay: {
    autoSaveInterval: number;
    showAnimations: boolean;
    soundEffects: boolean;
    gridSnapping: boolean;
  };
}

// User statistics
export interface UserStatistics {
  gamesPlayed: number;
  gamesCreated: number;
  totalPlayTime: number;
  favoriteGameSystems: string[];
  achievements: string[];
  level: number;
  experience: number;
}

// Authentication context
export interface AuthContext {
  user: ValidatedUser;
  session: UserSession;
  permissions: UserPermissions;
  isAuthenticated: true;
}

export interface UnauthenticatedContext {
  isAuthenticated: false;
}

export type AuthenticationContext = AuthContext | UnauthenticatedContext;

// User activity tracking
export interface UserActivity {
  userId: string;
  action: string;
  resource: string;
  resourceId: string;
  metadata: Record<string, unknown>;
  timestamp: string;
  sessionId: string;
}

// User connection information for WebSocket
export interface UserConnection {
  userId: string;
  socketId: string;
  connectedAt: number;
  lastActivity: number;
  roomId?: string;
  userAgent: string;
  ip: string;
}

// Type guards for user validation
export function isValidatedUser(user: unknown): user is ValidatedUser {
  return (
    typeof user === 'object' &&
    user !== null &&
    'uid' in user &&
    'source' in user &&
    typeof (user as ValidatedUser).uid === 'string'
  );
}

export function isAuthenticatedContext(context: AuthenticationContext): context is AuthContext {
  return context.isAuthenticated === true;
}

export function hasRoomPermission(
  claims: RoomClaims,
  permission: string
): boolean {
  return claims.permissions.includes(permission) || claims.role === 'owner';
}

export function isRoomOwner(claims: RoomClaims): boolean {
  return claims.role === 'owner';
}

export function isGameMaster(claims: RoomClaims): boolean {
  return claims.role === 'gm' || claims.role === 'owner';
}

// User creation and update types
export interface CreateUserRequest {
  uid: string;
  email: string;
  displayName: string;
  photoURL?: string;
  emailVerified?: boolean;
  preferences?: Partial<UserPreferences>;
}

export interface UpdateUserRequest {
  displayName?: string;
  photoURL?: string;
  preferences?: Partial<UserPreferences>;
}

// User search and filtering
export interface UserSearchFilters {
  query?: string;
  isOnline?: boolean;
  roles?: UserRole[];
  createdAfter?: string;
  createdBefore?: string;
}

export interface UserListItem {
  id: string;
  displayName: string;
  photoURL: string | null;
  isOnline: boolean;
  lastSeen: string;
  role?: UserRole;
}

// Admin user management
export interface AdminUserInfo extends UserProfile {
  roles: UserRole[];
  permissions: string[];
  sessions: UserSession[];
  recentActivity: UserActivity[];
  securityInfo: {
    loginAttempts: number;
    lastLoginFailed?: string;
    accountLocked: boolean;
    twoFactorEnabled: boolean;
  };
}

export interface UserModerationAction {
  type: 'warn' | 'suspend' | 'ban' | 'unlock';
  reason: string;
  duration?: number; // in seconds
  moderatorId: string;
  timestamp: string;
}

// Batch user operations
export interface BatchUserOperation {
  operation: 'update' | 'delete' | 'suspend' | 'activate';
  userIds: string[];
  data?: Partial<UpdateUserRequest>;
  reason?: string;
}

export interface BatchUserResult {
  successful: string[];
  failed: Array<{
    userId: string;
    error: string;
    code: string;
  }>;
  totalProcessed: number;
  successCount: number;
  failureCount: number;
}
