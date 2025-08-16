import { PaginationOptions, PaginatedQueryResult } from '../types/database.js';

// Repository Pattern Types from Phase 1 guide section 4.2

// Base repository interface with CRUD operations
export interface Repository<TEntity, TCreateInput, TUpdateInput> {
  findById(id: string): Promise<TEntity | null>;
  findMany(filters?: Partial<TEntity>): Promise<TEntity[]>;
  create(input: TCreateInput): Promise<TEntity>;
  update(id: string, input: Partial<TUpdateInput>): Promise<TEntity>;
  delete(id: string): Promise<boolean>;
}

// Enhanced repository interface with additional operations
export interface EnhancedRepository<TEntity, TCreateInput, TUpdateInput> 
  extends Repository<TEntity, TCreateInput, TUpdateInput> {
  findManyPaginated(
    filters?: Partial<TEntity>, 
    pagination?: PaginationOptions
  ): Promise<PaginatedQueryResult<TEntity>>;
  exists(id: string): Promise<boolean>;
  count(filters?: Partial<TEntity>): Promise<number>;
  bulkCreate(inputs: TCreateInput[]): Promise<TEntity[]>;
  bulkUpdate(updates: Array<{ id: string; data: Partial<TUpdateInput> }>): Promise<TEntity[]>;
  bulkDelete(ids: string[]): Promise<number>;
}

// Game Room entity types
export interface GameRoom {
  id: string;
  name: string;
  description?: string;
  ownerId: string;
  isPublic: boolean;
  maxPlayers: number;
  currentPlayers: number;
  status: 'active' | 'paused' | 'completed' | 'archived';
  settings: GameRoomSettings;
  createdAt: string;
  updatedAt: string;
  lastActivityAt: string;
}

export interface GameRoomSettings {
  allowSpectators: boolean;
  requireApproval: boolean;
  chatEnabled: boolean;
  voiceEnabled: boolean;
  recordSession: boolean;
  theme?: string;
  backgroundImage?: string;
}

export interface GameRoomWithPlayers extends GameRoom {
  players: RoomPlayer[];
  owner: {
    id: string;
    displayName: string;
    avatar?: string;
  };
}

export interface RoomPlayer {
  id: string;
  userId: string;
  displayName: string;
  role: 'owner' | 'gm' | 'player' | 'observer';
  isOnline: boolean;
  joinedAt: string;
  lastActiveAt: string;
  character?: {
    id: string;
    name: string;
    avatar?: string;
    sheet?: Record<string, unknown>;
  };
}

// Input types for game room operations
export interface CreateRoomInput {
  name: string;
  description?: string;
  ownerId: string;
  isPublic?: boolean;
  maxPlayers?: number;
  settings?: Partial<GameRoomSettings>;
}

export interface UpdateRoomInput {
  name?: string;
  description?: string;
  isPublic?: boolean;
  maxPlayers?: number;
  status?: GameRoom['status'];
  settings?: Partial<GameRoomSettings>;
}

// Game Room Repository interface from Phase 1 guide
export interface GameRoomRepository extends Repository<
  GameRoom,
  CreateRoomInput,
  UpdateRoomInput
> {
  findByUserId(userId: string): Promise<GameRoom[]>;
  findActiveRooms(): Promise<GameRoom[]>;
  findWithPlayers(roomId: string): Promise<GameRoomWithPlayers | null>;
}

// Enhanced Game Room Repository with additional methods
export interface EnhancedGameRoomRepository extends EnhancedRepository<
  GameRoom,
  CreateRoomInput,
  UpdateRoomInput
> {
  findByUserId(userId: string): Promise<GameRoom[]>;
  findActiveRooms(): Promise<GameRoom[]>;
  findWithPlayers(roomId: string): Promise<GameRoomWithPlayers | null>;
  findPublicRooms(pagination?: PaginationOptions): Promise<PaginatedQueryResult<GameRoom>>;
  findByOwner(ownerId: string): Promise<GameRoom[]>;
  addPlayer(roomId: string, player: Omit<RoomPlayer, 'id' | 'joinedAt' | 'lastActiveAt'>): Promise<RoomPlayer>;
  removePlayer(roomId: string, playerId: string): Promise<boolean>;
  updatePlayerRole(roomId: string, playerId: string, role: RoomPlayer['role']): Promise<RoomPlayer>;
  updateLastActivity(roomId: string): Promise<void>;
  archiveInactiveRooms(inactiveThresholdDays: number): Promise<number>;
}

// User Repository types
export interface User {
  id: string;
  email: string;
  displayName: string;
  avatar?: string;
  isActive: boolean;
  lastLoginAt?: string;
  createdAt: string;
  updatedAt: string;
  preferences: UserPreferences;
}

export interface UserPreferences {
  theme: 'light' | 'dark' | 'auto';
  notifications: {
    email: boolean;
    browser: boolean;
    gameInvites: boolean;
    gameUpdates: boolean;
  };
  privacy: {
    showOnlineStatus: boolean;
    allowDirectMessages: boolean;
  };
}

export interface CreateUserInput {
  email: string;
  displayName: string;
  avatar?: string;
  preferences?: Partial<UserPreferences>;
}

export interface UpdateUserInput {
  displayName?: string;
  avatar?: string;
  isActive?: boolean;
  preferences?: Partial<UserPreferences>;
}

export interface UserRepository extends Repository<
  User,
  CreateUserInput,
  UpdateUserInput
> {
  findByEmail(email: string): Promise<User | null>;
  findByDisplayName(displayName: string): Promise<User | null>;
  updateLastLogin(userId: string): Promise<void>;
  findActiveUsers(): Promise<User[]>;
}

// Asset Repository types
export interface Asset {
  id: string;
  roomId: string;
  type: 'token' | 'map' | 'handout' | 'dice' | 'card';
  name: string;
  imageUrl?: string;
  position: Position;
  rotation: number;
  scale: number;
  isVisible: boolean;
  isLocked: boolean;
  layer: number;
  metadata: Record<string, unknown>;
  ownerId: string;
  createdAt: string;
  updatedAt: string;
}

export interface Position {
  x: number;
  y: number;
  z?: number;
}

export interface CreateAssetInput {
  roomId: string;
  type: Asset['type'];
  name: string;
  imageUrl?: string;
  position: Position;
  rotation?: number;
  scale?: number;
  isVisible?: boolean;
  layer?: number;
  metadata?: Record<string, unknown>;
  ownerId: string;
}

export interface UpdateAssetInput {
  name?: string;
  imageUrl?: string;
  position?: Position;
  rotation?: number;
  scale?: number;
  isVisible?: boolean;
  isLocked?: boolean;
  layer?: number;
  metadata?: Record<string, unknown>;
}

export interface AssetRepository extends Repository<
  Asset,
  CreateAssetInput,
  UpdateAssetInput
> {
  findByRoomId(roomId: string): Promise<Asset[]>;
  findByType(type: Asset['type']): Promise<Asset[]>;
  findByOwner(ownerId: string): Promise<Asset[]>;
  updatePosition(assetId: string, position: Position): Promise<Asset>;
  bulkUpdatePositions(updates: Array<{ id: string; position: Position }>): Promise<Asset[]>;
}

// Repository factory interface
export interface RepositoryFactory {
  createGameRoomRepository(): GameRoomRepository;
  createUserRepository(): UserRepository;
  createAssetRepository(): AssetRepository;
}

// Type guards for repository operations
export function isRepository<TEntity, TCreateInput, TUpdateInput>(
  obj: unknown
): obj is Repository<TEntity, TCreateInput, TUpdateInput> {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    'findById' in obj &&
    'findMany' in obj &&
    'create' in obj &&
    'update' in obj &&
    'delete' in obj
  );
}
