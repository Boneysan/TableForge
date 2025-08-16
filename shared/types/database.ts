/**
 * Database type definitions for Drizzle ORM and query operations
 */

// Base database entity
export interface BaseEntity {
  id: string;
  createdAt: string;
  updatedAt: string;
}

// Soft delete entity
export interface SoftDeleteEntity extends BaseEntity {
  deletedAt: string | null;
  isDeleted: boolean;
}

// User entity
export interface UserEntity extends BaseEntity {
  uid: string;
  email: string | null;
  displayName: string;
  photoURL: string | null;
  emailVerified: boolean;
  source: 'firebase' | 'replit';
  preferences: UserPreferences | null;
  statistics: UserStatistics | null;
  lastLoginAt: string | null;
  isActive: boolean;
}

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

export interface UserStatistics {
  gamesPlayed: number;
  gamesCreated: number;
  totalPlayTime: number;
  favoriteGameSystems: string[];
  achievements: string[];
  level: number;
  experience: number;
}

// Room entity
export interface RoomEntity extends SoftDeleteEntity {
  name: string;
  description: string | null;
  ownerId: string;
  gameSystemId: string;
  isPublic: boolean;
  password: string | null;
  maxPlayers: number;
  currentPlayers: number;
  status: 'active' | 'paused' | 'ended' | 'archived';
  settings: RoomSettings;
  metadata: Record<string, unknown>;
}

export interface RoomSettings {
  allowSpectators: boolean;
  requireApproval: boolean;
  chatEnabled: boolean;
  voiceEnabled: boolean;
  recordSession: boolean;
  autoSave: boolean;
  saveInterval: number;
  rules: Record<string, unknown>;
}

// Game system entity
export interface GameSystemEntity extends BaseEntity {
  name: string;
  version: string;
  description: string;
  createdBy: string;
  isPublic: boolean;
  isOfficial: boolean;
  rules: GameSystemRules;
  assets: string[];
  tags: string[];
  downloadCount: number;
  rating: number;
  ratingCount: number;
}

export interface GameSystemRules {
  dice: DiceRule[];
  cards: CardRule[];
  tokens: TokenRule[];
  board: BoardRule | null;
  turns: TurnRule;
  victory: VictoryCondition[];
  setup: SetupRule;
}

export interface DiceRule {
  id: string;
  name: string;
  sides: number;
  color: string;
  modifier?: number;
}

export interface CardRule {
  id: string;
  name: string;
  type: 'deck' | 'hand' | 'single';
  count: number;
  properties: Record<string, unknown>;
}

export interface TokenRule {
  id: string;
  name: string;
  shape: 'circle' | 'square' | 'hex' | 'custom';
  size: number;
  color: string;
  stackable: boolean;
}

export interface BoardRule {
  type: 'grid' | 'hex' | 'free';
  width: number;
  height: number;
  cellSize: number;
  background: string;
  layers: BoardLayer[];
}

export interface BoardLayer {
  id: string;
  name: string;
  type: 'background' | 'objects' | 'overlay';
  visible: boolean;
  locked: boolean;
  zIndex: number;
}

export interface TurnRule {
  type: 'sequential' | 'simultaneous' | 'async';
  timeLimit?: number;
  skipInactive?: boolean;
  order: 'fixed' | 'initiative' | 'random';
}

export interface VictoryCondition {
  id: string;
  type: 'elimination' | 'objective' | 'points' | 'time';
  description: string;
  rules: Record<string, unknown>;
}

export interface SetupRule {
  playerCount: {
    min: number;
    max: number;
    optimal?: number;
  };
  initialState: Record<string, unknown>;
  randomization?: Record<string, unknown>;
}

// Asset entity
export interface AssetEntity extends SoftDeleteEntity {
  name: string;
  description: string | null;
  type: 'image' | 'audio' | 'video' | 'model' | 'document' | 'archive';
  mimeType: string;
  size: number;
  checksum: string;
  url: string;
  thumbnailUrl: string | null;
  metadata: AssetMetadata;
  tags: string[];
  ownerId: string;
  isPublic: boolean;
  downloadCount: number;
  usageCount: number;
}

export interface AssetMetadata {
  width?: number;
  height?: number;
  duration?: number;
  format?: string;
  quality?: string;
  colorProfile?: string;
  compression?: string;
  exif?: Record<string, unknown>;
  custom?: Record<string, unknown>;
}

// Room membership entity
export interface RoomMemberEntity extends BaseEntity {
  roomId: string;
  userId: string;
  role: 'owner' | 'gm' | 'player' | 'observer';
  permissions: string[];
  joinedAt: string;
  lastActiveAt: string;
  isOnline: boolean;
  position: number;
  nickname: string | null;
  characterId: string | null;
}

// Game session entity
export interface GameSessionEntity extends BaseEntity {
  roomId: string;
  startedAt: string;
  endedAt: string | null;
  duration: number;
  participants: SessionParticipant[];
  events: SessionEvent[];
  state: GameState;
  statistics: SessionStatistics;
}

export interface SessionParticipant {
  userId: string;
  joinedAt: string;
  leftAt: string | null;
  role: 'gm' | 'player' | 'observer';
  characterId: string | null;
}

export interface SessionEvent {
  id: string;
  type: string;
  userId: string;
  timestamp: string;
  data: Record<string, unknown>;
  sequence: number;
}

export interface GameState {
  turn: number;
  phase: string;
  activePlayer: string | null;
  board: BoardState | null;
  players: Record<string, PlayerState>;
  global: Record<string, unknown>;
}

export interface BoardState {
  objects: BoardObject[];
  dimensions: {
    width: number;
    height: number;
  };
  viewport: {
    x: number;
    y: number;
    zoom: number;
  };
}

export interface BoardObject {
  id: string;
  type: 'token' | 'card' | 'dice' | 'marker' | 'area';
  position: {
    x: number;
    y: number;
    z?: number;
  };
  properties: Record<string, unknown>;
  ownerId: string | null;
  locked: boolean;
  visible: boolean;
}

export interface PlayerState {
  id: string;
  resources: Record<string, number>;
  cards: Card[];
  tokens: Token[];
  score: number;
  status: 'active' | 'inactive' | 'eliminated';
  turnOrder: number;
}

export interface Card {
  id: string;
  deckId: string;
  position: 'hand' | 'table' | 'deck';
  faceUp: boolean;
  properties: Record<string, unknown>;
}

export interface Token {
  id: string;
  typeId: string;
  position: {
    x: number;
    y: number;
  };
  properties: Record<string, unknown>;
}

export interface SessionStatistics {
  totalActions: number;
  actionsPerPlayer: Record<string, number>;
  timePerPlayer: Record<string, number>;
  averageResponseTime: number;
  peakConcurrentPlayers: number;
  chatMessages: number;
  diceRolls: number;
  cardsPlayed: number;
}

// Database query types
export interface QueryOptions {
  limit?: number;
  offset?: number;
  orderBy?: Array<{
    field: string;
    direction: 'asc' | 'desc';
  }>;
  include?: string[];
  exclude?: string[];
  distinct?: boolean;
}

export interface FilterOptions {
  where?: WhereClause;
  search?: string;
  dateRange?: {
    field: string;
    start?: string;
    end?: string;
  };
  tags?: string[];
  status?: string[];
}

export type WhereClause = 
  | SimpleClause
  | CompoundClause;

export interface SimpleClause {
  field: string;
  operator: 'eq' | 'ne' | 'gt' | 'gte' | 'lt' | 'lte' | 'like' | 'ilike' | 'in' | 'nin' | 'null' | 'nnull';
  value: unknown;
}

export interface CompoundClause {
  operator: 'and' | 'or' | 'not';
  clauses: WhereClause[];
}

// Repository interfaces
export interface BaseRepository<T extends BaseEntity> {
  findById(id: string): Promise<T | null>;
  findMany(options?: QueryOptions & FilterOptions): Promise<T[]>;
  count(options?: FilterOptions): Promise<number>;
  create(data: Omit<T, keyof BaseEntity>): Promise<T>;
  update(id: string, data: Partial<Omit<T, 'id' | 'createdAt'>>): Promise<T>;
  delete(id: string): Promise<boolean>;
}

export interface SoftDeleteRepository<T extends SoftDeleteEntity> extends BaseRepository<T> {
  findManyIncludeDeleted(options?: QueryOptions & FilterOptions): Promise<T[]>;
  softDelete(id: string): Promise<boolean>;
  restore(id: string): Promise<boolean>;
  hardDelete(id: string): Promise<boolean>;
}

export interface UserRepository extends BaseRepository<UserEntity> {
  findByUid(uid: string): Promise<UserEntity | null>;
  findByEmail(email: string): Promise<UserEntity | null>;
  updateLastLogin(id: string): Promise<void>;
  updatePreferences(id: string, preferences: UserPreferences): Promise<UserEntity>;
  updateStatistics(id: string, statistics: Partial<UserStatistics>): Promise<UserEntity>;
  search(query: string, options?: QueryOptions): Promise<UserEntity[]>;
}

export interface RoomRepository extends SoftDeleteRepository<RoomEntity> {
  findByOwner(ownerId: string): Promise<RoomEntity[]>;
  findPublic(options?: QueryOptions): Promise<RoomEntity[]>;
  findByGameSystem(gameSystemId: string): Promise<RoomEntity[]>;
  updatePlayerCount(id: string, count: number): Promise<void>;
  updateStatus(id: string, status: RoomEntity['status']): Promise<void>;
  findActive(): Promise<RoomEntity[]>;
}

export interface GameSystemRepository extends BaseRepository<GameSystemEntity> {
  findPublic(options?: QueryOptions): Promise<GameSystemEntity[]>;
  findByCreator(creatorId: string): Promise<GameSystemEntity[]>;
  findByTags(tags: string[]): Promise<GameSystemEntity[]>;
  updateRating(id: string, rating: number): Promise<void>;
  incrementDownload(id: string): Promise<void>;
  search(query: string, options?: QueryOptions): Promise<GameSystemEntity[]>;
}

export interface AssetRepository extends SoftDeleteRepository<AssetEntity> {
  findByOwner(ownerId: string): Promise<AssetEntity[]>;
  findByType(type: AssetEntity['type']): Promise<AssetEntity[]>;
  findByTags(tags: string[]): Promise<AssetEntity[]>;
  incrementUsage(id: string): Promise<void>;
  updateMetadata(id: string, metadata: AssetMetadata): Promise<AssetEntity>;
  findOrphaned(olderThan: string): Promise<AssetEntity[]>;
}

export interface RoomMemberRepository extends BaseRepository<RoomMemberEntity> {
  findByRoom(roomId: string): Promise<RoomMemberEntity[]>;
  findByUser(userId: string): Promise<RoomMemberEntity[]>;
  findByRoomAndUser(roomId: string, userId: string): Promise<RoomMemberEntity | null>;
  updateLastActive(roomId: string, userId: string): Promise<void>;
  updateOnlineStatus(userId: string, isOnline: boolean): Promise<void>;
  removeFromRoom(roomId: string, userId: string): Promise<boolean>;
  updateRole(roomId: string, userId: string, role: RoomMemberEntity['role']): Promise<void>;
}

export interface GameSessionRepository extends BaseRepository<GameSessionEntity> {
  findByRoom(roomId: string): Promise<GameSessionEntity[]>;
  findActive(): Promise<GameSessionEntity[]>;
  endSession(id: string): Promise<void>;
  addEvent(sessionId: string, event: Omit<SessionEvent, 'id'>): Promise<SessionEvent>;
  updateState(sessionId: string, state: GameState): Promise<void>;
  findByDateRange(start: string, end: string): Promise<GameSessionEntity[]>;
}

// Transaction types
export interface DatabaseTransaction {
  commit(): Promise<void>;
  rollback(): Promise<void>;
  isCompleted(): boolean;
}

export type TransactionCallback<T> = (tx: DatabaseTransaction) => Promise<T>;

export interface DatabaseService {
  transaction<T>(callback: TransactionCallback<T>): Promise<T>;
  beginTransaction(): Promise<DatabaseTransaction>;
}

// Migration types
export interface MigrationScript {
  id: string;
  name: string;
  up: string;
  down: string;
  checksum: string;
  appliedAt?: string;
}

export interface MigrationService {
  applyPending(): Promise<void>;
  rollback(steps?: number): Promise<void>;
  getApplied(): Promise<MigrationScript[]>;
  getPending(): Promise<MigrationScript[]>;
  generateChecksum(script: string): string;
}

// Database health and monitoring
export interface DatabaseHealth {
  connected: boolean;
  responseTime: number;
  activeConnections: number;
  maxConnections: number;
  version: string;
  uptime: number;
  lastCheck: string;
}

export interface DatabaseMetrics {
  queries: {
    total: number;
    successful: number;
    failed: number;
    averageTime: number;
    slowQueries: number;
  };
  connections: {
    active: number;
    idle: number;
    waiting: number;
    total: number;
  };
  tables: Array<{
    name: string;
    rows: number;
    size: number;
    lastUpdated: string;
  }>;
  indexes: Array<{
    name: string;
    table: string;
    size: number;
    usage: number;
    lastUsed: string;
  }>;
}

// Database configuration
export interface DatabaseConfig {
  host: string;
  port: number;
  database: string;
  username: string;
  password: string;
  ssl: boolean;
  pool: {
    min: number;
    max: number;
    acquireTimeoutMillis: number;
    idleTimeoutMillis: number;
  };
  migration: {
    directory: string;
    tableName: string;
    schemaName?: string;
  };
  logging: {
    enabled: boolean;
    level: 'debug' | 'info' | 'warn' | 'error';
    slowQueryThreshold: number;
  };
}

// Backup and restore types
export interface BackupOptions {
  tables?: string[];
  includeData: boolean;
  includeSchema: boolean;
  compress: boolean;
  encryption?: {
    enabled: boolean;
    key: string;
    algorithm: string;
  };
}

export interface BackupResult {
  id: string;
  filename: string;
  size: number;
  checksum: string;
  createdAt: string;
  tables: string[];
  metadata: Record<string, unknown>;
}

export interface RestoreOptions {
  backupId: string;
  tables?: string[];
  dropExisting: boolean;
  verify: boolean;
}

export interface DatabaseBackupService {
  createBackup(options: BackupOptions): Promise<BackupResult>;
  listBackups(): Promise<BackupResult[]>;
  restoreBackup(options: RestoreOptions): Promise<void>;
  deleteBackup(backupId: string): Promise<void>;
  verifyBackup(backupId: string): Promise<boolean>;
}

// Seeding types
export interface SeedData<T> {
  table: string;
  data: T[];
  truncate?: boolean;
  conflicts?: 'ignore' | 'update' | 'error';
}

export interface SeedService {
  seed<T>(seedData: SeedData<T>): Promise<void>;
  seedAll(): Promise<void>;
  clearAll(): Promise<void>;
  getSeedStatus(): Promise<Array<{
    table: string;
    seeded: boolean;
    count: number;
    lastSeeded: string;
  }>>;
}

// Type utilities for database operations
export type EntityKeys<T> = keyof T;
export type EntityValues<T> = T[keyof T];
export type PartialEntity<T extends BaseEntity> = Partial<Omit<T, keyof BaseEntity>>;
export type CreateEntity<T extends BaseEntity> = Omit<T, keyof BaseEntity>;
export type UpdateEntity<T extends BaseEntity> = Partial<Omit<T, 'id' | 'createdAt'>>;

// Type guards for entities
export function isBaseEntity(obj: unknown): obj is BaseEntity {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    'id' in obj &&
    'createdAt' in obj &&
    'updatedAt' in obj
  );
}

export function isSoftDeleteEntity(obj: unknown): obj is SoftDeleteEntity {
  return (
    isBaseEntity(obj) &&
    'deletedAt' in obj &&
    'isDeleted' in obj
  );
}

export function isUserEntity(obj: unknown): obj is UserEntity {
  return (
    isBaseEntity(obj) &&
    'uid' in obj &&
    'email' in obj &&
    'displayName' in obj
  );
}

export function isRoomEntity(obj: unknown): obj is RoomEntity {
  return (
    isSoftDeleteEntity(obj) &&
    'name' in obj &&
    'ownerId' in obj &&
    'gameSystemId' in obj
  );
}
