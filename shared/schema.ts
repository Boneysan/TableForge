import { sql } from "drizzle-orm";
import { pgTable, text, varchar, json, jsonb, timestamp, integer, boolean, index, unique, decimal } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// Session storage table for Replit Auth
export const sessions = pgTable(
  "sessions",
  {
    sid: varchar("sid").primaryKey(),
    sess: jsonb("sess").notNull(),
    expire: timestamp("expire").notNull(),
  },
  (table) => [index("IDX_session_expire").on(table.expire)],
);

// User storage table for Replit Auth
export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  email: varchar("email").unique(),
  firstName: varchar("first_name"),
  lastName: varchar("last_name"),
  profileImageUrl: varchar("profile_image_url"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const gameRooms = pgTable("game_rooms", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull().unique(),
  createdBy: varchar("created_by").notNull().references(() => users.id),
  isActive: boolean("is_active").notNull().default(true),
  gameState: json("game_state"),
  boardWidth: integer("board_width").notNull().default(800),
  boardHeight: integer("board_height").notNull().default(600),
  createdAt: timestamp("created_at").notNull().default(sql`now()`),
}, (table) => [
  index("idx_game_rooms_created_by").on(table.createdBy),
  index("idx_game_rooms_is_active").on(table.isActive),
  index("idx_game_rooms_created_at").on(table.createdAt),
]);

export const gameAssets = pgTable("game_assets", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  roomId: varchar("room_id").references(() => gameRooms.id), // Now nullable for system assets
  systemId: varchar("system_id").references(() => gameSystems.id), // Reference to game system
  name: text("name").notNull(),
  type: text("type").notNull(), // 'card', 'token', 'map', 'other'
  filePath: text("file_path").notNull(),
  width: integer("width"),
  height: integer("height"),
  uploadedBy: varchar("uploaded_by").notNull().references(() => users.id),
  isSystemAsset: boolean("is_system_asset").notNull().default(false), // Mark system vs room assets
  createdAt: timestamp("created_at").notNull().default(sql`now()`),
}, (table) => [
  index("idx_game_assets_room_id").on(table.roomId),
  index("idx_game_assets_system_id").on(table.systemId),
  index("idx_game_assets_uploaded_by").on(table.uploadedBy),
  index("idx_game_assets_type").on(table.type),
  index("idx_game_assets_is_system_asset").on(table.isSystemAsset),
  index("idx_game_assets_created_at").on(table.createdAt),
  // Composite indexes for common query patterns
  index("idx_game_assets_room_type").on(table.roomId, table.type),
  index("idx_game_assets_system_type").on(table.systemId, table.type),
]);

export const roomPlayers = pgTable("room_players", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  roomId: varchar("room_id").notNull().references(() => gameRooms.id),
  playerId: varchar("player_id").notNull().references(() => users.id),
  role: text("role").notNull().default("player"), // 'admin' or 'player'
  isOnline: boolean("is_online").notNull().default(true),
  score: integer("score").notNull().default(0),
  joinedAt: timestamp("joined_at").notNull().default(sql`now()`),
}, (table) => [
  unique().on(table.roomId, table.playerId),
  index("idx_room_players_room_id").on(table.roomId),
  index("idx_room_players_player_id").on(table.playerId),
  index("idx_room_players_role").on(table.role),
  index("idx_room_players_is_online").on(table.isOnline),
  index("idx_room_players_joined_at").on(table.joinedAt),
]);

export const boardAssets = pgTable("board_assets", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  roomId: varchar("room_id").notNull().references(() => gameRooms.id),
  assetId: varchar("asset_id").notNull().references(() => gameAssets.id),
  positionX: integer("position_x").notNull(),
  positionY: integer("position_y").notNull(),
  rotation: integer("rotation").notNull().default(0),
  scale: integer("scale").notNull().default(100),
  isFlipped: boolean("is_flipped").notNull().default(false),
  zIndex: integer("z_index").notNull().default(0),
  ownedBy: varchar("owned_by").references(() => users.id),
  // Enhanced properties for cards and tokens
  visibility: varchar("visibility", { enum: ["public", "owner", "gm"] }).default("public"),
  assetType: varchar("asset_type", { enum: ["token", "card", "tile", "other"] }).default("other"),
  faceDown: boolean("face_down").default(false), // For cards specifically
  stackOrder: integer("stack_order").default(0), // For card stacks/piles
  snapToGrid: boolean("snap_to_grid").default(false),
  isLocked: boolean("is_locked").default(false),
  placedAt: timestamp("placed_at").defaultNow(),
  placedBy: varchar("placed_by").references(() => users.id),
}, (table) => [
  index("idx_board_assets_room_id").on(table.roomId),
  index("idx_board_assets_asset_id").on(table.assetId),
  index("idx_board_assets_owned_by").on(table.ownedBy),
  index("idx_board_assets_placed_by").on(table.placedBy),
  index("idx_board_assets_asset_type").on(table.assetType),
  index("idx_board_assets_visibility").on(table.visibility),
  index("idx_board_assets_z_index").on(table.zIndex),
  index("idx_board_assets_placed_at").on(table.placedAt),
  // Composite indexes for spatial queries and game logic
  index("idx_board_assets_room_position").on(table.roomId, table.positionX, table.positionY),
  index("idx_board_assets_room_z_order").on(table.roomId, table.zIndex),
  index("idx_board_assets_stack_order").on(table.roomId, table.stackOrder),
]);

// Deck theme interface
export interface DeckTheme {
  name?: string;
  cardBackColor: string;
  cardBorderColor: string;
  deckBackgroundColor: string;
  textColor: string;
  borderStyle: string;
  cornerRadius: number;
  shadowIntensity: string;
}

// Card decks - predefined collections of cards
export const cardDecks = pgTable("card_decks", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  roomId: varchar("room_id").notNull().references(() => gameRooms.id, { onDelete: "cascade" }),
  name: varchar("name", { length: 100 }).notNull(),
  description: text("description"),
  createdBy: varchar("created_by").notNull().references(() => users.id),
  isShuffled: boolean("is_shuffled").default(false),
  deckOrder: json("deck_order"), // Array of card asset IDs in order
  theme: json("theme").$type<DeckTheme>(), // Deck visual theme
  cardBackAssetId: varchar("card_back_asset_id").references(() => gameAssets.id), // Custom card back image
  createdAt: timestamp("created_at").defaultNow(),
}, (table) => [
  index("idx_card_decks_room_id").on(table.roomId),
  index("idx_card_decks_created_by").on(table.createdBy),
  index("idx_card_decks_card_back_asset_id").on(table.cardBackAssetId),
  index("idx_card_decks_created_at").on(table.createdAt),
]);

// Card piles - dynamic collections of cards on the board
export const cardPiles = pgTable("card_piles", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  roomId: varchar("room_id").notNull().references(() => gameRooms.id, { onDelete: "cascade" }),
  name: varchar("name", { length: 100 }).notNull(),
  positionX: integer("position_x").notNull(),
  positionY: integer("position_y").notNull(),
  pileType: varchar("pile_type", { enum: ["deck", "discard", "hand", "custom"] }).default("custom"),
  visibility: varchar("visibility", { enum: ["public", "owner", "gm"] }).default("public"),
  ownerId: varchar("owner_id").references(() => users.id), // For private hands
  cardOrder: json("card_order"), // Array of board asset IDs in stack order
  faceDown: boolean("face_down").default(false), // Default face orientation for cards in pile
  maxCards: integer("max_cards"), // Optional limit
  createdAt: timestamp("created_at").defaultNow(),
}, (table) => [
  index("idx_card_piles_room_id").on(table.roomId),
  index("idx_card_piles_owner_id").on(table.ownerId),
  index("idx_card_piles_pile_type").on(table.pileType),
  index("idx_card_piles_visibility").on(table.visibility),
  index("idx_card_piles_created_at").on(table.createdAt),
  // Composite indexes for spatial and game queries
  index("idx_card_piles_room_position").on(table.roomId, table.positionX, table.positionY),
  index("idx_card_piles_room_type").on(table.roomId, table.pileType),
]);

export const diceRolls = pgTable("dice_rolls", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  roomId: varchar("room_id").notNull().references(() => gameRooms.id),
  playerId: varchar("player_id").notNull().references(() => users.id),
  diceType: text("dice_type").notNull(),
  diceCount: integer("dice_count").notNull(),
  results: json("results").notNull(),
  total: integer("total").notNull(),
  rolledAt: timestamp("rolled_at").notNull().default(sql`now()`),
}, (table) => [
  index("idx_dice_rolls_room_id").on(table.roomId),
  index("idx_dice_rolls_player_id").on(table.playerId),
  index("idx_dice_rolls_rolled_at").on(table.rolledAt),
  // Composite index for room history queries
  index("idx_dice_rolls_room_rolled_at").on(table.roomId, table.rolledAt),
]);

export const chatMessages = pgTable("chat_messages", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  roomId: varchar("room_id").references(() => gameRooms.id, { onDelete: "cascade" }).notNull(),
  playerId: varchar("player_id").references(() => users.id).notNull(),
  message: varchar("message", { length: 1000 }).notNull(),
  messageType: varchar("message_type").default("chat").notNull(), // chat, whisper, system
  targetPlayerId: varchar("target_player_id").references(() => users.id), // for whispers
  sentAt: timestamp("sent_at").defaultNow(),
}, (table) => [
  index("idx_chat_messages_room_id").on(table.roomId),
  index("idx_chat_messages_player_id").on(table.playerId),
  index("idx_chat_messages_target_player_id").on(table.targetPlayerId),
  index("idx_chat_messages_message_type").on(table.messageType),
  index("idx_chat_messages_sent_at").on(table.sentAt),
  // Composite index for chat history queries
  index("idx_chat_messages_room_sent_at").on(table.roomId, table.sentAt),
]);

// Insert schemas for Replit Auth
export const upsertUserSchema = createInsertSchema(users).pick({
  id: true,
  email: true,
  firstName: true,
  lastName: true,
  profileImageUrl: true,
});

export const insertUserSchema = createInsertSchema(users).pick({
  email: true,
  firstName: true,
  lastName: true,
  profileImageUrl: true,
});

export const updateUserSchema = createInsertSchema(users).pick({
  firstName: true,
  lastName: true,
}).partial();

export const insertGameRoomSchema = createInsertSchema(gameRooms).pick({
  name: true,
});

export const insertGameAssetSchema = createInsertSchema(gameAssets).pick({
  roomId: true,
  systemId: true,
  name: true,
  type: true,
  filePath: true,
  width: true,
  height: true,
  isSystemAsset: true,
});

export const insertBoardAssetSchema = createInsertSchema(boardAssets).pick({
  roomId: true,
  assetId: true,
  positionX: true,
  positionY: true,
  rotation: true,
  scale: true,
  isFlipped: true,
  zIndex: true,
  visibility: true,
  assetType: true,
  faceDown: true,
  stackOrder: true,
  snapToGrid: true,
});

export const insertCardDeckSchema = createInsertSchema(cardDecks).pick({
  roomId: true,
  name: true,
  description: true,
  deckOrder: true,
  cardBackAssetId: true,
});

export const insertCardPileSchema = createInsertSchema(cardPiles).pick({
  roomId: true,
  name: true,
  positionX: true,
  positionY: true,
  pileType: true,
  visibility: true,
  ownerId: true,
  cardOrder: true,
  faceDown: true,
  maxCards: true,
});

export const insertDiceRollSchema = createInsertSchema(diceRolls).pick({
  roomId: true,
  diceType: true,
  diceCount: true,
  results: true,
  total: true,
});

export const insertChatMessageSchema = createInsertSchema(chatMessages).pick({
  roomId: true,
  message: true,
  messageType: true,
  targetPlayerId: true,
});

// Types
export type User = typeof users.$inferSelect;
export type UpsertUser = z.infer<typeof upsertUserSchema>;
export type InsertUser = z.infer<typeof insertUserSchema>;

export type GameRoom = typeof gameRooms.$inferSelect;
export type InsertGameRoom = z.infer<typeof insertGameRoomSchema>;

export type GameAsset = typeof gameAssets.$inferSelect;
export type InsertGameAsset = z.infer<typeof insertGameAssetSchema>;

export type RoomPlayer = typeof roomPlayers.$inferSelect;
export type InsertRoomPlayer = typeof roomPlayers.$inferInsert;
export type RoomPlayerWithName = RoomPlayer & { playerName: string; playerEmail: string };

export type BoardAsset = typeof boardAssets.$inferSelect;
export type InsertBoardAsset = z.infer<typeof insertBoardAssetSchema>;

export type CardDeck = typeof cardDecks.$inferSelect;
export type InsertCardDeck = z.infer<typeof insertCardDeckSchema>;

export type CardPile = typeof cardPiles.$inferSelect;
export type InsertCardPile = z.infer<typeof insertCardPileSchema>;

export type DiceRoll = typeof diceRolls.$inferSelect;
export type InsertDiceRoll = z.infer<typeof insertDiceRollSchema>;

export type ChatMessage = typeof chatMessages.$inferSelect;
export type InsertChatMessage = z.infer<typeof insertChatMessageSchema>;

// WebSocket message types
export interface WebSocketMessage {
  type: string;
  payload: any;
  roomId?: string;
  playerId?: string;
}

export interface AssetMovedMessage extends WebSocketMessage {
  type: 'asset_moved';
  payload: {
    assetId: string;
    positionX: number;
    positionY: number;
    rotation?: number;
    scale?: number;
  };
}

export interface ChatMessageEvent extends WebSocketMessage {
  type: 'chat_message';
  payload: ChatMessage & { playerName: string };
}

export interface AssetFlippedMessage extends WebSocketMessage {
  type: 'asset_flipped';
  payload: {
    assetId: string;
    isFlipped: boolean;
  };
}

export interface DiceRolledMessage extends WebSocketMessage {
  type: 'dice_rolled';
  payload: DiceRoll;
}

export interface PlayerJoinedMessage extends WebSocketMessage {
  type: 'player_joined';
  payload: {
    player: User;
  };
}

export interface PlayerLeftMessage extends WebSocketMessage {
  type: 'player_left';
  payload: {
    playerId: string;
  };
}

export interface PlayerScoreUpdatedMessage extends WebSocketMessage {
  type: 'player_score_updated';
  payload: {
    playerId: string;
    score: number;
    playerName: string;
  };
}

// Game Templates - Reusable game setups created by GMs
export const gameTemplates = pgTable("game_templates", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: varchar("name", { length: 255 }).notNull(),
  description: text("description"),
  createdBy: varchar("created_by").references(() => users.id, { onDelete: "cascade" }),
  isPublic: boolean("is_public").default(false),
  category: varchar("category", { length: 100 }), // e.g., "RPG", "Board Game", "Card Game"
  tags: text("tags").array(), // searchable tags
  thumbnailUrl: varchar("thumbnail_url"),
  
  // Template content - JSON snapshots of game state
  boardConfig: jsonb("board_config"), // board settings, background, grid config
  decksData: jsonb("decks_data"), // all card decks and their cards
  tokensData: jsonb("tokens_data"), // token types and default positions
  assetsData: jsonb("assets_data"), // uploaded assets (maps, images, etc.)
  
  // Metadata
  playersMin: integer("players_min").default(1),
  playersMax: integer("players_max").default(8),
  estimatedDuration: varchar("estimated_duration"), // e.g., "2-4 hours"
  
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
}, (table) => [
  index("idx_game_templates_created_by").on(table.createdBy),
  index("idx_game_templates_is_public").on(table.isPublic),
  index("idx_game_templates_category").on(table.category),
  index("idx_game_templates_created_at").on(table.createdAt),
  index("idx_game_templates_updated_at").on(table.updatedAt),
  // Composite indexes for browsing and filtering
  index("idx_game_templates_public_category").on(table.isPublic, table.category),
  index("idx_game_templates_public_created").on(table.isPublic, table.createdAt),
]);

// Game Systems - Administrative game configurations and setups (separate from templates)
export const gameSystems = pgTable("game_systems", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: varchar("name", { length: 255 }).notNull(),
  description: text("description"),
  createdBy: varchar("created_by").references(() => users.id, { onDelete: "cascade" }),
  isPublic: boolean("is_public").default(false),
  category: varchar("category", { length: 100 }), // e.g., "D&D 5e", "Pathfinder", "Custom"
  tags: text("tags").array(), // searchable tags
  thumbnailUrl: varchar("thumbnail_url"),
  
  // System content - JSON configurations for game systems
  systemConfig: jsonb("system_config"), // core system rules and settings
  assetLibrary: jsonb("asset_library"), // default assets for this system
  deckTemplates: jsonb("deck_templates"), // card deck templates
  tokenTypes: jsonb("token_types"), // standard token types for this system
  boardDefaults: jsonb("board_defaults"), // default board configurations
  
  // System metadata
  version: varchar("version", { length: 20 }).default("1.0"),
  isOfficial: boolean("is_official").default(false), // official vs community systems
  complexity: varchar("complexity", { length: 20 }).default("medium"), // "simple", "medium", "complex"
  
  // Usage stats
  downloadCount: integer("download_count").default(0),
  rating: decimal("rating", { precision: 3, scale: 2 }), // average rating
  
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
}, (table) => [
  index("idx_game_systems_created_by").on(table.createdBy),
  index("idx_game_systems_is_public").on(table.isPublic),
  index("idx_game_systems_is_official").on(table.isOfficial),
  index("idx_game_systems_category").on(table.category),
  index("idx_game_systems_complexity").on(table.complexity),
  index("idx_game_systems_download_count").on(table.downloadCount),
  index("idx_game_systems_rating").on(table.rating),
  index("idx_game_systems_created_at").on(table.createdAt),
  index("idx_game_systems_updated_at").on(table.updatedAt),
  // Composite indexes for browsing and filtering
  index("idx_game_systems_public_category").on(table.isPublic, table.category),
  index("idx_game_systems_public_official").on(table.isPublic, table.isOfficial),
  index("idx_game_systems_public_rating").on(table.isPublic, table.rating),
]);

// Template usage tracking
export const templateUsage = pgTable("template_usage", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  templateId: varchar("template_id").references(() => gameTemplates.id, { onDelete: "cascade" }),
  roomId: varchar("room_id").references(() => gameRooms.id, { onDelete: "cascade" }),
  usedBy: varchar("used_by").references(() => users.id, { onDelete: "cascade" }),
  usedAt: timestamp("used_at").defaultNow(),
});

export const insertGameTemplateSchema = createInsertSchema(gameTemplates).pick({
  name: true,
  description: true,
  isPublic: true,
  category: true,
  tags: true,
  thumbnailUrl: true,
  boardConfig: true,
  decksData: true,
  tokensData: true,
  assetsData: true,
  playersMin: true,
  playersMax: true,
  estimatedDuration: true,
});

export const insertGameSystemSchema = createInsertSchema(gameSystems).pick({
  name: true,
  description: true,
  isPublic: true,
  category: true,
  tags: true,
  thumbnailUrl: true,
  systemConfig: true,
  assetLibrary: true,
  deckTemplates: true,
  tokenTypes: true,
  boardDefaults: true,
  version: true,
  isOfficial: true,
  complexity: true,
});

export type GameTemplate = typeof gameTemplates.$inferSelect;
export type InsertGameTemplate = z.infer<typeof insertGameTemplateSchema>;
export type GameSystem = typeof gameSystems.$inferSelect;
export type InsertGameSystem = z.infer<typeof insertGameSystemSchema>;
