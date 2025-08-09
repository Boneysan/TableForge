import { sql } from "drizzle-orm";
import { pgTable, text, varchar, json, jsonb, timestamp, integer, boolean, index, unique } from "drizzle-orm/pg-core";
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
  createdAt: timestamp("created_at").notNull().default(sql`now()`),
});

export const gameAssets = pgTable("game_assets", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  roomId: varchar("room_id").notNull().references(() => gameRooms.id),
  name: text("name").notNull(),
  type: text("type").notNull(), // 'card', 'token', 'map', 'other'
  filePath: text("file_path").notNull(),
  width: integer("width"),
  height: integer("height"),
  uploadedBy: varchar("uploaded_by").notNull().references(() => users.id),
  createdAt: timestamp("created_at").notNull().default(sql`now()`),
});

export const roomPlayers = pgTable("room_players", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  roomId: varchar("room_id").notNull().references(() => gameRooms.id),
  playerId: varchar("player_id").notNull().references(() => users.id),
  role: text("role").notNull().default("player"), // 'admin' or 'player'
  isOnline: boolean("is_online").notNull().default(true),
  joinedAt: timestamp("joined_at").notNull().default(sql`now()`),
}, (table) => ({
  unique: unique().on(table.roomId, table.playerId)
}));

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
});

// Card decks - predefined collections of cards
export const cardDecks = pgTable("card_decks", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  roomId: varchar("room_id").notNull().references(() => gameRooms.id, { onDelete: "cascade" }),
  name: varchar("name", { length: 100 }).notNull(),
  description: text("description"),
  createdBy: varchar("created_by").notNull().references(() => users.id),
  isShuffled: boolean("is_shuffled").default(false),
  deckOrder: json("deck_order"), // Array of card asset IDs in order
  createdAt: timestamp("created_at").defaultNow(),
});

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
});

export const diceRolls = pgTable("dice_rolls", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  roomId: varchar("room_id").notNull().references(() => gameRooms.id),
  playerId: varchar("player_id").notNull().references(() => users.id),
  diceType: text("dice_type").notNull(),
  diceCount: integer("dice_count").notNull(),
  results: json("results").notNull(),
  total: integer("total").notNull(),
  rolledAt: timestamp("rolled_at").notNull().default(sql`now()`),
});

export const chatMessages = pgTable("chat_messages", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  roomId: varchar("room_id").references(() => gameRooms.id, { onDelete: "cascade" }).notNull(),
  playerId: varchar("player_id").references(() => users.id).notNull(),
  message: varchar("message", { length: 1000 }).notNull(),
  messageType: varchar("message_type").default("chat").notNull(), // chat, whisper, system
  targetPlayerId: varchar("target_player_id").references(() => users.id), // for whispers
  sentAt: timestamp("sent_at").defaultNow(),
});

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
  name: true,
  type: true,
  filePath: true,
  width: true,
  height: true,
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
