import { sql } from "drizzle-orm";
import { pgTable, text, varchar, json, timestamp, integer, boolean } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
});

export const gameRooms = pgTable("game_rooms", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull(),
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
  isOnline: boolean("is_online").notNull().default(true),
  joinedAt: timestamp("joined_at").notNull().default(sql`now()`),
});

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

// Insert schemas
export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
});

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
});

export const insertDiceRollSchema = createInsertSchema(diceRolls).pick({
  roomId: true,
  diceType: true,
  diceCount: true,
  results: true,
  total: true,
});

// Types
export type User = typeof users.$inferSelect;
export type InsertUser = z.infer<typeof insertUserSchema>;

export type GameRoom = typeof gameRooms.$inferSelect;
export type InsertGameRoom = z.infer<typeof insertGameRoomSchema>;

export type GameAsset = typeof gameAssets.$inferSelect;
export type InsertGameAsset = z.infer<typeof insertGameAssetSchema>;

export type RoomPlayer = typeof roomPlayers.$inferSelect;

export type BoardAsset = typeof boardAssets.$inferSelect;
export type InsertBoardAsset = z.infer<typeof insertBoardAssetSchema>;

export type DiceRoll = typeof diceRolls.$inferSelect;
export type InsertDiceRoll = z.infer<typeof insertDiceRollSchema>;

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
