import { 
  type User, 
  type InsertUser,
  type UpsertUser,
  type GameRoom,
  type InsertGameRoom,
  type GameAsset,
  type InsertGameAsset,
  type BoardAsset,
  type InsertBoardAsset,
  type DiceRoll,
  type InsertDiceRoll,
  type RoomPlayer,
  users,
  gameRooms,
  gameAssets,
  boardAssets,
  roomPlayers,
  diceRolls
} from "@shared/schema";
import { db } from "./db";
import { eq, desc, and } from "drizzle-orm";

export interface IStorage {
  // Users
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  upsertUser(user: UpsertUser): Promise<User>;

  // Game Rooms
  getGameRoom(id: string): Promise<GameRoom | undefined>;
  createGameRoom(room: InsertGameRoom, createdBy: string): Promise<GameRoom>;
  updateGameRoom(id: string, updates: Partial<GameRoom>): Promise<GameRoom>;
  deleteGameRoom(id: string): Promise<void>;
  getUserRooms(userId: string): Promise<GameRoom[]>;

  // Game Assets
  getGameAsset(id: string): Promise<GameAsset | undefined>;
  createGameAsset(asset: InsertGameAsset, uploadedBy: string): Promise<GameAsset>;
  getRoomAssets(roomId: string): Promise<GameAsset[]>;
  deleteGameAsset(id: string): Promise<void>;

  // Board Assets
  getBoardAsset(id: string): Promise<BoardAsset | undefined>;
  createBoardAsset(asset: InsertBoardAsset): Promise<BoardAsset>;
  updateBoardAsset(id: string, updates: Partial<BoardAsset>): Promise<BoardAsset>;
  getRoomBoardAssets(roomId: string): Promise<BoardAsset[]>;
  deleteBoardAsset(id: string): Promise<void>;

  // Room Players
  addPlayerToRoom(roomId: string, playerId: string, role?: 'admin' | 'player'): Promise<RoomPlayer>;
  removePlayerFromRoom(roomId: string, playerId: string): Promise<void>;
  getRoomPlayers(roomId: string): Promise<RoomPlayer[]>;
  getPlayerRole(roomId: string, playerId: string): Promise<'admin' | 'player' | null>;
  updatePlayerStatus(roomId: string, playerId: string, isOnline: boolean): Promise<void>;

  // Dice Rolls
  createDiceRoll(roll: InsertDiceRoll, playerId: string): Promise<DiceRoll>;
  getRoomDiceRolls(roomId: string, limit?: number): Promise<DiceRoll[]>;
}

export class DatabaseStorage implements IStorage {
  // Users
  async getUser(id: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user || undefined;
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.email, username));
    return user || undefined;
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const [user] = await db
      .insert(users)
      .values(insertUser)
      .returning();
    return user;
  }

  async upsertUser(userData: UpsertUser): Promise<User> {
    const [user] = await db
      .insert(users)
      .values(userData)
      .onConflictDoUpdate({
        target: users.id,
        set: {
          ...userData,
          updatedAt: new Date(),
        },
      })
      .returning();
    return user;
  }

  // Game Rooms
  async getGameRoom(id: string): Promise<GameRoom | undefined> {
    const [room] = await db.select().from(gameRooms).where(eq(gameRooms.id, id));
    return room || undefined;
  }

  async createGameRoom(room: InsertGameRoom, createdBy: string): Promise<GameRoom> {
    const [newRoom] = await db
      .insert(gameRooms)
      .values({ ...room, createdBy })
      .returning();
    return newRoom;
  }

  async updateGameRoom(id: string, updates: Partial<GameRoom>): Promise<GameRoom> {
    const [updatedRoom] = await db
      .update(gameRooms)
      .set(updates)
      .where(eq(gameRooms.id, id))
      .returning();
    return updatedRoom;
  }

  async deleteGameRoom(id: string): Promise<void> {
    // Delete related data first
    await db.delete(diceRolls).where(eq(diceRolls.roomId, id));
    await db.delete(boardAssets).where(eq(boardAssets.roomId, id));
    await db.delete(gameAssets).where(eq(gameAssets.roomId, id));
    await db.delete(roomPlayers).where(eq(roomPlayers.roomId, id));
    await db.delete(gameRooms).where(eq(gameRooms.id, id));
  }

  async getUserRooms(userId: string): Promise<GameRoom[]> {
    return db.select().from(gameRooms).where(eq(gameRooms.createdBy, userId));
  }

  // Game Assets
  async getGameAsset(id: string): Promise<GameAsset | undefined> {
    const [asset] = await db.select().from(gameAssets).where(eq(gameAssets.id, id));
    return asset || undefined;
  }

  async createGameAsset(asset: InsertGameAsset, uploadedBy: string): Promise<GameAsset> {
    const [newAsset] = await db
      .insert(gameAssets)
      .values({ ...asset, uploadedBy })
      .returning();
    return newAsset;
  }

  async getRoomAssets(roomId: string): Promise<GameAsset[]> {
    return db.select().from(gameAssets).where(eq(gameAssets.roomId, roomId));
  }

  async deleteGameAsset(id: string): Promise<void> {
    await db.delete(boardAssets).where(eq(boardAssets.assetId, id));
    await db.delete(gameAssets).where(eq(gameAssets.id, id));
  }

  // Board Assets
  async getBoardAsset(id: string): Promise<BoardAsset | undefined> {
    const [asset] = await db.select().from(boardAssets).where(eq(boardAssets.id, id));
    return asset || undefined;
  }

  async createBoardAsset(asset: InsertBoardAsset): Promise<BoardAsset> {
    const [newAsset] = await db
      .insert(boardAssets)
      .values(asset)
      .returning();
    return newAsset;
  }

  async updateBoardAsset(id: string, updates: Partial<BoardAsset>): Promise<BoardAsset> {
    const [updatedAsset] = await db
      .update(boardAssets)
      .set(updates)
      .where(eq(boardAssets.id, id))
      .returning();
    return updatedAsset;
  }

  async getRoomBoardAssets(roomId: string): Promise<BoardAsset[]> {
    return db.select().from(boardAssets).where(eq(boardAssets.roomId, roomId));
  }

  async deleteBoardAsset(id: string): Promise<void> {
    await db.delete(boardAssets).where(eq(boardAssets.id, id));
  }

  // Room Players
  async addPlayerToRoom(roomId: string, playerId: string, role: 'admin' | 'player' = 'player'): Promise<RoomPlayer> {
    // Check if user is room creator to set admin role
    const room = await this.getGameRoom(roomId);
    const actualRole = room?.createdBy === playerId ? 'admin' : role;
    
    const [player] = await db
      .insert(roomPlayers)
      .values({ roomId, playerId, role: actualRole })
      .onConflictDoUpdate({
        target: [roomPlayers.roomId, roomPlayers.playerId],
        set: {
          isOnline: true,
          role: actualRole,
        },
      })
      .returning();
    return player;
  }

  async removePlayerFromRoom(roomId: string, playerId: string): Promise<void> {
    await db.delete(roomPlayers).where(
      and(
        eq(roomPlayers.roomId, roomId),
        eq(roomPlayers.playerId, playerId)
      )
    );
  }

  async getRoomPlayers(roomId: string): Promise<RoomPlayer[]> {
    return db.select().from(roomPlayers).where(eq(roomPlayers.roomId, roomId));
  }

  async getPlayerRole(roomId: string, playerId: string): Promise<'admin' | 'player' | null> {
    const [player] = await db
      .select({ role: roomPlayers.role })
      .from(roomPlayers)
      .where(
        and(
          eq(roomPlayers.roomId, roomId),
          eq(roomPlayers.playerId, playerId)
        )
      );
    return player?.role as 'admin' | 'player' || null;
  }

  async updatePlayerStatus(roomId: string, playerId: string, isOnline: boolean): Promise<void> {
    await db
      .update(roomPlayers)
      .set({ isOnline })
      .where(
        and(
          eq(roomPlayers.roomId, roomId),
          eq(roomPlayers.playerId, playerId)
        )
      );
  }

  // Dice Rolls
  async createDiceRoll(roll: InsertDiceRoll, playerId: string): Promise<DiceRoll> {
    const [newRoll] = await db
      .insert(diceRolls)
      .values({ ...roll, playerId })
      .returning();
    return newRoll;
  }

  async getRoomDiceRolls(roomId: string, limit: number = 50): Promise<DiceRoll[]> {
    return db
      .select()
      .from(diceRolls)
      .where(eq(diceRolls.roomId, roomId))
      .orderBy(desc(diceRolls.rolledAt))
      .limit(limit);
  }
}

export const storage = new DatabaseStorage();