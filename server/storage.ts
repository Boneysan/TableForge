import { 
  type User, 
  type InsertUser,
  type GameRoom,
  type InsertGameRoom,
  type GameAsset,
  type InsertGameAsset,
  type BoardAsset,
  type InsertBoardAsset,
  type DiceRoll,
  type InsertDiceRoll,
  type RoomPlayer
} from "@shared/schema";
import { randomUUID } from "crypto";

export interface IStorage {
  // Users
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;

  // Game Rooms
  getGameRoom(id: string): Promise<GameRoom | undefined>;
  createGameRoom(room: InsertGameRoom, createdBy: string): Promise<GameRoom>;
  updateGameRoom(id: string, updates: Partial<GameRoom>): Promise<GameRoom>;
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
  addPlayerToRoom(roomId: string, playerId: string): Promise<RoomPlayer>;
  removePlayerFromRoom(roomId: string, playerId: string): Promise<void>;
  getRoomPlayers(roomId: string): Promise<RoomPlayer[]>;
  updatePlayerStatus(roomId: string, playerId: string, isOnline: boolean): Promise<void>;

  // Dice Rolls
  createDiceRoll(roll: InsertDiceRoll, playerId: string): Promise<DiceRoll>;
  getRoomDiceRolls(roomId: string, limit?: number): Promise<DiceRoll[]>;
}

export class MemStorage implements IStorage {
  private users: Map<string, User> = new Map();
  private gameRooms: Map<string, GameRoom> = new Map();
  private gameAssets: Map<string, GameAsset> = new Map();
  private boardAssets: Map<string, BoardAsset> = new Map();
  private roomPlayers: Map<string, RoomPlayer> = new Map();
  private diceRolls: Map<string, DiceRoll> = new Map();

  // Users
  async getUser(id: string): Promise<User | undefined> {
    return this.users.get(id);
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    return Array.from(this.users.values()).find(user => user.username === username);
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const id = randomUUID();
    const user: User = { ...insertUser, id };
    this.users.set(id, user);
    return user;
  }

  // Game Rooms
  async getGameRoom(id: string): Promise<GameRoom | undefined> {
    return this.gameRooms.get(id);
  }

  async createGameRoom(room: InsertGameRoom, createdBy: string): Promise<GameRoom> {
    const id = randomUUID();
    const gameRoom: GameRoom = {
      ...room,
      id,
      createdBy,
      isActive: true,
      gameState: null,
      createdAt: new Date(),
    };
    this.gameRooms.set(id, gameRoom);
    return gameRoom;
  }

  async updateGameRoom(id: string, updates: Partial<GameRoom>): Promise<GameRoom> {
    const room = this.gameRooms.get(id);
    if (!room) throw new Error("Room not found");
    const updatedRoom = { ...room, ...updates };
    this.gameRooms.set(id, updatedRoom);
    return updatedRoom;
  }

  async getUserRooms(userId: string): Promise<GameRoom[]> {
    return Array.from(this.gameRooms.values()).filter(room => room.createdBy === userId);
  }

  // Game Assets
  async getGameAsset(id: string): Promise<GameAsset | undefined> {
    return this.gameAssets.get(id);
  }

  async createGameAsset(asset: InsertGameAsset, uploadedBy: string): Promise<GameAsset> {
    const id = randomUUID();
    const gameAsset: GameAsset = {
      ...asset,
      id,
      uploadedBy,
      createdAt: new Date(),
    };
    this.gameAssets.set(id, gameAsset);
    return gameAsset;
  }

  async getRoomAssets(roomId: string): Promise<GameAsset[]> {
    return Array.from(this.gameAssets.values()).filter(asset => asset.roomId === roomId);
  }

  async deleteGameAsset(id: string): Promise<void> {
    this.gameAssets.delete(id);
  }

  // Board Assets
  async getBoardAsset(id: string): Promise<BoardAsset | undefined> {
    return this.boardAssets.get(id);
  }

  async createBoardAsset(asset: InsertBoardAsset): Promise<BoardAsset> {
    const id = randomUUID();
    const boardAsset: BoardAsset = { ...asset, id, ownedBy: null };
    this.boardAssets.set(id, boardAsset);
    return boardAsset;
  }

  async updateBoardAsset(id: string, updates: Partial<BoardAsset>): Promise<BoardAsset> {
    const asset = this.boardAssets.get(id);
    if (!asset) throw new Error("Board asset not found");
    const updatedAsset = { ...asset, ...updates };
    this.boardAssets.set(id, updatedAsset);
    return updatedAsset;
  }

  async getRoomBoardAssets(roomId: string): Promise<BoardAsset[]> {
    return Array.from(this.boardAssets.values()).filter(asset => asset.roomId === roomId);
  }

  async deleteBoardAsset(id: string): Promise<void> {
    this.boardAssets.delete(id);
  }

  // Room Players
  async addPlayerToRoom(roomId: string, playerId: string): Promise<RoomPlayer> {
    const id = randomUUID();
    const roomPlayer: RoomPlayer = {
      id,
      roomId,
      playerId,
      isOnline: true,
      joinedAt: new Date(),
    };
    this.roomPlayers.set(id, roomPlayer);
    return roomPlayer;
  }

  async removePlayerFromRoom(roomId: string, playerId: string): Promise<void> {
    for (const [id, player] of this.roomPlayers.entries()) {
      if (player.roomId === roomId && player.playerId === playerId) {
        this.roomPlayers.delete(id);
        break;
      }
    }
  }

  async getRoomPlayers(roomId: string): Promise<RoomPlayer[]> {
    return Array.from(this.roomPlayers.values()).filter(player => player.roomId === roomId);
  }

  async updatePlayerStatus(roomId: string, playerId: string, isOnline: boolean): Promise<void> {
    for (const [id, player] of this.roomPlayers.entries()) {
      if (player.roomId === roomId && player.playerId === playerId) {
        this.roomPlayers.set(id, { ...player, isOnline });
        break;
      }
    }
  }

  // Dice Rolls
  async createDiceRoll(roll: InsertDiceRoll, playerId: string): Promise<DiceRoll> {
    const id = randomUUID();
    const diceRoll: DiceRoll = {
      ...roll,
      id,
      playerId,
      rolledAt: new Date(),
    };
    this.diceRolls.set(id, diceRoll);
    return diceRoll;
  }

  async getRoomDiceRolls(roomId: string, limit: number = 10): Promise<DiceRoll[]> {
    return Array.from(this.diceRolls.values())
      .filter(roll => roll.roomId === roomId)
      .sort((a, b) => b.rolledAt.getTime() - a.rolledAt.getTime())
      .slice(0, limit);
  }
}

export const storage = new MemStorage();
