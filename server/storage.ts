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
  type ChatMessage,
  type InsertChatMessage,
  type RoomPlayer,
  type CardDeck,
  type InsertCardDeck,
  type CardPile,
  type InsertCardPile,
  users,
  gameRooms,
  gameAssets,
  boardAssets,
  roomPlayers,
  diceRolls,
  chatMessages,
  cardDecks,
  cardPiles
} from "@shared/schema";
import { db } from "./db";
import { eq, desc, and } from "drizzle-orm";

export interface IStorage {
  // Users
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  upsertUser(user: UpsertUser): Promise<User>;
  updateUser(userId: string, updates: { firstName?: string; lastName?: string }): Promise<User>;

  // Game Rooms
  getGameRoom(id: string): Promise<GameRoom | undefined>;
  getGameRoomByName(name: string): Promise<GameRoom | undefined>;
  getGameRoomByIdOrName(identifier: string): Promise<GameRoom | undefined>;
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
  getRoomPlayersWithNames(roomId: string): Promise<Array<RoomPlayer & { playerName: string; playerEmail: string }>>;
  getPlayerRole(roomId: string, playerId: string): Promise<'admin' | 'player' | null>;
  updatePlayerStatus(roomId: string, playerId: string, isOnline: boolean): Promise<void>;

  // Dice Rolls
  createDiceRoll(roll: InsertDiceRoll, playerId: string): Promise<DiceRoll>;
  getRoomDiceRolls(roomId: string, limit?: number): Promise<DiceRoll[]>;

  // Chat Messages
  createChatMessage(message: InsertChatMessage, playerId: string): Promise<ChatMessage>;
  getRoomChatMessages(roomId: string, limit?: number): Promise<Array<ChatMessage & { playerName: string }>>;

  // Card Decks
  createCardDeck(deck: InsertCardDeck, createdBy: string): Promise<CardDeck>;
  getCardDecks(roomId: string): Promise<CardDeck[]>;
  getCardDeck(id: string): Promise<CardDeck | undefined>;
  shuffleCardDeck(id: string): Promise<CardDeck | undefined>;

  // Card Piles
  createCardPile(pile: InsertCardPile): Promise<CardPile>;
  getCardPiles(roomId: string): Promise<CardPile[]>;
  getCardPile(id: string): Promise<CardPile | undefined>;

  // Enhanced Board Asset operations
  updateBoardAssetProperties(id: string, updates: Partial<BoardAsset>): Promise<BoardAsset | undefined>;
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

  async updateUser(userId: string, updates: { firstName?: string; lastName?: string }): Promise<User> {
    const [user] = await db
      .update(users)
      .set({
        ...updates,
        updatedAt: new Date(),
      })
      .where(eq(users.id, userId))
      .returning();
    return user;
  }

  // Game Rooms
  async getGameRoom(id: string): Promise<GameRoom | undefined> {
    const [room] = await db.select().from(gameRooms).where(eq(gameRooms.id, id));
    return room || undefined;
  }

  async getGameRoomByName(name: string): Promise<GameRoom | undefined> {
    const [room] = await db.select().from(gameRooms).where(eq(gameRooms.name, name));
    return room || undefined;
  }

  async getGameRoomByIdOrName(identifier: string): Promise<GameRoom | undefined> {
    // First try by ID (UUID format)
    if (identifier.match(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i)) {
      return this.getGameRoom(identifier);
    }
    // Then try by name
    return this.getGameRoomByName(identifier);
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

  async getRoomPlayersWithNames(roomId: string): Promise<Array<RoomPlayer & { playerName: string; playerEmail: string }>> {
    const result = await db
      .select({
        id: roomPlayers.id,
        roomId: roomPlayers.roomId,
        playerId: roomPlayers.playerId,
        role: roomPlayers.role,
        isOnline: roomPlayers.isOnline,
        joinedAt: roomPlayers.joinedAt,
        playerFirstName: users.firstName,
        playerLastName: users.lastName,
        playerEmail: users.email,
      })
      .from(roomPlayers)
      .innerJoin(users, eq(roomPlayers.playerId, users.id))
      .where(eq(roomPlayers.roomId, roomId));
    
    return result.map(player => ({
      id: player.id,
      roomId: player.roomId,
      playerId: player.playerId,
      role: player.role,
      isOnline: player.isOnline,
      joinedAt: player.joinedAt,
      playerName: player.playerFirstName && player.playerLastName 
        ? `${player.playerFirstName} ${player.playerLastName}`
        : player.playerFirstName 
        ? player.playerFirstName
        : player.playerEmail || "Player",
      playerEmail: player.playerEmail || ""
    }));
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

  // Chat Messages
  async createChatMessage(messageData: InsertChatMessage, playerId: string): Promise<ChatMessage> {
    const [message] = await db.insert(chatMessages).values({
      ...messageData,
      playerId,
    }).returning();
    return message;
  }

  async getRoomChatMessages(roomId: string, limit: number = 100): Promise<Array<ChatMessage & { playerName: string }>> {
    const result = await db
      .select({
        id: chatMessages.id,
        roomId: chatMessages.roomId,
        playerId: chatMessages.playerId,
        message: chatMessages.message,
        messageType: chatMessages.messageType,
        targetPlayerId: chatMessages.targetPlayerId,
        sentAt: chatMessages.sentAt,
        playerFirstName: users.firstName,
        playerLastName: users.lastName,
        playerEmail: users.email,
      })
      .from(chatMessages)
      .innerJoin(users, eq(chatMessages.playerId, users.id))
      .where(eq(chatMessages.roomId, roomId))
      .orderBy(desc(chatMessages.sentAt))
      .limit(limit);
    
    return result.map(msg => ({
      ...msg,
      playerName: msg.playerFirstName && msg.playerLastName 
        ? `${msg.playerFirstName} ${msg.playerLastName}`
        : msg.playerFirstName 
        ? msg.playerFirstName
        : msg.playerEmail || "Player"
    }));
  }

  // Card Deck operations
  async createCardDeck(deck: InsertCardDeck, createdBy: string): Promise<CardDeck> {
    const [newDeck] = await db
      .insert(cardDecks)
      .values({ ...deck, createdBy })
      .returning();
    return newDeck;
  }

  async getCardDecks(roomId: string): Promise<CardDeck[]> {
    return await db
      .select()
      .from(cardDecks)
      .where(eq(cardDecks.roomId, roomId))
      .orderBy(cardDecks.createdAt);
  }

  async getCardDeck(id: string): Promise<CardDeck | undefined> {
    const [deck] = await db
      .select()
      .from(cardDecks)
      .where(eq(cardDecks.id, id));
    return deck;
  }

  async shuffleCardDeck(id: string): Promise<CardDeck | undefined> {
    const deck = await this.getCardDeck(id);
    if (!deck) return undefined;
    
    const shuffledOrder = [...(deck.deckOrder as string[] || [])];
    for (let i = shuffledOrder.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [shuffledOrder[i], shuffledOrder[j]] = [shuffledOrder[j], shuffledOrder[i]];
    }
    
    const [updated] = await db
      .update(cardDecks)
      .set({ deckOrder: shuffledOrder, isShuffled: true })
      .where(eq(cardDecks.id, id))
      .returning();
    return updated;
  }

  // Card Pile operations
  async createCardPile(pile: InsertCardPile): Promise<CardPile> {
    const [newPile] = await db
      .insert(cardPiles)
      .values(pile)
      .returning();
    return newPile;
  }

  async getCardPiles(roomId: string): Promise<CardPile[]> {
    return await db
      .select()
      .from(cardPiles)
      .where(eq(cardPiles.roomId, roomId))
      .orderBy(cardPiles.createdAt);
  }

  async getCardPile(id: string): Promise<CardPile | undefined> {
    const [pile] = await db
      .select()
      .from(cardPiles)
      .where(eq(cardPiles.id, id));
    return pile;
  }

  // Enhanced Board Asset operations
  async updateBoardAssetProperties(id: string, updates: Partial<BoardAsset>): Promise<BoardAsset | undefined> {
    const [updated] = await db
      .update(boardAssets)
      .set(updates)
      .where(eq(boardAssets.id, id))
      .returning();
    return updated;
  }
}

export const storage = new DatabaseStorage();