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
  type GameTemplate,
  type InsertGameTemplate,
  type GameSystem,
  type InsertGameSystem,
  users,
  gameRooms,
  gameAssets,
  boardAssets,
  roomPlayers,
  diceRolls,
  chatMessages,
  cardDecks,
  cardPiles,
  gameTemplates,
  templateUsage,
  gameSystems,
} from '@shared/schema';
import { db } from './db';
import { eq, desc, and, or, sql } from 'drizzle-orm';

export interface IStorage {
  // Users
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  getUserByEmail(email: string): Promise<User | undefined>;
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
  findAssetByFilePath(filePath: string): Promise<GameAsset | undefined>;

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
  getRoomPlayersWithNames(roomId: string): Promise<(RoomPlayer & { playerName: string; playerEmail: string })[]>;
  getPlayerRole(roomId: string, playerId: string): Promise<'admin' | 'player' | null>;
  updatePlayerStatus(roomId: string, playerId: string, isOnline: boolean): Promise<void>;
  updateRoomPlayerScore(roomId: string, playerId: string, score: number): Promise<void>;

  // Room membership operations for auth
  getRoomMembership(userId: string, roomId: string): Promise<RoomPlayer | undefined>;
  getRoom(id: string): Promise<GameRoom | undefined>;

  // Dice Rolls
  createDiceRoll(roll: InsertDiceRoll, playerId: string): Promise<DiceRoll>;
  getRoomDiceRolls(roomId: string, limit?: number): Promise<DiceRoll[]>;

  // Chat Messages
  createChatMessage(message: InsertChatMessage, playerId: string): Promise<ChatMessage>;
  getRoomChatMessages(roomId: string, limit?: number): Promise<(ChatMessage & { playerName: string })[]>;

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

  // Game Templates
  createGameTemplate(template: InsertGameTemplate, createdBy: string): Promise<GameTemplate>;
  getGameTemplates(userId?: string, isPublic?: boolean): Promise<GameTemplate[]>;
  getGameTemplate(id: string): Promise<GameTemplate | undefined>;
  updateGameTemplate(id: string, updates: Partial<GameTemplate>): Promise<GameTemplate>;
  deleteGameTemplate(id: string): Promise<void>;
  applyTemplateToRoom(templateId: string, roomId: string, userId: string): Promise<void>;

  // Game Systems
  createGameSystem(system: InsertGameSystem, createdBy: string): Promise<GameSystem>;
  getGameSystems(userId?: string, isPublic?: boolean): Promise<GameSystem[]>;
  getGameSystem(id: string): Promise<GameSystem | undefined>;
  updateGameSystem(id: string, updates: Partial<GameSystem>): Promise<GameSystem>;
  deleteGameSystem(id: string): Promise<void>;
  applySystemToRoom(systemId: string, roomId: string, userId: string): Promise<void>;

  // Admin functions
  getAllRooms(): Promise<GameRoom[]>;
  getAllTemplates(): Promise<GameTemplate[]>;
  getAllGameSystems(): Promise<GameSystem[]>;
  updateRoom(id: string, updates: Partial<GameRoom>): Promise<GameRoom>;
  updateRoomBoardSize(roomId: string, width: number, height: number): Promise<GameRoom>;
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

  async getUserByEmail(email: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.email, email));
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
        target: users.email, // Conflict on email since that's the unique constraint causing issues
        set: {
          id: userData.id, // Update the ID to the new Firebase UID
          firstName: userData.firstName,
          lastName: userData.lastName,
          profileImageUrl: userData.profileImageUrl,
          updatedAt: new Date(),
        },
      })
      .returning();
    return user;
  }

  async updateUser(userId: string, updates: { firstName?: string; lastName?: string; profileImageUrl?: string }): Promise<User> {
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

  async deleteGameRoom(id: string, userId?: string): Promise<void> {
    // Create or find orphaned assets room to preserve game system assets
    let orphanedRoom;
    try {
      orphanedRoom = await this.getGameRoomByName('_orphaned_assets');
      if (!orphanedRoom) {
        // Create the orphaned assets room if it doesn't exist
        orphanedRoom = await this.createGameRoom({
          name: '_orphaned_assets',
          isActive: false,
          gameState: { description: 'System room for preserving assets from deleted rooms' },
        }, userId || 'system');
      }
    } catch (error) {
      console.log('[Delete Room] Could not create orphaned assets room, falling back to deletion');
      orphanedRoom = null;
    }

    // Delete related data in correct order to avoid foreign key constraints
    await db.delete(diceRolls).where(eq(diceRolls.roomId, id));
    await db.delete(boardAssets).where(eq(boardAssets.roomId, id));

    // Delete card piles first (they may reference game assets as card backs)
    await db.delete(cardPiles).where(eq(cardPiles.roomId, id));

    // Delete card decks (they reference game assets as card backs)
    await db.delete(cardDecks).where(eq(cardDecks.roomId, id));

    // Only delete room-specific assets, preserve system assets
    await db.delete(gameAssets)
      .where(and(
        eq(gameAssets.roomId, id),
        eq(gameAssets.isSystemAsset, false),
      ));

    console.log(`[Delete Room] Deleted room-specific assets, preserved system assets`);

    // Move any remaining room assets to orphaned room as backup
    if (orphanedRoom) {
      await db.update(gameAssets)
        .set({ roomId: orphanedRoom.id })
        .where(and(
          eq(gameAssets.roomId, id),
          eq(gameAssets.isSystemAsset, true),
        ));
    }

    await db.delete(roomPlayers).where(eq(roomPlayers.roomId, id));
    await db.delete(gameRooms).where(eq(gameRooms.id, id));

    console.log(`[Delete Room] Successfully deleted room ${id}`);
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
    // Get the room to check if it has an applied game system
    const room = await this.getGameRoom(roomId);

    // Query for room-specific assets and system assets if room has a system applied
    if (room?.gameState && (room.gameState as any)?.appliedSystemId) {
      const systemId = (room.gameState as any).appliedSystemId;
      return db.select().from(gameAssets).where(
        or(
          eq(gameAssets.roomId, roomId),
          and(
            eq(gameAssets.systemId, systemId),
            eq(gameAssets.isSystemAsset, true),
          ),
        ),
      );
    }

    // Fallback to just room assets if no system applied
    return db.select().from(gameAssets).where(eq(gameAssets.roomId, roomId));
  }

  async deleteGameAsset(id: string): Promise<void> {
    await db.delete(boardAssets).where(eq(boardAssets.assetId, id));
    await db.delete(gameAssets).where(eq(gameAssets.id, id));
  }

  async findAssetByFilePath(filePath: string): Promise<GameAsset | undefined> {
    const [asset] = await db.select().from(gameAssets).where(eq(gameAssets.filePath, filePath));
    return asset || undefined;
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
        eq(roomPlayers.playerId, playerId),
      ),
    );
  }

  async getRoomPlayers(roomId: string): Promise<RoomPlayer[]> {
    return db.select().from(roomPlayers).where(eq(roomPlayers.roomId, roomId));
  }

  async getRoomPlayersWithNames(roomId: string): Promise<(RoomPlayer & { playerName: string; playerEmail: string })[]> {
    const result = await db
      .select({
        id: roomPlayers.id,
        roomId: roomPlayers.roomId,
        playerId: roomPlayers.playerId,
        role: roomPlayers.role,
        isOnline: roomPlayers.isOnline,
        score: roomPlayers.score,
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
      score: player.score,
      joinedAt: player.joinedAt,
      playerName: player.playerFirstName && player.playerLastName
        ? `${player.playerFirstName} ${player.playerLastName}`
        : player.playerFirstName
        ? player.playerFirstName
        : player.playerEmail || 'Player',
      playerEmail: player.playerEmail || '',
    }));
  }

  async getPlayerRole(roomId: string, playerId: string): Promise<'admin' | 'player' | null> {
    // First check if user is room creator (auto admin)
    const [room] = await db
      .select({ createdBy: gameRooms.createdBy })
      .from(gameRooms)
      .where(eq(gameRooms.id, roomId));

    if (room?.createdBy === playerId) {
      return 'admin';
    }

    // Then check room players table
    const [player] = await db
      .select({ role: roomPlayers.role })
      .from(roomPlayers)
      .where(
        and(
          eq(roomPlayers.roomId, roomId),
          eq(roomPlayers.playerId, playerId),
        ),
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
          eq(roomPlayers.playerId, playerId),
        ),
      );
  }

  async updateRoomPlayerScore(roomId: string, playerId: string, score: number): Promise<void> {
    await db
      .update(roomPlayers)
      .set({ score })
      .where(
        and(
          eq(roomPlayers.roomId, roomId),
          eq(roomPlayers.playerId, playerId),
        ),
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

  async getRoomDiceRolls(roomId: string, limit = 50): Promise<DiceRoll[]> {
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

  async getRoomChatMessages(roomId: string, limit = 100): Promise<(ChatMessage & { playerName: string })[]> {
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
        : msg.playerEmail || 'Player',
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

  async updateCardDeck(id: string, updates: Partial<CardDeck>): Promise<CardDeck> {
    const [updatedDeck] = await db
      .update(cardDecks)
      .set(updates)
      .where(eq(cardDecks.id, id))
      .returning();
    return updatedDeck;
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

  async updateCardPile(id: string, updates: Partial<CardPile>): Promise<CardPile> {
    const [updatedPile] = await db
      .update(cardPiles)
      .set(updates)
      .where(eq(cardPiles.id, id))
      .returning();
    return updatedPile;
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

  // Game Templates
  async createGameTemplate(template: InsertGameTemplate, createdBy: string): Promise<GameTemplate> {
    const [newTemplate] = await db
      .insert(gameTemplates)
      .values({ ...template, createdBy })
      .returning();
    return newTemplate;
  }

  async getGameTemplates(userId?: string, isPublic?: boolean): Promise<GameTemplate[]> {
    if (userId && isPublic !== undefined) {
      // Get user's own templates OR public templates
      if (isPublic) {
        return db.select().from(gameTemplates)
          .where(eq(gameTemplates.isPublic, true))
          .orderBy(desc(gameTemplates.createdAt));
      } else {
        return db.select().from(gameTemplates)
          .where(eq(gameTemplates.createdBy, userId))
          .orderBy(desc(gameTemplates.createdAt));
      }
    } else if (userId) {
      // Get all templates accessible to the user (their own + public)
      return db.select().from(gameTemplates)
        .where(
          or(
            eq(gameTemplates.createdBy, userId),
            eq(gameTemplates.isPublic, true),
          ),
        )
        .orderBy(desc(gameTemplates.createdAt));
    } else if (isPublic !== undefined) {
      return db.select().from(gameTemplates)
        .where(eq(gameTemplates.isPublic, isPublic))
        .orderBy(desc(gameTemplates.createdAt));
    }

    return db.select().from(gameTemplates)
      .orderBy(desc(gameTemplates.createdAt));
  }

  async getGameTemplate(id: string): Promise<GameTemplate | undefined> {
    const [template] = await db
      .select()
      .from(gameTemplates)
      .where(eq(gameTemplates.id, id));
    return template;
  }

  async updateGameTemplate(id: string, updates: Partial<GameTemplate>): Promise<GameTemplate> {
    const [updated] = await db
      .update(gameTemplates)
      .set({ ...updates, updatedAt: new Date() })
      .where(eq(gameTemplates.id, id))
      .returning();
    return updated;
  }

  async deleteGameTemplate(id: string): Promise<void> {
    await db.delete(templateUsage).where(eq(templateUsage.templateId, id));
    await db.delete(gameTemplates).where(eq(gameTemplates.id, id));
  }

  async applyTemplateToRoom(templateId: string, roomId: string, userId: string): Promise<void> {
    const template = await this.getGameTemplate(templateId);
    if (!template) throw new Error('Template not found');

    // Track template usage
    await db.insert(templateUsage).values({
      templateId,
      roomId,
      usedBy: userId,
    });

    // Apply template data to the room
    if (template.decksData) {
      const decks = template.decksData as any[];
      for (const deckData of decks) {
        await this.createCardDeck({
          roomId,
          name: deckData.name,
          description: deckData.description,
          deckOrder: deckData.deckOrder,
        }, userId);
      }
    }

    if (template.assetsData) {
      const assets = template.assetsData as any[];
      for (const assetData of assets) {
        await this.createGameAsset({
          roomId,
          name: assetData.name,
          type: assetData.type,
          filePath: assetData.filePath,
          width: assetData.width,
          height: assetData.height,
        }, userId);
      }
    }

    if (template.tokensData) {
      const tokens = template.tokensData as any[];
      for (const tokenData of tokens) {
        await this.createBoardAsset({
          roomId,
          assetId: tokenData.assetId,
          positionX: tokenData.positionX,
          positionY: tokenData.positionY,
          rotation: tokenData.rotation || 0,
          scale: tokenData.scale || 100,
          assetType: 'token',
          visibility: 'public',
        });
      }
    }
  }

  // Game Systems
  async createGameSystem(system: InsertGameSystem, createdBy: string): Promise<GameSystem> {
    const [newSystem] = await db
      .insert(gameSystems)
      .values({ ...system, createdBy })
      .returning();
    return newSystem;
  }

  async getGameSystems(userId?: string, isPublic?: boolean): Promise<GameSystem[]> {
    if (userId && isPublic !== undefined) {
      // Get user's own systems OR public systems
      if (isPublic) {
        return db.select().from(gameSystems)
          .where(eq(gameSystems.isPublic, true))
          .orderBy(desc(gameSystems.createdAt));
      } else {
        return db.select().from(gameSystems)
          .where(eq(gameSystems.createdBy, userId))
          .orderBy(desc(gameSystems.createdAt));
      }
    } else if (userId) {
      // Get all systems accessible to the user (their own + public)
      return db.select().from(gameSystems)
        .where(
          or(
            eq(gameSystems.createdBy, userId),
            eq(gameSystems.isPublic, true),
          ),
        )
        .orderBy(desc(gameSystems.createdAt));
    } else if (isPublic !== undefined) {
      return db.select().from(gameSystems)
        .where(eq(gameSystems.isPublic, isPublic))
        .orderBy(desc(gameSystems.createdAt));
    }

    return db.select().from(gameSystems)
      .orderBy(desc(gameSystems.createdAt));
  }

  async getGameSystem(id: string): Promise<GameSystem | undefined> {
    const [system] = await db
      .select()
      .from(gameSystems)
      .where(eq(gameSystems.id, id));
    return system;
  }

  async updateGameSystem(id: string, updates: Partial<GameSystem>): Promise<GameSystem> {
    const [updated] = await db
      .update(gameSystems)
      .set({ ...updates, updatedAt: new Date() })
      .where(eq(gameSystems.id, id))
      .returning();
    return updated;
  }

  async deleteGameSystem(id: string): Promise<void> {
    await db.delete(gameSystems).where(eq(gameSystems.id, id));
  }

  async applySystemToRoom(systemId: string, roomId: string, userId: string): Promise<void> {
    const system = await this.getGameSystem(systemId);
    if (!system) {
      throw new Error('System not found');
    }

    const room = await this.getGameRoom(roomId);
    if (!room) {
      throw new Error('Room not found');
    }

    // Apply system configuration to the room and track which system was applied
    const gameState = system.systemConfig || {};
    (gameState as any).appliedSystemId = systemId; // Track which system was applied

    await this.updateGameRoom(roomId, {
      gameState,
    });

    // Find existing system assets instead of creating new ones
    const systemAssets = await db.select().from(gameAssets)
      .where(and(
        eq(gameAssets.systemId, systemId),
        eq(gameAssets.isSystemAsset, true),
      ));

    // Create asset mapping from existing system assets
    const createdAssets = new Map<string, string>(); // url -> assetId

    // Check if we have ALL expected system assets, not just some
    const expectedAssetCount = system.assetLibrary && (system.assetLibrary as any).assets ? (system.assetLibrary as any).assets.length : 0;
    const hasAllSystemAssets = systemAssets.length > 0 && systemAssets.length === expectedAssetCount;

    if (hasAllSystemAssets) {
      console.log(`[Apply System] Found all ${systemAssets.length}/${expectedAssetCount} existing system assets, using them directly`);
      for (const asset of systemAssets) {
        createdAssets.set(asset.filePath, asset.id);
      }
    } else {
      // Create missing system assets
      if (systemAssets.length > 0) {
        console.log(`[Apply System] Found ${systemAssets.length}/${expectedAssetCount} existing system assets, need to create ${expectedAssetCount - systemAssets.length} more`);
        // Add existing assets to mapping first
        for (const asset of systemAssets) {
          createdAssets.set(asset.filePath, asset.id);
        }
      } else {
        console.log(`[Apply System] No system assets found, creating all ${expectedAssetCount} assets in batches`);
      }
      console.log(`[Apply System] System has assetLibrary: ${!!system.assetLibrary}`);
      if (system.assetLibrary) {
        const assetLibrary = system.assetLibrary as any;
        console.log(`[Apply System] AssetLibrary type: ${typeof assetLibrary}, has assets: ${!!assetLibrary.assets}`);
        if (assetLibrary.assets && Array.isArray(assetLibrary.assets)) {
          // Process assets in smaller batches to avoid database timeout
          const BATCH_SIZE = 15; // Smaller batches for more reliability
          const totalAssets = assetLibrary.assets.length;
          console.log(`[Apply System] Processing ${totalAssets} assets in batches of ${BATCH_SIZE}`);

          for (let i = 0; i < assetLibrary.assets.length; i += BATCH_SIZE) {
            const batch = assetLibrary.assets.slice(i, i + BATCH_SIZE);
            console.log(`[Apply System] Processing batch ${Math.floor(i/BATCH_SIZE) + 1}/${Math.ceil(totalAssets/BATCH_SIZE)} (${batch.length} assets)`);

            // Create assets in parallel for this batch (skip existing ones)
            const batchPromises = batch.map(async (assetData: any) => {
              const assetUrl = assetData.url || assetData.filePath;

              // Skip if asset already exists
              if (createdAssets.has(assetUrl)) {
                console.log(`[Apply System] ⏭️ Skipping existing asset: ${assetData.name}`);
                return {
                  url: assetUrl,
                  assetId: createdAssets.get(assetUrl),
                  success: true,
                  skipped: true,
                };
              }

              try {
                console.log(`[Apply System] Creating asset: ${assetData.name} (type: ${assetData.type || 'unknown'})`);
                const newAsset = await this.createGameAsset({
                  systemId,
                  name: assetData.name,
                  type: assetData.type || assetData.category || 'image/jpeg',
                  filePath: assetUrl,
                  width: assetData.width || null,
                  height: assetData.height || null,
                  isSystemAsset: true,
                } as any, userId);

                console.log(`[Apply System] ✅ Created asset: ${assetData.name} -> ${newAsset.id}`);
                return {
                  url: assetUrl,
                  assetId: newAsset.id,
                  success: true,
                  skipped: false,
                };
              } catch (error) {
                console.error(`[Apply System] ❌ Failed to create asset ${assetData.name}:`, error);
                return {
                  url: assetUrl,
                  assetId: null,
                  success: false,
                  skipped: false,
                  error,
                };
              }
            });

            const batchResults = await Promise.all(batchPromises);

            // Process batch results
            let created = 0, skipped = 0, failed = 0;
            for (const result of batchResults) {
              if (result.success && result.assetId) {
                if (!result.skipped) {
                  createdAssets.set(result.url, result.assetId);
                  created++;
                } else {
                  skipped++;
                }
              } else {
                failed++;
              }
            }
            console.log(`[Apply System] Batch complete: ${created} created, ${skipped} skipped, ${failed} failed`);

            // Small delay between batches to prevent overwhelming the database
            if (i + BATCH_SIZE < assetLibrary.assets.length) {
              await new Promise(resolve => setTimeout(resolve, 100));
            }
          }

          console.log(`[Apply System] Asset creation complete: ${createdAssets.size} out of ${totalAssets} system assets ready`);
        }
      }
    }

    // Apply deck templates if present
    if (system.deckTemplates) {
      console.log('Deck templates would be applied:', system.deckTemplates);
      const deckTemplates = system.deckTemplates as any;
      if (deckTemplates.decks && Array.isArray(deckTemplates.decks)) {
        for (const deckData of deckTemplates.decks) {
          // Find the card back asset ID if it exists
          const cardBackAssetId = deckData.cardBack ? createdAssets.get(deckData.cardBack) || null : null;

          // Build deck order from card assets
          let deckOrder: string[] = [];
          if (deckData.cardAssets && Array.isArray(deckData.cardAssets)) {
            deckOrder = deckData.cardAssets.map((assetUrl: string) => {
              return createdAssets.get(assetUrl);
            }).filter(Boolean);
          }

          // Create the deck
          const newDeck = await this.createCardDeck({
            roomId,
            name: deckData.name,
            description: deckData.description || '',
            deckOrder,
            cardBackAssetId,
          }, userId);

          // Create card piles for the deck if it has cards
          if (deckData.cardAssets && Array.isArray(deckData.cardAssets)) {
            // Create main deck pile
            // Use the same cardOrder we built for the deck
            const cardOrder = deckOrder;

            await this.createCardPile({
              roomId,
              name: `${deckData.name} - Main`,
              positionX: Math.floor(Math.random() * 200 + 100),
              positionY: Math.floor(Math.random() * 200 + 100),
              pileType: 'deck',
              cardOrder,
              visibility: 'public',
            });

            // Create discard pile for the deck
            await this.createCardPile({
              roomId,
              name: `${deckData.name} - Discard`,
              positionX: Math.floor(Math.random() * 200 + 300),
              positionY: Math.floor(Math.random() * 200 + 100),
              pileType: 'discard',
              cardOrder: [],
              visibility: 'public',
            });
          }
        }
      }
    }

    // Apply token types if present
    if (system.tokenTypes) {
      // Logic to create default tokens would go here
      console.log('Token types would be applied:', system.tokenTypes);
    }

    // Apply board defaults if present
    if (system.boardDefaults) {
      // Logic to configure board defaults would go here
      console.log('Board defaults would be applied:', system.boardDefaults);
    }

    // Increment download count
    await this.updateGameSystem(systemId, {
      downloadCount: (system.downloadCount || 0) + 1,
    });
  }

  // Admin functions
  async getAllRooms(): Promise<any[]> {
    const roomsWithCreators = await db
      .select({
        id: gameRooms.id,
        name: gameRooms.name,
        createdBy: gameRooms.createdBy,
        isActive: gameRooms.isActive,
        gameState: gameRooms.gameState,
        createdAt: gameRooms.createdAt,
        creatorName: sql<string>`COALESCE(${users.firstName} || ' ' || ${users.lastName}, ${users.email}, ${gameRooms.createdBy})`,
        creatorEmail: users.email,
      })
      .from(gameRooms)
      .leftJoin(users, eq(gameRooms.createdBy, users.id))
      .orderBy(desc(gameRooms.createdAt));

    return roomsWithCreators;
  }

  async getAllTemplates(): Promise<GameTemplate[]> {
    return await db.select().from(gameTemplates).orderBy(desc(gameTemplates.createdAt));
  }

  async getAllGameSystems(): Promise<GameSystem[]> {
    return await db.select().from(gameSystems).orderBy(desc(gameSystems.createdAt));
  }

  async updateRoom(id: string, updates: Partial<GameRoom>): Promise<GameRoom> {
    const [room] = await db
      .update(gameRooms)
      .set(updates)
      .where(eq(gameRooms.id, id))
      .returning();
    return room;
  }

  async updateRoomBoardSize(roomId: string, width: number, height: number): Promise<GameRoom> {
    console.log(`[Storage] Updating room ${roomId} board size to ${width}x${height}`);
    const [room] = await db
      .update(gameRooms)
      .set({ boardWidth: width, boardHeight: height })
      .where(eq(gameRooms.id, roomId))
      .returning();
    console.log(`[Storage] Board size updated. New room data:`, {
      id: room.id,
      boardWidth: room.boardWidth,
      boardHeight: room.boardHeight,
    });
    return room;
  }

  // Room membership operations for auth
  async getRoomMembership(userId: string, roomId: string): Promise<RoomPlayer | undefined> {
    const [membership] = await db
      .select()
      .from(roomPlayers)
      .where(and(
        eq(roomPlayers.playerId, userId),
        eq(roomPlayers.roomId, roomId),
      ));
    return membership;
  }

  async getRoom(id: string): Promise<GameRoom | undefined> {
    // Alias for getGameRoom to satisfy the auth interface
    return this.getGameRoom(id);
  }
}

export const storage = new DatabaseStorage();
