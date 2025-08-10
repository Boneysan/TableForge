import type { Express } from "express";
import { createServer, type Server } from "http";
import { WebSocketServer, WebSocket } from "ws";
import { storage } from "./storage";
import { setupAuth } from "./replitAuth";
import { hybridAuthMiddleware } from "./hybridAuth";
import { ObjectStorageService } from "./objectStorage";
import * as admin from "firebase-admin";
import type { 
  WebSocketMessage, 
  AssetMovedMessage, 
  AssetFlippedMessage, 
  DiceRolledMessage,
  PlayerJoinedMessage,
  PlayerLeftMessage,
  PlayerScoreUpdatedMessage
} from "@shared/schema";
import { 
  insertGameRoomSchema, 
  insertGameAssetSchema, 
  insertBoardAssetSchema,
  insertDiceRollSchema,
  insertChatMessageSchema,
  insertGameTemplateSchema,
  insertGameSystemSchema
} from "@shared/schema";

// Store WebSocket connections by room
const roomConnections = new Map<string, Set<WebSocket>>();
const connectionRooms = new Map<WebSocket, string>();

export async function registerRoutes(app: Express): Promise<Server> {
  // Auth middleware
  await setupAuth(app);
  
  const httpServer = createServer(app);

  // WebSocket server for real-time multiplayer
  const wss = new WebSocketServer({ server: httpServer, path: '/ws' });

  wss.on('connection', (ws, req) => {
    console.log('WebSocket connection established');

    ws.on('message', async (data) => {
      try {
        const message: WebSocketMessage = JSON.parse(data.toString());
        await handleWebSocketMessage(ws, message);
      } catch (error) {
        console.error('WebSocket message error:', error);
        ws.send(JSON.stringify({ type: 'error', payload: { message: 'Invalid message format' } }));
      }
    });

    ws.on('close', () => {
      const roomId = connectionRooms.get(ws);
      if (roomId) {
        const connections = roomConnections.get(roomId);
        if (connections) {
          connections.delete(ws);
          if (connections.size === 0) {
            roomConnections.delete(roomId);
          }
        }
        connectionRooms.delete(ws);
      }
    });
  });

  async function handleWebSocketMessage(ws: WebSocket, message: WebSocketMessage) {
    const { type, payload, roomId } = message;

    switch (type) {
      case 'join_room':
        if (roomId) {
          // Add connection to room
          if (!roomConnections.has(roomId)) {
            roomConnections.set(roomId, new Set());
          }
          roomConnections.get(roomId)!.add(ws);
          connectionRooms.set(ws, roomId);

          // Broadcast player joined
          broadcastToRoom(roomId, {
            type: 'player_joined',
            payload: { player: payload.player }
          } as PlayerJoinedMessage, ws);
        }
        break;

      case 'asset_moved':
        if (roomId) {
          // Update board asset position in storage
          await storage.updateBoardAsset(payload.assetId, {
            positionX: payload.positionX,
            positionY: payload.positionY,
            rotation: payload.rotation,
            scale: payload.scale,
          });

          // Broadcast to other clients
          broadcastToRoom(roomId, message as AssetMovedMessage, ws);
        }
        break;

      case 'asset_flipped':
        if (roomId) {
          // Update board asset flip state
          await storage.updateBoardAsset(payload.assetId, {
            isFlipped: payload.isFlipped
          });

          // Broadcast to other clients
          broadcastToRoom(roomId, message as AssetFlippedMessage, ws);
        }
        break;

      case 'dice_rolled':
        if (roomId && payload.playerId) {
          // Save dice roll to storage
          const diceRoll = await storage.createDiceRoll({
            roomId,
            diceType: payload.diceType,
            diceCount: payload.diceCount,
            results: payload.results,
            total: payload.total,
          }, payload.playerId);

          // Broadcast to all clients in room
          broadcastToRoom(roomId, {
            type: 'dice_rolled',
            payload: diceRoll
          } as DiceRolledMessage);
        }
        break;

      case 'chat_message':
        if (roomId && payload.playerId) {
          // Save chat message to storage
          const chatMessage = await storage.createChatMessage({
            roomId,
            message: payload.message,
            messageType: payload.messageType || 'chat',
            targetPlayerId: payload.targetPlayerId,
          }, payload.playerId);

          // Get player name for broadcasting
          const player = await storage.getUser(payload.playerId);
          const playerName = player?.firstName && player?.lastName 
            ? `${player.firstName} ${player.lastName}`
            : player?.firstName 
            ? player.firstName
            : player?.email || "Player";

          // Broadcast to all clients in room
          broadcastToRoom(roomId, {
            type: 'chat_message',
            payload: { ...chatMessage, playerName }
          });
        }
        break;

      case 'player_score_updated':
        if (roomId && payload.playerId && typeof payload.score === 'number') {
          // Update player score in storage
          await storage.updateRoomPlayerScore(roomId, payload.playerId, payload.score);

          // Get player name for broadcasting
          const player = await storage.getUser(payload.playerId);
          const playerName = player?.firstName && player?.lastName 
            ? `${player.firstName} ${player.lastName}`
            : player?.firstName 
            ? player.firstName
            : player?.email || "Player";

          // Broadcast to all clients in room
          broadcastToRoom(roomId, {
            type: 'player_score_updated',
            payload: { 
              playerId: payload.playerId, 
              score: payload.score, 
              playerName 
            }
          } as PlayerScoreUpdatedMessage);
        }
        break;
    }
  }

  function broadcastToRoom(roomId: string, message: WebSocketMessage, excludeWs?: WebSocket) {
    const connections = roomConnections.get(roomId);
    if (connections) {
      const messageStr = JSON.stringify(message);
      connections.forEach(ws => {
        if (ws !== excludeWs && ws.readyState === WebSocket.OPEN) {
          ws.send(messageStr);
        }
      });
    }
  }

  // Debug endpoint to check Firebase Admin status
  app.get('/api/test-firebase-admin', async (req, res) => {
    try {
      // Import Firebase Admin with the correct syntax to get current status
      const adminModule = await import('../server/firebaseAuth.js');
      
      res.json({ 
        firebaseAdminInitialized: admin.apps && admin.apps.length > 0,
        appCount: admin.apps ? admin.apps.length : 0,
        hasServiceAccount: !!process.env.FIREBASE_SERVICE_ACCOUNT_KEY,
        nodeEnv: process.env.NODE_ENV,
        defaultApp: (admin.apps && admin.apps.length > 0) ? 'exists' : 'none',
        credentialAvailable: !!(admin.credential),
        appsProperty: !!(admin.apps),
        adminType: typeof admin
      });
    } catch (error) {
      res.json({ 
        error: error instanceof Error ? error.message : 'Unknown error',
        firebaseAdminInitialized: false,
        hasServiceAccount: !!process.env.FIREBASE_SERVICE_ACCOUNT_KEY,
        importError: true
      });
    }
  });

  // Object Storage Routes
  app.get("/public-objects/:filePath(*)", async (req, res) => {
    const filePath = req.params.filePath;
    const objectStorageService = new ObjectStorageService();
    try {
      const file = await objectStorageService.searchPublicObject(filePath);
      if (!file) {
        return res.status(404).json({ error: "File not found" });
      }
      objectStorageService.downloadObject(file, res);
    } catch (error) {
      console.error("Error searching for public object:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.post("/api/objects/upload", async (req, res) => {
    const objectStorageService = new ObjectStorageService();
    const uploadURL = await objectStorageService.getObjectEntityUploadURL();
    res.json({ uploadURL });
  });

  // Auth routes
  app.get('/api/auth/user', hybridAuthMiddleware, async (req: any, res) => {
    try {
      console.log("📊 [Auth User] ===== AUTH USER ENDPOINT CALLED =====");
      console.log("📊 [Auth User] Request timestamp:", new Date().toISOString());
      console.log("📊 [Auth User] Request method:", req.method);
      console.log("📊 [Auth User] Request URL:", req.url);
      console.log("📊 [Auth User] Request headers:", req.headers);
      
      const userId = req.user.uid;
      console.log("📊 [Auth User] Fetching user data for UID:", userId);
      console.log("📊 [Auth User] Full authenticated user object:", JSON.stringify(req.user, null, 2));
      
      let user = await storage.getUser(userId);
      console.log("📊 [Auth User] User from storage:", JSON.stringify(user, null, 2));
      
      // Try to find user by email if not found by UID (for existing users from different auth methods)
      if (!user) {
        console.log("📊 [Auth User] User not found by UID, trying email lookup for account merging...");
        try {
          const userByEmail = await storage.getUserByEmail(req.user.email);
          if (userByEmail) {
            console.log("📊 [Auth User] Found existing user by email (likely from Replit auth):", JSON.stringify(userByEmail, null, 2));
            console.log("📊 [Auth User] Merging accounts - this user will now be accessible via both Replit and Firebase auth");
            
            // Don't change the user ID to avoid foreign key constraint violations
            // Instead, just update the existing account with new Firebase profile info
            console.log("📊 [Auth User] Updating existing Replit account with Firebase profile info");
            
            const updatedUserData = {
              firstName: userByEmail.firstName || req.user.displayName?.split(' ')[0] || req.user.displayName || null,
              lastName: userByEmail.lastName || req.user.displayName?.split(' ')[1] || null,
              profileImageUrl: req.user.photoURL || userByEmail.profileImageUrl || null
            };
            
            console.log("📊 [Auth User] Updating user with data:", JSON.stringify(updatedUserData, null, 2));
            user = await storage.updateUser(userByEmail.id, updatedUserData);
            console.log("📊 [Auth User] Successfully updated account:", JSON.stringify(user, null, 2));
          }
        } catch (emailError) {
          console.log("📊 [Auth User] No existing user found by email, will create new account");
        }
      }
      
      // If still no user found, use upsert to handle conflicts gracefully
      if (!user) {
        console.log("📊 [Auth User] No existing user found, using upsert...");
        
        // Use upsert to handle potential conflicts
        const upsertUserData = {
          id: req.user.uid,
          email: req.user.email,
          firstName: req.user.displayName?.split(' ')[0] || req.user.displayName || null,
          lastName: req.user.displayName?.split(' ')[1] || null,
          profileImageUrl: req.user.photoURL || null
        };
        
        console.log("📊 [Auth User] Upserting user with data:", JSON.stringify(upsertUserData, null, 2));
        user = await storage.upsertUser(upsertUserData);
        console.log("📊 [Auth User] Upserted user:", JSON.stringify(user, null, 2));
      } else {
        console.log("📊 [Auth User] Existing user found in storage");
      }
      
      console.log("📊 [Auth User] ===== SENDING RESPONSE =====");
      console.log("📊 [Auth User] Response timestamp:", new Date().toISOString());
      console.log("📊 [Auth User] Returning user data:", JSON.stringify(user, null, 2));
      console.log("📊 [Auth User] Response status: 200");
      
      res.status(200).json(user);
      
      console.log("📊 [Auth User] Response sent successfully");
    } catch (error) {
      console.error("❌ [Auth User] ===== ERROR IN AUTH USER ENDPOINT =====");
      console.error("❌ [Auth User] Error timestamp:", new Date().toISOString());
      console.error("❌ [Auth User] Error fetching/creating user:", error);
      console.error("❌ [Auth User] Error type:", typeof error);
      console.error("❌ [Auth User] Error constructor:", error?.constructor?.name);
      console.error("❌ [Auth User] Error message:", error instanceof Error ? error.message : String(error));
      console.error("❌ [Auth User] Error stack:", error instanceof Error ? error.stack : "No stack trace");
      
      res.status(500).json({ message: "Failed to fetch user" });
    }
  });

  app.put('/api/auth/user', hybridAuthMiddleware, async (req: any, res) => {
    try {
      const userId = req.user.uid;
      const updates = req.body;
      
      // Validate the updates
      if (!updates.firstName && !updates.lastName) {
        return res.status(400).json({ message: "firstName or lastName is required" });
      }
      
      const user = await storage.updateUser(userId, updates);
      res.json(user);
    } catch (error) {
      console.error("Error updating user:", error);
      res.status(500).json({ message: "Failed to update user" });
    }
  });

  // Game Room Routes
  app.post("/api/rooms", hybridAuthMiddleware, async (req: any, res) => {
    try {
      const roomData = insertGameRoomSchema.parse(req.body);
      const userId = req.user.uid;
      const room = await storage.createGameRoom(roomData, userId);
      res.json(room);
    } catch (error) {
      console.error("Error creating room:", error);
      if (error instanceof Error && error.message.includes("unique constraint")) {
        res.status(409).json({ error: "A room with this name already exists" });
      } else {
        res.status(400).json({ error: "Invalid room data" });
      }
    }
  });

  app.get("/api/rooms/:id", async (req, res) => {
    try {
      const room = await storage.getGameRoomByIdOrName(req.params.id);
      if (!room) {
        return res.status(404).json({ error: "Room not found" });
      }
      res.json(room);
    } catch (error) {
      console.error("Error getting room:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.get("/api/user/:userId/rooms", hybridAuthMiddleware, async (req: any, res) => {
    try {
      const userId = req.user.uid;
      // Ensure users can only access their own rooms
      if (req.params.userId !== userId) {
        return res.status(403).json({ error: "Access denied" });
      }
      const rooms = await storage.getUserRooms(userId);
      res.json(rooms);
    } catch (error) {
      console.error("Error getting user rooms:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.delete("/api/rooms/:id", async (req, res) => {
    try {
      await storage.deleteGameRoom(req.params.id);
      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting room:", error);
      if (error instanceof Error && error.message === "Room not found") {
        res.status(404).json({ error: "Room not found" });
      } else {
        res.status(500).json({ error: "Internal server error" });
      }
    }
  });

  // Game Assets Routes
  app.post("/api/assets", hybridAuthMiddleware, async (req: any, res) => {
    try {
      const assetData = insertGameAssetSchema.parse(req.body);
      const userId = req.user.uid;
      
      // Check if user has admin role in room (only admins can upload)
      const userRole = await storage.getPlayerRole(assetData.roomId, userId);
      if (userRole !== 'admin') {
        return res.status(403).json({ error: "Only game masters can upload assets" });
      }
      
      // Normalize the object path
      const objectStorageService = new ObjectStorageService();
      const normalizedPath = objectStorageService.normalizeObjectEntityPath(assetData.filePath);
      
      const asset = await storage.createGameAsset({
        ...assetData,
        filePath: normalizedPath
      }, userId);
      
      res.json(asset);
    } catch (error) {
      console.error("Error creating asset:", error);
      res.status(400).json({ error: "Invalid asset data" });
    }
  });

  app.get("/api/rooms/:roomId/assets", async (req, res) => {
    try {
      // First, check if room exists and get the actual room ID
      const room = await storage.getGameRoomByIdOrName(req.params.roomId);
      if (!room) {
        return res.status(404).json({ error: "Room not found" });
      }
      
      const assets = await storage.getRoomAssets(room.id);
      res.json(assets);
    } catch (error) {
      console.error("Error getting room assets:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // Room player routes
  app.post('/api/rooms/:roomId/join', hybridAuthMiddleware, async (req: any, res) => {
    try {
      const { roomId } = req.params;
      const userId = req.user.uid;
      
      // First, check if room exists and get the actual room ID
      const room = await storage.getGameRoomByIdOrName(roomId);
      if (!room) {
        return res.status(404).json({ message: "Room not found" });
      }
      
      const roomPlayer = await storage.addPlayerToRoom(room.id, userId);
      
      res.json({ success: true, role: roomPlayer.role });
    } catch (error) {
      console.error("Error joining room:", error);
      res.status(500).json({ message: "Failed to join room" });
    }
  });

  app.get('/api/rooms/:roomId/role', hybridAuthMiddleware, async (req: any, res) => {
    try {
      const { roomId } = req.params;
      const userId = req.user.uid;
      
      // First, check if room exists and get the actual room ID
      const room = await storage.getGameRoomByIdOrName(roomId);
      if (!room) {
        return res.status(404).json({ message: "Room not found" });
      }
      
      const role = await storage.getPlayerRole(room.id, userId);
      
      res.json({ role });
    } catch (error) {
      console.error("Error getting player role:", error);
      res.status(500).json({ message: "Failed to get player role" });
    }
  });

  app.get('/api/rooms/:roomId/players', async (req, res) => {
    try {
      // First, check if room exists and get the actual room ID
      const room = await storage.getGameRoomByIdOrName(req.params.roomId);
      if (!room) {
        return res.status(404).json({ error: "Room not found" });
      }
      
      const players = await storage.getRoomPlayersWithNames(room.id);
      res.json(players);
    } catch (error) {
      console.error("Error getting room players:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // Object storage routes for file uploads
  app.post("/api/objects/upload", hybridAuthMiddleware, async (req: any, res) => {
    try {
      const objectStorageService = new ObjectStorageService();
      const uploadURL = await objectStorageService.getObjectEntityUploadURL();
      res.json({ uploadURL });
    } catch (error) {
      console.error("Error getting upload URL:", error);
      res.status(500).json({ error: "Failed to get upload URL" });
    }
  });

  app.delete("/api/assets/:id", async (req, res) => {
    try {
      await storage.deleteGameAsset(req.params.id);
      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting asset:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // Board Assets Routes
  app.post("/api/board-assets", async (req, res) => {
    try {
      const boardAssetData = insertBoardAssetSchema.parse(req.body);
      const boardAsset = await storage.createBoardAsset(boardAssetData);
      res.json(boardAsset);
    } catch (error) {
      console.error("Error creating board asset:", error);
      res.status(400).json({ error: "Invalid board asset data" });
    }
  });

  app.get("/api/rooms/:roomId/board-assets", async (req, res) => {
    try {
      const boardAssets = await storage.getRoomBoardAssets(req.params.roomId);
      res.json(boardAssets);
    } catch (error) {
      console.error("Error getting board assets:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.put("/api/board-assets/:id", async (req, res) => {
    try {
      const updates = req.body;
      const boardAsset = await storage.updateBoardAsset(req.params.id, updates);
      res.json(boardAsset);
    } catch (error) {
      console.error("Error updating board asset:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.delete("/api/board-assets/:id", async (req, res) => {
    try {
      await storage.deleteBoardAsset(req.params.id);
      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting board asset:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // Dice Roll Routes
  app.post("/api/dice-rolls", async (req, res) => {
    try {
      const diceRollData = insertDiceRollSchema.parse(req.body);
      const playerId = req.body.playerId; // In a real app, get from auth
      const diceRoll = await storage.createDiceRoll(diceRollData, playerId);
      res.json(diceRoll);
    } catch (error) {
      console.error("Error creating dice roll:", error);
      res.status(400).json({ error: "Invalid dice roll data" });
    }
  });

  app.get("/api/rooms/:roomId/dice-rolls", async (req, res) => {
    try {
      const limit = req.query.limit ? parseInt(req.query.limit as string) : 10;
      const diceRolls = await storage.getRoomDiceRolls(req.params.roomId, limit);
      res.json(diceRolls);
    } catch (error) {
      console.error("Error getting dice rolls:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // Chat Message Routes
  app.get("/api/rooms/:roomId/chat", hybridAuthMiddleware, async (req, res) => {
    try {
      const { roomId } = req.params;
      const limit = parseInt(req.query.limit as string) || 100;
      
      const messages = await storage.getRoomChatMessages(roomId, limit);
      res.json(messages.reverse()); // Return in chronological order
    } catch (error) {
      console.error("Error getting chat messages:", error);
      res.status(500).json({ message: "Failed to get chat messages" });
    }
  });

  app.post("/api/rooms/:roomId/chat", hybridAuthMiddleware, async (req: any, res) => {
    try {
      const { roomId } = req.params;
      const userId = req.user?.uid || req.user?.claims?.sub;
      
      if (!userId) {
        return res.status(401).json({ message: "User not authenticated" });
      }

      const validatedData = insertChatMessageSchema.parse({
        roomId,
        ...req.body
      });

      const message = await storage.createChatMessage(validatedData, userId);
      
      // Get player name for response
      const player = await storage.getUser(userId);
      const playerName = player?.firstName && player?.lastName 
        ? `${player.firstName} ${player.lastName}`
        : player?.firstName 
        ? player.firstName
        : player?.email || "Player";

      const messageWithName = { ...message, playerName };

      // Broadcast via WebSocket
      broadcastToRoom(roomId, {
        type: 'chat_message',
        payload: messageWithName
      });

      res.json(messageWithName);
    } catch (error) {
      console.error("Error sending chat message:", error);
      res.status(500).json({ message: "Failed to send chat message" });
    }
  });

  // Card Deck endpoints
  app.get("/api/rooms/:roomId/decks", hybridAuthMiddleware, async (req: any, res) => {
    try {
      const { roomId } = req.params;
      const decks = await storage.getCardDecks(roomId);
      res.json(decks);
    } catch (error) {
      console.error("Error fetching card decks:", error);
      res.status(500).json({ error: "Failed to fetch card decks" });
    }
  });

  app.post("/api/rooms/:roomId/decks", hybridAuthMiddleware, async (req: any, res) => {
    try {
      const { roomId } = req.params;
      const { name, description, deckOrder, cardBackAssetId } = req.body;
      const userId = req.user?.claims?.sub || req.user?.id;

      if (!name?.trim() || !Array.isArray(deckOrder)) {
        return res.status(400).json({ error: "Invalid deck data" });
      }

      const deck = await storage.createCardDeck({
        roomId,
        name,
        description: description || "",
        deckOrder,
        cardBackAssetId: cardBackAssetId || null,
      }, userId);

      res.json(deck);
    } catch (error) {
      console.error("Error creating deck:", error);
      res.status(500).json({ error: "Failed to create deck" });
    }
  });

  app.post("/api/rooms/:roomId/decks/:deckId/shuffle", hybridAuthMiddleware, async (req: any, res) => {
    try {
      const { deckId } = req.params;
      const deck = await storage.shuffleCardDeck(deckId);
      
      if (!deck) {
        return res.status(404).json({ error: "Deck not found" });
      }

      res.json(deck);
    } catch (error) {
      console.error("Error shuffling deck:", error);
      res.status(500).json({ error: "Failed to shuffle deck" });
    }
  });

  app.post("/api/rooms/:roomId/decks/:deckId/deal", hybridAuthMiddleware, async (req: any, res) => {
    try {
      const { deckId } = req.params;
      const { count = 1, targetPile = "board" } = req.body;
      
      const deck = await storage.getCardDeck(deckId);
      if (!deck) {
        return res.status(404).json({ error: "Deck not found" });
      }

      const deckOrder = deck.deckOrder as string[] || [];
      const dealtCards = deckOrder.slice(0, count);
      
      res.json({ cards: dealtCards, targetPile });
    } catch (error) {
      console.error("Error dealing cards:", error);
      res.status(500).json({ error: "Failed to deal cards" });
    }
  });

  // Card Pile endpoints
  app.get("/api/rooms/:roomId/piles", hybridAuthMiddleware, async (req: any, res) => {
    try {
      const { roomId } = req.params;
      const piles = await storage.getCardPiles(roomId);
      res.json(piles);
    } catch (error) {
      console.error("Error fetching card piles:", error);
      res.status(500).json({ error: "Failed to fetch card piles" });
    }
  });

  app.post("/api/rooms/:roomId/piles", hybridAuthMiddleware, async (req: any, res) => {
    try {
      const { roomId } = req.params;
      const { name, positionX, positionY, pileType, visibility, ownerId } = req.body;

      if (!name?.trim()) {
        return res.status(400).json({ error: "Pile name is required" });
      }

      const pile = await storage.createCardPile({
        roomId,
        name,
        positionX: positionX || 0,
        positionY: positionY || 0,
        pileType: pileType || "custom",
        visibility: visibility || "public",
        ownerId: ownerId || null,
      });

      res.json(pile);
    } catch (error) {
      console.error("Error creating pile:", error);
      res.status(500).json({ error: "Failed to create pile" });
    }
  });

  // Update deck theme
  app.put('/api/rooms/:roomId/decks/:deckId/theme', hybridAuthMiddleware, async (req: any, res) => {
    try {
      const { roomId, deckId } = req.params;
      const { theme } = req.body;
      
      // Validate theme object
      if (!theme || typeof theme !== 'object') {
        return res.status(400).json({ error: 'Invalid theme data' });
      }

      // Get deck to verify ownership/permissions
      const deck = await storage.getCardDeck(deckId);
      if (!deck || deck.roomId !== roomId) {
        return res.status(404).json({ error: 'Deck not found' });
      }

      // Update deck theme
      const updatedDeck = await storage.updateCardDeck(deckId, { theme });
      
      res.json({ 
        success: true, 
        deck: updatedDeck,
        theme 
      });
    } catch (error) {
      console.error('Error updating deck theme:', error);
      res.status(500).json({ error: 'Failed to update deck theme' });
    }
  });

  // Draw cards from deck - Player action
  app.post('/api/rooms/:roomId/decks/:deckId/draw', hybridAuthMiddleware, async (req: any, res) => {
    try {
      const { roomId, deckId } = req.params;
      const { playerId, count = 1 } = req.body;
      
      // Get deck
      const deck = await storage.getCardDeck(deckId);
      if (!deck || deck.roomId !== roomId) {
        return res.status(404).json({ error: 'Deck not found' });
      }

      const deckOrder = (deck.deckOrder || []) as string[];
      if (deckOrder.length < count) {
        return res.status(400).json({ error: 'Not enough cards in deck' });
      }

      // Draw cards from top of deck
      const drawnCards = deckOrder.slice(0, count);
      const remainingCards = deckOrder.slice(count);

      // Update deck
      await storage.updateCardDeck(deckId, {
        deckOrder: remainingCards
      });

      // Find or create player's hand pile
      const allPiles = await storage.getCardPiles(roomId);
      let handPile = allPiles.find(pile => 
        pile.pileType === 'hand' && pile.ownerId === playerId
      );
      
      if (!handPile) {
        // Create a new hand pile for the player
        handPile = await storage.createCardPile({
          roomId,
          name: `Player Hand`,
          positionX: 50,
          positionY: 50,
          pileType: 'hand',
          visibility: 'owner',
          ownerId: playerId,
          cardOrder: drawnCards,
          faceDown: true
        });
      } else {
        // Add cards to existing hand
        const currentCards = (handPile.cardOrder || []) as string[];
        await storage.updateCardPile(handPile.id, {
          cardOrder: [...currentCards, ...drawnCards]
        });
      }

      res.json({ 
        success: true, 
        drawnCards,
        remainingInDeck: remainingCards.length,
        handPileId: handPile.id
      });
    } catch (error) {
      console.error('Error drawing cards:', error);
      res.status(500).json({ error: 'Failed to draw cards' });
    }
  });

  // Enhanced Board Asset endpoints
  app.patch("/api/board-assets/:id", hybridAuthMiddleware, async (req: any, res) => {
    try {
      const { id } = req.params;
      const updates = req.body;
      
      const asset = await storage.updateBoardAssetProperties(id, updates);
      if (!asset) {
        return res.status(404).json({ error: "Board asset not found" });
      }

      res.json(asset);
    } catch (error) {
      console.error("Error updating board asset:", error);
      res.status(500).json({ error: "Failed to update board asset" });
    }
  });

  // Game Template endpoints
  app.get("/api/templates", hybridAuthMiddleware, async (req: any, res) => {
    try {
      const userId = req.user?.uid || req.user?.claims?.sub;
      const isPublic = req.query.public === 'true' ? true : req.query.public === 'false' ? false : undefined;
      
      const templates = await storage.getGameTemplates(userId, isPublic);
      res.json(templates);
    } catch (error) {
      console.error("Error fetching game templates:", error);
      res.status(500).json({ error: "Failed to fetch game templates" });
    }
  });

  app.post("/api/templates", hybridAuthMiddleware, async (req: any, res) => {
    try {
      const userId = req.user?.uid || req.user?.claims?.sub;
      
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      const templateData = insertGameTemplateSchema.parse(req.body);
      const template = await storage.createGameTemplate(templateData, userId);
      
      res.json(template);
    } catch (error) {
      console.error("Error creating game template:", error);
      res.status(500).json({ error: "Failed to create game template" });
    }
  });

  app.get("/api/templates/:id", hybridAuthMiddleware, async (req: any, res) => {
    try {
      const template = await storage.getGameTemplate(req.params.id);
      
      if (!template) {
        return res.status(404).json({ error: "Template not found" });
      }

      res.json(template);
    } catch (error) {
      console.error("Error fetching game template:", error);
      res.status(500).json({ error: "Failed to fetch game template" });
    }
  });

  app.put("/api/templates/:id", hybridAuthMiddleware, async (req: any, res) => {
    try {
      const userId = req.user?.uid || req.user?.claims?.sub;
      const template = await storage.getGameTemplate(req.params.id);
      
      if (!template) {
        return res.status(404).json({ error: "Template not found" });
      }

      // Check if user owns the template
      if (template.createdBy !== userId) {
        return res.status(403).json({ error: "Not authorized to edit this template" });
      }

      const updates = req.body;
      const updatedTemplate = await storage.updateGameTemplate(req.params.id, updates);
      
      res.json(updatedTemplate);
    } catch (error) {
      console.error("Error updating game template:", error);
      res.status(500).json({ error: "Failed to update game template" });
    }
  });

  app.delete("/api/templates/:id", hybridAuthMiddleware, async (req: any, res) => {
    try {
      const userId = req.user?.uid || req.user?.claims?.sub;
      const template = await storage.getGameTemplate(req.params.id);
      
      if (!template) {
        return res.status(404).json({ error: "Template not found" });
      }

      // Check if user owns the template
      if (template.createdBy !== userId) {
        return res.status(403).json({ error: "Not authorized to delete this template" });
      }

      await storage.deleteGameTemplate(req.params.id);
      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting game template:", error);
      res.status(500).json({ error: "Failed to delete game template" });
    }
  });

  app.post("/api/rooms/:roomId/apply-template", hybridAuthMiddleware, async (req: any, res) => {
    try {
      const { roomId } = req.params;
      const { templateId } = req.body;
      const userId = req.user?.uid || req.user?.claims?.sub;
      
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      if (!templateId) {
        return res.status(400).json({ error: "Template ID is required" });
      }

      // Verify user has access to the room
      const playerRole = await storage.getPlayerRole(roomId, userId);
      if (!playerRole) {
        return res.status(403).json({ error: "Not authorized to modify this room" });
      }

      await storage.applyTemplateToRoom(templateId, roomId, userId);
      res.json({ success: true });
    } catch (error) {
      console.error("Error applying template to room:", error);
      res.status(500).json({ error: "Failed to apply template to room" });
    }
  });

  // Save current room as template
  app.post("/api/rooms/:roomId/save-template", hybridAuthMiddleware, async (req: any, res) => {
    try {
      const { roomId } = req.params;
      const { name, description, isPublic, category, tags } = req.body;
      const userId = req.user?.uid || req.user?.claims?.sub;
      
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      if (!name?.trim()) {
        return res.status(400).json({ error: "Template name is required" });
      }

      // Verify user has access to the room
      const playerRole = await storage.getPlayerRole(roomId, userId);
      if (playerRole !== 'admin') {
        return res.status(403).json({ error: "Only room admin can save templates" });
      }

      // Gather room data for template
      const assets = await storage.getRoomAssets(roomId);
      const boardAssets = await storage.getRoomBoardAssets(roomId);
      const decks = await storage.getCardDecks(roomId);
      const piles = await storage.getCardPiles(roomId);

      // Create template data
      const templateData = {
        name: name.trim(),
        description: description || "",
        isPublic: Boolean(isPublic),
        category: category || "Custom",
        tags: Array.isArray(tags) ? tags : [],
        assetsData: assets,
        tokensData: boardAssets.filter(asset => asset.assetType === 'token'),
        decksData: decks,
        boardConfig: {
          piles: piles
        }
      };

      const template = await storage.createGameTemplate(templateData, userId);
      res.json(template);
    } catch (error) {
      console.error("Error saving room as template:", error);
      res.status(500).json({ error: "Failed to save room as template" });
    }
  });

  // Game Systems API Routes
  app.get("/api/systems", hybridAuthMiddleware, async (req: any, res) => {
    try {
      const userId = req.user?.uid || req.user?.claims?.sub;
      const isPublic = req.query.public === 'true' ? true : req.query.public === 'false' ? false : undefined;
      
      const systems = await storage.getGameSystems(userId, isPublic);
      res.json(systems);
    } catch (error) {
      console.error("Error fetching game systems:", error);
      res.status(500).json({ error: "Failed to fetch game systems" });
    }
  });

  app.post("/api/systems", hybridAuthMiddleware, async (req: any, res) => {
    try {
      const userId = req.user?.uid || req.user?.claims?.sub;
      
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      const systemData = insertGameSystemSchema.parse(req.body);
      const system = await storage.createGameSystem(systemData, userId);
      
      res.json(system);
    } catch (error) {
      console.error("Error creating game system:", error);
      res.status(500).json({ error: "Failed to create game system" });
    }
  });

  app.get("/api/systems/:id", hybridAuthMiddleware, async (req: any, res) => {
    try {
      const system = await storage.getGameSystem(req.params.id);
      
      if (!system) {
        return res.status(404).json({ error: "System not found" });
      }

      res.json(system);
    } catch (error) {
      console.error("Error fetching game system:", error);
      res.status(500).json({ error: "Failed to fetch game system" });
    }
  });

  app.put("/api/systems/:id", hybridAuthMiddleware, async (req: any, res) => {
    try {
      const userId = req.user?.uid || req.user?.claims?.sub;
      const system = await storage.getGameSystem(req.params.id);
      
      if (!system) {
        return res.status(404).json({ error: "System not found" });
      }

      // Check if user owns the system
      if (system.createdBy !== userId) {
        return res.status(403).json({ error: "Not authorized to edit this system" });
      }

      const updates = req.body;
      const updatedSystem = await storage.updateGameSystem(req.params.id, updates);
      
      res.json(updatedSystem);
    } catch (error) {
      console.error("Error updating game system:", error);
      res.status(500).json({ error: "Failed to update game system" });
    }
  });

  app.delete("/api/systems/:id", hybridAuthMiddleware, async (req: any, res) => {
    try {
      const userId = req.user?.uid || req.user?.claims?.sub;
      const system = await storage.getGameSystem(req.params.id);
      
      if (!system) {
        return res.status(404).json({ error: "System not found" });
      }

      // Check if user owns the system
      if (system.createdBy !== userId) {
        return res.status(403).json({ error: "Not authorized to delete this system" });
      }

      await storage.deleteGameSystem(req.params.id);
      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting game system:", error);
      res.status(500).json({ error: "Failed to delete game system" });
    }
  });

  app.post("/api/rooms/:roomId/apply-system", hybridAuthMiddleware, async (req: any, res) => {
    try {
      const { roomId } = req.params;
      const { systemId } = req.body;
      const userId = req.user?.uid || req.user?.claims?.sub;
      
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      if (!systemId) {
        return res.status(400).json({ error: "System ID is required" });
      }

      // Verify user has access to the room
      const playerRole = await storage.getPlayerRole(roomId, userId);
      if (!playerRole) {
        return res.status(403).json({ error: "Not authorized to modify this room" });
      }

      await storage.applySystemToRoom(systemId, roomId, userId);
      res.json({ success: true });
    } catch (error) {
      console.error("Error applying system to room:", error);
      res.status(500).json({ error: "Failed to apply system to room" });
    }
  });

  // Save current room as game system
  app.post("/api/rooms/:roomId/save-system", hybridAuthMiddleware, async (req: any, res) => {
    try {
      const { roomId } = req.params;
      const { name, description, isPublic, category, tags, version, complexity } = req.body;
      const userId = req.user?.uid || req.user?.claims?.sub;
      
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      if (!name?.trim()) {
        return res.status(400).json({ error: "System name is required" });
      }

      // Verify user has access to the room
      const playerRole = await storage.getPlayerRole(roomId, userId);
      if (playerRole !== 'admin') {
        return res.status(403).json({ error: "Only room admin can save systems" });
      }

      // Gather room data for system
      const assets = await storage.getRoomAssets(roomId);
      const boardAssets = await storage.getRoomBoardAssets(roomId);
      const decks = await storage.getCardDecks(roomId);
      const piles = await storage.getCardPiles(roomId);
      const room = await storage.getGameRoom(roomId);

      // Create system data
      const systemData = {
        name: name.trim(),
        description: description || "",
        isPublic: Boolean(isPublic),
        category: category || "Custom",
        tags: Array.isArray(tags) ? tags : [],
        version: version || "1.0",
        complexity: complexity || "medium",
        systemConfig: room?.gameState as any,
        assetLibrary: assets,
        deckTemplates: decks,
        tokenTypes: boardAssets.filter(asset => asset.assetType === 'token'),
        boardDefaults: {
          piles: piles,
          gridSettings: {},
          measurementUnits: "inches"
        }
      };

      const system = await storage.createGameSystem(systemData, userId);
      res.json(system);
    } catch (error) {
      console.error("Error saving room as system:", error);
      res.status(500).json({ error: "Failed to save room as system" });
    }
  });

  // Admin dashboard API routes
  app.get("/api/admin/rooms", hybridAuthMiddleware, async (req: any, res) => {
    try {
      // For now, return all rooms - in production you'd check admin privileges
      const allRooms = await storage.getAllRooms();
      res.json(allRooms);
    } catch (error) {
      console.error("Error fetching all rooms:", error);
      res.status(500).json({ error: "Failed to fetch rooms" });
    }
  });

  app.get("/api/admin/templates", hybridAuthMiddleware, async (req: any, res) => {
    try {
      const allTemplates = await storage.getAllTemplates();
      res.json(allTemplates);
    } catch (error) {
      console.error("Error fetching all templates:", error);
      res.status(500).json({ error: "Failed to fetch templates" });
    }
  });

  app.get("/api/admin/game-systems", hybridAuthMiddleware, async (req: any, res) => {
    try {
      const allGameSystems = await storage.getAllGameSystems();
      res.json(allGameSystems);
    } catch (error) {
      console.error("Error fetching all game systems:", error);
      res.status(500).json({ error: "Failed to fetch game systems" });
    }
  });

  // Player Score Management
  app.patch("/api/rooms/:roomId/players/:playerId/score", async (req, res) => {
    try {
      const roomId = req.params.roomId;
      const playerId = req.params.playerId;
      const { score } = req.body;

      if (typeof score !== 'number') {
        return res.status(400).json({ error: "Score must be a number" });
      }

      // Verify user has permission (must be admin or the player themselves)
      const userRole = await storage.getPlayerRole(roomId, req.user.uid);
      if (userRole !== 'admin' && req.user.uid !== playerId) {
        return res.status(403).json({ error: "Unauthorized" });
      }

      await storage.updateRoomPlayerScore(roomId, playerId, score);
      res.json({ success: true });
    } catch (error) {
      console.error("Error updating player score:", error);
      res.status(500).json({ error: "Failed to update score" });
    }
  });

  return httpServer;
}
