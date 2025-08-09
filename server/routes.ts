import type { Express } from "express";
import { createServer, type Server } from "http";
import { WebSocketServer, WebSocket } from "ws";
import { storage } from "./storage";
import { setupAuth } from "./replitAuth";
import { hybridAuthMiddleware } from "./hybridAuth";
import { ObjectStorageService } from "./objectStorage";
import type { 
  WebSocketMessage, 
  AssetMovedMessage, 
  AssetFlippedMessage, 
  DiceRolledMessage,
  PlayerJoinedMessage,
  PlayerLeftMessage
} from "@shared/schema";
import { 
  insertGameRoomSchema, 
  insertGameAssetSchema, 
  insertBoardAssetSchema,
  insertDiceRollSchema 
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
      const userId = req.user.uid;
      const user = await storage.getUser(userId);
      res.json(user);
    } catch (error) {
      console.error("Error fetching user:", error);
      res.status(500).json({ message: "Failed to fetch user" });
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
      res.status(400).json({ error: "Invalid room data" });
    }
  });

  app.get("/api/rooms/:id", async (req, res) => {
    try {
      const room = await storage.getGameRoom(req.params.id);
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
      const assets = await storage.getRoomAssets(req.params.roomId);
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
      
      const roomPlayer = await storage.addPlayerToRoom(roomId, userId);
      
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
      
      const role = await storage.getPlayerRole(roomId, userId);
      
      res.json({ role });
    } catch (error) {
      console.error("Error getting player role:", error);
      res.status(500).json({ message: "Failed to get player role" });
    }
  });

  app.get('/api/rooms/:roomId/players', async (req, res) => {
    try {
      const players = await storage.getRoomPlayers(req.params.roomId);
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

  return httpServer;
}
