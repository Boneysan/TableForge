/**
 * CRDT synchronization routes for server-side conflict resolution
 * Handles operation broadcasting and state synchronization
 */

import { Router } from 'express';
import { z } from 'zod';
import { withAuth } from '../middleware/auth';
import { validateRequest } from '../middleware/validation';
import { logger } from '../utils/logger';
import type { WebSocket } from 'ws';

const router = Router();

// CRDT operation schema
const crdtOperationSchema = z.object({
  type: z.enum(['set', 'delete', 'list_insert', 'list_delete', 'list_move']),
  key: z.string(),
  value: z.any().optional(),
  index: z.number().optional(),
  fromIndex: z.number().optional(),
  toIndex: z.number().optional(),
  timestamp: z.number(),
  userId: z.string(),
});

const crdtSyncRequestSchema = z.object({
  localVersion: z.number(),
  lastKnownRemoteVersion: z.number(),
});

// In-memory storage for CRDT documents (in production, use Redis or database)
const crdtDocuments = new Map<string, {
  operations: any[];
  version: number;
  lastModified: number;
}>();

// WebSocket connections by room
const roomConnections = new Map<string, Set<WebSocket>>();

// Broadcast operation to all clients in room
function broadcastToRoom(roomId: string, message: any, excludeWs?: WebSocket) {
  const connections = roomConnections.get(roomId);
  if (!connections) return;

  const messageStr = JSON.stringify(message);
  
  connections.forEach(ws => {
    if (ws !== excludeWs && ws.readyState === ws.OPEN) {
      try {
        ws.send(messageStr);
      } catch (error) {
        logger.warn('Failed to send message to WebSocket', { 
          roomId, 
          error: error.message 
        });
        connections.delete(ws);
      }
    }
  });
}

// Add WebSocket connection to room
export function addConnectionToRoom(roomId: string, ws: WebSocket) {
  if (!roomConnections.has(roomId)) {
    roomConnections.set(roomId, new Set());
  }
  roomConnections.get(roomId)!.add(ws);

  ws.on('close', () => {
    const connections = roomConnections.get(roomId);
    if (connections) {
      connections.delete(ws);
      if (connections.size === 0) {
        roomConnections.delete(roomId);
      }
    }
  });
}

// Apply CRDT operation
router.post('/rooms/:roomId/crdt/operation', withAuth, validateRequest({
  body: crdtOperationSchema,
}), async (req, res) => {
  try {
    const { roomId } = req.params;
    const operation = req.body;
    const userId = req.user?.uid;

    if (!userId) {
      return res.status(401).json({ message: 'User not authenticated' });
    }

    // Ensure operation is from authenticated user
    operation.userId = userId;

    // Get or create document
    let document = crdtDocuments.get(roomId);
    if (!document) {
      document = {
        operations: [],
        version: 0,
        lastModified: Date.now(),
      };
      crdtDocuments.set(roomId, document);
    }

    // Check for duplicate operation
    const isDuplicate = document.operations.some(op => 
      op.timestamp === operation.timestamp && op.userId === operation.userId
    );

    if (!isDuplicate) {
      // Add operation to document
      document.operations.push(operation);
      document.version++;
      document.lastModified = Date.now();

      logger.info('CRDT operation applied', {
        roomId,
        userId,
        operationType: operation.type,
        operationKey: operation.key,
        version: document.version,
      });

      // Broadcast to other clients in room
      broadcastToRoom(roomId, {
        type: 'crdt_operation',
        payload: operation,
      });

      // Clean up old operations (keep last 1000)
      if (document.operations.length > 1000) {
        document.operations = document.operations.slice(-1000);
      }
    }

    res.json({
      success: true,
      version: document.version,
      operationId: `${operation.timestamp}_${operation.userId}`,
    });

  } catch (error) {
    logger.error('Failed to apply CRDT operation', { error: error.message });
    res.status(500).json({ message: 'Failed to apply operation' });
  }
});

// Sync request - get operations since client version
router.post('/rooms/:roomId/crdt/sync', withAuth, validateRequest({
  body: crdtSyncRequestSchema,
}), async (req, res) => {
  try {
    const { roomId } = req.params;
    const { localVersion, lastKnownRemoteVersion } = req.body;
    const userId = req.user?.uid;

    if (!userId) {
      return res.status(401).json({ message: 'User not authenticated' });
    }

    const document = crdtDocuments.get(roomId);
    
    if (!document) {
      return res.json({
        operations: [],
        version: 0,
        isSync: true,
      });
    }

    // Return operations since the client's last known version
    // In a real implementation, you'd need to track version-to-operation mapping
    const missedOperations = document.operations.filter(op => 
      op.timestamp > lastKnownRemoteVersion
    );

    logger.info('CRDT sync request', {
      roomId,
      userId,
      localVersion,
      remoteVersion: document.version,
      missedOperations: missedOperations.length,
    });

    res.json({
      operations: missedOperations,
      version: document.version,
      isSync: missedOperations.length === 0,
    });

  } catch (error) {
    logger.error('Failed to process CRDT sync', { error: error.message });
    res.status(500).json({ message: 'Failed to sync' });
  }
});

// Get current document state
router.get('/rooms/:roomId/crdt/state', withAuth, async (req, res) => {
  try {
    const { roomId } = req.params;
    const userId = req.user?.uid;

    if (!userId) {
      return res.status(401).json({ message: 'User not authenticated' });
    }

    const document = crdtDocuments.get(roomId);
    
    if (!document) {
      return res.json({
        operations: [],
        version: 0,
        lastModified: Date.now(),
      });
    }

    logger.info('CRDT state requested', {
      roomId,
      userId,
      version: document.version,
      operationsCount: document.operations.length,
    });

    res.json({
      operations: document.operations,
      version: document.version,
      lastModified: document.lastModified,
    });

  } catch (error) {
    logger.error('Failed to get CRDT state', { error: error.message });
    res.status(500).json({ message: 'Failed to get state' });
  }
});

// Reset document (admin only)
router.delete('/rooms/:roomId/crdt/reset', withAuth, async (req, res) => {
  try {
    const { roomId } = req.params;
    const userId = req.user?.uid;

    if (!userId) {
      return res.status(401).json({ message: 'User not authenticated' });
    }

    // TODO: Add admin check here

    crdtDocuments.delete(roomId);

    logger.warn('CRDT document reset', {
      roomId,
      userId,
    });

    // Broadcast reset to all clients
    broadcastToRoom(roomId, {
      type: 'crdt_reset',
      payload: { timestamp: Date.now() },
    });

    res.json({ success: true });

  } catch (error) {
    logger.error('Failed to reset CRDT document', { error: error.message });
    res.status(500).json({ message: 'Failed to reset document' });
  }
});

export { router as crdtRouter };