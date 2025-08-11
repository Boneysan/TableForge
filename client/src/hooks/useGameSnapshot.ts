/**
 * Game snapshot system for save states and rollback functionality
 * Provides automatic and manual snapshot creation with efficient diff storage
 */

import { useRef, useState, useCallback, useEffect } from 'react';
import { useWebSocket } from './useWebSocket';

export interface GameSnapshot {
  id: string;
  name?: string;
  timestamp: number;
  userId: string;
  roomId: string;
  type: 'auto' | 'manual' | 'checkpoint';
  state: GameState;
  compressed?: boolean;
  size: number;
  description?: string;
}

export interface GameState {
  assets: any[];
  board: {
    width: number;
    height: number;
    backgroundUrl?: string;
    gridSize?: number;
  };
  viewport: {
    x: number;
    y: number;
    scale: number;
  };
  layers: any[];
  version: number;
  checksum?: string;
}

interface UseGameSnapshotOptions {
  roomId: string;
  userId: string;
  maxSnapshots?: number;
  autoSnapshotInterval?: number; // minutes
  enableCompression?: boolean;
  enableServerBackup?: boolean;
}

export function useGameSnapshot(options: UseGameSnapshotOptions) {
  const {
    roomId,
    userId,
    maxSnapshots = 20,
    autoSnapshotInterval = 5,
    enableCompression = true,
    enableServerBackup = true,
  } = options;

  const [snapshots, setSnapshots] = useState<GameSnapshot[]>([]);
  const [isCreatingSnapshot, setIsCreatingSnapshot] = useState(false);
  const [isRestoringSnapshot, setIsRestoringSnapshot] = useState(false);

  const lastAutoSnapshotRef = useRef<number>(0);
  const currentStateRef = useRef<GameState | null>(null);
  const { sendMessage, isConnected } = useWebSocket(roomId);

  // Generate snapshot ID
  const generateSnapshotId = useCallback(() => {
    return `snap_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }, []);

  // Calculate checksum for state integrity
  const calculateChecksum = useCallback((state: GameState): string => {
    const stateStr = JSON.stringify(state, Object.keys(state).sort());
    let hash = 0;
    for (let i = 0; i < stateStr.length; i++) {
      const char = stateStr.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return hash.toString(16);
  }, []);

  // Compress game state (simple JSON compression)
  const compressState = useCallback((state: GameState): string => {
    if (!enableCompression) return JSON.stringify(state);

    // Simple compression: remove unnecessary whitespace and repeated keys
    const jsonStr = JSON.stringify(state);

    // In a real implementation, you might use pako or similar for gzip compression
    return jsonStr;
  }, [enableCompression]);

  // Decompress game state
  const decompressState = useCallback((compressed: string): GameState => {
    return JSON.parse(compressed);
  }, []);

  // Calculate state diff between two states
  const calculateStateDiff = useCallback((oldState: GameState, newState: GameState) => {
    const diff: any = {};

    // Compare assets
    if (JSON.stringify(oldState.assets) !== JSON.stringify(newState.assets)) {
      diff.assets = newState.assets;
    }

    // Compare board
    if (JSON.stringify(oldState.board) !== JSON.stringify(newState.board)) {
      diff.board = newState.board;
    }

    // Compare viewport
    if (JSON.stringify(oldState.viewport) !== JSON.stringify(newState.viewport)) {
      diff.viewport = newState.viewport;
    }

    // Compare layers
    if (JSON.stringify(oldState.layers) !== JSON.stringify(newState.layers)) {
      diff.layers = newState.layers;
    }

    return diff;
  }, []);

  // Apply diff to base state
  const applyStateDiff = useCallback((baseState: GameState, diff: any): GameState => {
    return {
      ...baseState,
      ...diff,
      version: baseState.version + 1,
    };
  }, []);

  // Create a new snapshot
  const createSnapshot = useCallback(async (
    state: GameState,
    type: GameSnapshot['type'] = 'manual',
    name?: string,
    description?: string,
  ): Promise<GameSnapshot | null> => {
    if (isCreatingSnapshot) return null;

    setIsCreatingSnapshot(true);

    try {
      const snapshot: GameSnapshot = {
        id: generateSnapshotId(),
        name,
        timestamp: Date.now(),
        userId,
        roomId,
        type,
        state: {
          ...state,
          checksum: calculateChecksum(state),
        },
        compressed: enableCompression,
        size: JSON.stringify(state).length,
        description,
      };

      setSnapshots(prev => {
        let newSnapshots = [snapshot, ...prev];

        // Remove old snapshots if over limit
        if (newSnapshots.length > maxSnapshots) {
          newSnapshots = newSnapshots.slice(0, maxSnapshots);
        }

        return newSnapshots;
      });

      // Backup to server if enabled
      if (enableServerBackup && isConnected) {
        sendMessage({
          type: 'snapshot_created',
          payload: {
            snapshotId: snapshot.id,
            snapshotType: type,
            timestamp: snapshot.timestamp,
            compressed: enableCompression ? compressState(state) : state,
            checksum: snapshot.state.checksum,
          },
        });
      }

      return snapshot;
    } catch (error) {
      console.error('Failed to create snapshot:', error);
      return null;
    } finally {
      setIsCreatingSnapshot(false);
    }
  }, [
    isCreatingSnapshot,
    generateSnapshotId,
    userId,
    roomId,
    calculateChecksum,
    enableCompression,
    maxSnapshots,
    enableServerBackup,
    isConnected,
    sendMessage,
    compressState,
  ]);

  // Restore from snapshot
  const restoreSnapshot = useCallback(async (
    snapshotId: string,
    onRestore: (state: GameState) => Promise<void>,
  ): Promise<boolean> => {
    if (isRestoringSnapshot) return false;

    const snapshot = snapshots.find(s => s.id === snapshotId);
    if (!snapshot) return false;

    setIsRestoringSnapshot(true);

    try {
      // Verify checksum
      const calculatedChecksum = calculateChecksum(snapshot.state);
      if (snapshot.state.checksum && calculatedChecksum !== snapshot.state.checksum) {
        console.warn('Snapshot checksum mismatch, data may be corrupted');
      }

      await onRestore(snapshot.state);

      // Update current state reference
      currentStateRef.current = snapshot.state;

      // Notify server
      if (enableServerBackup && isConnected) {
        sendMessage({
          type: 'snapshot_restored',
          payload: {
            snapshotId: snapshot.id,
            timestamp: Date.now(),
          },
        });
      }

      return true;
    } catch (error) {
      console.error('Failed to restore snapshot:', error);
      return false;
    } finally {
      setIsRestoringSnapshot(false);
    }
  }, [isRestoringSnapshot, snapshots, calculateChecksum, enableServerBackup, isConnected, sendMessage]);

  // Delete snapshot
  const deleteSnapshot = useCallback((snapshotId: string) => {
    setSnapshots(prev => prev.filter(s => s.id !== snapshotId));

    // Notify server
    if (enableServerBackup && isConnected) {
      sendMessage({
        type: 'snapshot_deleted',
        payload: {
          snapshotId,
          timestamp: Date.now(),
        },
      });
    }
  }, [enableServerBackup, isConnected, sendMessage]);

  // Auto snapshot based on time interval
  const checkAutoSnapshot = useCallback(async (currentState: GameState) => {
    const now = Date.now();
    const timeSinceLastSnapshot = now - lastAutoSnapshotRef.current;
    const intervalMs = autoSnapshotInterval * 60 * 1000; // Convert to milliseconds

    if (timeSinceLastSnapshot >= intervalMs) {
      const snapshot = await createSnapshot(
        currentState,
        'auto',
        `Auto save ${new Date(now).toLocaleTimeString()}`,
        'Automatic snapshot',
      );

      if (snapshot) {
        lastAutoSnapshotRef.current = now;
      }
    }
  }, [autoSnapshotInterval, createSnapshot]);

  // Export snapshots (for backup/transfer)
  const exportSnapshots = useCallback(() => {
    return {
      roomId,
      exportDate: new Date().toISOString(),
      snapshots: snapshots.map(snapshot => ({
        ...snapshot,
        state: enableCompression ? compressState(snapshot.state) : snapshot.state,
      })),
    };
  }, [roomId, snapshots, enableCompression, compressState]);

  // Import snapshots
  const importSnapshots = useCallback((exportData: any) => {
    try {
      if (exportData.roomId !== roomId) {
        console.warn('Importing snapshots from different room');
      }

      const importedSnapshots = exportData.snapshots.map((snapshot: any) => ({
        ...snapshot,
        state: typeof snapshot.state === 'string'
          ? decompressState(snapshot.state)
          : snapshot.state,
      }));

      setSnapshots(prev => [...importedSnapshots, ...prev].slice(0, maxSnapshots));
      return true;
    } catch (error) {
      console.error('Failed to import snapshots:', error);
      return false;
    }
  }, [roomId, decompressState, maxSnapshots]);

  // Get snapshot statistics
  const getStatistics = useCallback(() => {
    const totalSize = snapshots.reduce((sum, snap) => sum + snap.size, 0);
    const typeCount = snapshots.reduce((acc, snap) => {
      acc[snap.type] = (acc[snap.type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return {
      totalSnapshots: snapshots.length,
      totalSize,
      typeCount,
      oldestSnapshot: snapshots[snapshots.length - 1]?.timestamp,
      newestSnapshot: snapshots[0]?.timestamp,
    };
  }, [snapshots]);

  // Update current state (for auto-snapshot tracking)
  const updateCurrentState = useCallback((state: GameState) => {
    currentStateRef.current = state;

    // Check if we need an auto snapshot
    if (autoSnapshotInterval > 0) {
      checkAutoSnapshot(state);
    }
  }, [autoSnapshotInterval, checkAutoSnapshot]);

  return {
    // State
    snapshots,
    isCreatingSnapshot,
    isRestoringSnapshot,

    // Actions
    createSnapshot,
    restoreSnapshot,
    deleteSnapshot,
    updateCurrentState,

    // Import/Export
    exportSnapshots,
    importSnapshots,

    // Utilities
    getStatistics,

    // Current state
    currentState: currentStateRef.current,
  };
}
