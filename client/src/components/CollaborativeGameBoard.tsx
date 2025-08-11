/**
 * Complete collaborative game board with CRDT, undo/redo, and snapshot functionality
 * Integrates all collaboration features into a single comprehensive component
 */

import React, { useRef, useState, useCallback, useEffect } from 'react';
import { AccessibleGameBoard } from './AccessibleGameBoard';
import { UndoRedoToolbar } from './UndoRedoToolbar';
import { useCommandStack } from '../hooks/useCommandStack';
import { useGameSnapshot } from '../hooks/useGameSnapshot';
import { useCRDT } from '../hooks/useCRDT';
import { Card } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Info, Users, Wifi, WifiOff } from 'lucide-react';

interface CollaborativeGameBoardProps {
  roomId: string;
  userId: string;
  userName?: string;
  assets: any[];
  onAssetMove?: (assetId: string, x: number, y: number, rotation?: number) => void;
  onAssetSelect?: (assetId: string) => void;
  onStateChange?: (state: any) => void;
  selectedAssetId?: string;
  className?: string;
}

export function CollaborativeGameBoard({
  roomId,
  userId,
  userName = 'Unknown User',
  assets,
  onAssetMove,
  onAssetSelect,
  onStateChange,
  selectedAssetId,
  className = '',
}: CollaborativeGameBoardProps) {
  const [gameState, setGameState] = useState({
    assets: assets || [],
    board: { width: 1920, height: 1080 },
    viewport: { x: 0, y: 0, scale: 1 },
    layers: [],
    version: 1,
  });

  const [collaborators, setCollaborators] = useState<string[]>([]);
  const [isOnline, setIsOnline] = useState(true);
  const [conflictCount, setConflictCount] = useState(0);

  // CRDT for real-time collaboration
  const {
    state: crdtState,
    isSync,
    pendingOperations,
    setValue,
    deleteValue,
    syncWithServer,
  } = useCRDT({
    roomId,
    userId,
    initialState: gameState,
  });

  // Command stack for undo/redo
  const {
    canUndo,
    canRedo,
    undo,
    redo,
    executeCommand,
    createCommand,
  } = useCommandStack({
    roomId,
    userId,
    enableServerSync: true,
    enableCommandMerging: true,
  });

  // Game snapshots
  const {
    snapshots,
    createSnapshot,
    updateCurrentState,
  } = useGameSnapshot({
    roomId,
    userId,
    autoSnapshotInterval: 5, // Auto-save every 5 minutes
  });

  // Handle asset movement with undo/redo support
  const handleAssetMoveWithHistory = useCallback(async (
    assetId: string,
    newX: number,
    newY: number,
    rotation?: number,
  ) => {
    const asset = gameState.assets.find(a => a.id === assetId);
    if (!asset) return;

    const originalState = {
      id: assetId,
      x: asset.positionX || 0,
      y: asset.positionY || 0,
      rotation: asset.rotation || 0,
    };

    const newState = {
      id: assetId,
      x: newX,
      y: newY,
      rotation: rotation ?? asset.rotation || 0,
    };

    // Create undoable command
    const command = createCommand(
      'move_asset',
      `Move ${asset.name || 'asset'}`,
      async () => {
        // Execute: Update local state and CRDT
        setGameState(prev => ({
          ...prev,
          assets: prev.assets.map(a =>
            a.id === assetId
              ? { ...a, positionX: newX, positionY: newY, rotation: rotation ?? a.rotation }
              : a,
          ),
          version: prev.version + 1,
        }));

        // Update CRDT for real-time sync
        setValue(`asset_${assetId}_position`, { x: newX, y: newY, rotation: rotation ?? asset.rotation });

        // Call original handler
        onAssetMove?.(assetId, newX, newY, rotation);
      },
      async () => {
        // Undo: Restore original state
        setGameState(prev => ({
          ...prev,
          assets: prev.assets.map(a =>
            a.id === assetId
              ? { ...a, positionX: originalState.x, positionY: originalState.y, rotation: originalState.rotation }
              : a,
          ),
          version: prev.version + 1,
        }));

        // Update CRDT
        setValue(`asset_${assetId}_position`, originalState);

        // Call original handler
        onAssetMove?.(assetId, originalState.x, originalState.y, originalState.rotation);
      },
      { originalState, newState },
    );

    await executeCommand(command);
  }, [gameState.assets, createCommand, executeCommand, setValue, onAssetMove]);

  // Handle asset selection with CRDT sync
  const handleAssetSelectWithSync = useCallback((assetId: string) => {
    onAssetSelect?.(assetId);

    // Update CRDT with selection (for showing other users' selections)
    setValue(`user_${userId}_selection`, {
      assetId,
      timestamp: Date.now(),
      userName,
    });
  }, [onAssetSelect, setValue, userId, userName]);

  // Restore game state from snapshot
  const handleRestoreState = useCallback(async (state: any) => {
    setGameState(state);
    onStateChange?.(state);

    // Sync with CRDT
    Object.entries(state).forEach(([key, value]) => {
      setValue(key, value);
    });
  }, [onStateChange, setValue]);

  // Sync CRDT state with local game state
  useEffect(() => {
    if (crdtState && Object.keys(crdtState).length > 0) {
      // Extract asset positions from CRDT
      const assetPositions: Record<string, any> = {};
      const userSelections: Record<string, any> = {};

      Object.entries(crdtState).forEach(([key, value]) => {
        if (key.startsWith('asset_') && key.endsWith('_position')) {
          const assetId = key.replace('asset_', '').replace('_position', '');
          assetPositions[assetId] = value;
        } else if (key.startsWith('user_') && key.endsWith('_selection')) {
          const userId = key.replace('user_', '').replace('_selection', '');
          userSelections[userId] = value;
        }
      });

      // Update game state with CRDT positions
      setGameState(prev => ({
        ...prev,
        assets: prev.assets.map(asset => {
          const crdtPosition = assetPositions[asset.id];
          if (crdtPosition) {
            return {
              ...asset,
              positionX: crdtPosition.x,
              positionY: crdtPosition.y,
              rotation: crdtPosition.rotation,
            };
          }
          return asset;
        }),
      }));

      // Update collaborators list
      const activeCollaborators = Object.entries(userSelections)
        .filter(([uId]) => uId !== userId)
        .map(([, selection]: [string, any]) => selection.userName)
        .filter(Boolean);

      setCollaborators(activeCollaborators);
    }
  }, [crdtState, userId]);

  // Update snapshot system when game state changes
  useEffect(() => {
    updateCurrentState(gameState);
    onStateChange?.(gameState);
  }, [gameState, updateCurrentState, onStateChange]);

  // Handle network status
  useEffect(() => {
    const handleOnline = () => {
      setIsOnline(true);
      syncWithServer();
    };

    const handleOffline = () => setIsOnline(false);

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, [syncWithServer]);

  // Monitor conflicts (when pending operations indicate conflicts)
  useEffect(() => {
    setConflictCount(pendingOperations);
  }, [pendingOperations]);

  return (
    <div className={`flex flex-col w-full h-full ${className}`}>
      {/* Collaboration Status Bar */}
      <div className="flex items-center justify-between p-2 bg-muted/30 border-b">
        <div className="flex items-center gap-4">
          {/* Online Status */}
          <div className="flex items-center gap-2">
            {isOnline ? (
              <Wifi className="w-4 h-4 text-green-500" />
            ) : (
              <WifiOff className="w-4 h-4 text-red-500" />
            )}
            <span className="text-sm">
              {isOnline ? 'Online' : 'Offline'}
            </span>
          </div>

          {/* Collaborators */}
          {collaborators.length > 0 && (
            <div className="flex items-center gap-2">
              <Users className="w-4 h-4 text-blue-500" />
              <div className="flex gap-1">
                {collaborators.slice(0, 3).map((name, index) => (
                  <Badge key={index} variant="secondary" className="text-xs">
                    {name}
                  </Badge>
                ))}
                {collaborators.length > 3 && (
                  <Badge variant="secondary" className="text-xs">
                    +{collaborators.length - 3}
                  </Badge>
                )}
              </div>
            </div>
          )}

          {/* Sync Status */}
          <div className="flex items-center gap-2">
            <div className={`w-2 h-2 rounded-full ${
              isSync ? 'bg-green-500' : 'bg-yellow-500 animate-pulse'
            }`} />
            <span className="text-sm text-muted-foreground">
              {isSync ? 'Synced' : `${pendingOperations} pending`}
            </span>
          </div>
        </div>

        {/* Undo/Redo Toolbar */}
        <UndoRedoToolbar
          roomId={roomId}
          userId={userId}
          currentGameState={gameState}
          onRestoreState={handleRestoreState}
        />
      </div>

      {/* Conflict Warning */}
      {conflictCount > 5 && (
        <Alert className="m-2">
          <Info className="w-4 h-4" />
          <AlertDescription>
            Multiple changes are being synchronized. Some edits may take longer to appear.
          </AlertDescription>
        </Alert>
      )}

      {/* Game Board */}
      <div className="flex-1 relative">
        <AccessibleGameBoard
          roomId={roomId}
          assets={gameState.assets}
          onAssetMove={handleAssetMoveWithHistory}
          onAssetSelect={handleAssetSelectWithSync}
          selectedAssetId={selectedAssetId}
          className="w-full h-full"
        />

        {/* Collaboration Overlay */}
        {!isSync && (
          <div className="absolute top-4 right-4">
            <Card className="p-3 bg-yellow-50 dark:bg-yellow-950/30 border-yellow-200 dark:border-yellow-800">
              <div className="flex items-center gap-2 text-yellow-800 dark:text-yellow-200">
                <div className="w-2 h-2 bg-yellow-500 rounded-full animate-pulse" />
                <span className="text-sm font-medium">Synchronizing changes...</span>
              </div>
              <div className="text-xs text-yellow-700 dark:text-yellow-300 mt-1">
                {pendingOperations} operations pending
              </div>
            </Card>
          </div>
        )}
      </div>

      {/* Development Debug Info */}
      {process.env.NODE_ENV === 'development' && (
        <div className="p-2 bg-muted/20 border-t">
          <div className="flex gap-4 text-xs text-muted-foreground">
            <div>Game Version: {gameState.version}</div>
            <div>Snapshots: {snapshots.length}</div>
            <div>Can Undo: {canUndo ? 'Yes' : 'No'}</div>
            <div>Can Redo: {canRedo ? 'Yes' : 'No'}</div>
            <div>CRDT Sync: {isSync ? 'Yes' : 'No'}</div>
            <div>Collaborators: {collaborators.length}</div>
          </div>
        </div>
      )}
    </div>
  );
}
