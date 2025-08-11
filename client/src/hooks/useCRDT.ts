/**
 * CRDT (Conflict-free Replicated Data Type) implementation for real-time collaboration
 * Provides automatic conflict resolution for simultaneous edits
 */

import { useRef, useState, useCallback, useEffect } from 'react';
import { useWebSocket } from './useWebSocket';

// Basic CRDT operation types
export type CRDTOperation = 
  | { type: 'set'; key: string; value: any; timestamp: number; userId: string; }
  | { type: 'delete'; key: string; timestamp: number; userId: string; }
  | { type: 'list_insert'; key: string; index: number; value: any; timestamp: number; userId: string; }
  | { type: 'list_delete'; key: string; index: number; timestamp: number; userId: string; }
  | { type: 'list_move'; key: string; fromIndex: number; toIndex: number; timestamp: number; userId: string; };

export interface CRDTDocument {
  state: Record<string, any>;
  operations: CRDTOperation[];
  version: number;
  lastModified: number;
}

export interface CRDTSyncState {
  localVersion: number;
  remoteVersion: number;
  pendingOperations: CRDTOperation[];
  isSync: boolean;
}

interface UseCRDTOptions {
  roomId: string;
  userId: string;
  initialState?: Record<string, any>;
  enableServerSync?: boolean;
  conflictResolution?: 'timestamp' | 'userId' | 'custom';
}

export function useCRDT(options: UseCRDTOptions) {
  const {
    roomId,
    userId,
    initialState = {},
    enableServerSync = true,
    conflictResolution = 'timestamp',
  } = options;

  const [document, setDocument] = useState<CRDTDocument>({
    state: { ...initialState },
    operations: [],
    version: 0,
    lastModified: Date.now(),
  });

  const [syncState, setSyncState] = useState<CRDTSyncState>({
    localVersion: 0,
    remoteVersion: 0,
    pendingOperations: [],
    isSync: true,
  });

  const operationQueueRef = useRef<CRDTOperation[]>([]);
  const { sendMessage, isConnected } = useWebSocket(roomId);

  // Generate timestamp with microsecond precision for ordering
  const generateTimestamp = useCallback(() => {
    return Date.now() * 1000 + Math.floor(Math.random() * 1000);
  }, []);

  // Resolve conflicts between operations
  const resolveConflict = useCallback((op1: CRDTOperation, op2: CRDTOperation): CRDTOperation => {
    switch (conflictResolution) {
      case 'timestamp':
        return op1.timestamp > op2.timestamp ? op1 : op2;
      
      case 'userId':
        return op1.userId > op2.userId ? op1 : op2;
      
      default:
        return op1.timestamp > op2.timestamp ? op1 : op2;
    }
  }, [conflictResolution]);

  // Apply operation to state
  const applyOperation = useCallback((state: Record<string, any>, operation: CRDTOperation): Record<string, any> => {
    const newState = { ...state };

    switch (operation.type) {
      case 'set':
        newState[operation.key] = operation.value;
        break;

      case 'delete':
        delete newState[operation.key];
        break;

      case 'list_insert':
        if (!Array.isArray(newState[operation.key])) {
          newState[operation.key] = [];
        }
        newState[operation.key] = [
          ...newState[operation.key].slice(0, operation.index),
          operation.value,
          ...newState[operation.key].slice(operation.index),
        ];
        break;

      case 'list_delete':
        if (Array.isArray(newState[operation.key])) {
          newState[operation.key] = [
            ...newState[operation.key].slice(0, operation.index),
            ...newState[operation.key].slice(operation.index + 1),
          ];
        }
        break;

      case 'list_move':
        if (Array.isArray(newState[operation.key])) {
          const list = [...newState[operation.key]];
          const [item] = list.splice(operation.fromIndex, 1);
          list.splice(operation.toIndex, 0, item);
          newState[operation.key] = list;
        }
        break;
    }

    return newState;
  }, []);

  // Process operations in causal order
  const processOperations = useCallback((operations: CRDTOperation[]): Record<string, any> => {
    // Sort operations by timestamp for causal ordering
    const sortedOps = [...operations].sort((a, b) => a.timestamp - b.timestamp);
    
    let state = { ...initialState };
    
    // Group conflicting operations by key and resolve conflicts
    const operationsByKey = sortedOps.reduce((acc, op) => {
      const key = op.key;
      if (!acc[key]) acc[key] = [];
      acc[key].push(op);
      return acc;
    }, {} as Record<string, CRDTOperation[]>);

    // Apply operations key by key, resolving conflicts
    Object.entries(operationsByKey).forEach(([key, ops]) => {
      // For conflicting operations on the same key at similar timestamps, resolve conflicts
      const resolvedOps = ops.reduce((resolved, currentOp) => {
        const conflictingOp = resolved.find(op => 
          Math.abs(op.timestamp - currentOp.timestamp) < 1000 && // Within 1ms
          op.type === currentOp.type &&
          op.key === currentOp.key
        );

        if (conflictingOp) {
          // Replace conflicting operation with resolved one
          const resolvedOp = resolveConflict(conflictingOp, currentOp);
          return resolved.map(op => op === conflictingOp ? resolvedOp : op);
        }

        return [...resolved, currentOp];
      }, [] as CRDTOperation[]);

      // Apply resolved operations to state
      resolvedOps.forEach(op => {
        state = applyOperation(state, op);
      });
    });

    return state;
  }, [initialState, resolveConflict, applyOperation]);

  // Create and apply local operation
  const applyLocalOperation = useCallback((operation: Omit<CRDTOperation, 'timestamp' | 'userId'>) => {
    const fullOperation: CRDTOperation = {
      ...operation,
      timestamp: generateTimestamp(),
      userId,
    };

    setDocument(prev => {
      const newOperations = [...prev.operations, fullOperation];
      const newState = processOperations(newOperations);

      return {
        state: newState,
        operations: newOperations,
        version: prev.version + 1,
        lastModified: Date.now(),
      };
    });

    setSyncState(prev => ({
      ...prev,
      localVersion: prev.localVersion + 1,
      pendingOperations: [...prev.pendingOperations, fullOperation],
      isSync: false,
    }));

    // Send to server if connected
    if (enableServerSync && isConnected) {
      sendMessage({
        type: 'crdt_operation',
        payload: fullOperation,
      });
    }
  }, [generateTimestamp, userId, processOperations, enableServerSync, isConnected, sendMessage]);

  // Receive and merge remote operation
  const mergeRemoteOperation = useCallback((operation: CRDTOperation) => {
    setDocument(prev => {
      // Check if we already have this operation
      const existingOp = prev.operations.find(op => 
        op.timestamp === operation.timestamp && op.userId === operation.userId
      );

      if (existingOp) return prev;

      const newOperations = [...prev.operations, operation];
      const newState = processOperations(newOperations);

      return {
        state: newState,
        operations: newOperations,
        version: prev.version + 1,
        lastModified: Date.now(),
      };
    });

    setSyncState(prev => ({
      ...prev,
      remoteVersion: prev.remoteVersion + 1,
      // Remove pending operation if it was acknowledged
      pendingOperations: prev.pendingOperations.filter(
        op => !(op.timestamp === operation.timestamp && op.userId === operation.userId)
      ),
    }));
  }, [processOperations]);

  // Sync with server
  const syncWithServer = useCallback(() => {
    if (!enableServerSync || !isConnected) return;

    // Send all pending operations
    syncState.pendingOperations.forEach(operation => {
      sendMessage({
        type: 'crdt_operation',
        payload: operation,
      });
    });

    // Request server state if we're out of sync
    if (!syncState.isSync) {
      sendMessage({
        type: 'crdt_sync_request',
        payload: {
          localVersion: syncState.localVersion,
          lastKnownRemoteVersion: syncState.remoteVersion,
        },
      });
    }
  }, [enableServerSync, isConnected, syncState, sendMessage]);

  // High-level CRDT operations
  const setValue = useCallback((key: string, value: any) => {
    applyLocalOperation({ type: 'set', key, value });
  }, [applyLocalOperation]);

  const deleteValue = useCallback((key: string) => {
    applyLocalOperation({ type: 'delete', key });
  }, [applyLocalOperation]);

  const insertToList = useCallback((key: string, index: number, value: any) => {
    applyLocalOperation({ type: 'list_insert', key, index, value });
  }, [applyLocalOperation]);

  const deleteFromList = useCallback((key: string, index: number) => {
    applyLocalOperation({ type: 'list_delete', key, index });
  }, [applyLocalOperation]);

  const moveInList = useCallback((key: string, fromIndex: number, toIndex: number) => {
    applyLocalOperation({ type: 'list_move', key, fromIndex, toIndex });
  }, [applyLocalOperation]);

  // Get current value
  const getValue = useCallback((key: string) => {
    return document.state[key];
  }, [document.state]);

  // Export/import document state
  const exportDocument = useCallback(() => {
    return JSON.stringify(document);
  }, [document]);

  const importDocument = useCallback((documentJson: string) => {
    try {
      const importedDoc = JSON.parse(documentJson);
      setDocument(importedDoc);
      setSyncState({
        localVersion: importedDoc.version,
        remoteVersion: importedDoc.version,
        pendingOperations: [],
        isSync: true,
      });
    } catch (error) {
      console.error('Failed to import document:', error);
    }
  }, []);

  // Auto-sync with server
  useEffect(() => {
    const syncInterval = setInterval(syncWithServer, 5000); // Sync every 5 seconds
    return () => clearInterval(syncInterval);
  }, [syncWithServer]);

  // Update sync state
  useEffect(() => {
    setSyncState(prev => ({
      ...prev,
      isSync: prev.pendingOperations.length === 0,
    }));
  }, [syncState.pendingOperations.length]);

  return {
    // Document state
    state: document.state,
    version: document.version,
    lastModified: document.lastModified,
    
    // Sync state
    isSync: syncState.isSync,
    pendingOperations: syncState.pendingOperations.length,
    
    // Operations
    setValue,
    deleteValue,
    insertToList,
    deleteFromList,
    moveInList,
    getValue,
    
    // Raw operations
    applyLocalOperation,
    mergeRemoteOperation,
    
    // Sync
    syncWithServer,
    
    // Import/Export
    exportDocument,
    importDocument,
  };
}