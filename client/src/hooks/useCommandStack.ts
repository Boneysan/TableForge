/**
 * Command stack for undo/redo functionality
 * Provides client-side command tracking with server synchronization
 */

import { useRef, useState, useCallback, useEffect } from 'react';
import { useWebSocket } from './useWebSocket';

export interface Command {
  id: string;
  type: string;
  timestamp: number;
  userId: string;
  roomId: string;
  execute: () => Promise<void> | void;
  undo: () => Promise<void> | void;
  redo?: () => Promise<void> | void;
  data: any;
  description: string;
  merged?: boolean;
}

export interface CommandStackState {
  undoStack: Command[];
  redoStack: Command[];
  currentIndex: number;
  isExecuting: boolean;
  lastCommandId: string | null;
}

interface UseCommandStackOptions {
  roomId: string;
  userId: string;
  maxStackSize?: number;
  enableServerSync?: boolean;
  enableCommandMerging?: boolean;
  mergeTimeoutMs?: number;
}

export function useCommandStack(options: UseCommandStackOptions) {
  const {
    roomId,
    userId,
    maxStackSize = 50,
    enableServerSync = true,
    enableCommandMerging = true,
    mergeTimeoutMs = 1000,
  } = options;

  const [state, setState] = useState<CommandStackState>({
    undoStack: [],
    redoStack: [],
    currentIndex: -1,
    isExecuting: false,
    lastCommandId: null,
  });

  const commandQueueRef = useRef<Command[]>([]);
  const mergingTimerRef = useRef<NodeJS.Timeout | null>(null);
  const { sendMessage, isConnected } = useWebSocket(roomId);

  // Generate unique command ID
  const generateCommandId = useCallback(() => {
    return `cmd_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }, []);

  // Check if two commands can be merged
  const canMergeCommands = useCallback((prev: Command, current: Command): boolean => {
    if (!enableCommandMerging) return false;
    if (prev.type !== current.type) return false;
    if (prev.userId !== current.userId) return false;
    if (current.timestamp - prev.timestamp > mergeTimeoutMs) return false;

    // Define mergeable command types
    const mergeableTypes = ['move_asset', 'resize_asset', 'rotate_asset'];
    return mergeableTypes.includes(prev.type);
  }, [enableCommandMerging, mergeTimeoutMs]);

  // Merge two commands
  const mergeCommands = useCallback((prev: Command, current: Command): Command => {
    return {
      ...current,
      id: prev.id, // Keep original ID
      merged: true,
      data: {
        ...prev.data,
        ...current.data,
        // Preserve original start state
        originalState: prev.data.originalState || prev.data.previousState,
      },
      undo: () => {
        // Undo to the original state before the first command
        return prev.undo();
      },
    };
  }, []);

  // Execute a command
  const executeCommand = useCallback(async (command: Command, skipHistory = false) => {
    setState(prev => ({ ...prev, isExecuting: true }));

    try {
      await command.execute();

      if (!skipHistory) {
        setState(prev => {
          let newUndoStack = [...prev.undoStack];
          const newRedoStack: Command[] = [];

          // Check if we can merge with the last command
          if (newUndoStack.length > 0 && canMergeCommands(newUndoStack[newUndoStack.length - 1], command)) {
            const lastCommand = newUndoStack[newUndoStack.length - 1];
            const mergedCommand = mergeCommands(lastCommand, command);
            newUndoStack[newUndoStack.length - 1] = mergedCommand;
          } else {
            // Add new command to stack
            newUndoStack.push(command);

            // Limit stack size
            if (newUndoStack.length > maxStackSize) {
              newUndoStack = newUndoStack.slice(-maxStackSize);
            }
          }

          return {
            ...prev,
            undoStack: newUndoStack,
            redoStack: newRedoStack,
            currentIndex: newUndoStack.length - 1,
            lastCommandId: command.id,
          };
        });

        // Sync with server if enabled
        if (enableServerSync && isConnected) {
          sendMessage({
            type: 'command_executed',
            payload: {
              commandId: command.id,
              commandType: command.type,
              timestamp: command.timestamp,
              data: command.data,
              description: command.description,
            },
          });
        }
      }
    } catch (error) {
      console.error('Command execution failed:', error);
      throw error;
    } finally {
      setState(prev => ({ ...prev, isExecuting: false }));
    }
  }, [canMergeCommands, mergeCommands, maxStackSize, enableServerSync, isConnected, sendMessage]);

  // Undo last command
  const undo = useCallback(async (): Promise<boolean> => {
    if (state.undoStack.length === 0 || state.isExecuting) return false;

    const command = state.undoStack[state.undoStack.length - 1];

    setState(prev => ({ ...prev, isExecuting: true }));

    try {
      await command.undo();

      setState(prev => ({
        ...prev,
        undoStack: prev.undoStack.slice(0, -1),
        redoStack: [command, ...prev.redoStack],
        currentIndex: prev.currentIndex - 1,
        isExecuting: false,
      }));

      // Sync with server
      if (enableServerSync && isConnected) {
        sendMessage({
          type: 'command_undone',
          payload: {
            commandId: command.id,
            timestamp: Date.now(),
          },
        });
      }

      return true;
    } catch (error) {
      console.error('Undo failed:', error);
      setState(prev => ({ ...prev, isExecuting: false }));
      return false;
    }
  }, [state.undoStack, state.isExecuting, enableServerSync, isConnected, sendMessage]);

  // Redo last undone command
  const redo = useCallback(async (): Promise<boolean> => {
    if (state.redoStack.length === 0 || state.isExecuting) return false;

    const command = state.redoStack[0];

    setState(prev => ({ ...prev, isExecuting: true }));

    try {
      // Use custom redo if available, otherwise re-execute
      if (command.redo) {
        await command.redo();
      } else {
        await command.execute();
      }

      setState(prev => ({
        ...prev,
        undoStack: [...prev.undoStack, command],
        redoStack: prev.redoStack.slice(1),
        currentIndex: prev.currentIndex + 1,
        isExecuting: false,
      }));

      // Sync with server
      if (enableServerSync && isConnected) {
        sendMessage({
          type: 'command_redone',
          payload: {
            commandId: command.id,
            timestamp: Date.now(),
          },
        });
      }

      return true;
    } catch (error) {
      console.error('Redo failed:', error);
      setState(prev => ({ ...prev, isExecuting: false }));
      return false;
    }
  }, [state.redoStack, state.isExecuting, enableServerSync, isConnected, sendMessage]);

  // Clear all commands
  const clearHistory = useCallback(() => {
    setState(prev => ({
      ...prev,
      undoStack: [],
      redoStack: [],
      currentIndex: -1,
      lastCommandId: null,
    }));
  }, []);

  // Get command history for debugging/audit
  const getHistory = useCallback(() => {
    return {
      undo: state.undoStack.map(cmd => ({
        id: cmd.id,
        type: cmd.type,
        description: cmd.description,
        timestamp: cmd.timestamp,
        merged: cmd.merged,
      })),
      redo: state.redoStack.map(cmd => ({
        id: cmd.id,
        type: cmd.type,
        description: cmd.description,
        timestamp: cmd.timestamp,
        merged: cmd.merged,
      })),
    };
  }, [state.undoStack, state.redoStack]);

  // Create a new command
  const createCommand = useCallback((
    type: string,
    description: string,
    executeFunction: () => Promise<void> | void,
    undoFunction: () => Promise<void> | void,
    data?: any,
    redoFunction?: () => Promise<void> | void,
  ): Command => {
    return {
      id: generateCommandId(),
      type,
      timestamp: Date.now(),
      userId,
      roomId,
      execute: executeFunction,
      undo: undoFunction,
      redo: redoFunction,
      data: data || {},
      description,
    };
  }, [generateCommandId, userId, roomId]);

  // Execute command with automatic history tracking
  const executeAndTrack = useCallback(async (command: Command) => {
    await executeCommand(command, false);
  }, [executeCommand]);

  // Process queued commands with debouncing for merging
  const processCommandQueue = useCallback(() => {
    if (commandQueueRef.current.length === 0) return;

    const commands = [...commandQueueRef.current];
    commandQueueRef.current = [];

    // Process commands in sequence
    commands.forEach(async (command) => {
      await executeAndTrack(command);
    });
  }, [executeAndTrack]);

  // Queue command for potential merging
  const queueCommand = useCallback((command: Command) => {
    commandQueueRef.current.push(command);

    // Clear existing timer
    if (mergingTimerRef.current) {
      clearTimeout(mergingTimerRef.current);
    }

    // Set new timer for processing
    mergingTimerRef.current = setTimeout(processCommandQueue, 100);
  }, [processCommandQueue]);

  // Cleanup
  useEffect(() => {
    return () => {
      if (mergingTimerRef.current) {
        clearTimeout(mergingTimerRef.current);
      }
    };
  }, []);

  return {
    // State
    canUndo: state.undoStack.length > 0 && !state.isExecuting,
    canRedo: state.redoStack.length > 0 && !state.isExecuting,
    isExecuting: state.isExecuting,
    stackSize: state.undoStack.length,

    // Actions
    executeCommand: executeAndTrack,
    undo,
    redo,
    clearHistory,
    createCommand,
    queueCommand,

    // Utilities
    getHistory,
    state,
  };
}
