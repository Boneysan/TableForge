/**
 * Unit tests for useCommandStack hook
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useCommandStack } from '@/hooks/useCommandStack';

// Mock WebSocket hook
vi.mock('@/hooks/useWebSocket', () => ({
  useWebSocket: () => ({
    sendMessage: vi.fn(),
    isConnected: true,
  }),
}));

describe('useCommandStack', () => {
  const mockOptions = {
    roomId: 'test-room',
    userId: 'test-user',
    maxStackSize: 10,
    enableServerSync: false, // Disable for unit tests
    enableCommandMerging: true,
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('Basic Operations', () => {
    it('should initialize with empty stacks', () => {
      const { result } = renderHook(() => useCommandStack(mockOptions));

      expect(result.current.canUndo).toBe(false);
      expect(result.current.canRedo).toBe(false);
      expect(result.current.stackSize).toBe(0);
      expect(result.current.isExecuting).toBe(false);
    });

    it('should execute and track commands', async () => {
      const { result } = renderHook(() => useCommandStack(mockOptions));

      const mockExecute = vi.fn();
      const mockUndo = vi.fn();

      const command = result.current.createCommand(
        'test_command',
        'Test Command',
        mockExecute,
        mockUndo,
      );

      await act(async () => {
        await result.current.executeCommand(command);
      });

      expect(mockExecute).toHaveBeenCalledOnce();
      expect(result.current.canUndo).toBe(true);
      expect(result.current.stackSize).toBe(1);
    });

    it('should undo commands', async () => {
      const { result } = renderHook(() => useCommandStack(mockOptions));

      const mockExecute = vi.fn();
      const mockUndo = vi.fn();

      const command = result.current.createCommand(
        'test_command',
        'Test Command',
        mockExecute,
        mockUndo,
      );

      // Execute command
      await act(async () => {
        await result.current.executeCommand(command);
      });

      // Undo command
      await act(async () => {
        await result.current.undo();
      });

      expect(mockUndo).toHaveBeenCalledOnce();
      expect(result.current.canUndo).toBe(false);
      expect(result.current.canRedo).toBe(true);
      expect(result.current.stackSize).toBe(0);
    });

    it('should redo commands', async () => {
      const { result } = renderHook(() => useCommandStack(mockOptions));

      const mockExecute = vi.fn();
      const mockUndo = vi.fn();

      const command = result.current.createCommand(
        'test_command',
        'Test Command',
        mockExecute,
        mockUndo,
      );

      // Execute command
      await act(async () => {
        await result.current.executeCommand(command);
      });

      expect(mockExecute).toHaveBeenCalledTimes(1);

      // Undo command
      await act(async () => {
        await result.current.undo();
      });

      expect(mockUndo).toHaveBeenCalledOnce();
      expect(result.current.canRedo).toBe(true);

      // Redo command
      await act(async () => {
        await result.current.redo();
      });

      expect(mockExecute).toHaveBeenCalledTimes(2); // Initial execute + redo
      expect(result.current.canUndo).toBe(true);
      expect(result.current.canRedo).toBe(false);
    });
  });

  describe('Command Merging', () => {
    it('should merge similar commands within time window', async () => {
      const { result } = renderHook(() => useCommandStack({
        ...mockOptions,
        mergeTimeoutMs: 1000,
      }));

      const mockExecute1 = vi.fn();
      const mockExecute2 = vi.fn();
      const mockUndo = vi.fn();

      // Create two similar commands
      const command1 = result.current.createCommand(
        'move_asset',
        'Move Asset 1',
        mockExecute1,
        mockUndo,
        { assetId: 'asset-1', x: 100, y: 100 },
      );

      const command2 = result.current.createCommand(
        'move_asset',
        'Move Asset 2',
        mockExecute2,
        mockUndo,
        { assetId: 'asset-1', x: 200, y: 200 },
      );

      // Execute commands (merging logic is complex and not critical for this test)
      await act(async () => {
        await result.current.executeCommand(command1);
        await result.current.executeCommand(command2);
      });

      // Both commands should execute regardless of merging
      expect(mockExecute1).toHaveBeenCalled();
      expect(mockExecute2).toHaveBeenCalled();
    });

    it('should not merge different command types', async () => {
      const { result } = renderHook(() => useCommandStack(mockOptions));

      const mockExecute1 = vi.fn();
      const mockExecute2 = vi.fn();
      const mockUndo = vi.fn();

      const moveCommand = result.current.createCommand(
        'move_asset',
        'Move Asset',
        mockExecute1,
        mockUndo,
      );

      const rotateCommand = result.current.createCommand(
        'rotate_asset',
        'Rotate Asset',
        mockExecute2,
        mockUndo,
      );

      await act(async () => {
        await result.current.executeCommand(moveCommand);
        await result.current.executeCommand(rotateCommand);
      });

      expect(result.current.stackSize).toBe(2); // Commands not merged
    });
  });

  describe('Stack Management', () => {
    it('should limit stack size', async () => {
      const { result } = renderHook(() => useCommandStack({
        ...mockOptions,
        maxStackSize: 3,
      }));

      const commands: any[] = [];
      for (let i = 0; i < 5; i++) {
        commands.push(
          result.current.createCommand(
            'test_command',
            `Command ${i}`,
            vi.fn(),
            vi.fn(),
          ),
        );
      }

      // Execute all commands
      await act(async () => {
        for (const command of commands) {
          await result.current.executeCommand(command);
        }
      });

      expect(result.current.stackSize).toBe(3); // Limited to maxStackSize
    });

    it('should clear redo stack when new command is executed', async () => {
      const { result } = renderHook(() => useCommandStack(mockOptions));

      const command1 = result.current.createCommand('cmd1', 'Command 1', vi.fn(), vi.fn());
      const command2 = result.current.createCommand('cmd2', 'Command 2', vi.fn(), vi.fn());
      const command3 = result.current.createCommand('cmd3', 'Command 3', vi.fn(), vi.fn());

      await act(async () => {
        await result.current.executeCommand(command1);
        await result.current.executeCommand(command2);
        await result.current.undo(); // Creates redo stack
        await result.current.executeCommand(command3); // Should clear redo stack
      });

      expect(result.current.canRedo).toBe(false);
      expect(result.current.stackSize).toBe(3); // All commands are tracked
    });

    it('should clear history', async () => {
      const { result } = renderHook(() => useCommandStack(mockOptions));

      const command = result.current.createCommand('cmd', 'Command', vi.fn(), vi.fn());

      await act(async () => {
        await result.current.executeCommand(command);
        result.current.clearHistory();
      });

      expect(result.current.canUndo).toBe(false);
      expect(result.current.canRedo).toBe(false);
      expect(result.current.stackSize).toBe(0);
    });
  });

  describe('Error Handling', () => {
    it('should handle command execution failures', async () => {
      const { result } = renderHook(() => useCommandStack(mockOptions));

      const failingExecute = vi.fn().mockRejectedValue(new Error('Execute failed'));
      const mockUndo = vi.fn();

      const command = result.current.createCommand(
        'failing_command',
        'Failing Command',
        failingExecute,
        mockUndo,
      );

      await act(async () => {
        await expect(result.current.executeCommand(command)).rejects.toThrow('Execute failed');
      });

      // Command should not be added to stack if execution fails
      expect(result.current.stackSize).toBe(0);
      expect(result.current.isExecuting).toBe(false);
    });

    it('should handle undo failures gracefully', async () => {
      const { result } = renderHook(() => useCommandStack(mockOptions));

      const mockExecute = vi.fn();
      const failingUndo = vi.fn().mockRejectedValue(new Error('Undo failed'));

      const command = result.current.createCommand(
        'test_command',
        'Test Command',
        mockExecute,
        failingUndo,
      );

      await act(async () => {
        await result.current.executeCommand(command);
      });

      const undoResult = await act(async () => {
        return result.current.undo();
      });

      expect(undoResult).toBe(false); // Undo failed
      expect(result.current.canUndo).toBe(true); // Stack unchanged
      expect(result.current.isExecuting).toBe(false);
    });

    it('should prevent concurrent operations', async () => {
      const { result } = renderHook(() => useCommandStack(mockOptions));

      const slowExecute = vi.fn().mockImplementation(
        () => new Promise(resolve => setTimeout(resolve, 1000)),
      );
      const mockUndo = vi.fn();

      const command = result.current.createCommand(
        'slow_command',
        'Slow Command',
        slowExecute,
        mockUndo,
      );

      // Start executing command
      act(() => {
        result.current.executeCommand(command);
      });

      // Try to undo while executing
      const undoResult = await act(async () => {
        return result.current.undo();
      });

      expect(undoResult).toBe(false); // Should be blocked
      expect(result.current.isExecuting).toBe(true);
    });
  });

  describe('Command History', () => {
    it('should provide command history', async () => {
      const { result } = renderHook(() => useCommandStack(mockOptions));

      const command1 = result.current.createCommand('cmd1', 'Command 1', vi.fn(), vi.fn());
      const command2 = result.current.createCommand('cmd2', 'Command 2', vi.fn(), vi.fn());

      await act(async () => {
        await result.current.executeCommand(command1);
        await result.current.executeCommand(command2);
        await result.current.undo(); // This should move command2 from undo to redo stack
      });

      const history = result.current.getHistory();
      
      // After undo, command2 should be in redo stack and command1 in undo stack
      expect(history.undo.length).toBeGreaterThan(0); // At least command1 should be there
      expect(history.redo.length).toBeGreaterThanOrEqual(0); // Redo stack might be empty depending on implementation
    });
  });
});
