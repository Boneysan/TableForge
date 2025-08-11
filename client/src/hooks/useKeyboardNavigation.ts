/**
 * Keyboard navigation and accessibility hook
 * Provides keyboard equivalents for drag/drop actions and board navigation
 */

import { useCallback, useEffect, useRef } from 'react';

export interface KeyboardNavigationOptions {
  onMoveAsset?: (direction: 'up' | 'down' | 'left' | 'right', distance?: number) => void;
  onSelectAsset?: (direction: 'next' | 'previous') => void;
  onRecenterBoard?: () => void;
  onToggleLayer?: (layerId: string) => void;
  onZoomIn?: () => void;
  onZoomOut?: () => void;
  onRotateAsset?: (degrees: number) => void;
  onDeleteAsset?: () => void;
  onDuplicateAsset?: () => void;
  onUndoAction?: () => void;
  onRedoAction?: () => void;
  disabled?: boolean;
}

interface KeyBinding {
  keys: string[];
  action: () => void;
  description: string;
  category: 'navigation' | 'selection' | 'manipulation' | 'board' | 'system';
  preventDefault?: boolean;
}

export function useKeyboardNavigation(options: KeyboardNavigationOptions) {
  const {
    onMoveAsset,
    onSelectAsset,
    onRecenterBoard,
    onToggleLayer,
    onZoomIn,
    onZoomOut,
    onRotateAsset,
    onDeleteAsset,
    onDuplicateAsset,
    onUndoAction,
    onRedoAction,
    disabled = false,
  } = options;

  const activeKeysRef = useRef<Set<string>>(new Set());
  const lastActionTimeRef = useRef<number>(0);

  // Key bindings configuration
  const keyBindings: KeyBinding[] = [
    // Asset movement (fine control)
    {
      keys: ['ArrowUp'],
      action: () => onMoveAsset?.('up', 1),
      description: 'Move selected asset up (1px)',
      category: 'manipulation',
      preventDefault: true,
    },
    {
      keys: ['ArrowDown'],
      action: () => onMoveAsset?.('down', 1),
      description: 'Move selected asset down (1px)',
      category: 'manipulation',
      preventDefault: true,
    },
    {
      keys: ['ArrowLeft'],
      action: () => onMoveAsset?.('left', 1),
      description: 'Move selected asset left (1px)',
      category: 'manipulation',
      preventDefault: true,
    },
    {
      keys: ['ArrowRight'],
      action: () => onMoveAsset?.('right', 1),
      description: 'Move selected asset right (1px)',
      category: 'manipulation',
      preventDefault: true,
    },

    // Asset movement (coarse control with Shift)
    {
      keys: ['Shift', 'ArrowUp'],
      action: () => onMoveAsset?.('up', 10),
      description: 'Move selected asset up (10px)',
      category: 'manipulation',
      preventDefault: true,
    },
    {
      keys: ['Shift', 'ArrowDown'],
      action: () => onMoveAsset?.('down', 10),
      description: 'Move selected asset down (10px)',
      category: 'manipulation',
      preventDefault: true,
    },
    {
      keys: ['Shift', 'ArrowLeft'],
      action: () => onMoveAsset?.('left', 10),
      description: 'Move selected asset left (10px)',
      category: 'manipulation',
      preventDefault: true,
    },
    {
      keys: ['Shift', 'ArrowRight'],
      action: () => onMoveAsset?.('right', 10),
      description: 'Move selected asset right (10px)',
      category: 'manipulation',
      preventDefault: true,
    },

    // Asset selection
    {
      keys: ['Tab'],
      action: () => onSelectAsset?.('next'),
      description: 'Select next asset',
      category: 'selection',
      preventDefault: true,
    },
    {
      keys: ['Shift', 'Tab'],
      action: () => onSelectAsset?.('previous'),
      description: 'Select previous asset',
      category: 'selection',
      preventDefault: true,
    },

    // Asset manipulation
    {
      keys: ['r'],
      action: () => onRotateAsset?.(90),
      description: 'Rotate asset 90 degrees clockwise',
      category: 'manipulation',
    },
    {
      keys: ['Shift', 'r'],
      action: () => onRotateAsset?.(-90),
      description: 'Rotate asset 90 degrees counterclockwise',
      category: 'manipulation',
    },
    {
      keys: ['Delete'],
      action: () => onDeleteAsset?.(),
      description: 'Delete selected asset',
      category: 'manipulation',
    },
    {
      keys: ['Backspace'],
      action: () => onDeleteAsset?.(),
      description: 'Delete selected asset',
      category: 'manipulation',
    },
    {
      keys: ['d'],
      action: () => onDuplicateAsset?.(),
      description: 'Duplicate selected asset',
      category: 'manipulation',
    },

    // Board navigation
    {
      keys: ['c'],
      action: () => onRecenterBoard?.(),
      description: 'Recenter board view',
      category: 'board',
    },
    {
      keys: ['Home'],
      action: () => onRecenterBoard?.(),
      description: 'Recenter board view',
      category: 'board',
    },
    {
      keys: ['+'],
      action: () => onZoomIn?.(),
      description: 'Zoom in',
      category: 'board',
    },
    {
      keys: ['='],
      action: () => onZoomIn?.(),
      description: 'Zoom in',
      category: 'board',
    },
    {
      keys: ['-'],
      action: () => onZoomOut?.(),
      description: 'Zoom out',
      category: 'board',
    },

    // System actions
    {
      keys: ['Meta', 'z'],
      action: () => onUndoAction?.(),
      description: 'Undo last action',
      category: 'system',
      preventDefault: true,
    },
    {
      keys: ['Control', 'z'],
      action: () => onUndoAction?.(),
      description: 'Undo last action',
      category: 'system',
      preventDefault: true,
    },
    {
      keys: ['Meta', 'Shift', 'z'],
      action: () => onRedoAction?.(),
      description: 'Redo last action',
      category: 'system',
      preventDefault: true,
    },
    {
      keys: ['Control', 'y'],
      action: () => onRedoAction?.(),
      description: 'Redo last action',
      category: 'system',
      preventDefault: true,
    },
  ];

  // Check if current key combination matches a binding
  const matchesKeyBinding = useCallback((binding: KeyBinding): boolean => {
    if (binding.keys.length !== activeKeysRef.current.size) return false;

    return binding.keys.every(key => activeKeysRef.current.has(key));
  }, []);

  // Throttle rapid key actions
  const throttleAction = useCallback((action: () => void, delay = 50): boolean => {
    const now = Date.now();
    if (now - lastActionTimeRef.current < delay) return false;

    lastActionTimeRef.current = now;
    action();
    return true;
  }, []);

  // Handle keydown events
  const handleKeyDown = useCallback((event: KeyboardEvent) => {
    if (disabled) return;

    // Don't interfere with input elements
    const target = event.target as HTMLElement;
    if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable) {
      return;
    }

    const key = event.key;
    activeKeysRef.current.add(key);

    // Find matching key binding
    const matchingBinding = keyBindings.find(matchesKeyBinding);

    if (matchingBinding) {
      if (matchingBinding.preventDefault) {
        event.preventDefault();
      }

      // Throttle movement actions more aggressively
      const isMovement = matchingBinding.category === 'manipulation' &&
                        matchingBinding.keys.some(k => k.startsWith('Arrow'));
      const delay = isMovement ? 16 : 100; // 60fps for movement, slower for other actions

      throttleAction(matchingBinding.action, delay);
    }
  }, [disabled, keyBindings, matchesKeyBinding, throttleAction]);

  // Handle keyup events
  const handleKeyUp = useCallback((event: KeyboardEvent) => {
    if (disabled) return;

    activeKeysRef.current.delete(event.key);
  }, [disabled]);

  // Blur event to clear active keys
  const handleBlur = useCallback(() => {
    activeKeysRef.current.clear();
  }, []);

  // Set up event listeners
  useEffect(() => {
    if (disabled) return;

    document.addEventListener('keydown', handleKeyDown);
    document.addEventListener('keyup', handleKeyUp);
    window.addEventListener('blur', handleBlur);

    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.removeEventListener('keyup', handleKeyUp);
      window.removeEventListener('blur', handleBlur);
    };
  }, [disabled, handleKeyDown, handleKeyUp, handleBlur]);

  // Get help text for keyboard shortcuts
  const getKeyboardHelp = useCallback(() => {
    const categories = keyBindings.reduce((acc, binding) => {
      if (!acc[binding.category]) {
        acc[binding.category] = [];
      }
      acc[binding.category].push({
        keys: binding.keys.join(' + '),
        description: binding.description,
      });
      return acc;
    }, {} as Record<string, { keys: string; description: string }[]>);

    return categories;
  }, [keyBindings]);

  // Announce current action for screen readers
  const announceAction = useCallback((message: string) => {
    const announcement = document.createElement('div');
    announcement.setAttribute('aria-live', 'polite');
    announcement.setAttribute('aria-atomic', 'true');
    announcement.className = 'sr-only';
    announcement.textContent = message;

    document.body.appendChild(announcement);

    setTimeout(() => {
      document.body.removeChild(announcement);
    }, 1000);
  }, []);

  return {
    keyBindings,
    getKeyboardHelp,
    announceAction,
    activeKeys: Array.from(activeKeysRef.current),
  };
}
