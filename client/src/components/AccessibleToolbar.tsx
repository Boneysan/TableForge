/**
 * Accessible toolbar component with ARIA labeling and keyboard navigation
 * Provides comprehensive accessibility support for game board tools
 */

import React, { useRef, useState, useCallback } from 'react';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import { useFocusManagement } from '../hooks/useFocusManagement';
import { useKeyboardNavigation } from '../hooks/useKeyboardNavigation';
import {
  Move,
  RotateCw,
  Copy,
  Trash2,
  ZoomIn,
  ZoomOut,
  Home,
  Layers,
  Grid3X3,
  Ruler,
  Palette,
  Settings,
  Keyboard,
} from 'lucide-react';

interface ToolbarItem {
  id: string;
  label: string;
  icon: React.ComponentType<{ size?: number; className?: string }>;
  action: () => void;
  hotkey?: string;
  category: 'movement' | 'manipulation' | 'view' | 'tools' | 'settings';
  disabled?: boolean;
  pressed?: boolean;
}

interface AccessibleToolbarProps {
  onMoveMode?: () => void;
  onRotateMode?: () => void;
  onCopyAsset?: () => void;
  onDeleteAsset?: () => void;
  onZoomIn?: () => void;
  onZoomOut?: () => void;
  onRecenter?: () => void;
  onToggleLayers?: () => void;
  onToggleGrid?: () => void;
  onRulerTool?: () => void;
  onColorPicker?: () => void;
  onSettings?: () => void;
  onShowKeyboardHelp?: () => void;
  selectedTool?: string;
  disabled?: boolean;
  className?: string;
}

export function AccessibleToolbar({
  onMoveMode,
  onRotateMode,
  onCopyAsset,
  onDeleteAsset,
  onZoomIn,
  onZoomOut,
  onRecenter,
  onToggleLayers,
  onToggleGrid,
  onRulerTool,
  onColorPicker,
  onSettings,
  onShowKeyboardHelp,
  selectedTool,
  disabled = false,
  className = '',
}: AccessibleToolbarProps) {
  const toolbarRef = useRef<HTMLDivElement>(null);
  const [activeSection, setActiveSection] = useState<string | null>(null);

  // Toolbar items configuration
  const toolbarItems: ToolbarItem[] = [
    {
      id: 'move',
      label: 'Move tool - Click and drag to move assets',
      icon: Move,
      action: () => onMoveMode?.(),
      hotkey: 'M',
      category: 'movement',
      pressed: selectedTool === 'move',
    },
    {
      id: 'rotate',
      label: 'Rotate tool - Click and drag to rotate assets',
      icon: RotateCw,
      action: () => onRotateMode?.(),
      hotkey: 'R',
      category: 'manipulation',
      pressed: selectedTool === 'rotate',
    },
    {
      id: 'copy',
      label: 'Copy selected asset',
      icon: Copy,
      action: () => onCopyAsset?.(),
      hotkey: 'Ctrl+D',
      category: 'manipulation',
    },
    {
      id: 'delete',
      label: 'Delete selected asset',
      icon: Trash2,
      action: () => onDeleteAsset?.(),
      hotkey: 'Del',
      category: 'manipulation',
    },
    {
      id: 'zoom-in',
      label: 'Zoom in on board',
      icon: ZoomIn,
      action: () => onZoomIn?.(),
      hotkey: '+',
      category: 'view',
    },
    {
      id: 'zoom-out',
      label: 'Zoom out from board',
      icon: ZoomOut,
      action: () => onZoomOut?.(),
      hotkey: '-',
      category: 'view',
    },
    {
      id: 'recenter',
      label: 'Recenter board view',
      icon: Home,
      action: () => onRecenter?.(),
      hotkey: 'C',
      category: 'view',
    },
    {
      id: 'layers',
      label: 'Toggle layer panel',
      icon: Layers,
      action: () => onToggleLayers?.(),
      hotkey: 'L',
      category: 'tools',
    },
    {
      id: 'grid',
      label: 'Toggle grid overlay',
      icon: Grid3X3,
      action: () => onToggleGrid?.(),
      hotkey: 'G',
      category: 'tools',
    },
    {
      id: 'ruler',
      label: 'Ruler measurement tool',
      icon: Ruler,
      action: () => onRulerTool?.(),
      hotkey: 'U',
      category: 'tools',
      pressed: selectedTool === 'ruler',
    },
    {
      id: 'color-picker',
      label: 'Color picker tool',
      icon: Palette,
      action: () => onColorPicker?.(),
      hotkey: 'P',
      category: 'tools',
      pressed: selectedTool === 'color-picker',
    },
    {
      id: 'settings',
      label: 'Open settings panel',
      icon: Settings,
      action: () => onSettings?.(),
      hotkey: 'S',
      category: 'settings',
    },
    {
      id: 'keyboard-help',
      label: 'Show keyboard shortcuts',
      icon: Keyboard,
      action: () => onShowKeyboardHelp?.(),
      hotkey: '?',
      category: 'settings',
    },
  ];

  // Group items by category
  const groupedItems = toolbarItems.reduce((acc, item) => {
    if (!acc[item.category]) {
      acc[item.category] = [];
    }
    acc[item.category].push(item);
    return acc;
  }, {} as Record<string, ToolbarItem[]>);

  // Focus management
  const { focusedElementId, isKeyboardNavigation, moveFocus } = useFocusManagement({
    containerRef: toolbarRef,
    onFocusChange: (focusedId) => {
      if (focusedId) {
        const item = toolbarItems.find(i => i.id === focusedId);
        if (item) {
          setActiveSection(item.category);
        }
      }
    },
  });

  // Keyboard navigation
  const { announceAction } = useKeyboardNavigation({
    onSelectAsset: (direction) => {
      if (direction === 'next') {
        moveFocus('next');
      } else {
        moveFocus('previous');
      }
    },
    disabled,
  });

  // Handle toolbar item activation
  const handleItemAction = useCallback((item: ToolbarItem) => {
    if (disabled || item.disabled) return;

    item.action();
    announceAction(`${item.label} activated`);
  }, [disabled, announceAction]);

  // Handle keyboard events
  const handleKeyDown = useCallback((event: React.KeyboardEvent, item: ToolbarItem) => {
    switch (event.key) {
      case 'Enter':
      case ' ':
        event.preventDefault();
        handleItemAction(item);
        break;

      case 'ArrowLeft':
      case 'ArrowUp':
        event.preventDefault();
        moveFocus('previous');
        break;

      case 'ArrowRight':
      case 'ArrowDown':
        event.preventDefault();
        moveFocus('next');
        break;

      case 'Home':
        event.preventDefault();
        moveFocus('next'); // This will focus the first element
        break;

      case 'End':
        event.preventDefault();
        // Focus last element by going to first then navigating backwards
        moveFocus('previous');
        break;
    }
  }, [handleItemAction, moveFocus]);

  // Render toolbar section
  const renderSection = (category: string, items: ToolbarItem[]) => (
    <div key={category} className="flex items-center gap-1">
      {items.map((item) => (
        <Button
          key={item.id}
          variant={item.pressed ? 'default' : 'ghost'}
          size="sm"
          className={`
            relative p-2 h-9 w-9
            ${focusedElementId === item.id && isKeyboardNavigation
              ? 'ring-2 ring-blue-500 ring-offset-2 ring-offset-background'
              : ''
            }
            ${item.disabled ? 'opacity-50 cursor-not-allowed' : ''}
            hover:bg-muted focus-visible:ring-2 focus-visible:ring-blue-500
          `}
          onClick={() => handleItemAction(item)}
          onKeyDown={(e) => handleKeyDown(e, item)}
          disabled={disabled || item.disabled}
          data-focus-id={item.id}
          data-focusable="true"
          data-testid={`toolbar-${item.id}`}
          aria-label={item.label}
          aria-pressed={item.pressed}
          aria-describedby={`${item.id}-description`}
          title={`${item.label}${item.hotkey ? ` (${item.hotkey})` : ''}`}
        >
          <item.icon size={16} className="text-current" />

          {/* Hotkey indicator */}
          {item.hotkey && (
            <span className="absolute -bottom-1 -right-1 text-xs opacity-60 pointer-events-none">
              {item.hotkey.length <= 2 ? item.hotkey : '⌘'}
            </span>
          )}

          {/* Hidden description for screen readers */}
          <span id={`${item.id}-description`} className="sr-only">
            {item.label}
            {item.hotkey && `. Hotkey: ${item.hotkey}`}
            {item.pressed && '. Currently active'}
          </span>
        </Button>
      ))}
    </div>
  );

  return (
    <div
      ref={toolbarRef}
      className={`
        inline-flex items-center gap-2 p-2 bg-background border rounded-lg shadow-sm
        ${disabled ? 'opacity-50' : ''}
        ${className}
      `}
      role="toolbar"
      aria-label="Game board tools"
      aria-orientation="horizontal"
      data-testid="accessible-toolbar"
    >
      {Object.entries(groupedItems).map(([category, items], index) => (
        <React.Fragment key={category}>
          {index > 0 && <Separator orientation="vertical" className="h-6" />}
          {renderSection(category, items)}
        </React.Fragment>
      ))}

      {/* Status region for screen reader announcements */}
      <div
        role="status"
        aria-live="polite"
        aria-atomic="true"
        className="sr-only"
        data-testid="toolbar-status"
      >
        {activeSection && `${activeSection} tools section`}
      </div>
    </div>
  );
}
