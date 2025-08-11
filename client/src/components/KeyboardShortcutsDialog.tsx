/**
 * Keyboard shortcuts help dialog with comprehensive accessibility information
 */

import React from 'react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogClose,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { ScrollArea } from '@/components/ui/scroll-area';
import { X, Keyboard } from 'lucide-react';

interface KeyboardShortcut {
  keys: string;
  description: string;
  category: string;
}

interface KeyboardShortcutsDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function KeyboardShortcutsDialog({
  open,
  onOpenChange,
}: KeyboardShortcutsDialogProps) {

  const shortcuts: KeyboardShortcut[] = [
    // Asset Movement
    { keys: '↑ ↓ ← →', description: 'Move selected asset (1px)', category: 'Asset Movement' },
    { keys: 'Shift + ↑ ↓ ← →', description: 'Move selected asset (10px)', category: 'Asset Movement' },
    { keys: 'R', description: 'Rotate asset 90° clockwise', category: 'Asset Movement' },
    { keys: 'Shift + R', description: 'Rotate asset 90° counterclockwise', category: 'Asset Movement' },

    // Asset Selection
    { keys: 'Tab', description: 'Select next asset', category: 'Asset Selection' },
    { keys: 'Shift + Tab', description: 'Select previous asset', category: 'Asset Selection' },
    { keys: 'Enter / Space', description: 'Activate focused element', category: 'Asset Selection' },

    // Asset Actions
    { keys: 'Delete / Backspace', description: 'Delete selected asset', category: 'Asset Actions' },
    { keys: 'D', description: 'Duplicate selected asset', category: 'Asset Actions' },
    { keys: 'Ctrl + C', description: 'Copy selected asset', category: 'Asset Actions' },
    { keys: 'Ctrl + V', description: 'Paste asset', category: 'Asset Actions' },

    // Board Navigation
    { keys: 'C / Home', description: 'Recenter board view', category: 'Board Navigation' },
    { keys: '+ / =', description: 'Zoom in', category: 'Board Navigation' },
    { keys: '-', description: 'Zoom out', category: 'Board Navigation' },
    { keys: 'G', description: 'Toggle grid', category: 'Board Navigation' },
    { keys: 'L', description: 'Toggle layers panel', category: 'Board Navigation' },

    // Tools
    { keys: 'M', description: 'Activate move tool', category: 'Tools' },
    { keys: 'U', description: 'Activate ruler tool', category: 'Tools' },
    { keys: 'P', description: 'Activate color picker', category: 'Tools' },
    { keys: 'S', description: 'Open settings', category: 'Tools' },

    // System
    { keys: 'Ctrl + Z / Cmd + Z', description: 'Undo last action', category: 'System' },
    { keys: 'Ctrl + Y / Cmd + Shift + Z', description: 'Redo last action', category: 'System' },
    { keys: 'Escape', description: 'Cancel current action', category: 'System' },
    { keys: '?', description: 'Show this help dialog', category: 'System' },

    // Accessibility
    { keys: 'Alt + Shift + K', description: 'Toggle high contrast mode', category: 'Accessibility' },
    { keys: 'Alt + Shift + F', description: 'Toggle focus indicators', category: 'Accessibility' },
    { keys: 'Alt + Shift + A', description: 'Announce current selection', category: 'Accessibility' },
  ];

  // Group shortcuts by category
  const groupedShortcuts = shortcuts.reduce((acc, shortcut) => {
    if (!acc[shortcut.category]) {
      acc[shortcut.category] = [];
    }
    acc[shortcut.category].push(shortcut);
    return acc;
  }, {} as Record<string, KeyboardShortcut[]>);

  // Category order for better UX
  const categoryOrder = [
    'Asset Selection',
    'Asset Movement',
    'Asset Actions',
    'Board Navigation',
    'Tools',
    'System',
    'Accessibility',
  ];

  // Render keyboard key
  const renderKey = (key: string) => (
    <Badge
      variant="outline"
      className="px-2 py-1 text-xs font-mono bg-muted"
      key={key}
    >
      {key}
    </Badge>
  );

  // Parse key combination string
  const parseKeys = (keyString: string) => {
    return keyString.split(' + ').map(renderKey);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        className="max-w-3xl max-h-[80vh]"
        aria-describedby="keyboard-shortcuts-description"
      >
        <DialogHeader>
          <div className="flex items-center justify-between">
            <DialogTitle className="flex items-center gap-2 text-xl">
              <Keyboard className="w-5 h-5" />
              Keyboard Shortcuts
            </DialogTitle>
            <DialogClose asChild>
              <Button
                variant="ghost"
                size="sm"
                aria-label="Close keyboard shortcuts dialog"
              >
                <X className="w-4 h-4" />
              </Button>
            </DialogClose>
          </div>
          <p id="keyboard-shortcuts-description" className="text-sm text-muted-foreground">
            Learn keyboard shortcuts to navigate and control the game board efficiently.
            Press Escape to close this dialog.
          </p>
        </DialogHeader>

        <ScrollArea className="max-h-[60vh] pr-4">
          <div className="space-y-6">
            {categoryOrder.map((category) => {
              const categoryShortcuts = groupedShortcuts[category];
              if (!categoryShortcuts) return null;

              return (
                <div key={category} className="space-y-3">
                  <h3 className="text-lg font-semibold text-foreground border-b pb-2">
                    {category}
                  </h3>
                  <div className="grid gap-3">
                    {categoryShortcuts.map((shortcut, index) => (
                      <div
                        key={`${category}-${index}`}
                        className="flex items-center justify-between py-2 px-3 rounded-lg bg-muted/30 hover:bg-muted/50 transition-colors"
                      >
                        <span className="text-sm text-foreground flex-1">
                          {shortcut.description}
                        </span>
                        <div className="flex items-center gap-1 ml-4">
                          {parseKeys(shortcut.keys)}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}

            <Separator className="my-6" />

            {/* Additional accessibility information */}
            <div className="space-y-3 p-4 bg-blue-50 dark:bg-blue-950/30 rounded-lg">
              <h3 className="text-sm font-semibold text-blue-900 dark:text-blue-100">
                Accessibility Tips
              </h3>
              <ul className="text-sm text-blue-800 dark:text-blue-200 space-y-2 list-disc list-inside">
                <li>Use Tab and Shift+Tab to navigate between interface elements</li>
                <li>Press Enter or Space to activate buttons and controls</li>
                <li>Arrow keys move focus within toolbars and menus</li>
                <li>Screen readers will announce focus changes and actions</li>
                <li>High contrast mode improves visibility of focus indicators</li>
                <li>All mouse actions have keyboard equivalents</li>
              </ul>
            </div>
          </div>
        </ScrollArea>

        <div className="flex justify-between items-center pt-4 border-t">
          <p className="text-sm text-muted-foreground">
            Tip: Most shortcuts work when not typing in text fields
          </p>
          <DialogClose asChild>
            <Button variant="outline">
              Got it
            </Button>
          </DialogClose>
        </div>
      </DialogContent>
    </Dialog>
  );
}
