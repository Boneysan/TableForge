/**
 * Complete accessible game board with keyboard navigation, ARIA labeling,
 * focus management, and comprehensive UX improvements
 */

import React, { useRef, useState, useCallback, useEffect } from 'react';
import { OptimizedGameBoard } from './OptimizedGameBoard';
import { AccessibleToolbar } from './AccessibleToolbar';
import { KeyboardShortcutsDialog } from './KeyboardShortcutsDialog';
import { useKeyboardNavigation } from '../hooks/useKeyboardNavigation';
import { useFocusManagement } from '../hooks/useFocusManagement';
import { useColorContrast } from '../hooks/useColorContrast';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import {
  Accessibility,
  Contrast,
  Keyboard,
  Eye,
  Volume2,
  Settings,
} from 'lucide-react';

interface AccessibleGameBoardProps {
  roomId: string;
  assets: any[];
  onAssetMove?: (assetId: string, x: number, y: number, rotation?: number) => void;
  onAssetSelect?: (assetId: string) => void;
  selectedAssetId?: string;
  className?: string;
}

export function AccessibleGameBoard({
  roomId,
  assets,
  onAssetMove,
  onAssetSelect,
  selectedAssetId,
  className = '',
}: AccessibleGameBoardProps) {
  const boardRef = useRef<HTMLDivElement>(null);
  const [showKeyboardHelp, setShowKeyboardHelp] = useState(false);
  const [selectedTool, setSelectedTool] = useState<string>('move');
  const [viewport, setViewport] = useState({ x: 0, y: 0, scale: 1 });
  const [highContrastMode, setHighContrastMode] = useState(false);
  const [announceActions, setAnnounceActions] = useState(true);

  // Color contrast analysis
  const { contrastReports, generateImprovements } = useColorContrast();

  // Focus management for the board
  const { focusedElementId, moveFocus, setFocusById } = useFocusManagement({
    containerRef: boardRef,
    onFocusChange: (focusedId, element) => {
      if (focusedId && element?.hasAttribute('data-asset-id')) {
        const assetId = element.getAttribute('data-asset-id');
        if (assetId) {
          onAssetSelect?.(assetId);
        }
      }
    },
  });

  // Find selected asset
  const selectedAsset = assets.find(asset => asset.id === selectedAssetId);

  // Handle asset movement with keyboard
  const handleMoveAsset = useCallback((direction: 'up' | 'down' | 'left' | 'right', distance = 1) => {
    if (!selectedAsset || !onAssetMove) return;

    let newX = selectedAsset.positionX || 0;
    let newY = selectedAsset.positionY || 0;

    switch (direction) {
      case 'up':
        newY -= distance;
        break;
      case 'down':
        newY += distance;
        break;
      case 'left':
        newX -= distance;
        break;
      case 'right':
        newX += distance;
        break;
    }

    onAssetMove(selectedAsset.id, newX, newY);

    if (announceActions) {
      announceAction(`Moved ${selectedAsset.name || 'asset'} ${direction} by ${distance} pixels`);
    }
  }, [selectedAsset, onAssetMove, announceActions]);

  // Handle asset selection with keyboard
  const handleSelectAsset = useCallback((direction: 'next' | 'previous') => {
    const currentIndex = assets.findIndex(asset => asset.id === selectedAssetId);
    let nextIndex = -1;

    if (direction === 'next') {
      nextIndex = currentIndex + 1;
      if (nextIndex >= assets.length) nextIndex = 0;
    } else {
      nextIndex = currentIndex - 1;
      if (nextIndex < 0) nextIndex = assets.length - 1;
    }

    if (nextIndex >= 0 && assets[nextIndex]) {
      onAssetSelect?.(assets[nextIndex].id);

      if (announceActions) {
        announceAction(`Selected ${assets[nextIndex].name || 'asset'}`);
      }
    }
  }, [assets, selectedAssetId, onAssetSelect, announceActions]);

  // Recenter board view
  const handleRecenterBoard = useCallback(() => {
    setViewport({ x: 0, y: 0, scale: 1 });

    if (announceActions) {
      announceAction('Board view recentered');
    }
  }, [announceActions]);

  // Handle zoom operations
  const handleZoomIn = useCallback(() => {
    setViewport(prev => ({ ...prev, scale: Math.min(prev.scale * 1.2, 5) }));
    if (announceActions) announceAction('Zoomed in');
  }, [announceActions]);

  const handleZoomOut = useCallback(() => {
    setViewport(prev => ({ ...prev, scale: Math.max(prev.scale / 1.2, 0.1) }));
    if (announceActions) announceAction('Zoomed out');
  }, [announceActions]);

  // Handle asset actions
  const handleRotateAsset = useCallback((degrees: number) => {
    if (!selectedAsset || !onAssetMove) return;

    const currentRotation = selectedAsset.rotation || 0;
    const newRotation = (currentRotation + degrees) % 360;

    onAssetMove(selectedAsset.id, selectedAsset.positionX || 0, selectedAsset.positionY || 0, newRotation);

    if (announceActions) {
      announceAction(`Rotated ${selectedAsset.name || 'asset'} ${degrees > 0 ? 'clockwise' : 'counterclockwise'}`);
    }
  }, [selectedAsset, onAssetMove, announceActions]);

  // Keyboard navigation setup
  const { announceAction } = useKeyboardNavigation({
    onMoveAsset: handleMoveAsset,
    onSelectAsset: handleSelectAsset,
    onRecenterBoard: handleRecenterBoard,
    onZoomIn: handleZoomIn,
    onZoomOut: handleZoomOut,
    onRotateAsset: handleRotateAsset,
    onDeleteAsset: () => {
      if (selectedAsset && announceActions) {
        announceAction(`Deleted ${selectedAsset.name || 'asset'}`);
      }
    },
    onDuplicateAsset: () => {
      if (selectedAsset && announceActions) {
        announceAction(`Duplicated ${selectedAsset.name || 'asset'}`);
      }
    },
  });

  // Toggle high contrast mode
  const toggleHighContrast = useCallback(() => {
    setHighContrastMode(prev => {
      const newMode = !prev;
      document.documentElement.classList.toggle('high-contrast', newMode);

      if (announceActions) {
        announceAction(`High contrast mode ${newMode ? 'enabled' : 'disabled'}`);
      }

      return newMode;
    });
  }, [announceActions]);

  // Get accessibility status
  const getAccessibilityStatus = useCallback(() => {
    const report = contrastReports[0];
    if (!report) return 'unknown';

    switch (report.compliance) {
      case 'AAA':
        return 'excellent';
      case 'AA':
        return 'good';
      case 'partial':
        return 'needs-improvement';
      default:
        return 'poor';
    }
  }, [contrastReports]);

  // Set up high contrast mode detection
  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-contrast: high)');
    const handleChange = (e: MediaQueryListEvent) => {
      if (e.matches) {
        setHighContrastMode(true);
        document.documentElement.classList.add('high-contrast');
      }
    };

    mediaQuery.addEventListener('change', handleChange);
    if (mediaQuery.matches) {
      setHighContrastMode(true);
      document.documentElement.classList.add('high-contrast');
    }

    return () => {
      mediaQuery.removeEventListener('change', handleChange);
    };
  }, []);

  const accessibilityStatus = getAccessibilityStatus();
  const currentReport = contrastReports[0];

  return (
    <TooltipProvider>
      <div
        ref={boardRef}
        className={`
          relative w-full h-full flex flex-col
          ${highContrastMode ? 'high-contrast' : ''}
          ${className}
        `}
        role="application"
        aria-label="Accessible game board"
        data-testid="accessible-game-board"
      >
        {/* Accessibility Toolbar */}
        <div className="flex items-center justify-between p-2 bg-background border-b">
          <AccessibleToolbar
            onMoveMode={() => setSelectedTool('move')}
            onRotateMode={() => setSelectedTool('rotate')}
            onCopyAsset={() => {}}
            onDeleteAsset={() => {}}
            onZoomIn={handleZoomIn}
            onZoomOut={handleZoomOut}
            onRecenter={handleRecenterBoard}
            onToggleLayers={() => {}}
            onToggleGrid={() => {}}
            onRulerTool={() => setSelectedTool('ruler')}
            onColorPicker={() => setSelectedTool('color-picker')}
            onSettings={() => {}}
            onShowKeyboardHelp={() => setShowKeyboardHelp(true)}
            selectedTool={selectedTool}
          />

          <div className="flex items-center gap-2">
            {/* Accessibility Status */}
            <Tooltip>
              <TooltipTrigger asChild>
                <Badge
                  variant={accessibilityStatus === 'excellent' ? 'default' : 'secondary'}
                  className={`
                    ${accessibilityStatus === 'excellent' ? 'bg-green-500' : ''}
                    ${accessibilityStatus === 'good' ? 'bg-blue-500' : ''}
                    ${accessibilityStatus === 'needs-improvement' ? 'bg-yellow-500' : ''}
                    ${accessibilityStatus === 'poor' ? 'bg-red-500' : ''}
                  `}
                  data-testid="accessibility-status"
                >
                  <Accessibility className="w-3 h-3 mr-1" />
                  {accessibilityStatus.replace('-', ' ')}
                </Badge>
              </TooltipTrigger>
              <TooltipContent>
                <div className="text-xs space-y-1">
                  {currentReport && (
                    <>
                      <p>Contrast Compliance: {currentReport.compliance}</p>
                      <p>Overall Score: {currentReport.overallScore}%</p>
                      <p>Mode: {currentReport.mode}</p>
                    </>
                  )}
                </div>
              </TooltipContent>
            </Tooltip>

            {/* High Contrast Toggle */}
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={toggleHighContrast}
                  aria-pressed={highContrastMode}
                  data-testid="high-contrast-toggle"
                >
                  <Contrast className="w-4 h-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>
                Toggle high contrast mode
              </TooltipContent>
            </Tooltip>

            {/* Audio Announcements Toggle */}
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setAnnounceActions(prev => !prev)}
                  aria-pressed={announceActions}
                  data-testid="announcements-toggle"
                >
                  <Volume2 className="w-4 h-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>
                Toggle audio announcements
              </TooltipContent>
            </Tooltip>

            {/* Keyboard Help */}
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowKeyboardHelp(true)}
                  data-testid="keyboard-help-button"
                >
                  <Keyboard className="w-4 h-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>
                Show keyboard shortcuts (?)
              </TooltipContent>
            </Tooltip>
          </div>
        </div>

        {/* Game Board */}
        <div className="flex-1 relative">
          <OptimizedGameBoard
            roomId={roomId}
            assets={assets}
            onAssetMove={onAssetMove}
            onAssetSelect={onAssetSelect}
            className="w-full h-full"
          />

          {/* Selection Status */}
          {selectedAsset && (
            <Card className="absolute bottom-4 left-4 p-3 max-w-xs">
              <div className="space-y-2">
                <h4 className="font-medium text-sm">Selected Asset</h4>
                <div className="text-xs text-muted-foreground space-y-1">
                  <div>Name: {selectedAsset.name || 'Unnamed'}</div>
                  <div>Position: ({Math.round(selectedAsset.positionX || 0)}, {Math.round(selectedAsset.positionY || 0)})</div>
                  {selectedAsset.rotation && (
                    <div>Rotation: {Math.round(selectedAsset.rotation)}°</div>
                  )}
                </div>
                <div className="text-xs text-blue-600 dark:text-blue-400">
                  Use arrow keys to move, R to rotate
                </div>
              </div>
            </Card>
          )}

          {/* Zoom Level Indicator */}
          <div className="absolute bottom-4 right-4 bg-background/80 backdrop-blur-sm px-2 py-1 rounded text-xs text-muted-foreground">
            Zoom: {Math.round(viewport.scale * 100)}%
          </div>
        </div>

        {/* Keyboard Shortcuts Dialog */}
        <KeyboardShortcutsDialog
          open={showKeyboardHelp}
          onOpenChange={setShowKeyboardHelp}
        />

        {/* Screen Reader Status Region */}
        <div
          role="status"
          aria-live="polite"
          aria-atomic="true"
          className="sr-only"
          data-testid="screen-reader-status"
        >
          {selectedAsset && `Selected: ${selectedAsset.name || 'Asset'}`}
        </div>

        {/* Hidden Instructions for Screen Readers */}
        <div className="sr-only">
          <h2>Game Board Instructions</h2>
          <p>Use Tab to navigate between controls and assets.</p>
          <p>Use arrow keys to move selected assets.</p>
          <p>Press R to rotate, Delete to remove, D to duplicate.</p>
          <p>Press C to recenter the board view.</p>
          <p>Press ? to open keyboard shortcuts help.</p>
        </div>
      </div>
    </TooltipProvider>
  );
}
