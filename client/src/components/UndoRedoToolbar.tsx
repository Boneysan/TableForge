/**
 * Undo/Redo toolbar component with visual feedback and keyboard shortcuts
 */

import React from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuItem,
} from '@/components/ui/dropdown-menu';
import { 
  Undo2, 
  Redo2, 
  History, 
  Save, 
  Clock, 
  ChevronDown,
  Trash2,
  Download,
  Upload,
} from 'lucide-react';
import { useCommandStack } from '../hooks/useCommandStack';
import { useGameSnapshot } from '../hooks/useGameSnapshot';

interface UndoRedoToolbarProps {
  roomId: string;
  userId: string;
  currentGameState: any;
  onRestoreState: (state: any) => Promise<void>;
  className?: string;
}

export function UndoRedoToolbar({
  roomId,
  userId,
  currentGameState,
  onRestoreState,
  className = '',
}: UndoRedoToolbarProps) {
  const {
    canUndo,
    canRedo,
    isExecuting,
    stackSize,
    undo,
    redo,
    clearHistory,
    getHistory,
  } = useCommandStack({ roomId, userId });

  const {
    snapshots,
    isCreatingSnapshot,
    isRestoringSnapshot,
    createSnapshot,
    restoreSnapshot,
    deleteSnapshot,
    exportSnapshots,
    importSnapshots,
    getStatistics,
  } = useGameSnapshot({ roomId, userId });

  const history = getHistory();
  const stats = getStatistics();

  const handleCreateSnapshot = async () => {
    if (!currentGameState) return;
    
    await createSnapshot(
      currentGameState,
      'manual',
      `Manual save ${new Date().toLocaleTimeString()}`,
      'User created checkpoint'
    );
  };

  const handleRestoreSnapshot = async (snapshotId: string) => {
    await restoreSnapshot(snapshotId, onRestoreState);
  };

  const handleExportSnapshots = () => {
    const exportData = exportSnapshots();
    const blob = new Blob([JSON.stringify(exportData, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vorpal-snapshots-${roomId}-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleImportSnapshots = () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.onchange = (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (file) {
        const reader = new FileReader();
        reader.onload = (e) => {
          try {
            const importData = JSON.parse(e.target?.result as string);
            importSnapshots(importData);
          } catch (error) {
            console.error('Failed to import snapshots:', error);
          }
        };
        reader.readAsText(file);
      }
    };
    input.click();
  };

  return (
    <TooltipProvider>
      <div className={`flex items-center gap-2 p-2 bg-background border rounded-lg ${className}`}>
        {/* Undo Button */}
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="sm"
              onClick={undo}
              disabled={!canUndo || isExecuting}
              data-testid="undo-button"
            >
              <Undo2 className="w-4 h-4" />
            </Button>
          </TooltipTrigger>
          <TooltipContent>
            <div className="text-xs">
              <div>Undo (Ctrl+Z)</div>
              {history.undo.length > 0 && (
                <div className="text-muted-foreground">
                  {history.undo[history.undo.length - 1].description}
                </div>
              )}
            </div>
          </TooltipContent>
        </Tooltip>

        {/* Redo Button */}
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="sm"
              onClick={redo}
              disabled={!canRedo || isExecuting}
              data-testid="redo-button"
            >
              <Redo2 className="w-4 h-4" />
            </Button>
          </TooltipTrigger>
          <TooltipContent>
            <div className="text-xs">
              <div>Redo (Ctrl+Y)</div>
              {history.redo.length > 0 && (
                <div className="text-muted-foreground">
                  {history.redo[0].description}
                </div>
              )}
            </div>
          </TooltipContent>
        </Tooltip>

        <Separator orientation="vertical" className="h-6" />

        {/* Command History Dropdown */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="sm" data-testid="history-dropdown">
              <History className="w-4 h-4 mr-1" />
              <Badge variant="secondary" className="ml-1 h-5 text-xs">
                {stackSize}
              </Badge>
              <ChevronDown className="w-3 h-3 ml-1" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" className="w-80">
            <DropdownMenuLabel>Command History</DropdownMenuLabel>
            <DropdownMenuSeparator />
            
            {history.undo.length === 0 && history.redo.length === 0 ? (
              <div className="p-2 text-sm text-muted-foreground">
                No commands in history
              </div>
            ) : (
              <>
                {history.redo.length > 0 && (
                  <>
                    <DropdownMenuLabel className="text-xs text-muted-foreground">
                      Available to Redo
                    </DropdownMenuLabel>
                    {history.redo.slice(0, 5).map((command, index) => (
                      <DropdownMenuItem key={command.id} className="text-xs">
                        <Redo2 className="w-3 h-3 mr-2" />
                        <span>{command.description}</span>
                        {command.merged && (
                          <Badge variant="outline" className="ml-auto h-4 text-xs">
                            merged
                          </Badge>
                        )}
                      </DropdownMenuItem>
                    ))}
                    <DropdownMenuSeparator />
                  </>
                )}
                
                {history.undo.length > 0 && (
                  <>
                    <DropdownMenuLabel className="text-xs text-muted-foreground">
                      Available to Undo
                    </DropdownMenuLabel>
                    {history.undo.slice(-5).reverse().map((command, index) => (
                      <DropdownMenuItem key={command.id} className="text-xs">
                        <Undo2 className="w-3 h-3 mr-2" />
                        <span>{command.description}</span>
                        {command.merged && (
                          <Badge variant="outline" className="ml-auto h-4 text-xs">
                            merged
                          </Badge>
                        )}
                      </DropdownMenuItem>
                    ))}
                  </>
                )}
                
                <DropdownMenuSeparator />
                <DropdownMenuItem 
                  onClick={clearHistory}
                  className="text-destructive text-xs"
                >
                  <Trash2 className="w-3 h-3 mr-2" />
                  Clear History
                </DropdownMenuItem>
              </>
            )}
          </DropdownMenuContent>
        </DropdownMenu>

        <Separator orientation="vertical" className="h-6" />

        {/* Create Snapshot Button */}
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="sm"
              onClick={handleCreateSnapshot}
              disabled={isCreatingSnapshot}
              data-testid="create-snapshot-button"
            >
              <Save className="w-4 h-4" />
            </Button>
          </TooltipTrigger>
          <TooltipContent>
            <div className="text-xs">
              Create Snapshot
              <div className="text-muted-foreground">Save current game state</div>
            </div>
          </TooltipContent>
        </Tooltip>

        {/* Snapshots Dropdown */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="sm" data-testid="snapshots-dropdown">
              <Clock className="w-4 h-4 mr-1" />
              <Badge variant="secondary" className="ml-1 h-5 text-xs">
                {snapshots.length}
              </Badge>
              <ChevronDown className="w-3 h-3 ml-1" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" className="w-96">
            <DropdownMenuLabel>Game Snapshots</DropdownMenuLabel>
            <DropdownMenuSeparator />
            
            {snapshots.length === 0 ? (
              <div className="p-2 text-sm text-muted-foreground">
                No snapshots available
              </div>
            ) : (
              <>
                {snapshots.slice(0, 10).map((snapshot) => (
                  <DropdownMenuItem 
                    key={snapshot.id}
                    onClick={() => handleRestoreSnapshot(snapshot.id)}
                    disabled={isRestoringSnapshot}
                    className="flex-col items-start p-3"
                  >
                    <div className="flex items-center justify-between w-full">
                      <span className="font-medium text-sm">
                        {snapshot.name || `Snapshot ${new Date(snapshot.timestamp).toLocaleString()}`}
                      </span>
                      <div className="flex items-center gap-2">
                        <Badge 
                          variant={snapshot.type === 'manual' ? 'default' : 'secondary'}
                          className="h-5 text-xs"
                        >
                          {snapshot.type}
                        </Badge>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={(e) => {
                            e.stopPropagation();
                            deleteSnapshot(snapshot.id);
                          }}
                          className="h-6 w-6 p-0 hover:bg-destructive hover:text-destructive-foreground"
                        >
                          <Trash2 className="w-3 h-3" />
                        </Button>
                      </div>
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">
                      {new Date(snapshot.timestamp).toLocaleString()}
                      {snapshot.description && ` • ${snapshot.description}`}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      Size: {(snapshot.size / 1024).toFixed(1)}KB
                    </div>
                  </DropdownMenuItem>
                ))}
                
                {snapshots.length > 10 && (
                  <div className="p-2 text-xs text-muted-foreground text-center">
                    ... and {snapshots.length - 10} more snapshots
                  </div>
                )}
                
                <DropdownMenuSeparator />
                
                <div className="p-2 space-y-1">
                  <div className="text-xs text-muted-foreground">
                    Total: {stats.totalSnapshots} snapshots, {(stats.totalSize / 1024).toFixed(1)}KB
                  </div>
                  <div className="flex gap-1">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={handleExportSnapshots}
                      className="flex-1 h-7 text-xs"
                    >
                      <Download className="w-3 h-3 mr-1" />
                      Export
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={handleImportSnapshots}
                      className="flex-1 h-7 text-xs"
                    >
                      <Upload className="w-3 h-3 mr-1" />
                      Import
                    </Button>
                  </div>
                </div>
              </>
            )}
          </DropdownMenuContent>
        </DropdownMenu>

        {/* Status Indicator */}
        {isExecuting && (
          <div className="flex items-center gap-1 text-xs text-muted-foreground ml-2">
            <div className="w-2 h-2 bg-yellow-500 rounded-full animate-pulse" />
            Executing...
          </div>
        )}
        
        {(isCreatingSnapshot || isRestoringSnapshot) && (
          <div className="flex items-center gap-1 text-xs text-muted-foreground ml-2">
            <div className="w-2 h-2 bg-blue-500 rounded-full animate-pulse" />
            {isCreatingSnapshot ? 'Saving...' : 'Restoring...'}
          </div>
        )}
      </div>
    </TooltipProvider>
  );
}