import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { GridOverlay, snapToGrid } from "./GridOverlay";
import { MeasurementTool } from "./MeasurementTool";
import { AnnotationSystem } from "./AnnotationSystem";
import { authenticatedApiRequest } from "@/lib/authClient";
import type { GameAsset, BoardAsset, CardPile, CardDeck } from "@shared/schema";

interface GameBoardProps {
  assets: GameAsset[];
  boardAssets: BoardAsset[];
  onAssetMoved: (assetId: string, x: number, y: number) => void;
  onAssetPlaced: (assetId: string, x: number, y: number) => void;
  playerRole: 'admin' | 'player';
  roomId: string;
  roomBoardWidth?: number;
  roomBoardHeight?: number;
  'data-testid'?: string;
}

export function GameBoard({ 
  assets, 
  boardAssets, 
  onAssetMoved, 
  onAssetPlaced, 
  playerRole,
  roomId,
  roomBoardWidth = 800,
  roomBoardHeight = 600,
  'data-testid': testId 
}: GameBoardProps) {
  // Board Tools State
  const [showGrid, setShowGrid] = useState(false);
  const [gridSize, setGridSize] = useState(20);
  const [measurementActive, setMeasurementActive] = useState(false);
  const [annotationActive, setAnnotationActive] = useState(false);
  const [boardWidth, setBoardWidth] = useState(roomBoardWidth);
  const [boardHeight, setBoardHeight] = useState(roomBoardHeight);
  const [isResizing, setIsResizing] = useState(false);
  const [customSizeMode, setCustomSizeMode] = useState(false);
  const [customWidth, setCustomWidth] = useState(roomBoardWidth.toString());
  const [customHeight, setCustomHeight] = useState(roomBoardHeight.toString());

  // Update local state when room dimensions change
  useEffect(() => {
    setBoardWidth(roomBoardWidth);
    setBoardHeight(roomBoardHeight);
    setCustomWidth(roomBoardWidth.toString());
    setCustomHeight(roomBoardHeight.toString());
  }, [roomBoardWidth, roomBoardHeight]);
  
  const queryClient = useQueryClient();

  // Fetch card piles for the room
  const { data: cardPiles = [] } = useQuery({
    queryKey: ["/api/rooms", roomId, "piles"],
    enabled: !!roomId,
  });

  // Fetch card decks for the room
  const { data: cardDecks = [] } = useQuery({
    queryKey: ["/api/rooms", roomId, "decks"],
    enabled: !!roomId,
  });

  // Move pile mutation
  const movePileMutation = useMutation({
    mutationFn: async ({ pileId, x, y }: { pileId: string; x: number; y: number }) => {
      const response = await authenticatedApiRequest("PATCH", `/api/rooms/${roomId}/piles/${pileId}/position`, {
        positionX: x,
        positionY: y,
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/rooms", roomId, "piles"] });
    },
  });

  // Board size mutation - only for admins
  const updateBoardSizeMutation = useMutation({
    mutationFn: async ({ width, height }: { width: number; height: number }) => {
      console.log(`[GameBoard] Updating board size to ${width}x${height}`);
      const response = await authenticatedApiRequest("PATCH", `/api/rooms/${roomId}/board-size`, {
        width,
        height,
      });
      const result = await response.json();
      console.log(`[GameBoard] Board size update response:`, result);
      return result;
    },
    onSuccess: (data) => {
      console.log(`[GameBoard] Board size updated successfully:`, data);
      queryClient.invalidateQueries({ queryKey: ["/api/rooms", roomId] });
    },
    onError: (error) => {
      console.error(`[GameBoard] Board size update failed:`, error);
    },
  });

  const handleAssetMove = (assetId: string, x: number, y: number) => {
    // Apply snap-to-grid if enabled
    if (showGrid) {
      const snapped = snapToGrid(x, y, gridSize);
      onAssetMoved(assetId, snapped.x, snapped.y);
    } else {
      onAssetMoved(assetId, x, y);
    }
  };

  return (
    <div 
      className={`bg-gray-800 rounded-lg relative overflow-hidden ${
        playerRole === 'player' ? 'w-full' : ''
      }`}
      data-testid={testId}
      style={playerRole === 'player' ? 
        { height: boardHeight, minHeight: boardHeight } : 
        { width: boardWidth, height: boardHeight, minWidth: boardWidth, minHeight: boardHeight }
      }
    >
      {/* Background Layer */}
      <div className="absolute inset-0 bg-gradient-to-br from-green-900 to-green-800"></div>
      
      {/* Grid Overlay */}
      {showGrid && (
        <GridOverlay
          isVisible={showGrid}
          gridSize={gridSize}
          onToggle={setShowGrid}
          onGridSizeChange={setGridSize}
          boardWidth={boardWidth}
          boardHeight={boardHeight}
        />
      )}
      
      {/* Game Board Controls */}
      <div className="absolute top-2 right-2 z-40 flex gap-2">
        {/* Resize Controls - Only show for GMs */}
        {playerRole === 'admin' && (
          <div className="flex gap-1 items-center bg-gray-800 rounded px-2 py-1">
            <span className="text-white text-xs">Size:</span>
          {!customSizeMode ? (
            <select
              value={`${boardWidth}x${boardHeight}`}
              onChange={(e) => {
                if (e.target.value === 'custom') {
                  setCustomSizeMode(true);
                  setCustomWidth(boardWidth.toString());
                  setCustomHeight(boardHeight.toString());
                } else {
                  const [width, height] = e.target.value.split('x').map(Number);
                  if (playerRole === 'admin') {
                    updateBoardSizeMutation.mutate({ width, height });
                  } else {
                    setBoardWidth(width);
                    setBoardHeight(height);
                  }
                }
              }}
              className="bg-gray-700 text-white text-xs px-1 py-0.5 rounded border-0"
              data-testid="select-board-size"
            >
              <option value="600x400">Small (600×400)</option>
              <option value="800x600">Medium (800×600)</option>
              <option value="1000x750">Large (1000×750)</option>
              <option value="1200x900">XL (1200×900)</option>
              <option value="1400x1050">XXL (1400×1050)</option>
              <option value="1600x1200">Huge (1600×1200)</option>
              <option value="custom">Custom Size...</option>
            </select>
          ) : (
            <div className="flex gap-1 items-center">
              <input
                type="number"
                value={customWidth}
                onChange={(e) => setCustomWidth(e.target.value)}
                className="bg-gray-700 text-white text-xs px-1 py-0.5 rounded border-0 w-12"
                min="200"
                max="3000"
                data-testid="input-custom-width"
              />
              <span className="text-white text-xs">×</span>
              <input
                type="number"
                value={customHeight}
                onChange={(e) => setCustomHeight(e.target.value)}
                className="bg-gray-700 text-white text-xs px-1 py-0.5 rounded border-0 w-12"
                min="200"
                max="3000"
                data-testid="input-custom-height"
              />
              <button
                onClick={() => {
                  const width = Math.max(200, Math.min(3000, parseInt(customWidth) || 800));
                  const height = Math.max(200, Math.min(3000, parseInt(customHeight) || 600));
                  if (playerRole === 'admin') {
                    updateBoardSizeMutation.mutate({ width, height });
                  } else {
                    setBoardWidth(width);
                    setBoardHeight(height);
                  }
                  setCustomSizeMode(false);
                }}
                className="bg-green-600 text-white text-xs px-1 py-0.5 rounded hover:bg-green-500"
                data-testid="button-apply-custom-size"
              >
                ✓
              </button>
              <button
                onClick={() => setCustomSizeMode(false)}
                className="bg-red-600 text-white text-xs px-1 py-0.5 rounded hover:bg-red-500"
                data-testid="button-cancel-custom-size"
              >
                ×
              </button>
            </div>
          )}
        </div>
        )}
        
        {/* Admin-only tools */}
        {playerRole === 'admin' && (
          <>
            <button
              onClick={() => setShowGrid(!showGrid)}
              className="px-2 py-1 bg-gray-700 text-white text-xs rounded hover:bg-gray-600"
              data-testid="button-toggle-grid"
            >
              Grid {showGrid ? 'On' : 'Off'}
            </button>
            <button
              onClick={() => setMeasurementActive(!measurementActive)}
              className={`px-2 py-1 text-xs rounded ${
                measurementActive 
                  ? 'bg-blue-600 text-white' 
                  : 'bg-gray-700 text-white hover:bg-gray-600'
              }`}
              data-testid="button-toggle-measurement"
            >
              Ruler
            </button>
            <button
              onClick={() => setAnnotationActive(!annotationActive)}
              className={`px-2 py-1 text-xs rounded ${
                annotationActive 
                  ? 'bg-purple-600 text-white' 
                  : 'bg-gray-700 text-white hover:bg-gray-600'
              }`}
              data-testid="button-toggle-annotation"
            >
              Draw
            </button>
          </>
        )}
      </div>

      {/* Measurement Tool */}
      <MeasurementTool
        isActive={measurementActive}
        onToggle={setMeasurementActive}
        boardWidth={boardWidth}
        boardHeight={boardHeight}
        gridSize={gridSize}
      />

      {/* Annotation System */}
      <AnnotationSystem
        isActive={annotationActive}
        onToggle={setAnnotationActive}
        boardWidth={boardWidth}
        boardHeight={boardHeight}
      />
      
      {/* Game Assets Layer */}
      <div className="absolute inset-0 z-15">
        {boardAssets.map((boardAsset) => {
          const asset = assets.find(a => a.id === boardAsset.assetId);
          
          return (
            <div
              key={boardAsset.id}
              className="absolute cursor-move rounded-md shadow-lg hover:shadow-xl transition-shadow"
              style={{
                left: `${boardAsset.positionX}px`,
                top: `${boardAsset.positionY}px`,
                transform: `scale(${boardAsset.scale || 1}) rotate(${boardAsset.rotation || 0}deg)`,
                zIndex: boardAsset.zIndex || 1,
              }}
              data-testid={`board-asset-${boardAsset.id}`}
              onMouseDown={(e) => {
                if (playerRole === 'admin') {
                  // Start drag operation
                  const startX = e.clientX;
                  const startY = e.clientY;
                  const initialX = boardAsset.positionX;
                  const initialY = boardAsset.positionY;

                  const handleMouseMove = (moveEvent: MouseEvent) => {
                    const deltaX = moveEvent.clientX - startX;
                    const deltaY = moveEvent.clientY - startY;
                    const newX = Math.max(0, Math.min(boardWidth - 50, initialX + deltaX));
                    const newY = Math.max(0, Math.min(boardHeight - 50, initialY + deltaY));
                    
                    handleAssetMove(boardAsset.id, newX, newY);
                  };

                  const handleMouseUp = () => {
                    document.removeEventListener('mousemove', handleMouseMove);
                    document.removeEventListener('mouseup', handleMouseUp);
                  };

                  document.addEventListener('mousemove', handleMouseMove);
                  document.addEventListener('mouseup', handleMouseUp);
                }
              }}
            >
              {asset ? (
                <div className="relative">
                  <img 
                    src={asset.filePath}
                    alt={asset.name}
                    className="w-16 h-16 object-cover rounded-md border-2 border-white"
                    style={{
                      transform: boardAsset.isFlipped ? 'scaleX(-1)' : 'none'
                    }}
                  />
                  {boardAsset.isLocked && (
                    <div className="absolute top-0 right-0 w-3 h-3 bg-red-500 rounded-full border border-white"></div>
                  )}
                  {playerRole === 'admin' && (
                    <div className="absolute -top-2 -right-2 bg-black bg-opacity-50 text-white text-xs px-1 rounded">
                      {boardAsset.zIndex || 1}
                    </div>
                  )}
                </div>
              ) : (
                <div className="w-16 h-16 bg-gray-600 rounded-md flex items-center justify-center border-2 border-gray-400">
                  <span className="text-xs text-gray-300">?</span>
                </div>
              )}
            </div>
          );
        })}
        
        {/* Empty state */}
        {boardAssets.length === 0 && (cardPiles as CardPile[]).length === 0 && (
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="text-center text-gray-400">
              <div className="text-lg font-medium mb-2">Empty Game Board</div>
              <div className="text-sm">
                {playerRole === 'admin' 
                  ? "Upload assets and place them on the board to get started" 
                  : "Wait for the Game Master to place assets on the board"
                }
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Card Piles/Deck Spots Layer */}
      <div className="absolute inset-0 z-20">
        {(cardPiles as CardPile[]).map((pile) => {
          const deck = (cardDecks as CardDeck[]).find(d => d.name === pile.name);
          const cardCount = Array.isArray(pile.cardOrder) ? pile.cardOrder.length : 0;
          
          return (
            <div
              key={pile.id}
              className={`absolute transition-all duration-200 ${
                playerRole === 'admin' ? 'cursor-move hover:scale-105' : 'cursor-pointer'
              }`}
              style={{
                left: `${pile.positionX}px`,
                top: `${pile.positionY}px`,
              }}
              data-testid={`deck-spot-${pile.id}`}
              onMouseDown={(e) => {
                if (playerRole === 'admin') {
                  // Start drag operation for GMs
                  const startX = e.clientX;
                  const startY = e.clientY;
                  const initialX = pile.positionX;
                  const initialY = pile.positionY;

                  const handleMouseMove = (moveEvent: MouseEvent) => {
                    const deltaX = moveEvent.clientX - startX;
                    const deltaY = moveEvent.clientY - startY;
                    const newX = Math.max(0, Math.min(boardWidth - 80, initialX + deltaX));
                    const newY = Math.max(0, Math.min(boardHeight - 100, initialY + deltaY));
                    
                    // Apply snap-to-grid if enabled
                    if (showGrid) {
                      const snapped = snapToGrid(newX, newY, gridSize);
                      movePileMutation.mutate({ pileId: pile.id, x: snapped.x, y: snapped.y });
                    } else {
                      movePileMutation.mutate({ pileId: pile.id, x: newX, y: newY });
                    }
                  };

                  const handleMouseUp = () => {
                    document.removeEventListener('mousemove', handleMouseMove);
                    document.removeEventListener('mouseup', handleMouseUp);
                  };

                  document.addEventListener('mousemove', handleMouseMove);
                  document.addEventListener('mouseup', handleMouseUp);
                }
              }}
            >
              {/* Deck Spot Visual */}
              <div className={`relative w-20 h-24 rounded-lg border-2 shadow-lg ${
                pile.pileType === 'deck' 
                  ? 'bg-blue-800 border-blue-600' 
                  : pile.pileType === 'discard'
                  ? 'bg-red-800 border-red-600'
                  : 'bg-gray-800 border-gray-600'
              }`}>
                {/* Deck stack effect */}
                {cardCount > 0 && (
                  <>
                    <div className="absolute -top-1 -left-1 w-20 h-24 rounded-lg border-2 border-gray-400 bg-gray-700 opacity-60"></div>
                    <div className="absolute -top-0.5 -left-0.5 w-20 h-24 rounded-lg border-2 border-gray-400 bg-gray-700 opacity-80"></div>
                  </>
                )}
                
                {/* Main deck area */}
                <div className="relative w-full h-full rounded-lg flex flex-col items-center justify-center text-white text-xs text-center p-1">
                  {/* Deck name */}
                  <div className="font-bold mb-1 line-clamp-2 leading-tight">
                    {pile.name}
                  </div>
                  
                  {/* Card count */}
                  <div className="text-xs opacity-75">
                    {cardCount} {cardCount === 1 ? 'card' : 'cards'}
                  </div>
                  
                  {/* Pile type indicator */}
                  <div className={`absolute top-1 right-1 w-2 h-2 rounded-full ${
                    pile.pileType === 'deck' 
                      ? 'bg-blue-400' 
                      : pile.pileType === 'discard'
                      ? 'bg-red-400'
                      : 'bg-gray-400'
                  }`}></div>
                </div>
                
                {/* GM controls indicator */}
                {playerRole === 'admin' && (
                  <div className="absolute -top-2 -right-2 bg-yellow-500 text-black text-xs px-1 rounded font-bold">
                    GM
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}