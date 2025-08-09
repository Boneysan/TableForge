import { useState } from "react";
import { GridOverlay, snapToGrid } from "./GridOverlay";
import { MeasurementTool } from "./MeasurementTool";
import { AnnotationSystem } from "./AnnotationSystem";
import type { GameAsset, BoardAsset } from "@shared/schema";

interface GameBoardProps {
  assets: GameAsset[];
  boardAssets: BoardAsset[];
  onAssetMoved: (assetId: string, x: number, y: number) => void;
  onAssetPlaced: (assetId: string, x: number, y: number) => void;
  playerRole: 'admin' | 'player';
  'data-testid'?: string;
}

export function GameBoard({ 
  assets, 
  boardAssets, 
  onAssetMoved, 
  onAssetPlaced, 
  playerRole,
  'data-testid': testId 
}: GameBoardProps) {
  // Board Tools State
  const [showGrid, setShowGrid] = useState(false);
  const [gridSize, setGridSize] = useState(20);
  const [measurementActive, setMeasurementActive] = useState(false);
  const [annotationActive, setAnnotationActive] = useState(false);

  const boardWidth = 800;
  const boardHeight = 600;

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
      className="w-full h-full bg-gray-800 rounded-lg relative overflow-hidden"
      data-testid={testId}
      style={{ width: boardWidth, height: boardHeight }}
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
      
      {/* Game Board Controls - Only for Admin */}
      {playerRole === 'admin' && (
        <div className="absolute top-2 right-2 z-40 flex gap-2">
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
        </div>
      )}

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
        {boardAssets.length === 0 && (
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
    </div>
  );
}