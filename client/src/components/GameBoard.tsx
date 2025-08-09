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
  return (
    <div 
      className="w-full h-full bg-gray-800 rounded-lg relative overflow-hidden"
      data-testid={testId}
    >
      <div className="absolute inset-0 bg-grid-pattern opacity-10"></div>
      
      <div className="absolute inset-4 space-y-4">
        {/* Board assets */}
        {boardAssets.map((boardAsset) => (
          <div
            key={boardAsset.id}
            className="absolute cursor-move rounded-md shadow-lg"
            style={{
              left: `${boardAsset.positionX}px`,
              top: `${boardAsset.positionY}px`,
              transform: `scale(${boardAsset.scale || 1}) rotate(${boardAsset.rotation || 0}deg)`,
              zIndex: boardAsset.zIndex,
            }}
            data-testid={`board-asset-${boardAsset.id}`}
          >
            {/* Find matching asset and display */}
            {(() => {
              const asset = assets.find(a => a.id === boardAsset.assetId);
              return asset ? (
                <img 
                  src={asset.filePath}
                  alt={asset.name}
                  className="w-24 h-24 object-cover rounded-md"
                  style={{
                    transform: boardAsset.isFlipped ? 'scaleX(-1)' : 'none'
                  }}
                />
              ) : (
                <div className="w-24 h-24 bg-gray-600 rounded-md flex items-center justify-center">
                  <span className="text-xs text-gray-300">Missing Asset</span>
                </div>
              );
            })()}
          </div>
        ))}
        
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