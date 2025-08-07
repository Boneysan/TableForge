import { useRef, useState, useEffect } from "react";
import { useMutation } from "@tanstack/react-query";
import { ZoomIn, ZoomOut, Home, Grid3X3 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useDragAndDrop } from "@/hooks/useDragAndDrop";
import { useToast } from "@/hooks/use-toast";
import type { GameAsset, BoardAsset } from "@shared/schema";

interface GameBoardProps {
  roomId: string;
  assets: GameAsset[];
  boardAssets: BoardAsset[];
  onAssetPlaced: (assetId: string, x: number, y: number) => void;
  onAssetMoved: (assetId: string, x: number, y: number) => void;
  onAssetFlipped: (assetId: string, isFlipped: boolean) => void;
}

interface PlacedAsset extends BoardAsset {
  asset: GameAsset;
}

export function GameBoard({ 
  roomId, 
  assets, 
  boardAssets, 
  onAssetPlaced, 
  onAssetMoved,
  onAssetFlipped 
}: GameBoardProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [showGrid, setShowGrid] = useState(true);
  const [draggedAsset, setDraggedAsset] = useState<string | null>(null);
  const { toast } = useToast();

  const { dragOver, drop } = useDragAndDrop();

  // Combine board assets with asset data
  const placedAssets: PlacedAsset[] = boardAssets.map(boardAsset => {
    const asset = assets.find(a => a.id === boardAsset.assetId);
    return { ...boardAsset, asset: asset! };
  }).filter(pa => pa.asset); // Filter out any with missing assets

  const createBoardAssetMutation = useMutation({
    mutationFn: async (data: {
      roomId: string;
      assetId: string;
      positionX: number;
      positionY: number;
      rotation?: number;
      scale?: number;
      zIndex?: number;
    }) => {
      const response = await apiRequest("POST", "/api/board-assets", data);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/rooms", roomId, "board-assets"] });
    },
  });

  const updateBoardAssetMutation = useMutation({
    mutationFn: async ({ id, updates }: { id: string; updates: Partial<BoardAsset> }) => {
      const response = await apiRequest("PUT", `/api/board-assets/${id}`, updates);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/rooms", roomId, "board-assets"] });
    },
  });

  const deleteBoardAssetMutation = useMutation({
    mutationFn: async (id: string) => {
      const response = await apiRequest("DELETE", `/api/board-assets/${id}`, {});
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/rooms", roomId, "board-assets"] });
    },
  });

  const handleDrop = (event: React.DragEvent) => {
    const result = drop(event);
    if (result?.type === 'asset') {
      const rect = containerRef.current?.getBoundingClientRect();
      if (rect) {
        const x = (event.clientX - rect.left - pan.x) / zoom;
        const y = (event.clientY - rect.top - pan.y) / zoom;
        
        createBoardAssetMutation.mutate({
          roomId,
          assetId: result.data.id,
          positionX: Math.round(x),
          positionY: Math.round(y),
          rotation: 0,
          scale: 100,
          zIndex: boardAssets.length,
        });

        onAssetPlaced(result.data.id, Math.round(x), Math.round(y));
      }
    }
  };

  const handleAssetMouseDown = (asset: PlacedAsset, event: React.MouseEvent) => {
    if (event.button !== 0) return; // Only left click

    setDraggedAsset(asset.id);
    const startX = event.clientX;
    const startY = event.clientY;
    const startPosX = asset.positionX;
    const startPosY = asset.positionY;

    const handleMouseMove = (e: MouseEvent) => {
      const deltaX = (e.clientX - startX) / zoom;
      const deltaY = (e.clientY - startY) / zoom;
      
      const newX = Math.round(startPosX + deltaX);
      const newY = Math.round(startPosY + deltaY);

      // Update position immediately for smooth dragging
      updateBoardAssetMutation.mutate({
        id: asset.id,
        updates: { positionX: newX, positionY: newY }
      });
    };

    const handleMouseUp = (e: MouseEvent) => {
      const deltaX = (e.clientX - startX) / zoom;
      const deltaY = (e.clientY - startY) / zoom;
      
      const newX = Math.round(startPosX + deltaX);
      const newY = Math.round(startPosY + deltaY);

      onAssetMoved(asset.id, newX, newY);
      setDraggedAsset(null);
      
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);

    event.preventDefault();
  };

  const handleAssetDoubleClick = (asset: PlacedAsset) => {
    if (asset.asset.type === 'card') {
      const newFlipState = !asset.isFlipped;
      updateBoardAssetMutation.mutate({
        id: asset.id,
        updates: { isFlipped: newFlipState }
      });
      onAssetFlipped(asset.id, newFlipState);
    }
  };

  const handleDeleteAsset = (assetId: string, event: React.MouseEvent) => {
    event.stopPropagation();
    deleteBoardAssetMutation.mutate(assetId);
  };

  const handleZoomIn = () => setZoom(Math.min(zoom * 1.2, 3));
  const handleZoomOut = () => setZoom(Math.max(zoom / 1.2, 0.5));
  const handleResetView = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };
  const handleToggleGrid = () => setShowGrid(!showGrid);

  return (
    <main className="flex-1 relative bg-[#1F2937]" data-testid="game-board">
      <div 
        ref={containerRef}
        className="w-full h-full relative overflow-auto"
        onDragOver={dragOver}
        onDrop={handleDrop}
        style={{ cursor: draggedAsset ? 'grabbing' : 'default' }}
      >
        {/* Grid Background */}
        {showGrid && (
          <div 
            className="absolute inset-0 opacity-20 pointer-events-none"
            style={{
              backgroundImage: `
                linear-gradient(rgba(99, 102, 241, 0.3) 1px, transparent 1px),
                linear-gradient(90deg, rgba(99, 102, 241, 0.3) 1px, transparent 1px)
              `,
              backgroundSize: `${40 * zoom}px ${40 * zoom}px`,
              transform: `translate(${pan.x}px, ${pan.y}px)`,
            }}
          />
        )}

        {/* Game Board Content */}
        <div 
          className="relative w-full min-h-full p-8"
          style={{ 
            minWidth: '1200px', 
            minHeight: '800px',
            transform: `scale(${zoom}) translate(${pan.x / zoom}px, ${pan.y / zoom}px)`,
            transformOrigin: '0 0',
          }}
        >
          {/* Placed Assets */}
          {placedAssets.map((placedAsset) => {
            const isDragging = draggedAsset === placedAsset.id;
            const isCard = placedAsset.asset.type === 'card';
            const isToken = placedAsset.asset.type === 'token';
            
            return (
              <div
                key={placedAsset.id}
                className={`absolute cursor-move select-none hover:ring-2 hover:ring-[#2563EB] transition-all ${
                  isCard ? 'rounded-lg' : isToken ? 'rounded-full' : 'rounded-lg'
                } ${isDragging ? 'z-50 opacity-80' : ''}`}
                style={{
                  left: placedAsset.positionX,
                  top: placedAsset.positionY,
                  width: isToken ? '40px' : placedAsset.asset.width || 80,
                  height: isToken ? '40px' : placedAsset.asset.height || (isCard ? 110 : 80),
                  transform: `rotate(${placedAsset.rotation}deg) scale(${placedAsset.scale / 100})`,
                  zIndex: placedAsset.zIndex,
                }}
                onMouseDown={(e) => handleAssetMouseDown(placedAsset, e)}
                onDoubleClick={() => handleAssetDoubleClick(placedAsset)}
                data-testid={`placed-asset-${placedAsset.id}`}
              >
                <img
                  src={placedAsset.asset.filePath.startsWith('/objects/') 
                    ? placedAsset.asset.filePath 
                    : `/public-objects/${placedAsset.asset.filePath}`
                  }
                  alt={placedAsset.asset.name}
                  className={`w-full h-full ${isCard ? 'rounded-lg' : isToken ? 'rounded-full' : 'rounded-lg'} object-cover shadow-lg ${
                    placedAsset.isFlipped ? 'transform scale-x-[-1]' : ''
                  }`}
                  draggable={false}
                  onError={(e) => {
                    const target = e.target as HTMLImageElement;
                    target.src = "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iODAiIGhlaWdodD0iODAiIHZpZXdCb3g9IjAgMCA4MCA4MCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHJlY3Qgd2lkdGg9IjgwIiBoZWlnaHQ9IjgwIiBmaWxsPSIjNEI1NTYzIiByeD0iOCIvPgo8cGF0aCBkPSJNNDAgMjBDMzAuMzM1IDIwIDIyLjUgMjcuODM1IDIyLjUgMzcuNVMyNy44MzUgNTUgNDAgNTVTNTcuNSA0Ny4xNjUgNTcuNSAzNy41UzQ5LjY2NSAyMCA0MCAyMFpNNDAgNTBDMzMuMDk2IDUwIDI3LjUgNDQuNDA0IDI3LjUgMzcuNVMzMy4wOTYgMjUgNDAgMjVTNTIuNSAzMC41OTYgNTIuNSAzNy41UzQ2LjkwNCA1MCA0MCA1MFoiIGZpbGw9IiM2QjcyODAiLz4KPC9zdmc+Cg==";
                  }}
                />
                
                {/* Delete button */}
                <button
                  className="absolute -top-2 -right-2 w-6 h-6 bg-red-500 hover:bg-red-600 rounded-full text-xs flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity"
                  onClick={(e) => handleDeleteAsset(placedAsset.id, e)}
                  data-testid={`button-delete-asset-${placedAsset.id}`}
                >
                  ✕
                </button>

                {/* Card flip indicator */}
                {isCard && (
                  <div className="absolute -bottom-6 left-0 right-0 text-center opacity-0 hover:opacity-100 transition-opacity">
                    <span className="text-xs bg-[#4B5563] px-2 py-1 rounded text-gray-300">
                      Double-click to flip
                    </span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Board Controls */}
      <div className="absolute top-4 right-4 flex flex-col space-y-2">
        <Button
          variant="outline"
          size="sm"
          onClick={handleZoomIn}
          className="bg-[#4B5563] border-gray-600 text-gray-300 hover:bg-[#374151]"
          title="Zoom In"
          data-testid="button-zoom-in"
        >
          <ZoomIn className="w-4 h-4" />
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={handleZoomOut}
          className="bg-[#4B5563] border-gray-600 text-gray-300 hover:bg-[#374151]"
          title="Zoom Out"
          data-testid="button-zoom-out"
        >
          <ZoomOut className="w-4 h-4" />
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={handleResetView}
          className="bg-[#4B5563] border-gray-600 text-gray-300 hover:bg-[#374151]"
          title="Reset View"
          data-testid="button-reset-view"
        >
          <Home className="w-4 h-4" />
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={handleToggleGrid}
          className={`border-gray-600 text-gray-300 hover:bg-[#374151] ${
            showGrid ? 'bg-[#2563EB]' : 'bg-[#4B5563]'
          }`}
          title="Toggle Grid"
          data-testid="button-toggle-grid"
        >
          <Grid3X3 className="w-4 h-4" />
        </Button>
      </div>
    </main>
  );
}
