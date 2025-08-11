import { useState } from 'react';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  RotateCcw,
  Move,
  Lock,
  Unlock,
  FlipHorizontal,
  Users,
  User,
  Eye,
  Grid3X3,
  Maximize2,
} from 'lucide-react';
import type { BoardAsset, GameAsset } from '@shared/schema';

interface EnhancedTokenProps {
  asset: BoardAsset & { gameAsset: GameAsset };
  onMove: (id: string, x: number, y: number) => void;
  onRotate: (id: string, rotation: number) => void;
  onFlip: (id: string, flipped: boolean) => void;
  onVisibilityChange: (id: string, visibility: 'public' | 'owner' | 'gm') => void;
  onLock: (id: string, locked: boolean) => void;
  onZIndexChange: (id: string, zIndex: number) => void;
  onScaleChange: (id: string, scale: number) => void;
  onSnapToGrid: (id: string, snap: boolean) => void;
  playerRole: 'admin' | 'player';
  currentUserId: string;
  canEdit: boolean;
  gridSize?: number;
}

export function EnhancedToken({
  asset,
  onMove,
  onRotate,
  onFlip,
  onVisibilityChange,
  onLock,
  onZIndexChange,
  onScaleChange,
  onSnapToGrid,
  playerRole,
  currentUserId,
  canEdit,
  gridSize = 25,
}: EnhancedTokenProps) {
  const [isSelected, setIsSelected] = useState(false);
  const [dragStart, setDragStart] = useState<{ x: number; y: number } | null>(null);

  const isOwner = asset.ownedBy === currentUserId;
  const isAdmin = playerRole === 'admin';
  const canInteract = canEdit && (isAdmin || isOwner || asset.visibility === 'public');

  const visibilityIcon = {
    public: <Users className="w-3 h-3" />,
    owner: <User className="w-3 h-3" />,
    gm: <Eye className="w-3 h-3" />,
  }[asset.visibility || 'public'];

  const snapToGridPosition = (x: number, y: number) => {
    if (!asset.snapToGrid) return { x, y };
    return {
      x: Math.round(x / gridSize) * gridSize,
      y: Math.round(y / gridSize) * gridSize,
    };
  };

  const handleMouseDown = (e: React.MouseEvent) => {
    if (!canInteract) return;
    setDragStart({ x: e.clientX - asset.positionX, y: e.clientY - asset.positionY });
    setIsSelected(true);
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!dragStart || !canInteract) return;
    const rawX = e.clientX - dragStart.x;
    const rawY = e.clientY - dragStart.y;
    const { x, y } = snapToGridPosition(rawX, rawY);
    onMove(asset.id, x, y);
  };

  const handleMouseUp = () => {
    setDragStart(null);
    setIsSelected(false);
  };

  const handleRotate = () => {
    if (!canInteract) return;
    const newRotation = (asset.rotation + 45) % 360; // 45-degree increments for tokens
    onRotate(asset.id, newRotation);
  };

  const handleFlip = () => {
    if (!canInteract) return;
    onFlip(asset.id, !asset.isFlipped);
  };

  const handleVisibilityToggle = () => {
    if (!isAdmin && !isOwner) return;
    const nextVisibility = {
      public: 'owner' as const,
      owner: 'gm' as const,
      gm: 'public' as const,
    }[asset.visibility || 'public'];
    onVisibilityChange(asset.id, nextVisibility);
  };

  const handleLockToggle = () => {
    if (!isAdmin) return;
    onLock(asset.id, !asset.isLocked);
  };

  const handleLayerUp = () => {
    if (!canInteract) return;
    onZIndexChange(asset.id, asset.zIndex + 1);
  };

  const handleLayerDown = () => {
    if (!canInteract) return;
    onZIndexChange(asset.id, Math.max(0, asset.zIndex - 1));
  };

  const handleScaleUp = () => {
    if (!canInteract) return;
    const newScale = Math.min(200, asset.scale + 25);
    onScaleChange(asset.id, newScale);
  };

  const handleScaleDown = () => {
    if (!canInteract) return;
    const newScale = Math.max(25, asset.scale - 25);
    onScaleChange(asset.id, newScale);
  };

  const handleSnapToggle = () => {
    if (!canInteract) return;
    onSnapToGrid(asset.id, !asset.snapToGrid);
  };

  // Determine if this token should be visible to the current user
  const shouldShow = asset.visibility === 'public' ||
                    (asset.visibility === 'owner' && isOwner) ||
                    (asset.visibility === 'gm' && isAdmin);

  if (!shouldShow) {
    return null; // Hide from unauthorized users
  }

  const tokenSize = asset.assetType === 'token' ? 40 : 32; // Tokens slightly larger than other assets

  const tokenStyle = {
    position: 'absolute' as const,
    left: asset.positionX,
    top: asset.positionY,
    transform: `rotate(${asset.rotation}deg) scale(${asset.scale / 100})`,
    zIndex: asset.zIndex,
    cursor: canInteract ? (dragStart ? 'grabbing' : 'grab') : 'default',
    opacity: asset.isLocked ? 0.7 : 1,
    filter: asset.isFlipped ? 'brightness(0.6) hue-rotate(180deg)' : 'none',
  };

  return (
    <div
      style={tokenStyle}
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onMouseLeave={handleMouseUp}
      className={`
        border-2 rounded-full shadow-lg transition-all duration-200
        ${isSelected ? 'border-green-500 shadow-xl' : 'border-gray-300'}
        ${asset.assetType === 'token' ? 'bg-white' : 'bg-gray-50'}
        ${canInteract ? 'hover:shadow-xl' : ''}
        ${asset.snapToGrid ? 'ring-2 ring-blue-200' : ''}
      `}
      data-testid={`enhanced-token-${asset.id}`}
    >
      <div
        className="relative overflow-hidden rounded-full"
        style={{ width: tokenSize, height: tokenSize }}
      >
        {/* Token Image */}
        <img
          src={asset.gameAsset.filePath.includes('storage.googleapis.com') && asset.gameAsset.filePath.includes('.private/uploads/')
            ? `/api/image-proxy?url=${encodeURIComponent(asset.gameAsset.filePath)}`
            : asset.gameAsset.filePath}
          alt={asset.gameAsset.name}
          className="w-full h-full object-cover"
          draggable={false}
        />

        {/* Controls Overlay */}
        {isSelected && canInteract && (
          <div className="absolute inset-0 bg-black bg-opacity-50 flex flex-col justify-between p-1">
            {/* Top Controls */}
            <div className="flex justify-between items-start">
              <Badge variant="secondary" className="text-xs scale-75">
                {visibilityIcon}
              </Badge>
              {asset.isLocked && (
                <Lock className="w-2 h-2 text-red-400" />
              )}
            </div>

            {/* Center Controls */}
            <div className="flex justify-center items-center">
              <div className="flex space-x-1">
                <Button
                  size="sm"
                  variant="ghost"
                  className="w-4 h-4 p-0 text-white hover:bg-white hover:bg-opacity-20"
                  onClick={handleRotate}
                  data-testid={`button-rotate-token-${asset.id}`}
                >
                  <RotateCcw className="w-2 h-2" />
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  className="w-4 h-4 p-0 text-white hover:bg-white hover:bg-opacity-20"
                  onClick={handleFlip}
                  data-testid={`button-flip-token-${asset.id}`}
                >
                  <FlipHorizontal className="w-2 h-2" />
                </Button>
              </div>
            </div>
          </div>
        )}

        {/* Asset Type Indicator */}
        <div className="absolute -top-1 -right-1">
          <Badge
            variant={asset.assetType === 'token' ? 'default' : 'secondary'}
            className="text-xs scale-75"
          >
            T
          </Badge>
        </div>

        {/* Snap to Grid Indicator */}
        {asset.snapToGrid && (
          <div className="absolute -bottom-1 -left-1">
            <Badge variant="outline" className="text-xs scale-75">
              <Grid3X3 className="w-2 h-2" />
            </Badge>
          </div>
        )}
      </div>

      {/* Extended Controls Menu */}
      {isSelected && canInteract && (
        <div className="absolute -top-12 -left-8 bg-white border rounded-lg shadow-lg p-1 flex space-x-1">
          <Button
            size="sm"
            variant="ghost"
            className="w-6 h-6 p-0"
            onClick={handleLayerUp}
            title="Layer Up"
            data-testid={`button-layer-up-token-${asset.id}`}
          >
            ↑
          </Button>
          <Button
            size="sm"
            variant="ghost"
            className="w-6 h-6 p-0"
            onClick={handleLayerDown}
            title="Layer Down"
            data-testid={`button-layer-down-token-${asset.id}`}
          >
            ↓
          </Button>
          <Button
            size="sm"
            variant="ghost"
            className="w-6 h-6 p-0"
            onClick={handleScaleUp}
            title="Scale Up"
            data-testid={`button-scale-up-token-${asset.id}`}
          >
            <Maximize2 className="w-3 h-3" />
          </Button>
          <Button
            size="sm"
            variant="ghost"
            className="w-6 h-6 p-0"
            onClick={handleScaleDown}
            title="Scale Down"
            data-testid={`button-scale-down-token-${asset.id}`}
          >
            <Maximize2 className="w-3 h-3 scale-75" />
          </Button>
          <Button
            size="sm"
            variant="ghost"
            className="w-6 h-6 p-0"
            onClick={handleSnapToggle}
            title="Toggle Snap to Grid"
            data-testid={`button-snap-toggle-${asset.id}`}
          >
            <Grid3X3 className={`w-3 h-3 ${asset.snapToGrid ? 'text-blue-600' : 'text-gray-400'}`} />
          </Button>
          {(isAdmin || isOwner) && (
            <Button
              size="sm"
              variant="ghost"
              className="w-6 h-6 p-0"
              onClick={handleVisibilityToggle}
              title="Change Visibility"
              data-testid={`button-visibility-token-${asset.id}`}
            >
              {visibilityIcon}
            </Button>
          )}
          {isAdmin && (
            <Button
              size="sm"
              variant="ghost"
              className="w-6 h-6 p-0"
              onClick={handleLockToggle}
              title="Toggle Lock"
              data-testid={`button-lock-token-${asset.id}`}
            >
              {asset.isLocked ? <Unlock className="w-3 h-3" /> : <Lock className="w-3 h-3" />}
            </Button>
          )}
        </div>
      )}
    </div>
  );
}
