import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Shuffle,
  Eye,
  EyeOff,
  RotateCcw,
  Move,
  Lock,
  Unlock,
  FlipHorizontal,
  Layers,
  Users,
  User,
} from 'lucide-react';
import type { BoardAsset, GameAsset } from '@shared/schema';

interface CardDeckProps {
  asset: BoardAsset & { gameAsset: GameAsset };
  onMove: (id: string, x: number, y: number) => void;
  onRotate: (id: string, rotation: number) => void;
  onFlip: (id: string, faceDown: boolean) => void;
  onVisibilityChange: (id: string, visibility: 'public' | 'owner' | 'gm') => void;
  onLock: (id: string, locked: boolean) => void;
  onZIndexChange: (id: string, zIndex: number) => void;
  playerRole: 'admin' | 'player';
  currentUserId: string;
  canEdit: boolean;
}

export function CardDeck({
  asset,
  onMove,
  onRotate,
  onFlip,
  onVisibilityChange,
  onLock,
  onZIndexChange,
  playerRole,
  currentUserId,
  canEdit,
}: CardDeckProps) {
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

  const handleMouseDown = (e: React.MouseEvent) => {
    if (!canInteract) return;
    setDragStart({ x: e.clientX - asset.positionX, y: e.clientY - asset.positionY });
    setIsSelected(true);
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!dragStart || !canInteract) return;
    const newX = e.clientX - dragStart.x;
    const newY = e.clientY - dragStart.y;
    onMove(asset.id, newX, newY);
  };

  const handleMouseUp = () => {
    setDragStart(null);
    setIsSelected(false);
  };

  const handleRotate = () => {
    if (!canInteract) return;
    const newRotation = (asset.rotation + 90) % 360;
    onRotate(asset.id, newRotation);
  };

  const handleFlip = () => {
    if (!canInteract) return;
    onFlip(asset.id, !asset.faceDown);
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

  // Determine if this card should be visible to the current user
  const shouldShow = asset.visibility === 'public' ||
                    (asset.visibility === 'owner' && isOwner) ||
                    (asset.visibility === 'gm' && isAdmin);

  if (!shouldShow) {
    return null; // Hide from unauthorized users
  }

  const cardStyle = {
    position: 'absolute' as const,
    left: asset.positionX,
    top: asset.positionY,
    transform: `rotate(${asset.rotation}deg) scale(${asset.scale / 100})`,
    zIndex: asset.zIndex,
    cursor: canInteract ? (dragStart ? 'grabbing' : 'grab') : 'default',
    opacity: asset.isLocked ? 0.7 : 1,
    filter: asset.faceDown ? 'brightness(0.3)' : 'none',
  };

  return (
    <div
      style={cardStyle}
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onMouseLeave={handleMouseUp}
      className={`
        border-2 rounded-lg shadow-lg transition-all duration-200
        ${isSelected ? 'border-blue-500 shadow-xl' : 'border-gray-300'}
        ${asset.assetType === 'card' ? 'bg-white' : 'bg-gray-100'}
        ${canInteract ? 'hover:shadow-xl' : ''}
      `}
      data-testid={`card-deck-${asset.id}`}
    >
      <Card className="w-24 h-32 relative overflow-hidden">
        {/* Asset Image */}
        <div className="absolute inset-0">
          {asset.faceDown ? (
            <div className="w-full h-full bg-gradient-to-br from-blue-600 to-blue-800 flex items-center justify-center">
              <div className="text-white text-xs font-bold">CARD</div>
            </div>
          ) : (
            <img
              src={asset.gameAsset.filePath.includes('storage.googleapis.com') && asset.gameAsset.filePath.includes('.private/uploads/')
                ? `/api/image-proxy?url=${encodeURIComponent(asset.gameAsset.filePath)}`
                : asset.gameAsset.filePath}
              alt={asset.gameAsset.name}
              className="w-full h-full object-cover"
              draggable={false}
            />
          )}
        </div>

        {/* Controls Overlay */}
        {isSelected && canInteract && (
          <div className="absolute inset-0 bg-black bg-opacity-50 flex flex-col justify-between p-1">
            {/* Top Controls */}
            <div className="flex justify-between items-start">
              <Badge variant="secondary" className="text-xs">
                {visibilityIcon}
              </Badge>
              {asset.isLocked && (
                <Lock className="w-3 h-3 text-red-400" />
              )}
            </div>

            {/* Bottom Controls */}
            <div className="flex justify-center space-x-1">
              <Button
                size="sm"
                variant="ghost"
                className="w-6 h-6 p-0 text-white hover:bg-white hover:bg-opacity-20"
                onClick={handleRotate}
                data-testid={`button-rotate-${asset.id}`}
              >
                <RotateCcw className="w-3 h-3" />
              </Button>
              <Button
                size="sm"
                variant="ghost"
                className="w-6 h-6 p-0 text-white hover:bg-white hover:bg-opacity-20"
                onClick={handleFlip}
                data-testid={`button-flip-${asset.id}`}
              >
                <FlipHorizontal className="w-3 h-3" />
              </Button>
              {(isAdmin || isOwner) && (
                <Button
                  size="sm"
                  variant="ghost"
                  className="w-6 h-6 p-0 text-white hover:bg-white hover:bg-opacity-20"
                  onClick={handleVisibilityToggle}
                  data-testid={`button-visibility-${asset.id}`}
                >
                  {visibilityIcon}
                </Button>
              )}
            </div>
          </div>
        )}

        {/* Asset Type Indicator */}
        <div className="absolute top-1 right-1">
          <Badge
            variant={asset.assetType === 'card' ? 'default' : 'secondary'}
            className="text-xs"
          >
            {asset.assetType?.toUpperCase() || 'OTHER'}
          </Badge>
        </div>

        {/* Stack Order Indicator */}
        {(asset.stackOrder || 0) > 0 && (
          <div className="absolute bottom-1 left-1">
            <Badge variant="outline" className="text-xs">
              <Layers className="w-2 h-2 mr-1" />
              {asset.stackOrder}
            </Badge>
          </div>
        )}
      </Card>

      {/* Quick Actions Menu */}
      {isSelected && canInteract && (
        <div className="absolute -top-8 left-0 bg-white border rounded-lg shadow-lg p-1 flex space-x-1">
          <Button
            size="sm"
            variant="ghost"
            className="w-6 h-6 p-0"
            onClick={handleLayerUp}
            data-testid={`button-layer-up-${asset.id}`}
          >
            ↑
          </Button>
          <Button
            size="sm"
            variant="ghost"
            className="w-6 h-6 p-0"
            onClick={handleLayerDown}
            data-testid={`button-layer-down-${asset.id}`}
          >
            ↓
          </Button>
          {isAdmin && (
            <Button
              size="sm"
              variant="ghost"
              className="w-6 h-6 p-0"
              onClick={handleLockToggle}
              data-testid={`button-lock-${asset.id}`}
            >
              {asset.isLocked ? <Unlock className="w-3 h-3" /> : <Lock className="w-3 h-3" />}
            </Button>
          )}
        </div>
      )}
    </div>
  );
}
