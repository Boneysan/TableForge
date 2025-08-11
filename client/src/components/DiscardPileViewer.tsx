import { useState } from 'react';
import { X, Eye } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';

interface Asset {
  id: string;
  name: string;
  filePath: string;
  type: string;
}

interface CardPile {
  id: string;
  name: string;
  cardOrder: string[] | null;
  pileType: string;
}

interface DiscardPileViewerProps {
  pile: CardPile;
  assets: Asset[];
  isVisible?: boolean;
}

export function DiscardPileViewer({ pile, assets, isVisible = true }: DiscardPileViewerProps) {
  const [isOpen, setIsOpen] = useState(false);
  
  // Only show for discard piles
  if (pile.pileType !== 'discard') {
    return null;
  }

  const cardOrder = Array.isArray(pile.cardOrder) ? pile.cardOrder : [];
  const cardCount = cardOrder.length;
  
  // Get the cards in order (most recently discarded first)
  const discardedCards = cardOrder.map(cardId => 
    assets.find(asset => asset.id === cardId)
  ).filter(Boolean);

  if (!isVisible || cardCount === 0) {
    return null;
  }

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          className="absolute -bottom-8 left-1/2 transform -translate-x-1/2 bg-black/80 hover:bg-black/90 text-white border-gray-600 text-xs px-2 py-1 h-6"
          data-testid={`view-discard-${pile.id}`}
        >
          <Eye className="w-3 h-3 mr-1" />
          View ({cardCount})
        </Button>
      </DialogTrigger>
      
      <DialogContent className="max-w-4xl max-h-[80vh] overflow-hidden">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <span>{pile.name}</span>
            <span className="text-sm text-gray-500">({cardCount} cards)</span>
          </DialogTitle>
        </DialogHeader>
        
        <div className="overflow-y-auto max-h-[60vh] pr-2">
          {discardedCards.length > 0 ? (
            <div className="grid grid-cols-4 sm:grid-cols-6 md:grid-cols-8 gap-2">
              {discardedCards.map((card, index) => (
                <div
                  key={`${card?.id}-${index}`}
                  className="relative group cursor-pointer"
                  data-testid={`discard-card-${card?.id}`}
                >
                  <div className="aspect-[2/3] rounded-lg overflow-hidden bg-gray-200 hover:ring-2 hover:ring-blue-400 transition-all">
                    {card ? (
                      <img
                        src={`/api/image-proxy?url=${encodeURIComponent(card.filePath)}`}
                        alt={card.name}
                        className="w-full h-full object-cover"
                        onError={(e) => {
                          const target = e.target as HTMLImageElement;
                          target.src = 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTAwIiBoZWlnaHQ9IjE1MCIgdmlld0JveD0iMCAwIDEwMCAxNTAiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxyZWN0IHdpZHRoPSIxMDAiIGhlaWdodD0iMTUwIiBmaWxsPSIjRjNGNEY2Ii8+CjxwYXRoIGQ9Ik0zNSA2MEw2NSA5MEwzNSAxMjBWNjBaIiBmaWxsPSIjOUNBM0FGIi8+Cjx0ZXh0IHg9IjUwIiB5PSI0MCIgZm9udC1mYW1pbHk9InNhbnMtc2VyaWYiIGZvbnQtc2l6ZT0iMTIiIGZpbGw9IiM2QjcyODAiIHRleHQtYW5jaG9yPSJtaWRkbGUiPkltYWdlPC90ZXh0Pgo8L3N2Zz4K';
                        }}
                      />
                    ) : (
                      <div className="w-full h-full bg-gray-300 flex items-center justify-center">
                        <span className="text-xs text-gray-500">?</span>
                      </div>
                    )}
                  </div>
                  
                  {/* Card order indicator */}
                  <div className="absolute top-1 right-1 bg-black/70 text-white text-xs px-1 rounded">
                    {discardedCards.length - index}
                  </div>
                  
                  {/* Card name tooltip on hover */}
                  {card && (
                    <div className="absolute bottom-0 left-0 right-0 bg-black/80 text-white text-xs p-1 rounded-b-lg opacity-0 group-hover:opacity-100 transition-opacity truncate">
                      {card.name.replace(/\.(jpg|jpeg|png|gif|bmp|webp)$/i, '')}
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-gray-500">
              <p>No cards in discard pile</p>
            </div>
          )}
        </div>
        
        <div className="flex justify-between items-center pt-4 border-t">
          <div className="text-sm text-gray-600">
            Cards are shown in discard order (most recent first)
          </div>
          <Button 
            onClick={() => setIsOpen(false)}
            variant="outline"
            size="sm"
          >
            Close
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}