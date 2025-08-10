import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { CardDeck, DeckTheme, GameAsset } from "@shared/schema";

interface ThemedDeckCardProps {
  deck: CardDeck;
  assets: GameAsset[];
  children?: React.ReactNode;
  className?: string;
}

// Default theme
const DEFAULT_THEME: DeckTheme = {
  name: "Classic",
  cardBackColor: "#2B4C8C",
  cardBorderColor: "#1E3A8A",
  deckBackgroundColor: "#F3F4F6",
  textColor: "#1F2937",
  borderStyle: "solid",
  cornerRadius: 8,
  shadowIntensity: "medium"
};

export function ThemedDeckCard({ deck, assets, children, className = "" }: ThemedDeckCardProps) {
  const theme = deck.theme || DEFAULT_THEME;
  
  // Get the card assets for this deck
  const deckCards = (deck.deckOrder as string[] || [])
    .map(cardId => assets.find(asset => asset.id === cardId))
    .filter(Boolean) as GameAsset[];
  
  // Generate CSS styles from theme
  const deckStyle = {
    backgroundColor: theme.deckBackgroundColor,
    borderRadius: `${theme.cornerRadius}px`,
    color: theme.textColor,
    boxShadow: theme.shadowIntensity === "low" ? "0 1px 3px rgba(0,0,0,0.1)" :
               theme.shadowIntensity === "medium" ? "0 4px 6px rgba(0,0,0,0.1)" :
               "0 10px 15px rgba(0,0,0,0.2)"
  };

  const cardPreviewStyle = {
    backgroundColor: theme.cardBackColor,
    borderColor: theme.cardBorderColor,
    borderStyle: theme.borderStyle,
    borderWidth: "2px",
    borderRadius: `${theme.cornerRadius}px`,
    color: theme.textColor,
  };

  return (
    <Card 
      className={`relative overflow-hidden ${className}`}
      style={deckStyle}
      data-testid={`themed-deck-${deck.id}`}
    >
      <CardContent className="p-4">
        <div className="flex items-start justify-between mb-3">
          <div className="flex-1">
            <div className="font-medium mb-1" style={{ color: theme.textColor }}>
              {deck.name}
            </div>
            {deck.description && (
              <div className="text-sm opacity-75" style={{ color: theme.textColor }}>
                {deck.description}
              </div>
            )}
          </div>
          
          {/* Card stack preview with actual images */}
          <div className="relative w-16 h-20 ml-3">
            {[0, 1, 2].map((index) => {
              const cardAsset = deckCards[index];
              return (
                <div
                  key={index}
                  className="absolute w-full h-full overflow-hidden"
                  style={{
                    ...cardPreviewStyle,
                    transform: `translateX(${index * 2}px) translateY(${index * 2}px)`,
                    zIndex: 3 - index,
                  }}
                >
                  {cardAsset ? (
                    <img
                      src={cardAsset.filePath.includes('storage.googleapis.com') && cardAsset.filePath.includes('.private/uploads/') 
                        ? `/api/image-proxy?url=${encodeURIComponent(cardAsset.filePath)}`
                        : cardAsset.filePath}
                      alt={cardAsset.name}
                      className="w-full h-full object-cover"
                      style={{
                        filter: index > 0 ? 'brightness(0.8)' : 'none'
                      }}
                    />
                  ) : (
                    <div className="w-full h-full flex items-center justify-center text-xs">
                      <div 
                        className="w-3 h-3 rounded-full opacity-50"
                        style={{ backgroundColor: theme.textColor }}
                      />
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        <div className="flex items-center gap-2 mb-3">
          <Badge 
            variant="outline" 
            className="text-xs border-current"
            style={{ 
              color: theme.textColor,
              borderColor: theme.textColor + "40" // 25% opacity
            }}
          >
            {(deck.deckOrder as string[] || []).length} cards
          </Badge>
          {deck.isShuffled && (
            <Badge 
              variant="secondary" 
              className="text-xs"
              style={{ 
                backgroundColor: theme.cardBackColor + "20", // 12% opacity
                color: theme.textColor 
              }}
            >
              Shuffled
            </Badge>
          )}
          {theme.name && theme.name !== "Classic" && (
            <Badge 
              variant="outline" 
              className="text-xs border-current"
              style={{ 
                color: theme.cardBackColor,
                borderColor: theme.cardBackColor + "60" // 38% opacity
              }}
            >
              {theme.name}
            </Badge>
          )}
        </div>

        {/* Action buttons area */}
        <div className="flex items-center justify-end">
          {children}
        </div>
      </CardContent>
    </Card>
  );
}