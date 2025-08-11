import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { 
  Plus, 
  Shuffle, 
  Package, 
  Eye, 
  EyeOff,
  Trash2,
  Edit,
  Play,
  Square,
  Users,
  User,
  X
} from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { queryKeys } from "@/lib/queryKeys";
import { useCreateDeck, useShuffleDeck, useDrawCards, useCreatePile, useRoomDecks, useRoomPiles } from "@/hooks/useGameRoomQuery";
import { DeckThemeCustomizer } from "./DeckThemeCustomizer";
import { ThemedDeckCard } from "./ThemedDeckCard";
import type { CardDeck, CardPile, GameAsset, DeckTheme } from "@shared/schema";

interface CardDeckManagerProps {
  roomId: string;
  assets: GameAsset[];
  currentUserId: string;
  playerRole: "admin" | "player";
  onCardDealt: (cards: string[], targetPile: string) => void;
  onCardDrawn?: (deckId: string, playerId: string, count: number) => void;
  onThemeUpdated?: (deckId: string, theme: DeckTheme) => void;
}

export function CardDeckManager({ 
  roomId, 
  assets, 
  currentUserId, 
  playerRole,
  onCardDealt,
  onCardDrawn,
  onThemeUpdated
}: CardDeckManagerProps) {
  const [showCreateDeck, setShowCreateDeck] = useState(false);
  const [showCreatePile, setShowCreatePile] = useState(false);
  const [deckName, setDeckName] = useState("");
  const [deckDescription, setDeckDescription] = useState("");
  const [selectedCards, setSelectedCards] = useState<string[]>([]);
  const [cardFilter, setCardFilter] = useState("");
  const [quickTemplate, setQuickTemplate] = useState<string | null>(null);
  const [selectedCardBack, setSelectedCardBack] = useState<string | null>(null);
  const [pileName, setPileName] = useState("");
  const [showDeckPresets, setShowDeckPresets] = useState(false);
  const [pileType, setPileType] = useState<"deck" | "discard" | "hand" | "custom">("custom");
  const [pileVisibility, setPileVisibility] = useState<"public" | "owner" | "gm">("public");
  const { toast } = useToast();
  const queryClient = useQueryClient();

  // Use centralized query hooks with stable keys
  const { data: decks = [] } = useRoomDecks(roomId);
  const { data: piles = [] } = useRoomPiles(roomId);

  // Use optimized mutation hooks
  const createDeckMutation = useCreateDeck(roomId);

  const createPileMutation = useCreatePile(roomId);

  const shuffleDeckMutation = useShuffleDeck(roomId);

  const drawCardMutation = useDrawCards(roomId);

  // Deal cards mutation - Keep this one as is since it's more complex
  const dealCardsMutation = useMutation({
    mutationFn: async (data: { deckId: string; count: number; targetPile: string }) => {
      const response = await apiRequest("POST", `/api/rooms/${roomId}/decks/${data.deckId}/deal`, {
        count: data.count, 
        targetPile: data.targetPile
      });
      return response.json();
    },
    onSuccess: (data: any, variables) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.decks.all(roomId) });
      queryClient.invalidateQueries({ queryKey: queryKeys.piles.all(roomId) });
      onCardDealt(data.cards || [], variables.targetPile);
      toast({ title: `Dealt ${variables.count} cards!` });
    },
    onError: () => {
      toast({ title: "Failed to deal cards", variant: "destructive" });
    },
  });

  const cardAssets = assets.filter(asset => 
    asset.type === "card" || 
    asset.type === "image/jpeg" || 
    asset.type === "image/png" || 
    asset.type === "image/webp" || 
    asset.name.toLowerCase().includes("card")
  );

  // Card back assets - these could be any image asset that would work as a card back
  const cardBackAssets = assets.filter(asset => 
    asset.type === "card" || 
    asset.type === "image/jpeg" || 
    asset.type === "image/png" || 
    asset.type === "image/webp" || 
    asset.name.toLowerCase().includes("back") ||
    asset.name.toLowerCase().includes("cardback") ||
    asset.type === "other" // Allow any image asset to be used as card back
  );

  // Get cards that are already used in existing decks
  const usedCardIds = new Set<string>();
  (decks as CardDeck[]).forEach(deck => {
    if (deck.deckOrder && Array.isArray(deck.deckOrder)) {
      deck.deckOrder.forEach((cardId: string) => usedCardIds.add(cardId));
    }
  });

  // Filter to show only available (unused) cards
  const availableCardAssets = cardAssets.filter(asset => !usedCardIds.has(asset.id));
  
  // Filter cards based on search
  const filteredCardAssets = availableCardAssets.filter(asset => 
    asset.name.toLowerCase().includes(cardFilter.toLowerCase())
  );
  
  // Debug logging
  console.log("🔍 [Deck Manager Debug]");
  console.log("Total cardAssets:", cardAssets.length);
  console.log("Used card IDs:", Array.from(usedCardIds));
  console.log("Available card assets:", availableCardAssets.length);
  console.log("Filtered card assets:", filteredCardAssets.length);
  console.log("Show create deck dialog:", showCreateDeck);
  console.log("availableCardAssets.length > 0:", availableCardAssets.length > 0);

  const handleCreateDeck = () => {
    if (!deckName.trim() || selectedCards.length === 0) {
      toast({ title: "Please provide a deck name and select cards", variant: "destructive" });
      return;
    }

    createDeckMutation.mutate({
      name: deckName,
      description: deckDescription,
      deckOrder: selectedCards,
    });
  };

  const handleCreatePile = () => {
    if (!pileName.trim()) {
      toast({ title: "Please provide a pile name", variant: "destructive" });
      return;
    }

    createPileMutation.mutate({
      name: pileName,
      positionX: Math.random() * 400 + 100, // Random position for now
      positionY: Math.random() * 300 + 100,
      pileType,
      visibility: pileVisibility,
      ownerId: pileVisibility === "owner" ? currentUserId : undefined,
    });
  };

  const toggleCardSelection = (cardId: string) => {
    setSelectedCards(prev => 
      prev.includes(cardId) 
        ? prev.filter(id => id !== cardId)
        : [...prev, cardId]
    );
  };

  const selectAllFilteredCards = () => {
    const filteredAssets = availableCardAssets.filter(asset => 
      asset.name.toLowerCase().includes(cardFilter.toLowerCase())
    );
    const allFilteredIds = filteredAssets.map(asset => asset.id);
    setSelectedCards(prev => Array.from(new Set([...prev, ...allFilteredIds])));
  };

  const selectAllAvailableCards = () => {
    const allAvailableCardIds = availableCardAssets.map(asset => asset.id);
    setSelectedCards(allAvailableCardIds);
  };

  const deselectAllFilteredCards = () => {
    const filteredAssets = availableCardAssets.filter(asset => 
      asset.name.toLowerCase().includes(cardFilter.toLowerCase())
    );
    const filteredIds = new Set(filteredAssets.map(asset => asset.id));
    setSelectedCards(prev => prev.filter(id => !filteredIds.has(id)));
  };

  const applyQuickTemplate = (template: string) => {
    setQuickTemplate(template);
    setDeckName(template);
    setDeckDescription(`Auto-generated ${template.toLowerCase()} deck`);
    
    // Auto-select cards based on template
    const templateKeywords = {
      "Attack Cards": ["attack", "damage", "strike", "sword", "weapon"],
      "Defense Cards": ["defend", "shield", "block", "armor", "protection"],
      "Resource Cards": ["mana", "energy", "gold", "resource", "coin"],
      "Spell Cards": ["spell", "magic", "enchant", "potion", "scroll"],
      "Character Cards": ["character", "hero", "player", "warrior", "mage"],
      "Action Cards": ["action", "move", "turn", "ability", "skill"]
    };

    if (templateKeywords[template as keyof typeof templateKeywords]) {
      const keywords = templateKeywords[template as keyof typeof templateKeywords];
      const matchingCards = availableCardAssets.filter(asset => 
        keywords.some(keyword => 
          asset.name.toLowerCase().includes(keyword.toLowerCase())
        )
      );
      setSelectedCards(matchingCards.map(card => card.id));
    }
  };

  const canManageDecks = playerRole === "admin";
  const canCreatePiles = playerRole === "admin";

  const createPresetDecks = () => {
    const presets = [
      {
        name: "Standard Playing Cards",
        description: "Traditional 52-card deck",
        keywords: ["ace", "king", "queen", "jack", "hearts", "diamonds", "clubs", "spades"]
      },
      {
        name: "Tarot Deck",
        description: "Tarot cards for divination",
        keywords: ["tarot", "major", "minor", "arcana", "cups", "wands", "swords", "pentacles"]
      },
      {
        name: "Battle Cards",
        description: "Combat and action cards",
        keywords: ["attack", "damage", "battle", "fight", "weapon", "armor"]
      },
      {
        name: "Magic Spells",
        description: "Magical spells and enchantments",
        keywords: ["spell", "magic", "enchant", "potion", "scroll", "ritual"]
      },
      {
        name: "Resources & Economy",
        description: "Economic and resource management cards",
        keywords: ["gold", "mana", "energy", "resource", "coin", "trade"]
      }
    ];

    presets.forEach(preset => {
      const matchingCards = cardAssets.filter(asset => 
        preset.keywords.some(keyword => 
          asset.name.toLowerCase().includes(keyword.toLowerCase())
        )
      );

      if (matchingCards.length > 0) {
        createDeckMutation.mutate({
          name: preset.name,
          description: preset.description,
          deckOrder: matchingCards.map(card => card.id),
        });
      }
    });

    setShowDeckPresets(false);
    toast({
      title: "Preset Decks Created",
      description: "Multiple decks have been created based on your uploaded cards.",
    });
  };

  return (
    <div className="space-y-4">
      {/* Deck Management */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm flex items-center gap-2">
              <Package className="w-4 h-4" />
              Card Decks
            </CardTitle>
            {canManageDecks && (
              <div className="flex gap-2">
                <Dialog open={showDeckPresets} onOpenChange={setShowDeckPresets}>
                  <DialogTrigger asChild>
                    <Button size="sm" variant="outline" data-testid="button-create-presets">
                      <Package className="w-3 h-3 mr-1" />
                      Auto-Create Decks
                    </Button>
                  </DialogTrigger>
                  <DialogContent>
                    <DialogHeader>
                      <DialogTitle>Create Preset Decks</DialogTitle>
                    </DialogHeader>
                    <div className="space-y-4">
                      <p className="text-sm text-gray-600">
                        This will automatically create multiple decks based on your uploaded cards using common deck types.
                        Only decks with matching cards will be created.
                      </p>
                      <div className="bg-blue-50 p-3 rounded-lg">
                        <h4 className="font-medium text-sm mb-2">Preset Decks Include:</h4>
                        <ul className="text-xs space-y-1 text-gray-600">
                          <li>• Standard Playing Cards (52-card deck)</li>
                          <li>• Tarot Deck (divination cards)</li>
                          <li>• Battle Cards (combat actions)</li>
                          <li>• Magic Spells (enchantments)</li>
                          <li>• Resources & Economy (gold, mana, etc.)</li>
                        </ul>
                      </div>
                      <div className="flex gap-2">
                        <Button 
                          onClick={createPresetDecks}
                          disabled={createDeckMutation.isPending || cardAssets.length === 0}
                          className="flex-1"
                          data-testid="button-confirm-presets"
                        >
                          {createDeckMutation.isPending ? "Creating..." : "Create Preset Decks"}
                        </Button>
                        <Button 
                          variant="outline" 
                          onClick={() => setShowDeckPresets(false)}
                          className="flex-1"
                        >
                          Cancel
                        </Button>
                      </div>
                    </div>
                  </DialogContent>
                </Dialog>
                
                <Dialog open={showCreateDeck} onOpenChange={setShowCreateDeck}>
                  <DialogTrigger asChild>
                    <Button size="sm" data-testid="button-create-deck">
                      <Plus className="w-3 h-3 mr-1" />
                      Custom Deck
                    </Button>
                  </DialogTrigger>
                <DialogContent className="max-h-[90vh] overflow-y-auto">
                  <DialogHeader>
                    <DialogTitle>Create New Card Deck</DialogTitle>
                  </DialogHeader>
                  <div className="space-y-4">
                    <div>
                      <Label htmlFor="deck-name">Deck Name</Label>
                      <Input
                        id="deck-name"
                        value={deckName}
                        onChange={(e) => setDeckName(e.target.value)}
                        placeholder="Enter deck name..."
                        data-testid="input-deck-name"
                      />
                    </div>
                    <div>
                      <Label htmlFor="deck-description">Description (Optional)</Label>
                      <Textarea
                        id="deck-description"
                        value={deckDescription}
                        onChange={(e) => setDeckDescription(e.target.value)}
                        placeholder="Describe this deck..."
                        data-testid="textarea-deck-description"
                      />
                    </div>
                    
                    {/* Card Back Selection */}
                    <div>
                      <Label>Card Back (Optional)</Label>
                      <p className="text-xs text-gray-500 mb-2">Choose an image to use as the card back for this deck</p>
                      
                      {selectedCardBack && (
                        <div className="mb-2 p-2 border rounded bg-blue-50">
                          <div className="flex items-center gap-2">
                            <img 
                              src={cardBackAssets.find(asset => asset.id === selectedCardBack)?.filePath}
                              alt="Selected card back"
                              className="w-8 h-8 object-cover rounded"
                            />
                            <span className="text-sm font-medium">
                              {cardBackAssets.find(asset => asset.id === selectedCardBack)?.name}
                            </span>
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => setSelectedCardBack(null)}
                              data-testid="button-remove-card-back"
                            >
                              <X className="w-3 h-3" />
                            </Button>
                          </div>
                        </div>
                      )}
                      
                      <div className="grid grid-cols-4 gap-2 max-h-32 overflow-y-auto border rounded p-2">
                        {cardBackAssets.length > 0 ? (
                          cardBackAssets.map((asset) => (
                            <div
                              key={asset.id}
                              className={`
                                cursor-pointer rounded border-2 p-1 text-center transition-colors
                                ${selectedCardBack === asset.id 
                                  ? "border-blue-500 bg-blue-50" 
                                  : "border-gray-200 hover:border-gray-300"
                                }
                              `}
                              onClick={() => setSelectedCardBack(asset.id)}
                              data-testid={`card-back-selector-${asset.id}`}
                            >
                              <img
                                src={asset.filePath}
                                alt={asset.name}
                                className="w-full h-12 object-cover rounded mb-1"
                              />
                              <div className="text-xs truncate">
                                {asset.name}
                              </div>
                            </div>
                          ))
                        ) : (
                          <div className="col-span-4 text-center py-4 text-gray-500 text-xs">
                            No assets available for card backs.<br />
                            Upload some images to use as card backs.
                          </div>
                        )}
                      </div>
                    </div>
                    
                    {/* Quick Templates */}
                    <div>
                      <Label>Quick Templates</Label>
                      <div className="grid grid-cols-2 gap-2 mt-2">
                        {["Attack Cards", "Defense Cards", "Resource Cards", "Spell Cards", "Character Cards", "Action Cards"].map((template) => (
                          <Button
                            key={template}
                            variant={quickTemplate === template ? "default" : "outline"}
                            size="sm"
                            onClick={() => applyQuickTemplate(template)}
                            data-testid={`template-${template.toLowerCase().replace(/\s+/g, '-')}`}
                          >
                            {template}
                          </Button>
                        ))}
                      </div>
                    </div>
                    <div className="border-t pt-4">
                      <div className="space-y-3">
                        <Label className="text-base font-semibold">Select Cards for Deck ({selectedCards.length} selected)</Label>
                        
                        {/* Selection Action Buttons */}
                        <div className="bg-yellow-50 border border-yellow-200 p-4 rounded-lg">
                          <p className="text-sm font-medium text-yellow-800 mb-3">🚀 Quick Selection Options:</p>
                          <div className="text-xs text-gray-600 mb-2">
                            DEBUG: availableCardAssets.length = {availableCardAssets.length}, condition: {availableCardAssets.length > 0 ? 'TRUE' : 'FALSE'}
                          </div>
                          {availableCardAssets.length > 0 ? (
                            <div className="space-y-2">
                              <Button
                                variant="default"
                                size="default"
                                onClick={() => {
                                  console.log("🎯 SELECT ALL BUTTON CLICKED!");
                                  selectAllAvailableCards();
                                }}
                                disabled={availableCardAssets.length === 0}
                                data-testid="button-select-all-available"
                                className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold"
                              >
                                🎯 SELECT ALL {availableCardAssets.length} AVAILABLE CARDS
                              </Button>
                              <div className="flex gap-2">
                                <Button
                                  variant="outline"
                                  size="sm"
                                  onClick={selectAllFilteredCards}
                                  disabled={filteredCardAssets.length === 0}
                                  data-testid="button-select-all-filtered"
                                  className="flex-1"
                                >
                                  Select Filtered ({filteredCardAssets.length})
                                </Button>
                                <Button
                                  variant="outline"
                                  size="sm"
                                  onClick={deselectAllFilteredCards}
                                  disabled={selectedCards.length === 0}
                                  data-testid="button-deselect-all"
                                  className="flex-1"
                                >
                                  Clear ({selectedCards.length})
                                </Button>
                              </div>
                            </div>
                          ) : (
                            <div className="bg-red-100 border border-red-300 p-3 rounded">
                              <p className="text-red-700 font-medium">⚠️ No Available Cards</p>
                              <p className="text-red-600 text-sm">All {cardAssets.length} cards are already used in existing decks.</p>
                            </div>
                          )}
                        </div>
                      </div>
                      
                      {/* Card Filter */}
                      <Input
                        placeholder="Filter cards by name..."
                        value={cardFilter}
                        onChange={(e) => setCardFilter(e.target.value)}
                        className="mb-2"
                        data-testid="input-card-filter"
                      />
                      
                      <div className="text-xs text-gray-500 mb-2">
                        Showing {filteredCardAssets.length} of {availableCardAssets.length} available cards
                        {usedCardIds.size > 0 && (
                          <span className="text-orange-600 ml-2">
                            ({usedCardIds.size} cards already used in decks)
                          </span>
                        )}
                      </div>
                      
                      <div className="grid grid-cols-3 gap-2 max-h-60 overflow-y-auto border rounded p-2">
                        {filteredCardAssets.map((asset) => (
                          <div
                            key={asset.id}
                            className={`
                              cursor-pointer rounded border-2 p-2 text-center transition-colors
                              ${selectedCards.includes(asset.id) 
                                ? "border-blue-500 bg-blue-50" 
                                : "border-gray-200 hover:border-gray-300"
                              }
                            `}
                            onClick={() => toggleCardSelection(asset.id)}
                            data-testid={`card-selector-${asset.id}`}
                          >
                            <img
                              src={asset.filePath}
                              alt={asset.name}
                              className="w-full h-16 object-cover rounded mb-1"
                            />
                            <div className="text-xs font-medium truncate">
                              {asset.name}
                            </div>
                          </div>
                        ))}
                        {filteredCardAssets.length === 0 && availableCardAssets.length > 0 && (
                          <div className="col-span-3 text-center py-4 text-gray-500 text-sm">
                            No available cards match "{cardFilter}"
                          </div>
                        )}
                        {availableCardAssets.length === 0 && cardAssets.length > 0 && (
                          <div className="col-span-3 text-center py-4 text-gray-500 text-sm">
                            All cards are already used in existing decks
                          </div>
                        )}
                        {cardAssets.length === 0 && (
                          <div className="col-span-3 text-center py-4 text-gray-500 text-sm">
                            No card assets uploaded yet
                          </div>
                        )}
                      </div>
                    </div>
                    <Button 
                      onClick={handleCreateDeck}
                      disabled={createDeckMutation.isPending || !deckName.trim() || selectedCards.length === 0}
                      className="w-full"
                      data-testid="button-save-deck"
                    >
                      {createDeckMutation.isPending ? "Creating..." : "Create Deck"}
                    </Button>
                  </div>
                </DialogContent>
              </Dialog>
              </div>
            )}
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {(decks as CardDeck[]).length === 0 ? (
              <div className="text-center py-4 text-gray-500 text-sm">
                No decks created yet
              </div>
            ) : (
              (decks as CardDeck[]).map((deck: CardDeck) => (
                <ThemedDeckCard
                  key={deck.id}
                  deck={deck}
                  assets={assets}
                  piles={piles as any[]}
                  className="mb-3"
                >
                  <div className="flex items-center gap-1">
                    {/* Draw card button - available to all players */}
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => drawCardMutation.mutate({ deckId: deck.id, count: 1 })}
                      disabled={drawCardMutation.isPending || (() => {
                        const mainPile = (piles as any[]).find((pile: any) => pile.name === `${deck.name} - Main`);
                        const cardOrder = mainPile?.cardOrder as string[] || deck.deckOrder as string[] || [];
                        return cardOrder.length === 0;
                      })()}
                      data-testid={`button-draw-${deck.id}`}
                      title="Draw 1 card to your hand"
                    >
                      <User className="w-3 h-3" />
                    </Button>
                    
                    {canManageDecks && (
                      <>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => shuffleDeckMutation.mutate(deck.id)}
                          disabled={shuffleDeckMutation.isPending}
                          data-testid={`button-shuffle-${deck.id}`}
                          title="Shuffle deck"
                        >
                          <Shuffle className="w-3 h-3" />
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => dealCardsMutation.mutate({ deckId: deck.id, count: 1, targetPile: "board" })}
                          disabled={dealCardsMutation.isPending}
                          data-testid={`button-deal-${deck.id}`}
                          title="Deal 1 card to board"
                        >
                          <Play className="w-3 h-3" />
                        </Button>
                        <DeckThemeCustomizer
                          deck={deck}
                          roomId={roomId}
                          assets={assets}
                          onThemeUpdated={onThemeUpdated}
                        />
                      </>
                    )}
                  </div>
                </ThemedDeckCard>
              ))
            )}
          </div>
        </CardContent>
      </Card>

      {/* Card Piles */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm flex items-center gap-2">
              <Square className="w-4 h-4" />
              Card Piles
            </CardTitle>
            {canCreatePiles && (
              <Dialog open={showCreatePile} onOpenChange={setShowCreatePile}>
                <DialogTrigger asChild>
                  <Button size="sm" data-testid="button-create-pile">
                    <Plus className="w-3 h-3 mr-1" />
                    Create Pile
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Create Card Pile</DialogTitle>
                  </DialogHeader>
                  <div className="space-y-4">
                    <div>
                      <Label htmlFor="pile-name">Pile Name</Label>
                      <Input
                        id="pile-name"
                        value={pileName}
                        onChange={(e) => setPileName(e.target.value)}
                        placeholder="Enter pile name..."
                        data-testid="input-pile-name"
                      />
                    </div>
                    <div>
                      <Label htmlFor="pile-type">Pile Type</Label>
                      <Select value={pileType} onValueChange={(value: any) => setPileType(value)}>
                        <SelectTrigger data-testid="select-pile-type">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="deck">Deck</SelectItem>
                          <SelectItem value="discard">Discard Pile</SelectItem>
                          <SelectItem value="hand">Player Hand</SelectItem>
                          <SelectItem value="custom">Custom</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div>
                      <Label htmlFor="pile-visibility">Visibility</Label>
                      <Select value={pileVisibility} onValueChange={(value: any) => setPileVisibility(value)}>
                        <SelectTrigger data-testid="select-pile-visibility">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="public">Public</SelectItem>
                          <SelectItem value="owner">Owner Only</SelectItem>
                          <SelectItem value="gm">GM Only</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <Button 
                      onClick={handleCreatePile}
                      disabled={createPileMutation.isPending || !pileName.trim()}
                      className="w-full"
                      data-testid="button-save-pile"
                    >
                      {createPileMutation.isPending ? "Creating..." : "Create Pile"}
                    </Button>
                  </div>
                </DialogContent>
              </Dialog>
            )}
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {(piles as CardPile[]).length === 0 ? (
              <div className="text-center py-4 text-gray-500 text-sm">
                No card piles created yet
              </div>
            ) : (
              (piles as CardPile[]).map((pile: CardPile) => (
                <div
                  key={pile.id}
                  className="flex items-center justify-between p-3 border rounded-lg"
                  data-testid={`pile-${pile.id}`}
                >
                  <div className="flex-1">
                    <div className="font-medium">{pile.name}</div>
                    <div className="flex items-center gap-2 mt-1">
                      <Badge variant="outline" className="text-xs">
                        {pile.pileType}
                      </Badge>
                      <Badge variant="secondary" className="text-xs">
                        {pile.visibility === "public" ? <Users className="w-2 h-2" /> : 
                         pile.visibility === "owner" ? <User className="w-2 h-2" /> : 
                         <Eye className="w-2 h-2" />}
                        {pile.visibility}
                      </Badge>
                      <Badge variant="outline" className="text-xs">
                        {(pile.cardOrder as string[] || []).length} cards
                      </Badge>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}