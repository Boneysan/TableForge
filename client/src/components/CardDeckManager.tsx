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
  User
} from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { CardDeck, CardPile, GameAsset } from "@shared/schema";

interface CardDeckManagerProps {
  roomId: string;
  assets: GameAsset[];
  currentUserId: string;
  playerRole: "admin" | "player";
  onCardDealt: (cards: string[], targetPile: string) => void;
  onCardDrawn?: (deckId: string, playerId: string, count: number) => void;
}

export function CardDeckManager({ 
  roomId, 
  assets, 
  currentUserId, 
  playerRole,
  onCardDealt,
  onCardDrawn
}: CardDeckManagerProps) {
  const [showCreateDeck, setShowCreateDeck] = useState(false);
  const [showCreatePile, setShowCreatePile] = useState(false);
  const [deckName, setDeckName] = useState("");
  const [deckDescription, setDeckDescription] = useState("");
  const [selectedCards, setSelectedCards] = useState<string[]>([]);
  const [pileName, setPileName] = useState("");
  const [pileType, setPileType] = useState<"deck" | "discard" | "hand" | "custom">("custom");
  const [pileVisibility, setPileVisibility] = useState<"public" | "owner" | "gm">("public");
  const { toast } = useToast();
  const queryClient = useQueryClient();

  // Fetch card decks
  const { data: decks = [] } = useQuery({
    queryKey: ["/api/rooms", roomId, "decks"],
  });

  // Fetch card piles
  const { data: piles = [] } = useQuery({
    queryKey: ["/api/rooms", roomId, "piles"],
  });

  // Create deck mutation
  const createDeckMutation = useMutation({
    mutationFn: async (data: { name: string; description: string; deckOrder: string[] }) => {
      const response = await fetch(`/api/rooms/${roomId}/decks`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });
      if (!response.ok) throw new Error("Failed to create deck");
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/rooms", roomId, "decks"] });
      setShowCreateDeck(false);
      setDeckName("");
      setDeckDescription("");
      setSelectedCards([]);
      toast({ title: "Deck created successfully!" });
    },
    onError: () => {
      toast({ title: "Failed to create deck", variant: "destructive" });
    },
  });

  // Create pile mutation
  const createPileMutation = useMutation({
    mutationFn: async (data: { 
      name: string; 
      positionX: number; 
      positionY: number; 
      pileType: string;
      visibility: string;
      ownerId?: string;
    }) => {
      const response = await fetch(`/api/rooms/${roomId}/piles`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });
      if (!response.ok) throw new Error("Failed to create pile");
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/rooms", roomId, "piles"] });
      setShowCreatePile(false);
      setPileName("");
      setPileType("custom");
      setPileVisibility("public");
      toast({ title: "Card pile created successfully!" });
    },
    onError: () => {
      toast({ title: "Failed to create pile", variant: "destructive" });
    },
  });

  // Shuffle deck mutation
  const shuffleDeckMutation = useMutation({
    mutationFn: async (deckId: string) => {
      const response = await fetch(`/api/rooms/${roomId}/decks/${deckId}/shuffle`, {
        method: "POST",
      });
      if (!response.ok) throw new Error("Failed to shuffle deck");
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/rooms", roomId, "decks"] });
      toast({ title: "Deck shuffled!" });
    },
    onError: () => {
      toast({ title: "Failed to shuffle deck", variant: "destructive" });
    },
  });

  // Draw card mutation
  const drawCardMutation = useMutation({
    mutationFn: async ({ deckId, count = 1 }: { deckId: string; count?: number }) => {
      const response = await fetch(`/api/rooms/${roomId}/decks/${deckId}/draw`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ playerId: currentUserId, count }),
      });
      if (!response.ok) throw new Error("Failed to draw card");
      return response.json();
    },
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: ["/api/rooms", roomId, "decks"] });
      queryClient.invalidateQueries({ queryKey: ["/api/rooms", roomId, "piles"] });
      onCardDrawn?.(variables.deckId, currentUserId, variables.count || 1);
      toast({ 
        title: `Drew ${variables.count || 1} card${(variables.count || 1) > 1 ? 's' : ''}!`,
        description: `Cards added to your hand`
      });
    },
    onError: () => {
      toast({ title: "Failed to draw card", variant: "destructive" });
    },
  });

  // Deal cards mutation
  const dealCardsMutation = useMutation({
    mutationFn: async (data: { deckId: string; count: number; targetPile: string }) => {
      const response = await fetch(`/api/rooms/${roomId}/decks/${data.deckId}/deal`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ count: data.count, targetPile: data.targetPile }),
      });
      if (!response.ok) throw new Error("Failed to deal cards");
      return response.json();
    },
    onSuccess: (data: any, variables) => {
      queryClient.invalidateQueries({ queryKey: ["/api/rooms", roomId, "decks"] });
      queryClient.invalidateQueries({ queryKey: ["/api/rooms", roomId, "piles"] });
      onCardDealt(data.cards || [], variables.targetPile);
      toast({ title: `Dealt ${variables.count} cards!` });
    },
    onError: () => {
      toast({ title: "Failed to deal cards", variant: "destructive" });
    },
  });

  const cardAssets = assets.filter(asset => 
    asset.type === "card" || asset.name.toLowerCase().includes("card")
  );

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

  const canManageDecks = playerRole === "admin";
  const canCreatePiles = playerRole === "admin";

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
              <Dialog open={showCreateDeck} onOpenChange={setShowCreateDeck}>
                <DialogTrigger asChild>
                  <Button size="sm" data-testid="button-create-deck">
                    <Plus className="w-3 h-3 mr-1" />
                    Create Deck
                  </Button>
                </DialogTrigger>
                <DialogContent>
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
                    <div>
                      <Label>Select Cards ({selectedCards.length} selected)</Label>
                      <div className="grid grid-cols-3 gap-2 max-h-60 overflow-y-auto border rounded p-2">
                        {cardAssets.map((asset) => (
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
            )}
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {decks.length === 0 ? (
              <div className="text-center py-4 text-gray-500 text-sm">
                No decks created yet
              </div>
            ) : (
              (decks as CardDeck[]).map((deck) => (
                <div
                  key={deck.id}
                  className="flex items-center justify-between p-3 border rounded-lg"
                  data-testid={`deck-${deck.id}`}
                >
                  <div className="flex-1">
                    <div className="font-medium">{deck.name}</div>
                    {deck.description && (
                      <div className="text-sm text-gray-600">{deck.description}</div>
                    )}
                    <div className="flex items-center gap-2 mt-1">
                      <Badge variant="outline" className="text-xs">
                        {(deck.deckOrder as string[] || []).length} cards
                      </Badge>
                      {deck.isShuffled && (
                        <Badge variant="secondary" className="text-xs">
                          Shuffled
                        </Badge>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-1">
                    {/* Draw card button - available to all players */}
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => drawCardMutation.mutate({ deckId: deck.id, count: 1 })}
                      disabled={drawCardMutation.isPending || (deck.deckOrder as string[] || []).length === 0}
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
                      </>
                    )}
                  </div>
                </div>
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
            {piles.length === 0 ? (
              <div className="text-center py-4 text-gray-500 text-sm">
                No card piles created yet
              </div>
            ) : (
              (piles as CardPile[]).map((pile) => (
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