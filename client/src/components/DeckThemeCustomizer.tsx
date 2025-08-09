import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
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
import { Palette, Eye, Save, RotateCcw } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import type { CardDeck, DeckTheme, GameAsset } from "@shared/schema";

interface DeckThemeCustomizerProps {
  deck: CardDeck;
  roomId: string;
  assets: GameAsset[];
  onThemeUpdated?: (deckId: string, theme: DeckTheme) => void;
}

// Predefined theme templates
const THEME_TEMPLATES = {
  classic: {
    name: "Classic",
    cardBackColor: "#2B4C8C",
    cardBorderColor: "#1E3A8A",
    deckBackgroundColor: "#F3F4F6",
    textColor: "#1F2937",
    borderStyle: "solid",
    cornerRadius: 8,
    shadowIntensity: "medium"
  },
  vintage: {
    name: "Vintage",
    cardBackColor: "#92400E",
    cardBorderColor: "#78350F",
    deckBackgroundColor: "#FEF3C7",
    textColor: "#451A03",
    borderStyle: "double",
    cornerRadius: 12,
    shadowIntensity: "high"
  },
  modern: {
    name: "Modern",
    cardBackColor: "#1F2937",
    cardBorderColor: "#374151",
    deckBackgroundColor: "#F9FAFB",
    textColor: "#111827",
    borderStyle: "solid",
    cornerRadius: 4,
    shadowIntensity: "low"
  },
  fantasy: {
    name: "Fantasy",
    cardBackColor: "#7C3AED",
    cardBorderColor: "#5B21B6",
    deckBackgroundColor: "#EDE9FE",
    textColor: "#3730A3",
    borderStyle: "dashed",
    cornerRadius: 16,
    shadowIntensity: "high"
  },
  cyberpunk: {
    name: "Cyberpunk",
    cardBackColor: "#DC2626",
    cardBorderColor: "#B91C1C",
    deckBackgroundColor: "#1F2937",
    textColor: "#F59E0B",
    borderStyle: "solid",
    cornerRadius: 2,
    shadowIntensity: "medium"
  }
};

export function DeckThemeCustomizer({ 
  deck, 
  roomId, 
  assets,
  onThemeUpdated 
}: DeckThemeCustomizerProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [currentTheme, setCurrentTheme] = useState<DeckTheme>(
    deck.theme || THEME_TEMPLATES.classic
  );
  const [previewMode, setPreviewMode] = useState(false);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  // Save theme mutation
  const saveThemeMutation = useMutation({
    mutationFn: async (theme: DeckTheme) => {
      const response = await fetch(`/api/rooms/${roomId}/decks/${deck.id}/theme`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ theme }),
      });
      if (!response.ok) throw new Error("Failed to save theme");
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/rooms", roomId, "decks"] });
      onThemeUpdated?.(deck.id, currentTheme);
      setIsOpen(false);
      toast({ 
        title: "Theme saved!", 
        description: "Your deck theme has been updated successfully." 
      });
    },
    onError: () => {
      toast({ 
        title: "Failed to save theme", 
        variant: "destructive" 
      });
    },
  });

  const handleTemplateSelect = (templateKey: string) => {
    const template = THEME_TEMPLATES[templateKey as keyof typeof THEME_TEMPLATES];
    setCurrentTheme({ ...template });
  };

  const handleSave = () => {
    saveThemeMutation.mutate(currentTheme);
  };

  const handleReset = () => {
    setCurrentTheme(deck.theme || THEME_TEMPLATES.classic);
  };

  const updateThemeProperty = (property: keyof DeckTheme, value: any) => {
    setCurrentTheme(prev => ({ ...prev, [property]: value }));
  };

  // Get the card assets for this deck
  const deckCards = (deck.deckOrder as string[] || [])
    .map(cardId => assets.find(asset => asset.id === cardId))
    .filter(Boolean) as GameAsset[];

  // Generate preview styles
  const previewCardStyle = {
    backgroundColor: currentTheme.cardBackColor,
    borderColor: currentTheme.cardBorderColor,
    borderStyle: currentTheme.borderStyle,
    borderRadius: `${currentTheme.cornerRadius}px`,
    color: currentTheme.textColor,
    boxShadow: currentTheme.shadowIntensity === "low" ? "0 1px 3px rgba(0,0,0,0.1)" :
               currentTheme.shadowIntensity === "medium" ? "0 4px 6px rgba(0,0,0,0.1)" :
               "0 10px 15px rgba(0,0,0,0.2)"
  };

  const previewDeckStyle = {
    backgroundColor: currentTheme.deckBackgroundColor,
    borderRadius: `${currentTheme.cornerRadius}px`,
  };

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogTrigger asChild>
        <Button 
          size="sm" 
          variant="ghost" 
          data-testid={`button-theme-${deck.id}`}
          title="Customize deck theme"
        >
          <Palette className="w-3 h-3" />
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Palette className="w-5 h-5" />
            Customize Deck Theme: {deck.name}
          </DialogTitle>
        </DialogHeader>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Theme Configuration */}
          <div className="space-y-4">
            <div>
              <Label className="text-sm font-medium mb-3 block">Theme Templates</Label>
              <div className="grid grid-cols-2 gap-2">
                {Object.entries(THEME_TEMPLATES).map(([key, template]) => (
                  <Button
                    key={key}
                    variant="outline"
                    size="sm"
                    onClick={() => handleTemplateSelect(key)}
                    className="justify-start"
                    data-testid={`template-${key}`}
                  >
                    <div 
                      className="w-3 h-3 rounded mr-2 border"
                      style={{ backgroundColor: template.cardBackColor }}
                    />
                    {template.name}
                  </Button>
                ))}
              </div>
            </div>

            <div className="space-y-3">
              <Label className="text-sm font-medium">Custom Colors</Label>
              
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label htmlFor="card-back-color" className="text-xs">Card Back</Label>
                  <div className="flex items-center gap-2">
                    <Input
                      id="card-back-color"
                      type="color"
                      value={currentTheme.cardBackColor}
                      onChange={(e) => updateThemeProperty('cardBackColor', e.target.value)}
                      className="w-12 h-8 p-1"
                      data-testid="input-card-back-color"
                    />
                    <Input
                      value={currentTheme.cardBackColor}
                      onChange={(e) => updateThemeProperty('cardBackColor', e.target.value)}
                      className="flex-1 text-xs"
                      placeholder="#2B4C8C"
                    />
                  </div>
                </div>

                <div>
                  <Label htmlFor="card-border-color" className="text-xs">Card Border</Label>
                  <div className="flex items-center gap-2">
                    <Input
                      id="card-border-color"
                      type="color"
                      value={currentTheme.cardBorderColor}
                      onChange={(e) => updateThemeProperty('cardBorderColor', e.target.value)}
                      className="w-12 h-8 p-1"
                      data-testid="input-card-border-color"
                    />
                    <Input
                      value={currentTheme.cardBorderColor}
                      onChange={(e) => updateThemeProperty('cardBorderColor', e.target.value)}
                      className="flex-1 text-xs"
                      placeholder="#1E3A8A"
                    />
                  </div>
                </div>

                <div>
                  <Label htmlFor="deck-bg-color" className="text-xs">Deck Background</Label>
                  <div className="flex items-center gap-2">
                    <Input
                      id="deck-bg-color"
                      type="color"
                      value={currentTheme.deckBackgroundColor}
                      onChange={(e) => updateThemeProperty('deckBackgroundColor', e.target.value)}
                      className="w-12 h-8 p-1"
                      data-testid="input-deck-bg-color"
                    />
                    <Input
                      value={currentTheme.deckBackgroundColor}
                      onChange={(e) => updateThemeProperty('deckBackgroundColor', e.target.value)}
                      className="flex-1 text-xs"
                      placeholder="#F3F4F6"
                    />
                  </div>
                </div>

                <div>
                  <Label htmlFor="text-color" className="text-xs">Text Color</Label>
                  <div className="flex items-center gap-2">
                    <Input
                      id="text-color"
                      type="color"
                      value={currentTheme.textColor}
                      onChange={(e) => updateThemeProperty('textColor', e.target.value)}
                      className="w-12 h-8 p-1"
                      data-testid="input-text-color"
                    />
                    <Input
                      value={currentTheme.textColor}
                      onChange={(e) => updateThemeProperty('textColor', e.target.value)}
                      className="flex-1 text-xs"
                      placeholder="#1F2937"
                    />
                  </div>
                </div>
              </div>
            </div>

            <div className="space-y-3">
              <Label className="text-sm font-medium">Style Options</Label>
              
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label htmlFor="border-style" className="text-xs">Border Style</Label>
                  <Select 
                    value={currentTheme.borderStyle} 
                    onValueChange={(value) => updateThemeProperty('borderStyle', value)}
                  >
                    <SelectTrigger data-testid="select-border-style">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="solid">Solid</SelectItem>
                      <SelectItem value="dashed">Dashed</SelectItem>
                      <SelectItem value="dotted">Dotted</SelectItem>
                      <SelectItem value="double">Double</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div>
                  <Label htmlFor="corner-radius" className="text-xs">Corner Radius</Label>
                  <Input
                    id="corner-radius"
                    type="number"
                    min="0"
                    max="32"
                    value={currentTheme.cornerRadius}
                    onChange={(e) => updateThemeProperty('cornerRadius', parseInt(e.target.value))}
                    className="text-xs"
                    data-testid="input-corner-radius"
                  />
                </div>

                <div className="col-span-2">
                  <Label htmlFor="shadow-intensity" className="text-xs">Shadow Intensity</Label>
                  <Select 
                    value={currentTheme.shadowIntensity} 
                    onValueChange={(value) => updateThemeProperty('shadowIntensity', value)}
                  >
                    <SelectTrigger data-testid="select-shadow-intensity">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="low">Low</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </div>
          </div>

          {/* Preview */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <Label className="text-sm font-medium">Preview</Label>
              <Button
                size="sm"
                variant="outline"
                onClick={() => setPreviewMode(!previewMode)}
                data-testid="button-toggle-preview"
              >
                <Eye className="w-3 h-3 mr-1" />
                {previewMode ? "Exit Preview" : "Full Preview"}
              </Button>
            </div>

            <Card className="p-4" style={previewDeckStyle}>
              <div className="space-y-3">
                <div className="flex items-center gap-2 mb-3">
                  <Badge variant="outline" style={{ color: currentTheme.textColor }}>
                    {deck.name}
                  </Badge>
                  <Badge variant="secondary" style={{ color: currentTheme.textColor }}>
                    {(deck.deckOrder as string[] || []).length} cards
                  </Badge>
                </div>

                {/* Card preview stack with actual images */}
                <div className="relative w-32 h-44 mx-auto">
                  {[0, 1, 2].map((index) => {
                    const cardAsset = deckCards[index];
                    return (
                      <div
                        key={index}
                        className="absolute border-2 w-full h-full overflow-hidden"
                        style={{
                          ...previewCardStyle,
                          transform: `translateX(${index * 3}px) translateY(${index * 3}px)`,
                          zIndex: 3 - index,
                        }}
                      >
                        {cardAsset ? (
                          <img
                            src={cardAsset.filePath}
                            alt={cardAsset.name}
                            className="w-full h-full object-cover"
                            style={{
                              filter: index > 0 ? 'brightness(0.7) contrast(0.8)' : 'none'
                            }}
                          />
                        ) : (
                          <div className="w-full h-full flex items-center justify-center text-xs font-medium">
                            {index === 0 && "No Cards"}
                          </div>
                        )}
                        {/* Theme overlay for visual effect */}
                        <div 
                          className="absolute inset-0 pointer-events-none"
                          style={{
                            background: `linear-gradient(135deg, ${currentTheme.cardBackColor}15, transparent 50%, ${currentTheme.cardBorderColor}10)`,
                          }}
                        />
                      </div>
                    );
                  })}
                </div>

                <div className="text-center text-xs" style={{ color: currentTheme.textColor }}>
                  Card Stack Preview
                </div>
              </div>
            </Card>

            {previewMode && (
              <Card className="p-3 border-dashed">
                <div className="text-xs text-gray-600 space-y-1">
                  <div><strong>Theme:</strong> {currentTheme.name || "Custom"}</div>
                  <div><strong>Card Back:</strong> {currentTheme.cardBackColor}</div>
                  <div><strong>Border:</strong> {currentTheme.borderStyle} {currentTheme.cardBorderColor}</div>
                  <div><strong>Radius:</strong> {currentTheme.cornerRadius}px</div>
                  <div><strong>Shadow:</strong> {currentTheme.shadowIntensity}</div>
                </div>
              </Card>
            )}
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center justify-between pt-4 border-t">
          <Button
            variant="outline"
            onClick={handleReset}
            data-testid="button-reset-theme"
          >
            <RotateCcw className="w-4 h-4 mr-2" />
            Reset
          </Button>
          
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              onClick={() => setIsOpen(false)}
              data-testid="button-cancel-theme"
            >
              Cancel
            </Button>
            <Button
              onClick={handleSave}
              disabled={saveThemeMutation.isPending}
              data-testid="button-save-theme"
            >
              <Save className="w-4 h-4 mr-2" />
              {saveThemeMutation.isPending ? "Saving..." : "Save Theme"}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}