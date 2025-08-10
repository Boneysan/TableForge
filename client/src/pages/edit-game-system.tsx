import { useState, useEffect } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { 
  ArrowLeft, 
  Upload, 
  Save,
  Plus,
  X,
  FileImage,
  Settings,
  CreditCard,
  Circle,
  Map,
  FileText,
  Loader2,
  Trash2
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { ObjectUploader } from "@/components/ObjectUploader";
import { useLocation } from "wouter";
import { authenticatedApiRequest } from "@/lib/authClient";
import { queryClient } from "@/lib/queryClient";

interface UploadedAsset {
  name: string;
  url: string;
  type: string;
  size: number;
  category: 'cards' | 'tokens' | 'maps' | 'rules';
}

interface EditGameSystemProps {
  systemId: string;
}

export default function EditGameSystem({ systemId }: EditGameSystemProps) {
  const { toast } = useToast();
  const [, setLocation] = useLocation();
  
  // Form state
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [isPublic, setIsPublic] = useState(false);
  const [tags, setTags] = useState<string[]>([]);
  const [newTag, setNewTag] = useState("");
  const [showTagSuggestions, setShowTagSuggestions] = useState(false);
  const [uploadedAssets, setUploadedAssets] = useState<UploadedAsset[]>([]);
  const [selectedCategory, setSelectedCategory] = useState<'cards' | 'tokens' | 'maps' | 'rules'>('cards');
  const [selectedTab, setSelectedTab] = useState<'assets' | 'decks'>('assets');

  // Fetch existing game system data
  const { data: systemData, isLoading: isLoadingSystem, error: systemError } = useQuery({
    queryKey: ["/api/systems", systemId],
    queryFn: async () => {
      const response = await authenticatedApiRequest("GET", `/api/systems/${systemId}`);
      if (!response.ok) {
        throw new Error("Failed to fetch game system");
      }
      return response.json();
    },
    enabled: !!systemId,
  });

  // Initialize form with existing data
  useEffect(() => {
    if (systemData) {
      setName(systemData.name || "");
      setDescription(systemData.description || "");
      setIsPublic(systemData.isPublic || false);
      setTags(systemData.tags || []);
      // Convert existing assets to the expected format
      if (systemData.assets) {
        const formattedAssets = systemData.assets.map((asset: any) => ({
          name: asset.name,
          url: asset.filePath || asset.url,
          type: asset.type,
          size: asset.size || 0,
          category: asset.category || 'cards',
        }));
        setUploadedAssets(formattedAssets);
      }
    }
  }, [systemData]);

  // Preset tag suggestions categorized by type
  const tagSuggestions = {
    "Game Types": ["strategy", "card-game", "board-game", "rpg", "party-game", "cooperative", "competitive", "abstract"],
    "Mechanics": ["deck-building", "area-control", "worker-placement", "dice-rolling", "tile-placement", "trading", "resource-management", "drafting"],
    "Themes": ["fantasy", "sci-fi", "medieval", "modern", "historical", "horror", "adventure", "mystery", "war", "space"],
    "Player Count": ["solo", "2-player", "3-4-players", "5+ players", "party-size"],
    "Complexity": ["beginner", "family", "intermediate", "advanced", "expert"],
    "Time": ["quick", "30-min", "60-min", "90+ min", "epic"]
  };

  const addTag = (tag?: string) => {
    const tagToAdd = tag || newTag.trim();
    if (tagToAdd && !tags.includes(tagToAdd.toLowerCase())) {
      setTags([...tags, tagToAdd.toLowerCase()]);
      setNewTag("");
      setShowTagSuggestions(false);
    }
  };

  const addMultipleTags = (input: string) => {
    // Split by commas, newlines, or semicolons and clean up
    const newTags = input
      .split(/[,;\n\r]+/)
      .map(tag => tag.trim().toLowerCase())
      .filter(tag => tag && !tags.includes(tag));
    
    if (newTags.length > 0) {
      setTags([...tags, ...newTags]);
      setNewTag("");
      setShowTagSuggestions(false);
    }
  };

  const removeTag = (tagToRemove: string) => {
    setTags(tags.filter(tag => tag !== tagToRemove));
  };

  const handleTagInputKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      // Check if input contains multiple tags (comma, semicolon, or newline separated)
      if (newTag.includes(',') || newTag.includes(';') || newTag.includes('\n')) {
        addMultipleTags(newTag);
      } else {
        addTag();
      }
    } else if (e.key === 'Escape') {
      setShowTagSuggestions(false);
    }
  };

  const handleTagInputPaste = (e: React.ClipboardEvent) => {
    const pastedText = e.clipboardData.getData('text');
    // Check if pasted text contains multiple tags
    if (pastedText.includes(',') || pastedText.includes(';') || pastedText.includes('\n')) {
      e.preventDefault();
      addMultipleTags(pastedText);
    }
  };

  // Handle asset upload
  const handleGetUploadParameters = async () => {
    try {
      const response = await authenticatedApiRequest("GET", "/api/upload/presigned-url");
      if (!response.ok) {
        throw new Error("Failed to get upload parameters");
      }
      const data = await response.json();
      return {
        method: "PUT" as const,
        url: data.uploadUrl,
      };
    } catch (error) {
      console.error("Error getting upload parameters:", error);
      toast({
        title: "Upload Error",
        description: "Failed to prepare upload. Please try again.",
        variant: "destructive",
      });
      throw error;
    }
  };

  const handleUploadComplete = (result: any) => {
    if (result.successful && result.successful.length > 0) {
      const newAssets = result.successful.map((file: any) => ({
        name: file.name,
        url: file.uploadURL,
        type: file.type,
        size: file.size,
        category: selectedCategory,
      }));
      setUploadedAssets(prev => [...prev, ...newAssets]);
      toast({
        title: "Assets Uploaded",
        description: `Successfully uploaded ${result.successful.length} ${selectedCategory} asset(s)`,
      });
    }
  };

  const removeAsset = (indexToRemove: number) => {
    setUploadedAssets(prev => prev.filter((_, index) => index !== indexToRemove));
  };

  // Update game system
  const updateGameSystemMutation = useMutation({
    mutationFn: async () => {
      const gameSystemData = {
        name: name.trim(),
        description: description.trim(),
        isPublic,
        tags,
        assets: uploadedAssets,
      };

      const response = await authenticatedApiRequest("PUT", `/api/systems/${systemId}`, gameSystemData);
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || "Failed to update game system");
      }
      
      return response.json();
    },
    onSuccess: (data) => {
      toast({
        title: "Game System Updated",
        description: `"${name}" has been updated successfully!`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/game-systems"] });
      queryClient.invalidateQueries({ queryKey: ["/api/game-systems"] });
      queryClient.invalidateQueries({ queryKey: ["/api/systems", systemId] });
      setLocation("/admin");
    },
    onError: (error: any) => {
      toast({
        title: "Failed to Update Game System",
        description: error.message || "An error occurred while updating the game system.",
        variant: "destructive",
      });
    },
  });

  // Delete game system
  const deleteGameSystemMutation = useMutation({
    mutationFn: async () => {
      const response = await authenticatedApiRequest("DELETE", `/api/systems/${systemId}`);
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || "Failed to delete game system");
      }
      
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "Game System Deleted",
        description: `"${name}" has been deleted successfully.`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/game-systems"] });
      queryClient.invalidateQueries({ queryKey: ["/api/game-systems"] });
      setLocation("/admin");
    },
    onError: (error: any) => {
      toast({
        title: "Failed to Delete Game System",
        description: error.message || "An error occurred while deleting the game system.",
        variant: "destructive",
      });
    },
  });

  const handleSave = () => {
    if (!name.trim()) {
      toast({
        title: "Validation Error",
        description: "Please provide a name for your game system.",
        variant: "destructive",
      });
      return;
    }
    updateGameSystemMutation.mutate();
  };

  const handleDelete = () => {
    if (window.confirm(`Are you sure you want to delete "${name}"? This action cannot be undone.`)) {
      deleteGameSystemMutation.mutate();
    }
  };

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const assetCategories = [
    { id: 'cards' as const, name: 'Cards', icon: CreditCard, description: 'Playing cards, character cards, action cards' },
    { id: 'tokens' as const, name: 'Tokens', icon: Circle, description: 'Game pieces, markers, counters' },
    { id: 'maps' as const, name: 'Maps', icon: Map, description: 'Game boards, battlefields, terrain' },
    { id: 'rules' as const, name: 'Rules', icon: FileText, description: 'Rulebooks, guides, reference sheets' },
  ];

  const getAssetsByCategory = (category: string) => {
    return uploadedAssets.filter(asset => asset.category === category);
  };

  if (isLoadingSystem) {
    return (
      <div className="min-h-screen bg-background p-6 flex items-center justify-center">
        <div className="flex items-center gap-2">
          <Loader2 className="w-6 h-6 animate-spin" />
          <span>Loading game system...</span>
        </div>
      </div>
    );
  }

  if (systemError) {
    return (
      <div className="min-h-screen bg-background p-6">
        <Alert variant="destructive">
          <AlertDescription>
            Failed to load game system. Please try again or go back.
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background p-6">
      {/* Header */}
      <div className="flex justify-between items-center mb-8">
        <div className="flex items-center space-x-4">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setLocation("/admin")}
            className="flex items-center gap-2"
            data-testid="button-back-admin"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to Admin
          </Button>
          <Separator orientation="vertical" className="h-6" />
          <div className="flex items-center space-x-3">
            <Settings className="w-8 h-8 text-primary" />
            <h1 className="text-3xl font-bold">Edit Game System</h1>
          </div>
        </div>
        <Button
          variant="destructive"
          size="sm"
          onClick={handleDelete}
          disabled={deleteGameSystemMutation.isPending}
          data-testid="button-delete-system"
        >
          {deleteGameSystemMutation.isPending ? (
            <Loader2 className="w-4 h-4 animate-spin mr-2" />
          ) : (
            <Trash2 className="w-4 h-4 mr-2" />
          )}
          Delete System
        </Button>
      </div>

      <div className="max-w-4xl mx-auto space-y-6">
        {/* Basic Information */}
        <Card>
          <CardHeader>
            <CardTitle>Basic Information</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Name *</Label>
              <Input
                id="name"
                placeholder="Enter game system name..."
                value={name}
                onChange={(e) => setName(e.target.value)}
                data-testid="input-system-name"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="description">Description</Label>
              <Textarea
                id="description"
                placeholder="Describe your game system..."
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={4}
                data-testid="textarea-system-description"
              />
            </div>

            <div className="flex items-center space-x-2">
              <Switch
                id="public"
                checked={isPublic}
                onCheckedChange={setIsPublic}
                data-testid="switch-public"
              />
              <Label htmlFor="public">Make this game system public</Label>
            </div>
          </CardContent>
        </Card>

        {/* Tags */}
        <Card>
          <CardHeader>
            <CardTitle>Tags</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-sm text-gray-600">Add tags to help players discover your game system</p>
            
            {/* Current Tags */}
            <div className="flex flex-wrap gap-2 mb-2">
              {tags.map((tag, index) => (
                <Badge key={index} variant="secondary" className="flex items-center gap-1">
                  {tag}
                  <X 
                    className="w-3 h-3 cursor-pointer" 
                    onClick={() => removeTag(tag)}
                    data-testid={`remove-tag-${tag}`}
                  />
                </Badge>
              ))}
              {tags.length === 0 && (
                <span className="text-gray-400 text-sm">No tags added yet</span>
              )}
            </div>
            
            {/* Tag Input */}
            <div className="relative">
              <div className="flex gap-2">
                <Input
                  placeholder="Type tags (comma/line separated) or browse suggestions..."
                  value={newTag}
                  onChange={(e) => setNewTag(e.target.value)}
                  onKeyDown={handleTagInputKeyPress}
                  onPaste={handleTagInputPaste}
                  onFocus={() => setShowTagSuggestions(true)}
                  data-testid="input-new-tag"
                />
                <Button 
                  type="button" 
                  variant="outline" 
                  onClick={() => {
                    if (newTag.includes(',') || newTag.includes(';') || newTag.includes('\n')) {
                      addMultipleTags(newTag);
                    } else {
                      addTag();
                    }
                  }}
                  disabled={!newTag.trim()}
                  data-testid="button-add-tag"
                >
                  <Plus className="w-4 h-4" />
                </Button>
                <Button 
                  type="button" 
                  variant="outline" 
                  onClick={() => setShowTagSuggestions(!showTagSuggestions)}
                  data-testid="button-toggle-suggestions"
                >
                  Suggestions
                </Button>
              </div>
              
              {/* Tag Suggestions Dropdown */}
              {showTagSuggestions && (
                <div className="absolute top-full left-0 right-0 mt-1 bg-white border border-gray-200 rounded-lg shadow-lg z-50 max-h-96 overflow-y-auto">
                  <div className="p-3">
                    <div className="flex justify-between items-center mb-3">
                      <h4 className="font-medium text-sm">Popular Tags</h4>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setShowTagSuggestions(false)}
                        className="h-6 w-6 p-0"
                      >
                        <X className="w-3 h-3" />
                      </Button>
                    </div>
                    
                    {Object.entries(tagSuggestions).map(([category, categoryTags]) => (
                      <div key={category} className="mb-4 last:mb-0">
                        <h5 className="text-xs font-medium text-gray-500 mb-2">{category}</h5>
                        <div className="flex flex-wrap gap-1">
                          {categoryTags.map((tag) => (
                            <button
                              key={tag}
                              className={`px-2 py-1 text-xs rounded-md border transition-colors
                                ${tags.includes(tag) 
                                  ? 'bg-blue-100 border-blue-300 text-blue-700 cursor-not-allowed' 
                                  : 'bg-gray-50 border-gray-200 text-gray-700 hover:bg-blue-50 hover:border-blue-300'
                                }`}
                              onClick={() => addTag(tag)}
                              disabled={tags.includes(tag)}
                              data-testid={`suggestion-tag-${tag}`}
                            >
                              {tag} {tags.includes(tag) && '✓'}
                            </button>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
            
            {/* Tag Helper Text */}
            <div className="text-xs text-gray-500 space-y-1">
              <div>
                <strong>Single tag:</strong> Type and press Enter • <strong>Multiple tags:</strong> Use commas, semicolons, or new lines
              </div>
              <div>
                Examples: "strategy, fantasy, 2-player" or paste a vertical list • Use suggestions above or create your own
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Asset and Deck Management */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FileImage className="w-5 h-5" />
              Asset & Deck Management
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Tab Selection */}
            <div className="flex space-x-1 bg-muted p-1 rounded-lg">
              <Button
                variant={selectedTab === 'assets' ? 'default' : 'ghost'}
                size="sm"
                onClick={() => setSelectedTab('assets')}
                className="flex-1"
                data-testid="tab-assets"
              >
                <FileImage className="w-4 h-4 mr-2" />
                Assets
              </Button>
              <Button
                variant={selectedTab === 'decks' ? 'default' : 'ghost'}
                size="sm"
                onClick={() => setSelectedTab('decks')}
                className="flex-1"
                data-testid="tab-decks"
              >
                <CreditCard className="w-4 h-4 mr-2" />
                Card Decks
              </Button>
            </div>

            {/* Assets Tab */}
            {selectedTab === 'assets' && (
              <div className="space-y-6">
                {/* Category Selection */}
                <div className="space-y-3">
                  <Label>Select Asset Category</Label>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    {assetCategories.map((category) => {
                      const Icon = category.icon;
                      const isSelected = selectedCategory === category.id;
                      return (
                        <Button
                          key={category.id}
                          variant={isSelected ? "default" : "outline"}
                          onClick={() => setSelectedCategory(category.id)}
                          className="flex flex-col h-auto p-4 text-center"
                          data-testid={`button-category-${category.id}`}
                        >
                          <Icon className="w-6 h-6 mb-2" />
                          <span className="font-medium">{category.name}</span>
                          <span className="text-xs text-muted-foreground mt-1">
                            {getAssetsByCategory(category.id).length} assets
                          </span>
                        </Button>
                      );
                    })}
                  </div>
                </div>

                {/* Upload Component */}
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <h4 className="font-medium">Upload {assetCategories.find(c => c.id === selectedCategory)?.name}</h4>
                    <Badge variant="outline">{getAssetsByCategory(selectedCategory).length} assets</Badge>
                  </div>
                  
                  <ObjectUploader
                    onGetUploadParameters={handleGetUploadParameters}
                    onComplete={handleUploadComplete}
                    maxNumberOfFiles={10}
                  >
                    <Upload className="w-4 h-4 mr-2" />
                    Upload {assetCategories.find(c => c.id === selectedCategory)?.name}
                  </ObjectUploader>
                </div>

                {/* Assets by Category */}
                {assetCategories.map((category) => {
                  const categoryAssets = getAssetsByCategory(category.id);
                  if (categoryAssets.length === 0) return null;

                  const Icon = category.icon;
                  return (
                    <div key={category.id} className="space-y-3">
                      <div className="flex items-center gap-2">
                        <Icon className="w-4 h-4" />
                        <h4 className="font-medium">{category.name}</h4>
                        <Badge variant="outline">{categoryAssets.length}</Badge>
                      </div>
                      
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                        {categoryAssets.map((asset, index) => (
                          <div key={index} className="border rounded-lg p-3">
                            <div className="flex justify-between items-start mb-2">
                              <div className="flex-1 min-w-0">
                                <p className="font-medium text-sm truncate">{asset.name}</p>
                                <p className="text-xs text-gray-500">{formatFileSize(asset.size)}</p>
                              </div>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => removeAsset(uploadedAssets.indexOf(asset))}
                                className="ml-2 h-6 w-6 p-0"
                                data-testid={`button-remove-asset-${index}`}
                              >
                                <X className="w-3 h-3" />
                              </Button>
                            </div>
                            
                            {asset.type.startsWith('image/') && (
                              <div className="mt-2">
                                <img 
                                  src={asset.url} 
                                  alt={asset.name}
                                  className="w-full h-20 object-cover rounded border"
                                  onError={(e) => {
                                    (e.target as HTMLImageElement).style.display = 'none';
                                  }}
                                />
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {/* Card Decks Tab */}
            {selectedTab === 'decks' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h4 className="font-medium">Card Deck Management</h4>
                  <Badge variant="outline">System Editor</Badge>
                </div>
                
                <Alert>
                  <CreditCard className="h-4 w-4" />
                  <AlertDescription>
                    Create and manage card decks for your game system. Upload card images to the "Cards" category above, then create decks using those cards here.
                  </AlertDescription>
                </Alert>
                
                {/* Simple Deck Creator for Game Systems */}
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h5 className="font-medium">Available Card Assets</h5>
                    <Badge variant="outline">{getAssetsByCategory('cards').length} cards</Badge>
                  </div>
                  
                  {getAssetsByCategory('cards').length === 0 ? (
                    <div className="text-center py-8 border-2 border-dashed border-muted rounded-lg">
                      <CreditCard className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
                      <p className="text-muted-foreground mb-2">No card assets uploaded yet</p>
                      <p className="text-sm text-muted-foreground">Switch to the "Assets" tab and upload card images to get started</p>
                      <Button 
                        variant="outline" 
                        size="sm" 
                        className="mt-4"
                        onClick={() => setSelectedTab('assets')}
                      >
                        Upload Cards
                      </Button>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
                        {getAssetsByCategory('cards').map((card, index) => (
                          <div key={index} className="border rounded-lg p-2">
                            <img 
                              src={card.url} 
                              alt={card.name}
                              className="w-full h-24 object-cover rounded mb-2"
                              onError={(e) => {
                                (e.target as HTMLImageElement).style.display = 'none';
                              }}
                            />
                            <p className="text-xs font-medium truncate">{card.name}</p>
                          </div>
                        ))}
                      </div>
                      
                      <div className="bg-muted p-4 rounded-lg">
                        <h6 className="font-medium mb-2">Deck Creation</h6>
                        <p className="text-sm text-muted-foreground mb-4">
                          Card deck functionality will be fully integrated in the next update. For now, your uploaded card assets are stored and can be used when creating game rooms.
                        </p>
                        <div className="flex gap-2">
                          <Button variant="outline" size="sm" disabled>
                            <Plus className="w-4 h-4 mr-2" />
                            Create Deck (Coming Soon)
                          </Button>
                          <Button variant="outline" size="sm" disabled>
                            <Shuffle className="w-4 h-4 mr-2" />
                            Import Deck (Coming Soon)
                          </Button>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Save Button */}
        <div className="flex justify-end gap-3">
          <Button
            variant="outline"
            onClick={() => setLocation("/admin")}
            data-testid="button-cancel"
          >
            Cancel
          </Button>
          <Button
            onClick={handleSave}
            disabled={updateGameSystemMutation.isPending || !name.trim()}
            data-testid="button-save-system"
          >
            {updateGameSystemMutation.isPending ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin mr-2" />
                Updating...
              </>
            ) : (
              <>
                <Save className="w-4 h-4 mr-2" />
                Update Game System
              </>
            )}
          </Button>
        </div>
      </div>
    </div>
  );
}