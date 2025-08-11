import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { Switch } from '@/components/ui/switch';
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
  Package,
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { ObjectUploader } from '@/components/ObjectUploader';
import { BulkUploader } from '@/components/BulkUploader';
import { useLocation } from 'wouter';
import { authenticatedApiRequest } from '@/lib/authClient';
import { queryClient } from '@/lib/queryClient';

interface UploadedAsset {
  name: string;
  url: string;
  type: string;
  size: number;
  category: 'cards' | 'tokens' | 'maps' | 'rules';
}

export default function CreateGameSystem() {
  const { toast } = useToast();
  const [, setLocation] = useLocation();

  // Form state
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [isPublic, setIsPublic] = useState(false);
  const [tags, setTags] = useState<string[]>([]);
  const [newTag, setNewTag] = useState('');
  const [showTagSuggestions, setShowTagSuggestions] = useState(false);
  const [uploadedAssets, setUploadedAssets] = useState<UploadedAsset[]>([]);
  const [selectedCategory, setSelectedCategory] = useState<'cards' | 'tokens' | 'maps' | 'rules'>('cards');
  const [currentSystemId, setCurrentSystemId] = useState<string | null>(null);

  // Handle asset upload
  const handleAssetUpload = async () => {
    try {
      const response = await authenticatedApiRequest('POST', '/api/objects/upload');
      if (!response.ok) {
        throw new Error('Failed to get upload parameters');
      }
      const data = await response.json();
      return {
        method: 'PUT' as const,
        url: data.uploadURL,
      };
    } catch (error) {
      console.error('Error getting upload parameters:', error);
      toast({
        title: 'Upload Error',
        description: 'Failed to prepare upload. Please try again.',
        variant: 'destructive',
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
        title: 'Assets Uploaded',
        description: `Successfully uploaded ${result.successful.length} ${selectedCategory} asset(s)`,
      });
    }
  };

  // New callback for system assets that creates database records immediately
  const handleSystemAssetUploadComplete = async (result: any) => {
    console.log('🎯 [System Asset Upload] Processing completed upload:', {
      hasSystemId: !!currentSystemId,
      systemId: currentSystemId,
      successfulCount: result.successful?.length || 0,
    });

    if (!currentSystemId) {
      console.error('❌ [System Asset Upload] No system ID available for asset creation');
      toast({
        title: 'Upload Error',
        description: 'Please create the system first before uploading assets',
        variant: 'destructive',
      });
      return;
    }

    if (result.successful && result.successful.length > 0) {
      try {
        for (const file of result.successful) {
          const assetData = {
            name: file.name,
            type: selectedCategory,
            filePath: new URL(file.uploadURL).pathname.substring(1), // Remove leading slash
            fileSize: file.size,
            category: selectedCategory,
            tags: [],
            visibility: 'public',
          };

          console.log('📝 [System Asset] Creating database record:', {
            systemId: currentSystemId,
            name: assetData.name,
            type: assetData.type,
            path: assetData.filePath,
          });

          const response = await authenticatedApiRequest(
            'POST',
            `/api/systems/${currentSystemId}/assets`,
            assetData,
          );

          if (!response.ok) {
            const errorData = await response.json();
            throw new Error(`Failed to create asset ${file.name}: ${errorData.error}`);
          }

          const createdAsset = await response.json();
          console.log('✅ [System Asset] Created asset:', createdAsset.id);
        }

        // Update local state
        const newAssets = result.successful.map((file: any) => ({
          name: file.name,
          url: file.uploadURL,
          type: file.type,
          size: file.size,
          category: selectedCategory,
        }));
        setUploadedAssets(prev => [...prev, ...newAssets]);

        toast({
          title: 'System Assets Created',
          description: `Successfully created ${result.successful.length} ${selectedCategory} asset(s) in database`,
        });
      } catch (error) {
        console.error('❌ [System Asset Upload] Failed to create database records:', error);
        toast({
          title: 'Database Error',
          description: `Upload succeeded but failed to create database records: ${error.message}`,
          variant: 'destructive',
        });
      }
    }
  };

  // Handle tag management
  // Preset tag suggestions categorized by type
  const tagSuggestions = {
    'Game Types': ['strategy', 'card-game', 'board-game', 'rpg', 'party-game', 'cooperative', 'competitive', 'abstract'],
    'Mechanics': ['deck-building', 'area-control', 'worker-placement', 'dice-rolling', 'tile-placement', 'trading', 'resource-management', 'drafting'],
    'Themes': ['fantasy', 'sci-fi', 'medieval', 'modern', 'historical', 'horror', 'adventure', 'mystery', 'war', 'space'],
    'Player Count': ['solo', '2-player', '3-4-players', '5+ players', 'party-size'],
    'Complexity': ['beginner', 'family', 'intermediate', 'advanced', 'expert'],
    'Time': ['quick', '30-min', '60-min', '90+ min', 'epic'],
  };

  const addTag = (tag?: string) => {
    const tagToAdd = tag || newTag.trim();
    if (tagToAdd && !tags.includes(tagToAdd.toLowerCase())) {
      setTags([...tags, tagToAdd.toLowerCase()]);
      setNewTag('');
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
      setNewTag('');
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

  const removeAsset = (indexToRemove: number) => {
    setUploadedAssets(prev => prev.filter((_, index) => index !== indexToRemove));
  };

  // Save game system
  const saveGameSystemMutation = useMutation({
    mutationFn: async () => {
      const gameSystemData = {
        name: name.trim(),
        description: description.trim(),
        isPublic,
        tags,
        assets: uploadedAssets,
      };

      const response = await authenticatedApiRequest('POST', '/api/systems', gameSystemData);

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to create game system');
      }

      return response.json();
    },
    onSuccess: (data) => {
      console.log('🎯 [Game System] Created successfully:', data.id);
      setCurrentSystemId(data.id); // Store system ID for asset uploads

      toast({
        title: 'Game System Created',
        description: `"${name}" has been created successfully! You can now upload assets.`,
      });
      queryClient.invalidateQueries({ queryKey: ['/api/admin/game-systems'] });
      queryClient.invalidateQueries({ queryKey: ['/api/game-systems'] });
    },
    onError: (error: any) => {
      toast({
        title: 'Failed to Create Game System',
        description: error.message || 'An error occurred while creating the game system.',
        variant: 'destructive',
      });
    },
  });

  const handleSave = () => {
    if (!name.trim()) {
      toast({
        title: 'Validation Error',
        description: 'Please provide a name for your game system.',
        variant: 'destructive',
      });
      return;
    }
    saveGameSystemMutation.mutate();
  };

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))  } ${  sizes[i]}`;
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

  return (
    <div className="min-h-screen bg-background p-6">
      {/* Header */}
      <div className="flex justify-between items-center mb-8">
        <div className="flex items-center space-x-4">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setLocation('/')}
            className="flex items-center gap-2"
            data-testid="button-back-home"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to Home
          </Button>
          <Separator orientation="vertical" className="h-6" />
          <div className="flex items-center space-x-3">
            <Settings className="w-8 h-8 text-primary" />
            <h1 className="text-3xl font-bold">Create Game System</h1>
          </div>
        </div>
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

        {/* Asset Upload */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FileImage className="w-5 h-5" />
              Upload Assets by Category
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
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
                      variant={isSelected ? 'default' : 'outline'}
                      onClick={() => setSelectedCategory(category.id)}
                      className="flex flex-col h-auto p-4 text-center"
                      data-testid={`button-category-${category.id}`}
                    >
                      <Icon className="w-6 h-6 mb-2" />
                      <span className="font-medium">{category.name}</span>
                      <span className="text-xs text-muted-foreground mt-1">
                        {category.description}
                      </span>
                    </Button>
                  );
                })}
              </div>
            </div>

            {!currentSystemId && (
              <div className="bg-amber-50 border border-amber-200 rounded-lg p-4">
                <div className="flex items-start gap-3">
                  <div className="text-amber-600 mt-0.5">
                    <Settings className="w-4 h-4" />
                  </div>
                  <div className="text-sm text-amber-800">
                    <strong>First Step:</strong> Create your game system by filling out the basic information and clicking "Create Game System" below.
                    Once created, you can upload assets that will be automatically saved to the database.
                  </div>
                </div>
              </div>
            )}

            {currentSystemId && (
              <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                <div className="flex items-start gap-3">
                  <div className="text-green-600 mt-0.5">
                    <Package className="w-4 h-4" />
                  </div>
                  <div className="text-sm text-green-800">
                    <strong>System Created!</strong> Your game system is ready. Assets uploaded now will be automatically saved to the database.
                  </div>
                </div>
              </div>
            )}

            {/* Upload Options */}
            <div className="space-y-4">
              {selectedCategory === 'cards' ? (
                <div className="space-y-4">
                  <div className="text-center">
                    <h4 className="font-medium text-lg mb-2">Card Upload Options</h4>
                    <p className="text-sm text-muted-foreground">Choose your upload method based on the number of cards</p>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Standard Upload */}
                    <div className="text-center">
                      <ObjectUploader
                        maxNumberOfFiles={50}
                        maxFileSize={50485760} // 50MB
                        onGetUploadParameters={handleAssetUpload}
                        onComplete={currentSystemId ? handleSystemAssetUploadComplete : handleUploadComplete}
                        buttonClassName="w-full flex items-center justify-center gap-2 py-3"
                      >
                        <Upload className="w-5 h-5" />
                        Standard Upload (up to 50 cards)
                      </ObjectUploader>
                      <p className="text-xs text-muted-foreground mt-2">Good for smaller card sets</p>
                    </div>

                    {/* Bulk Upload */}
                    <div className="text-center">
                      <BulkUploader
                        maxTotalFiles={500}
                        batchSize={50}
                        maxFileSize={50485760} // 50MB
                        onGetUploadParameters={handleAssetUpload}
                        onBatchComplete={currentSystemId ? handleSystemAssetUploadComplete : handleUploadComplete}
                        onAllComplete={(total) => {
                          toast({
                            title: 'System Assets Complete',
                            description: `Successfully processed ${total} cards! ${currentSystemId ? 'All assets created in database.' : 'Create the system first to save assets.'}`,
                          });
                        }}
                        buttonClassName="w-full flex items-center justify-center gap-2 py-3 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700"
                      >
                        <Package className="w-5 h-5" />
                        Bulk Upload (up to 500 cards)
                      </BulkUploader>
                      <p className="text-xs text-muted-foreground mt-2">Perfect for complete card sets like your 140 cards</p>
                    </div>
                  </div>

                  <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                    <div className="flex items-start gap-3">
                      <div className="text-blue-600 mt-0.5">
                        <Package className="w-4 h-4" />
                      </div>
                      <div className="text-sm text-blue-800">
                        <strong>Bulk Upload Features:</strong>
                        <ul className="mt-1 space-y-1 list-disc list-inside ml-2">
                          <li>Handles 100+ files automatically in batches</li>
                          <li>Progress tracking across all batches</li>
                          <li>Automatic retry for failed uploads</li>
                          <li>Continues processing even if some files fail</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                /* Regular upload for non-card categories */
                <div className="flex justify-center">
                  <ObjectUploader
                    maxNumberOfFiles={50}
                    maxFileSize={50485760} // 50MB
                    onGetUploadParameters={handleAssetUpload}
                    onComplete={currentSystemId ? handleSystemAssetUploadComplete : handleUploadComplete}
                    buttonClassName="flex items-center gap-2"
                  >
                    <Upload className="w-4 h-4" />
                    Upload {assetCategories.find(c => c.id === selectedCategory)?.name} Assets
                  </ObjectUploader>
                </div>
              )}
            </div>

            {/* Assets by Category */}
            {uploadedAssets.length > 0 && (
              <div className="space-y-4">
                <h4 className="font-medium">Uploaded Assets ({uploadedAssets.length} total)</h4>
                {assetCategories.map((category) => {
                  const categoryAssets = getAssetsByCategory(category.id);
                  const Icon = category.icon;

                  if (categoryAssets.length === 0) return null;

                  return (
                    <div key={category.id} className="space-y-2">
                      <div className="flex items-center gap-2">
                        <Icon className="w-4 h-4 text-primary" />
                        <h5 className="font-medium">{category.name} ({categoryAssets.length})</h5>
                      </div>
                      <div className="grid gap-2">
                        {categoryAssets.map((asset, index) => {
                          const globalIndex = uploadedAssets.indexOf(asset);
                          return (
                            <div
                              key={globalIndex}
                              className="flex items-center justify-between p-3 bg-muted rounded-lg"
                            >
                              <div className="flex items-center space-x-3">
                                <Icon className="w-4 h-4 text-muted-foreground" />
                                <div>
                                  <p className="text-sm font-medium">{asset.name}</p>
                                  <p className="text-xs text-muted-foreground">
                                    {formatFileSize(asset.size)} • {asset.type}
                                  </p>
                                </div>
                              </div>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => removeAsset(globalIndex)}
                                data-testid={`button-remove-asset-${globalIndex}`}
                              >
                                <X className="w-4 h-4" />
                              </Button>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Actions */}
        <div className="flex justify-end space-x-4">
          <Button
            variant="outline"
            onClick={() => setLocation('/')}
            data-testid="button-cancel"
          >
            Cancel
          </Button>
          {!currentSystemId ? (
            <Button
              onClick={handleSave}
              disabled={saveGameSystemMutation.isPending || !name.trim()}
              data-testid="button-save-system"
            >
              {saveGameSystemMutation.isPending ? (
                <>
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                  Creating...
                </>
              ) : (
                <>
                  <Save className="w-4 h-4 mr-2" />
                  Create Game System
                </>
              )}
            </Button>
          ) : (
            <Button
              onClick={() => setLocation('/admin')}
              data-testid="button-finish"
            >
              <Save className="w-4 h-4 mr-2" />
              Finish & Go to Admin
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}
