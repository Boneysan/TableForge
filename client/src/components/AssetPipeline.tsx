import { useState, useRef } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { ObjectUploader } from './ObjectUploader';
import {
  Upload,
  FileImage,
  Package,
  Tag,
  Search,
  Filter,
  Edit3,
  Copy,
  Trash2,
  Eye,
  EyeOff,
} from 'lucide-react';
import type { GameAsset } from '@shared/schema';

interface AssetPipelineProps {
  roomId: string;
  assets: GameAsset[];
  onAssetUploaded: (asset: GameAsset) => void;
  onAssetUpdated: (assetId: string, updates: Partial<GameAsset>) => void;
  onAssetDeleted: (assetId: string) => void;
  playerRole: 'admin' | 'player';
}

interface AssetTag {
  id: string;
  name: string;
  color: string;
}

interface AssetFilter {
  search: string;
  category: string;
  tags: string[];
  visibility: string;
}

export function AssetPipeline({
  roomId,
  assets,
  onAssetUploaded,
  onAssetUpdated,
  onAssetDeleted,
  playerRole,
}: AssetPipelineProps) {
  const [activeTab, setActiveTab] = useState('library');
  const [filter, setFilter] = useState<AssetFilter>({
    search: '',
    category: 'all',
    tags: [],
    visibility: 'all',
  });

  const [selectedAssets, setSelectedAssets] = useState<string[]>([]);
  const [showBulkActions, setShowBulkActions] = useState(false);
  const [showTagEditor, setShowTagEditor] = useState(false);
  const [editingAsset, setEditingAsset] = useState<GameAsset | null>(null);

  // Asset categories for organization
  const categories = [
    { id: 'all', name: 'All Assets' },
    { id: 'cards', name: 'Cards' },
    { id: 'tokens', name: 'Tokens' },
    { id: 'maps', name: 'Maps' },
    { id: 'boards', name: 'Boards' },
    { id: 'other', name: 'Other' },
  ];

  // Common asset tags
  const availableTags: AssetTag[] = [
    { id: 'character', name: 'Character', color: '#3b82f6' },
    { id: 'monster', name: 'Monster', color: '#ef4444' },
    { id: 'equipment', name: 'Equipment', color: '#8b5cf6' },
    { id: 'spell', name: 'Spell', color: '#06b6d4' },
    { id: 'terrain', name: 'Terrain', color: '#10b981' },
    { id: 'prop', name: 'Prop', color: '#f59e0b' },
  ];

  const filteredAssets = assets.filter(asset => {
    // Search filter
    if (filter.search && !asset.name.toLowerCase().includes(filter.search.toLowerCase())) {
      return false;
    }

    // Category filter
    if (filter.category !== 'all' && asset.category !== filter.category) {
      return false;
    }

    // Tag filter
    if (filter.tags.length > 0) {
      const assetTags = asset.tags ? asset.tags.split(',') : [];
      if (!filter.tags.some(tag => assetTags.includes(tag))) {
        return false;
      }
    }

    return true;
  });

  const handleAssetSelect = (assetId: string, selected: boolean) => {
    if (selected) {
      setSelectedAssets(prev => [...prev, assetId]);
    } else {
      setSelectedAssets(prev => prev.filter(id => id !== assetId));
    }
  };

  const handleBulkAction = (action: string) => {
    switch (action) {
      case 'delete':
        selectedAssets.forEach(assetId => onAssetDeleted(assetId));
        setSelectedAssets([]);
        break;
      case 'tag':
        setShowTagEditor(true);
        break;
      case 'duplicate':
        // Implement bulk duplication
        break;
    }
    setShowBulkActions(false);
  };

  const handleGetUploadParameters = async () => {
    const response = await fetch('/api/objects/upload', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    const data = await response.json();
    return {
      method: 'PUT' as const,
      url: data.uploadURL,
    };
  };

  const handleUploadComplete = async (result: any) => {
    if (result.successful && result.successful.length > 0) {
      const uploadedFile = result.successful[0];

      // Create asset record
      const assetData = {
        roomId,
        name: uploadedFile.name,
        filePath: uploadedFile.uploadURL,
        fileType: uploadedFile.type,
        fileSize: uploadedFile.data?.size || 0,
        category: 'other',
        tags: '',
        visibility: 'room',
      };

      try {
        const response = await fetch(`/api/rooms/${roomId}/assets`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(assetData),
        });

        if (response.ok) {
          const newAsset = await response.json();
          onAssetUploaded(newAsset);
        }
      } catch (error) {
        console.error('Failed to create asset record:', error);
      }
    }
  };

  return (
    <div className="w-full h-full flex flex-col">
      <Tabs value={activeTab} onValueChange={setActiveTab} className="flex-1 flex flex-col">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="library" className="flex items-center gap-2">
            <FileImage className="w-4 h-4" />
            Library
          </TabsTrigger>
          <TabsTrigger value="upload" className="flex items-center gap-2">
            <Upload className="w-4 h-4" />
            Upload
          </TabsTrigger>
          <TabsTrigger value="builder" className="flex items-center gap-2">
            <Edit3 className="w-4 h-4" />
            Builder
          </TabsTrigger>
        </TabsList>

        {/* Asset Library Tab */}
        <TabsContent value="library" className="flex-1 space-y-4">
          {/* Search and Filter Controls */}
          <div className="space-y-3">
            <div className="flex gap-2">
              <div className="flex-1">
                <Input
                  placeholder="Search assets..."
                  value={filter.search}
                  onChange={(e) => setFilter(prev => ({ ...prev, search: e.target.value }))}
                  data-testid="input-asset-search"
                />
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowBulkActions(!showBulkActions)}
                disabled={selectedAssets.length === 0}
                data-testid="button-bulk-actions"
              >
                <Filter className="w-4 h-4" />
                Actions ({selectedAssets.length})
              </Button>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <Select value={filter.category} onValueChange={(value) => setFilter(prev => ({ ...prev, category: value }))}>
                <SelectTrigger className="h-8">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {categories.map(category => (
                    <SelectItem key={category.id} value={category.id}>
                      {category.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>

              <Select value={filter.visibility} onValueChange={(value) => setFilter(prev => ({ ...prev, visibility: value }))}>
                <SelectTrigger className="h-8">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Visibility</SelectItem>
                  <SelectItem value="public">Public</SelectItem>
                  <SelectItem value="room">Room Only</SelectItem>
                  <SelectItem value="private">Private</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {/* Tag Filter */}
            <div className="flex flex-wrap gap-1">
              {availableTags.map(tag => (
                <Badge
                  key={tag.id}
                  variant={filter.tags.includes(tag.id) ? 'default' : 'outline'}
                  className="cursor-pointer text-xs"
                  style={{ backgroundColor: filter.tags.includes(tag.id) ? tag.color : undefined }}
                  onClick={() => {
                    setFilter(prev => ({
                      ...prev,
                      tags: prev.tags.includes(tag.id)
                        ? prev.tags.filter(t => t !== tag.id)
                        : [...prev.tags, tag.id],
                    }));
                  }}
                  data-testid={`tag-filter-${tag.id}`}
                >
                  {tag.name}
                </Badge>
              ))}
            </div>
          </div>

          {/* Bulk Actions Panel */}
          {showBulkActions && selectedAssets.length > 0 && (
            <Card>
              <CardContent className="p-3">
                <div className="flex gap-2">
                  <Button size="sm" variant="outline" onClick={() => handleBulkAction('tag')}>
                    <Tag className="w-3 h-3 mr-1" />
                    Tag
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => handleBulkAction('duplicate')}>
                    <Copy className="w-3 h-3 mr-1" />
                    Duplicate
                  </Button>
                  {playerRole === 'admin' && (
                    <Button size="sm" variant="destructive" onClick={() => handleBulkAction('delete')}>
                      <Trash2 className="w-3 h-3 mr-1" />
                      Delete
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Asset Grid */}
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3 overflow-y-auto">
            {filteredAssets.map(asset => (
              <Card key={asset.id} className="cursor-pointer hover:shadow-md transition-shadow">
                <CardContent className="p-2">
                  {/* Selection Checkbox */}
                  {playerRole === 'admin' && (
                    <div className="flex justify-between items-center mb-2">
                      <input
                        type="checkbox"
                        checked={selectedAssets.includes(asset.id)}
                        onChange={(e) => handleAssetSelect(asset.id, e.target.checked)}
                        className="w-3 h-3"
                        data-testid={`checkbox-asset-${asset.id}`}
                      />
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => setEditingAsset(asset)}
                        className="p-1 h-6"
                        data-testid={`button-edit-asset-${asset.id}`}
                      >
                        <Edit3 className="w-3 h-3" />
                      </Button>
                    </div>
                  )}

                  {/* Asset Preview */}
                  <div className="aspect-square bg-gray-100 dark:bg-gray-800 rounded mb-2 overflow-hidden">
                    {asset.fileType?.startsWith('image/') ? (
                      <img
                        src={asset.filePath}
                        alt={asset.name}
                        className="w-full h-full object-cover"
                        draggable={false}
                      />
                    ) : (
                      <div className="w-full h-full flex items-center justify-center">
                        <FileImage className="w-8 h-8 text-gray-400" />
                      </div>
                    )}
                  </div>

                  {/* Asset Info */}
                  <div className="space-y-1">
                    <div className="text-sm font-medium truncate" title={asset.name}>
                      {asset.name}
                    </div>
                    <div className="text-xs text-gray-500">
                      {asset.fileSize ? `${Math.round(asset.fileSize / 1024)}KB` : 'Unknown size'}
                    </div>

                    {/* Tags */}
                    {asset.tags && (
                      <div className="flex flex-wrap gap-1">
                        {asset.tags.split(',').slice(0, 2).map(tagId => {
                          const tag = availableTags.find(t => t.id === tagId.trim());
                          return tag ? (
                            <Badge key={tag.id} className="text-xs" style={{ backgroundColor: tag.color }}>
                              {tag.name}
                            </Badge>
                          ) : null;
                        })}
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* Upload Tab */}
        <TabsContent value="upload" className="flex-1 space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Upload New Assets</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <ObjectUploader
                maxNumberOfFiles={10}
                maxFileSize={10485760} // 10MB
                onGetUploadParameters={handleGetUploadParameters}
                onComplete={handleUploadComplete}
                buttonClassName="w-full h-32 border-2 border-dashed"
              >
                <div className="flex flex-col items-center gap-2">
                  <Upload className="w-8 h-8 text-gray-400" />
                  <div className="text-sm text-gray-600">
                    Drop files here or click to upload
                  </div>
                  <div className="text-xs text-gray-500">
                    Supports: PNG, JPG, PDF, SVG (max 10MB each)
                  </div>
                </div>
              </ObjectUploader>

              <div className="text-sm text-gray-500">
                <p className="font-medium mb-2">Bulk Import Tips:</p>
                <ul className="space-y-1 text-xs">
                  <li>• Use consistent naming for easier organization</li>
                  <li>• Cards should be 300 DPI for best quality</li>
                  <li>• Consider using ZIP files for large sets</li>
                  <li>• Add descriptive tags during upload</li>
                </ul>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Card Builder Tab */}
        <TabsContent value="builder" className="flex-1">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Card Builder</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-center text-gray-500 py-8">
                <Edit3 className="w-12 h-12 mx-auto mb-4 text-gray-300" />
                <p className="text-sm">Card builder functionality coming soon!</p>
                <p className="text-xs mt-2">
                  This will include cropping tools, face/back assignment, and template creation.
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Asset Editor Dialog */}
      {editingAsset && (
        <Dialog open={!!editingAsset} onOpenChange={() => setEditingAsset(null)}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Edit Asset</DialogTitle>
            </DialogHeader>
            <div className="space-y-4">
              <div>
                <Label>Asset Name</Label>
                <Input
                  value={editingAsset.name}
                  onChange={(e) => setEditingAsset(prev => prev ? { ...prev, name: e.target.value } : null)}
                  data-testid="input-edit-asset-name"
                />
              </div>

              <div>
                <Label>Category</Label>
                <Select
                  value={editingAsset.category || 'other'}
                  onValueChange={(value) => setEditingAsset(prev => prev ? { ...prev, category: value } : null)}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {categories.filter(c => c.id !== 'all').map(category => (
                      <SelectItem key={category.id} value={category.id}>
                        {category.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="flex justify-end space-x-2">
                <Button variant="outline" onClick={() => setEditingAsset(null)}>
                  Cancel
                </Button>
                <Button
                  onClick={() => {
                    onAssetUpdated(editingAsset.id, {
                      name: editingAsset.name,
                      category: editingAsset.category,
                    });
                    setEditingAsset(null);
                  }}
                  data-testid="button-save-asset"
                >
                  Save Changes
                </Button>
              </div>
            </div>
          </DialogContent>
        </Dialog>
      )}
    </div>
  );
}
