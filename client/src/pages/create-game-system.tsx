import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { 
  ArrowLeft, 
  Upload, 
  Save,
  Plus,
  X,
  FileImage,
  Settings
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
}

export default function CreateGameSystem() {
  const { toast } = useToast();
  const [, setLocation] = useLocation();
  
  // Form state
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [isPublic, setIsPublic] = useState(false);
  const [tags, setTags] = useState<string[]>([]);
  const [newTag, setNewTag] = useState("");
  const [uploadedAssets, setUploadedAssets] = useState<UploadedAsset[]>([]);

  // Handle asset upload
  const handleAssetUpload = async () => {
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
      }));
      setUploadedAssets(prev => [...prev, ...newAssets]);
      toast({
        title: "Assets Uploaded",
        description: `Successfully uploaded ${result.successful.length} asset(s)`,
      });
    }
  };

  // Handle tag management
  const addTag = () => {
    if (newTag.trim() && !tags.includes(newTag.trim())) {
      setTags([...tags, newTag.trim()]);
      setNewTag("");
    }
  };

  const removeTag = (tagToRemove: string) => {
    setTags(tags.filter(tag => tag !== tagToRemove));
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

      const response = await authenticatedApiRequest("POST", "/api/systems", gameSystemData);
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || "Failed to create game system");
      }
      
      return response.json();
    },
    onSuccess: (data) => {
      toast({
        title: "Game System Created",
        description: `"${name}" has been created successfully!`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/game-systems"] });
      queryClient.invalidateQueries({ queryKey: ["/api/game-systems"] });
      setLocation("/admin");
    },
    onError: (error: any) => {
      toast({
        title: "Failed to Create Game System",
        description: error.message || "An error occurred while creating the game system.",
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
    saveGameSystemMutation.mutate();
  };

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="min-h-screen bg-background p-6">
      {/* Header */}
      <div className="flex justify-between items-center mb-8">
        <div className="flex items-center space-x-4">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setLocation("/")}
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
            <div className="flex gap-2">
              <Input
                placeholder="Add a tag..."
                value={newTag}
                onChange={(e) => setNewTag(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && addTag()}
                data-testid="input-new-tag"
              />
              <Button onClick={addTag} size="sm" data-testid="button-add-tag">
                <Plus className="w-4 h-4" />
              </Button>
            </div>
            
            {tags.length > 0 && (
              <div className="flex flex-wrap gap-2">
                {tags.map((tag, index) => (
                  <Badge key={index} variant="secondary" className="flex items-center gap-1">
                    {tag}
                    <X 
                      className="w-3 h-3 cursor-pointer" 
                      onClick={() => removeTag(tag)}
                      data-testid={`button-remove-tag-${index}`}
                    />
                  </Badge>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Asset Upload */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FileImage className="w-5 h-5" />
              Upload Assets
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex justify-center">
              <ObjectUploader
                maxNumberOfFiles={50}
                maxFileSize={50485760} // 50MB
                onGetUploadParameters={handleAssetUpload}
                onComplete={handleUploadComplete}
                buttonClassName="flex items-center gap-2"
              >
                <Upload className="w-4 h-4" />
                Upload Game Assets
              </ObjectUploader>
            </div>

            {uploadedAssets.length > 0 && (
              <div className="space-y-2">
                <h4 className="font-medium">Uploaded Assets ({uploadedAssets.length})</h4>
                <div className="grid gap-2">
                  {uploadedAssets.map((asset, index) => (
                    <div 
                      key={index} 
                      className="flex items-center justify-between p-3 bg-muted rounded-lg"
                    >
                      <div className="flex items-center space-x-3">
                        <FileImage className="w-4 h-4 text-muted-foreground" />
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
                        onClick={() => removeAsset(index)}
                        data-testid={`button-remove-asset-${index}`}
                      >
                        <X className="w-4 h-4" />
                      </Button>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Actions */}
        <div className="flex justify-end space-x-4">
          <Button
            variant="outline"
            onClick={() => setLocation("/")}
            data-testid="button-cancel"
          >
            Cancel
          </Button>
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
        </div>
      </div>
    </div>
  );
}