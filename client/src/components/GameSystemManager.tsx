import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/hooks/use-toast";
import { Download, Save, Eye, Calendar, User, Tag, Settings, Globe, Lock } from "lucide-react";
import { authenticatedApiRequest } from "@/lib/authClient";
import { queryClient } from "@/lib/queryClient";
import type { GameSystem } from "@shared/schema";

interface GameSystemManagerProps {
  roomId: string;
  currentUser: { id: string; firstName?: string | null; lastName?: string | null };
}

export function GameSystemManager({ roomId, currentUser }: GameSystemManagerProps) {
  const { toast } = useToast();

  // Form state for saving systems
  const [saveForm, setSaveForm] = useState({
    name: "",
    description: "",
    category: "Custom",
    tags: [] as string[],
    version: "1.0",
    complexity: "medium",
    isPublic: false
  });

  const [newTag, setNewTag] = useState("");
  const [filter, setFilter] = useState<"all" | "public" | "private">("all");

  // Fetch systems
  const { data: systems = [], isLoading: systemsLoading } = useQuery({
    queryKey: ["/api/systems", filter],
    queryFn: async () => {
      const params = filter === "all" ? "" : `?public=${filter === "public"}`;
      const response = await authenticatedApiRequest("GET", `/api/systems${params}`);
      return response.json();
    }
  });

  // Save current room as system
  const saveSystemMutation = useMutation({
    mutationFn: async () => {
      const response = await authenticatedApiRequest("POST", `/api/rooms/${roomId}/save-system`, saveForm);
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || "Failed to save system");
      }
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "System Saved",
        description: `Game system "${saveForm.name}" has been saved successfully.`
      });
      setSaveForm({
        name: "",
        description: "",
        category: "Custom",
        tags: [],
        version: "1.0",
        complexity: "medium",
        isPublic: false
      });
      queryClient.invalidateQueries({ queryKey: ["/api/systems"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Save Failed",
        description: error.message,
        variant: "destructive"
      });
    }
  });

  // Apply system to room
  const applySystemMutation = useMutation({
    mutationFn: async (systemId: string) => {
      const response = await authenticatedApiRequest("POST", `/api/rooms/${roomId}/apply-system`, {
        systemId
      });
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || "Failed to apply system");
      }
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "System Applied",
        description: "Game system has been applied to this room successfully."
      });
    },
    onError: (error: Error) => {
      toast({
        title: "Apply Failed",
        description: error.message,
        variant: "destructive"
      });
    }
  });

  const handleSaveSystem = () => {
    if (!saveForm.name.trim()) {
      toast({
        title: "Name Required",
        description: "Please enter a name for your game system.",
        variant: "destructive"
      });
      return;
    }
    saveSystemMutation.mutate();
  };

  const handleApplySystem = (systemId: string) => {
    applySystemMutation.mutate(systemId);
  };

  const addTag = () => {
    if (newTag.trim() && !saveForm.tags.includes(newTag.trim())) {
      setSaveForm(prev => ({
        ...prev,
        tags: [...prev.tags, newTag.trim()]
      }));
      setNewTag("");
    }
  };

  const removeTag = (tagToRemove: string) => {
    setSaveForm(prev => ({
      ...prev,
      tags: prev.tags.filter(tag => tag !== tagToRemove)
    }));
  };

  const getComplexityColor = (complexity: string) => {
    switch (complexity) {
      case "simple": return "text-green-600 bg-green-100 dark:text-green-300 dark:bg-green-900/30";
      case "medium": return "text-yellow-600 bg-yellow-100 dark:text-yellow-300 dark:bg-yellow-900/30";
      case "complex": return "text-red-600 bg-red-100 dark:text-red-300 dark:bg-red-900/30";
      default: return "text-gray-600 bg-gray-100 dark:text-gray-300 dark:bg-gray-900/30";
    }
  };

  return (
    <div className="w-full space-y-4" data-testid="game-system-manager">
      <Tabs defaultValue="browse" className="w-full">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="browse" data-testid="tab-browse-systems">
            <Eye className="w-4 h-4 mr-2" />
            Browse Systems
          </TabsTrigger>
          <TabsTrigger value="save" data-testid="tab-save-system">
            <Save className="w-4 h-4 mr-2" />
            Save Current Room
          </TabsTrigger>
        </TabsList>

        <TabsContent value="browse" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center space-x-2">
                  <Eye className="w-5 h-5" />
                  <span>Available Game Systems</span>
                </CardTitle>
                <Select value={filter} onValueChange={(value: "all" | "public" | "private") => setFilter(value)}>
                  <SelectTrigger className="w-40">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Systems</SelectItem>
                    <SelectItem value="public">Public Only</SelectItem>
                    <SelectItem value="private">My Systems</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </CardHeader>
            <CardContent>
              {systemsLoading ? (
                <div className="text-center py-8">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto"></div>
                  <p className="mt-2 text-sm text-muted-foreground">Loading systems...</p>
                </div>
              ) : systems.length === 0 ? (
                <div className="text-center py-8">
                  <Settings className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                  <p className="text-muted-foreground">No game systems found</p>
                  <p className="text-sm text-muted-foreground mt-1">
                    {filter === "private" ? "You haven't created any systems yet." : "No public systems available."}
                  </p>
                </div>
              ) : (
                <div className="grid gap-4">
                  {systems.map((system: GameSystem) => (
                    <div
                      key={system.id}
                      className="border rounded-lg p-4 hover:shadow-md transition-shadow"
                      data-testid={`system-${system.id}`}
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1 space-y-2">
                          <div className="flex items-center space-x-2">
                            <h3 className="font-semibold text-lg">{system.name}</h3>
                            <Badge variant={system.isPublic ? "default" : "secondary"}>
                              {system.isPublic ? (
                                <>
                                  <Globe className="w-3 h-3 mr-1" />
                                  Public
                                </>
                              ) : (
                                <>
                                  <Lock className="w-3 h-3 mr-1" />
                                  Private
                                </>
                              )}
                            </Badge>
                            <Badge 
                              variant="outline" 
                              className={getComplexityColor(system.complexity || "medium")}
                            >
                              {(system.complexity || "medium").charAt(0).toUpperCase() + (system.complexity || "medium").slice(1)}
                            </Badge>
                          </div>
                          
                          {system.description && (
                            <p className="text-sm text-muted-foreground">{system.description}</p>
                          )}
                          
                          <div className="flex items-center space-x-4 text-xs text-muted-foreground">
                            <span className="flex items-center space-x-1">
                              <User className="w-3 h-3" />
                              <span>Created by {system.createdBy === currentUser.id ? "You" : "User"}</span>
                            </span>
                            <span className="flex items-center space-x-1">
                              <Calendar className="w-3 h-3" />
                              <span>{system.createdAt ? new Date(system.createdAt).toLocaleDateString() : "Unknown"}</span>
                            </span>
                            {system.downloadCount && system.downloadCount > 0 && (
                              <span className="flex items-center space-x-1">
                                <Download className="w-3 h-3" />
                                <span>{system.downloadCount} downloads</span>
                              </span>
                            )}
                          </div>
                          
                          {system.tags && system.tags.length > 0 && (
                            <div className="flex flex-wrap gap-1">
                              {system.tags.map((tag) => (
                                <Badge key={tag} variant="outline" className="text-xs">
                                  <Tag className="w-2 h-2 mr-1" />
                                  {tag}
                                </Badge>
                              ))}
                            </div>
                          )}
                        </div>
                        
                        <Button
                          onClick={() => handleApplySystem(system.id)}
                          disabled={applySystemMutation.isPending}
                          data-testid={`button-apply-system-${system.id}`}
                        >
                          <Download className="w-4 h-4 mr-2" />
                          Apply System
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="save" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Save className="w-5 h-5" />
                <span>Save Current Room as Game System</span>
              </CardTitle>
              <p className="text-sm text-muted-foreground">
                Save your current room configuration, assets, and rules as a reusable game system that others can apply to their rooms.
              </p>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="system-name">System Name *</Label>
                  <Input
                    id="system-name"
                    value={saveForm.name}
                    onChange={(e) => setSaveForm(prev => ({ ...prev, name: e.target.value }))}
                    placeholder="Enter game system name"
                    data-testid="input-system-name"
                  />
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="system-category">Category</Label>
                  <Select value={saveForm.category} onValueChange={(value) => setSaveForm(prev => ({ ...prev, category: value }))}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="Custom">Custom</SelectItem>
                      <SelectItem value="RPG">RPG</SelectItem>
                      <SelectItem value="Board Game">Board Game</SelectItem>
                      <SelectItem value="Card Game">Card Game</SelectItem>
                      <SelectItem value="Strategy">Strategy</SelectItem>
                      <SelectItem value="Educational">Educational</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="system-version">Version</Label>
                  <Input
                    id="system-version"
                    value={saveForm.version}
                    onChange={(e) => setSaveForm(prev => ({ ...prev, version: e.target.value }))}
                    placeholder="1.0"
                    data-testid="input-system-version"
                  />
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="system-complexity">Complexity</Label>
                  <Select value={saveForm.complexity} onValueChange={(value) => setSaveForm(prev => ({ ...prev, complexity: value }))}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="simple">Simple</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="complex">Complex</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="system-description">Description</Label>
                <Textarea
                  id="system-description"
                  value={saveForm.description}
                  onChange={(e) => setSaveForm(prev => ({ ...prev, description: e.target.value }))}
                  placeholder="Describe your game system..."
                  rows={3}
                  data-testid="input-system-description"
                />
              </div>

              <Separator />

              <div className="space-y-4">
                <div className="space-y-2">
                  <Label>Tags</Label>
                  <div className="flex space-x-2">
                    <Input
                      value={newTag}
                      onChange={(e) => setNewTag(e.target.value)}
                      placeholder="Add a tag"
                      onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), addTag())}
                      className="flex-1"
                      data-testid="input-new-tag"
                    />
                    <Button type="button" variant="outline" onClick={addTag} data-testid="button-add-tag">
                      Add
                    </Button>
                  </div>
                  {saveForm.tags.length > 0 && (
                    <div className="flex flex-wrap gap-2 mt-2">
                      {saveForm.tags.map((tag) => (
                        <Badge 
                          key={tag} 
                          variant="secondary" 
                          className="cursor-pointer"
                          onClick={() => removeTag(tag)}
                          data-testid={`tag-${tag}`}
                        >
                          {tag} ×
                        </Badge>
                      ))}
                    </div>
                  )}
                </div>

                <div className="flex items-center space-x-2">
                  <Switch
                    id="system-public"
                    checked={saveForm.isPublic}
                    onCheckedChange={(checked) => setSaveForm(prev => ({ ...prev, isPublic: checked }))}
                    data-testid="switch-system-public"
                  />
                  <Label htmlFor="system-public">Make this system publicly available</Label>
                </div>
              </div>

              <Separator />

              <Button
                onClick={handleSaveSystem}
                disabled={saveSystemMutation.isPending || !saveForm.name.trim()}
                className="w-full"
                data-testid="button-save-system"
              >
                <Save className="w-4 h-4 mr-2" />
                {saveSystemMutation.isPending ? "Saving..." : "Save Game System"}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}