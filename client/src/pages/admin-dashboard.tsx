import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Separator } from "@/components/ui/separator";
import { 
  Search, 
  Plus, 
  Edit, 
  Trash2, 
  Users, 
  Calendar, 
  Database, 
  Settings,
  Eye,
  Download,
  Upload,
  Copy,
  ArrowLeft
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { ThemeToggle } from "@/components/ThemeToggle";
import { authenticatedApiRequest } from "@/lib/authClient";
import { queryClient } from "@/lib/queryClient";
import { useLocation } from "wouter";
import type { GameRoom, GameTemplate, GameSystem } from "@shared/schema";


export default function AdminDashboard() {
  const { toast } = useToast();
  const [, setLocation] = useLocation();
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedTab, setSelectedTab] = useState("rooms");

  
  // Fetch all data
  const { data: allRooms = [], isLoading: roomsLoading } = useQuery<GameRoom[]>({
    queryKey: ["/api/admin/rooms"],
    queryFn: async () => {
      const response = await authenticatedApiRequest("GET", "/api/admin/rooms");
      return response.json();
    },
  });

  const { data: allTemplates = [], isLoading: templatesLoading } = useQuery<GameTemplate[]>({
    queryKey: ["/api/admin/templates"],
    queryFn: async () => {
      const response = await authenticatedApiRequest("GET", "/api/admin/templates");
      return response.json();
    },
  });

  const { data: allGameSystems = [], isLoading: systemsLoading } = useQuery<GameSystem[]>({
    queryKey: ["/api/admin/game-systems"],
    queryFn: async () => {
      const response = await authenticatedApiRequest("GET", "/api/admin/game-systems");
      return response.json();
    },
  });

  // Delete mutations
  const deleteRoomMutation = useMutation({
    mutationFn: async (roomId: string) => {
      const response = await authenticatedApiRequest("DELETE", `/api/rooms/${roomId}`);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/rooms"] });
      toast({ title: "Room deleted successfully" });
    },
    onError: () => {
      toast({ title: "Failed to delete room", variant: "destructive" });
    },
  });

  const deleteTemplateMutation = useMutation({
    mutationFn: async (templateId: string) => {
      const response = await authenticatedApiRequest("DELETE", `/api/templates/${templateId}`);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/templates"] });
      toast({ title: "Template deleted successfully" });
    },
    onError: () => {
      toast({ title: "Failed to delete template", variant: "destructive" });
    },
  });

  const deleteGameSystemMutation = useMutation({
    mutationFn: async (systemId: string) => {
      const response = await authenticatedApiRequest("DELETE", `/api/game-systems/${systemId}`);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/game-systems"] });
      toast({ title: "Game system deleted successfully" });
    },
    onError: () => {
      toast({ title: "Failed to delete game system", variant: "destructive" });
    },
  });

  // Cleanup orphaned files mutation
  const cleanupOrphanedFilesMutation = useMutation({
    mutationFn: async () => {
      const response = await authenticatedApiRequest("POST", "/api/admin/cleanup-orphaned-files");
      return response.json();
    },
    onSuccess: (data) => {
      toast({ 
        title: "Cleanup completed", 
        description: `Deleted ${data.deleted} orphaned files` 
      });
    },
    onError: () => {
      toast({ title: "Failed to cleanup orphaned files", variant: "destructive" });
    },
  });

  // Filter functions
  const filteredRooms = allRooms.filter(room => 
    room.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredTemplates = allTemplates.filter(template => 
    template.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    template.description?.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredGameSystems = allGameSystems.filter(system => 
    system.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    system.description?.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const formatDate = (date: Date | string | null) => {
    if (!date) return 'Unknown';
    return new Date(date).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
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
            <Database className="w-8 h-8 text-primary" />
            <h1 className="text-3xl font-bold">Admin Dashboard</h1>
          </div>
        </div>
        <div className="flex items-center space-x-4">
          <Button
            onClick={() => cleanupOrphanedFilesMutation.mutate()}
            disabled={cleanupOrphanedFilesMutation.isPending}
            variant="outline"
            size="sm"
            className="flex items-center gap-2"
            data-testid="button-cleanup-files"
          >
            {cleanupOrphanedFilesMutation.isPending ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-primary"></div>
                Cleaning...
              </>
            ) : (
              <>
                <Trash2 className="w-4 h-4" />
                Cleanup Orphaned Files
              </>
            )}
          </Button>
          <ThemeToggle />
          <Button 
            onClick={() => setLocation("/")}
            variant="ghost"
            size="sm"
            data-testid="button-home"
          >
            Home
          </Button>
        </div>
      </div>

      {/* Search */}
      <div className="mb-6">
        <div className="relative max-w-md">
          <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search rooms, templates, game systems..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10"
            data-testid="input-search"
          />
        </div>
      </div>

      {/* Main Content */}
      <Tabs value={selectedTab} onValueChange={setSelectedTab} className="w-full">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="rooms" data-testid="tab-rooms">
            <Users className="w-4 h-4 mr-2" />
            Game Rooms ({allRooms.length})
          </TabsTrigger>
          <TabsTrigger value="templates" data-testid="tab-templates">
            <Copy className="w-4 h-4 mr-2" />
            Templates ({allTemplates.length})
          </TabsTrigger>
          <TabsTrigger value="systems" data-testid="tab-systems">
            <Settings className="w-4 h-4 mr-2" />
            Game Systems ({allGameSystems.length})
          </TabsTrigger>
        </TabsList>

        {/* Game Rooms Tab */}
        <TabsContent value="rooms" className="space-y-4">
          {roomsLoading ? (
            <div className="text-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto mb-4"></div>
              <p className="text-muted-foreground">Loading rooms...</p>
            </div>
          ) : (
            <div className="grid gap-4">
              {filteredRooms.length === 0 ? (
                <Card>
                  <CardContent className="py-8 text-center">
                    <p className="text-muted-foreground">No rooms found</p>
                  </CardContent>
                </Card>
              ) : (
                filteredRooms.map((room) => (
                  <Card key={room.id} className="hover:shadow-md transition-shadow">
                    <CardContent className="p-6">
                      <div className="flex justify-between items-start">
                        <div className="space-y-2">
                          <div className="flex items-center space-x-3">
                            <h3 className="text-lg font-semibold" data-testid={`room-name-${room.id}`}>
                              {room.name}
                            </h3>
                            <Badge variant="secondary">
                              ID: {room.id.slice(0, 8)}...
                            </Badge>
                          </div>
                          <p className="text-sm text-muted-foreground">
                            Created: {formatDate(room.createdAt)}
                          </p>
                          <p className="text-sm text-muted-foreground">
                            Created by: {(room as any).creatorName || room.createdBy} ({room.createdBy})
                          </p>

                        </div>
                        <div className="flex space-x-2">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => setLocation(`/room/${room.id}`)}
                            data-testid={`button-view-room-${room.id}`}
                          >
                            <Eye className="w-4 h-4 mr-1" />
                            View
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => deleteRoomMutation.mutate(room.id)}
                            disabled={deleteRoomMutation.isPending}
                            data-testid={`button-delete-room-${room.id}`}
                          >
                            <Trash2 className="w-4 h-4 mr-1" />
                            Delete
                          </Button>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))
              )}
            </div>
          )}
        </TabsContent>

        {/* Templates Tab */}
        <TabsContent value="templates" className="space-y-4">
          {templatesLoading ? (
            <div className="text-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto mb-4"></div>
              <p className="text-muted-foreground">Loading templates...</p>
            </div>
          ) : (
            <div className="grid gap-4">
              {filteredTemplates.length === 0 ? (
                <Card>
                  <CardContent className="py-8 text-center">
                    <p className="text-muted-foreground">No templates found</p>
                  </CardContent>
                </Card>
              ) : (
                filteredTemplates.map((template) => (
                  <Card key={template.id} className="hover:shadow-md transition-shadow">
                    <CardContent className="p-6">
                      <div className="flex justify-between items-start">
                        <div className="space-y-2">
                          <div className="flex items-center space-x-3">
                            <h3 className="text-lg font-semibold" data-testid={`template-name-${template.id}`}>
                              {template.name}
                            </h3>
                            <Badge variant="secondary">
                              ID: {template.id.slice(0, 8)}...
                            </Badge>
                            <Badge variant={template.isPublic ? "default" : "outline"}>
                              {template.isPublic ? "Public" : "Private"}
                            </Badge>
                          </div>
                          <p className="text-sm text-muted-foreground">
                            Created: {formatDate(template.createdAt)}
                          </p>
                          <p className="text-sm text-muted-foreground">
                            Created by: {template.createdBy}
                          </p>
                          {template.description && (
                            <p className="text-sm">{template.description}</p>
                          )}
                          {template.tags && template.tags.length > 0 && (
                            <div className="flex flex-wrap gap-1">
                              {template.tags.map((tag, index) => (
                                <Badge key={index} variant="outline" className="text-xs">
                                  {tag}
                                </Badge>
                              ))}
                            </div>
                          )}
                        </div>
                        <div className="flex space-x-2">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => {
                              // Download template data as JSON
                              const dataStr = JSON.stringify(template, null, 2);
                              const dataBlob = new Blob([dataStr], {type: 'application/json'});
                              const url = URL.createObjectURL(dataBlob);
                              const link = document.createElement('a');
                              link.href = url;
                              link.download = `${template.name}-template.json`;
                              link.click();
                              URL.revokeObjectURL(url);
                            }}
                            data-testid={`button-download-template-${template.id}`}
                          >
                            <Download className="w-4 h-4 mr-1" />
                            Export
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => deleteTemplateMutation.mutate(template.id)}
                            disabled={deleteTemplateMutation.isPending}
                            data-testid={`button-delete-template-${template.id}`}
                          >
                            <Trash2 className="w-4 h-4 mr-1" />
                            Delete
                          </Button>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))
              )}
            </div>
          )}
        </TabsContent>

        {/* Game Systems Tab */}
        <TabsContent value="systems" className="space-y-4">
          {/* Create Game System Button */}
          <div className="flex justify-between items-center">
            <div className="flex items-center space-x-2">
              <h2 className="text-xl font-semibold">Game Systems</h2>
              <Badge variant="secondary">{filteredGameSystems.length} systems</Badge>
            </div>
            <div className="flex space-x-2">
              <Button
                onClick={() => setLocation("/create-game-system")}
                className="flex items-center gap-2"
                data-testid="button-create-game-system"
              >
                <Plus className="w-4 h-4" />
                Create Game System
              </Button>
            </div>
          </div>
          
          {systemsLoading ? (
            <div className="text-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto mb-4"></div>
              <p className="text-muted-foreground">Loading game systems...</p>
            </div>
          ) : (
            <div className="grid gap-4">
              {filteredGameSystems.length === 0 ? (
                <Card>
                  <CardContent className="py-8 text-center">
                    <p className="text-muted-foreground">No game systems found</p>
                  </CardContent>
                </Card>
              ) : (
                filteredGameSystems.map((system) => (
                  <Card key={system.id} className="hover:shadow-md transition-shadow">
                    <CardContent className="p-6">
                      <div className="flex justify-between items-start">
                        <div className="space-y-2">
                          <div className="flex items-center space-x-3">
                            <h3 className="text-lg font-semibold" data-testid={`system-name-${system.id}`}>
                              {system.name}
                            </h3>
                            <Badge variant="secondary">
                              ID: {system.id.slice(0, 8)}...
                            </Badge>
                            <Badge variant={system.isPublic ? "default" : "outline"}>
                              {system.isPublic ? "Public" : "Private"}
                            </Badge>
                          </div>
                          <p className="text-sm text-muted-foreground">
                            Created: {formatDate(system.createdAt)}
                          </p>
                          <p className="text-sm text-muted-foreground">
                            Created by: {system.createdBy}
                          </p>
                          {system.description && (
                            <p className="text-sm">{system.description}</p>
                          )}
                          {system.tags && system.tags.length > 0 && (
                            <div className="flex flex-wrap gap-1">
                              {system.tags.map((tag, index) => (
                                <Badge key={index} variant="outline" className="text-xs">
                                  {tag}
                                </Badge>
                              ))}
                            </div>
                          )}
                        </div>
                        <div className="flex space-x-2">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => setLocation(`/edit-game-system/${system.id}`)}
                            data-testid={`button-edit-system-${system.id}`}
                          >
                            <Settings className="w-4 h-4 mr-1" />
                            Edit
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => {
                              // Download system data as JSON
                              const dataStr = JSON.stringify(system, null, 2);
                              const dataBlob = new Blob([dataStr], {type: 'application/json'});
                              const url = URL.createObjectURL(dataBlob);
                              const link = document.createElement('a');
                              link.href = url;
                              link.download = `${system.name}-system.json`;
                              link.click();
                              URL.revokeObjectURL(url);
                            }}
                            data-testid={`button-download-system-${system.id}`}
                          >
                            <Download className="w-4 h-4 mr-1" />
                            Export
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => deleteGameSystemMutation.mutate(system.id)}
                            disabled={deleteGameSystemMutation.isPending}
                            data-testid={`button-delete-system-${system.id}`}
                          >
                            <Trash2 className="w-4 h-4 mr-1" />
                            Delete
                          </Button>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))
              )}
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}