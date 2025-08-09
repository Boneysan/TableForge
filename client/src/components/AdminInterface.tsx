import { useState } from "react";
import { Upload, Plus, Settings, Users, Shield, ArrowLeft } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { ObjectUploader } from "@/components/ObjectUploader";
import { ThemeToggle } from "@/components/ThemeToggle";
import { authenticatedApiRequest } from "@/lib/authClient";
import { queryClient } from "@/lib/queryClient";
import { useLocation } from "wouter";
import type { GameRoom, GameAsset, RoomPlayer } from "@shared/schema";

interface AdminInterfaceProps {
  roomId: string;
  assets: GameAsset[];
  boardAssets: BoardAsset[];
  players: RoomPlayer[];
  currentUser: { id: string; firstName?: string | null; lastName?: string | null };
  onAssetUploaded: () => void;
  onSwitchView?: () => void;
}

export function AdminInterface({ roomId, assets, boardAssets, players, currentUser, onAssetUploaded, onSwitchView }: AdminInterfaceProps) {
  const { toast } = useToast();
  const [, setLocation] = useLocation();
  const [selectedAssetType, setSelectedAssetType] = useState<'card' | 'token' | 'map' | 'other'>('card');

  const handleGetUploadParameters = async () => {
    try {
      const response = await authenticatedApiRequest("POST", "/api/objects/upload");
      const data = await response.json();
      return {
        method: 'PUT' as const,
        url: data.uploadURL,
      };
    } catch (error) {
      console.error("Error getting upload parameters:", error);
      throw error;
    }
  };

  const handleUploadComplete = async (result: any) => {
    try {
      if (result.successful.length > 0) {
        const uploadedFile = result.successful[0];
        
        // Create asset record in database
        const assetData = {
          roomId: roomId,
          name: uploadedFile.name,
          type: selectedAssetType,
          filePath: uploadedFile.uploadURL,
        };

        const response = await authenticatedApiRequest("POST", "/api/assets", assetData);
        
        if (response.ok) {
          toast({
            title: "Asset Uploaded",
            description: `${uploadedFile.name} has been uploaded successfully.`,
          });
          onAssetUploaded();
          queryClient.invalidateQueries({ queryKey: ["/api/rooms", roomId, "assets"] });
        }
      }
    } catch (error) {
      console.error("Error saving asset:", error);
      toast({
        title: "Upload Error",
        description: "Failed to save asset. Please try again.",
        variant: "destructive",
      });
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      <div className="container mx-auto px-4 py-6 space-y-6" data-testid="admin-interface">
      {/* Admin Header */}
      <div className="bg-gradient-to-r from-blue-600 to-indigo-600 rounded-lg p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Settings className="w-6 h-6 text-white" />
            <div>
              <h2 className="text-xl font-bold text-white">Admin Interface</h2>
              <p className="text-blue-100">Upload and manage game assets</p>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <ThemeToggle />
            <Button
              variant="outline"
              size="sm"
              onClick={() => setLocation('/')}
              className="bg-white/10 border-white/20 text-white hover:bg-white/20"
              data-testid="button-leave-room"
            >
              <ArrowLeft className="w-4 h-4 mr-1" />
              Leave Room
            </Button>
            {onSwitchView && (
              <Button 
                variant="secondary" 
                onClick={onSwitchView}
                data-testid="button-switch-view"
              >
                Switch to Game Master Console
              </Button>
            )}
          </div>
        </div>
      </div>

      <Tabs defaultValue="assets" className="w-full">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="assets" data-testid="tab-assets">
            <Upload className="w-4 h-4 mr-2" />
            Assets
          </TabsTrigger>
          <TabsTrigger value="players" data-testid="tab-players">
            <Users className="w-4 h-4 mr-2" />
            Players
          </TabsTrigger>
          <TabsTrigger value="settings" data-testid="tab-settings">
            <Settings className="w-4 h-4 mr-2" />
            Game Settings
          </TabsTrigger>
        </TabsList>

        <TabsContent value="assets" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Upload className="w-5 h-5" />
                <span>Upload Game Assets</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Asset Type Selection */}
              <div className="space-y-2">
                <label className="text-sm font-medium">Asset Type</label>
                <div className="flex space-x-2">
                  {(['card', 'token', 'map', 'other'] as const).map((type) => (
                    <Button
                      key={type}
                      variant={selectedAssetType === type ? "default" : "outline"}
                      size="sm"
                      onClick={() => setSelectedAssetType(type)}
                      data-testid={`asset-type-${type}`}
                    >
                      {type.charAt(0).toUpperCase() + type.slice(1)}
                    </Button>
                  ))}
                </div>
              </div>

              {/* Upload Button */}
              <ObjectUploader
                maxNumberOfFiles={10}
                maxFileSize={10485760} // 10MB
                onGetUploadParameters={handleGetUploadParameters}
                onComplete={handleUploadComplete}
                buttonClassName="w-full"
              >
                <div className="flex items-center justify-center space-x-2 py-4">
                  <Upload className="w-5 h-5" />
                  <span>Upload {selectedAssetType} Assets</span>
                </div>
              </ObjectUploader>

              <p className="text-sm text-gray-500">
                Upload cards, tokens, maps, or other game assets. Supports PNG, JPG, and PDF files up to 10MB each.
              </p>
            </CardContent>
          </Card>

          {/* Asset Library */}
          <Card>
            <CardHeader>
              <CardTitle>Asset Library ({assets.length} items)</CardTitle>
            </CardHeader>
            <CardContent>
              {assets.length === 0 ? (
                <p className="text-gray-500 text-center py-4">No assets uploaded yet. Upload some assets to get started.</p>
              ) : (
                <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
                  {assets.map((asset) => (
                    <div key={asset.id} className="relative group" data-testid={`asset-${asset.id}`}>
                      <div className="aspect-square bg-gray-100 rounded-lg overflow-hidden">
                        <img
                          src={asset.filePath}
                          alt={asset.name}
                          className="w-full h-full object-cover"
                        />
                      </div>
                      <div className="mt-2 space-y-1">
                        <p className="text-sm font-medium truncate">{asset.name}</p>
                        <Badge variant="secondary" className="text-xs">
                          {asset.type}
                        </Badge>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="players" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Player Management</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {players.map((player) => (
                  <div key={player.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg" data-testid={`player-${player.playerId}`}>
                    <div className="flex items-center space-x-3">
                      <div className={`w-3 h-3 rounded-full ${player.isOnline ? 'bg-green-500' : 'bg-gray-400'}`} />
                      <div>
                        <p className="font-medium">Player {player.playerId}</p>
                        <p className="text-sm text-gray-500">
                          {player.role === 'admin' ? 'Game Master' : 'Player'} • 
                          {player.isOnline ? ' Online' : ' Offline'}
                        </p>
                      </div>
                    </div>
                    <Badge variant={player.role === 'admin' ? 'default' : 'secondary'}>
                      {player.role === 'admin' ? 'GM' : 'Player'}
                    </Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="settings" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Game Settings</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <label className="text-sm font-medium">Room ID</label>
                <p className="text-sm text-gray-600 font-mono">{roomId}</p>
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium">Connected Players</label>
                <p className="text-sm text-gray-600">{players.filter(p => p.isOnline).length} online</p>
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium">Total Assets</label>
                <p className="text-sm text-gray-600">{assets.length} files</p>
              </div>

              <div className="pt-4 border-t">
                <Button variant="outline" className="w-full" data-testid="button-room-settings">
                  <Settings className="w-4 h-4 mr-2" />
                  Advanced Room Settings
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
      </div>
    </div>
  );
}