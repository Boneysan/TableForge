import { useState } from "react";
import { Upload, Settings, Users, Dice6, Eye, EyeOff, Edit, MessageCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Separator } from "@/components/ui/separator";
import { ObjectUploader } from "./ObjectUploader";
import { GameBoard } from "./GameBoard";
import { GameControls } from "./GameControls";
import { AssetLibrary } from "./AssetLibrary";
import { ChatComponent } from "./ChatComponent";
import { useToast } from "@/hooks/use-toast";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { authenticatedApiRequest } from "@/lib/authClient";
import type { GameAsset, BoardAsset, RoomPlayer } from "@shared/schema";

interface GameMasterInterfaceProps {
  roomId: string;
  assets: GameAsset[];
  boardAssets: BoardAsset[];
  players: RoomPlayer[];
  currentUser: { id: string; firstName?: string | null; lastName?: string | null };
  websocket: WebSocket | null;
  onAssetUploaded: () => void;
  onAssetPlaced: (assetId: string, x: number, y: number) => void;
  onAssetMoved: (assetId: string, x: number, y: number) => void;
  onDiceRolled: (diceType: string, diceCount: number, results: number[], total: number) => void;
  onSwitchView?: () => void;
}

export function GameMasterInterface({
  roomId,
  assets,
  boardAssets,
  players,
  currentUser,
  websocket,
  onAssetUploaded,
  onAssetPlaced,
  onAssetMoved,
  onDiceRolled,
  onSwitchView,
}: GameMasterInterfaceProps) {
  const [isGMPanelVisible, setIsGMPanelVisible] = useState(true);
  const [selectedTab, setSelectedTab] = useState("game");
  const [showNameEdit, setShowNameEdit] = useState(false);
  const [newFirstName, setNewFirstName] = useState(currentUser.firstName || "");
  const [newLastName, setNewLastName] = useState(currentUser.lastName || "");
  
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const handleGetUploadParameters = async () => {
    const response = await fetch("/api/objects/upload", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    const { uploadURL } = await response.json();
    return { method: "PUT" as const, url: uploadURL };
  };

  const handleUploadComplete = async (result: any) => {
    try {
      if (result.successful && result.successful.length > 0) {
        const uploadedFile = result.successful[0];
        const response = await fetch(`/api/rooms/${roomId}/assets`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name: uploadedFile.name,
            type: "other",
            filePath: uploadedFile.uploadURL,
          }),
        });
        
        if (response.ok) {
          onAssetUploaded();
        }
      }
    } catch (error) {
      console.error("Error uploading asset:", error);
    }
  };

  const updateNameMutation = useMutation({
    mutationFn: async (updates: { firstName?: string; lastName?: string }) => {
      const response = await authenticatedApiRequest("PUT", "/api/auth/user", updates);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/auth/user"] });
      setShowNameEdit(false);
      toast({
        title: "Success",
        description: "Your name has been updated successfully!",
      });
    },
    onError: (error) => {
      toast({
        title: "Error",
        description: "Failed to update your name. Please try again.",
        variant: "destructive",
      });
    },
  });

  const handleNameSubmit = () => {
    const updates: { firstName?: string; lastName?: string } = {};
    if (newFirstName.trim()) updates.firstName = newFirstName.trim();
    if (newLastName.trim()) updates.lastName = newLastName.trim();
    
    if (Object.keys(updates).length === 0) {
      toast({
        title: "Error",
        description: "Please enter at least a first name or last name.",
        variant: "destructive",
      });
      return;
    }
    
    updateNameMutation.mutate(updates);
  };

  const currentPlayerName = currentUser.firstName || currentUser.lastName 
    ? `${currentUser.firstName || ''} ${currentUser.lastName || ''}`.trim()
    : 'Game Master';

  return (
    <div className="h-screen flex flex-col">
      {/* Header with GM Controls Toggle */}
      <div className="flex items-center justify-between p-4 border-b bg-purple-50 dark:bg-purple-900/20">
        <div className="flex items-center gap-3">
          <Settings className="w-5 h-5 text-purple-600" />
          <div>
            <h2 className="text-lg font-semibold text-purple-800 dark:text-purple-200">
              Game Master Console
            </h2>
            <div className="flex items-center gap-2">
              <span className="text-sm text-purple-600 dark:text-purple-300">
                GM: {currentPlayerName}
              </span>
              <Dialog open={showNameEdit} onOpenChange={setShowNameEdit}>
                <DialogTrigger asChild>
                  <Button 
                    variant="ghost" 
                    size="sm" 
                    className="h-5 w-5 p-0 text-purple-600 hover:text-purple-800 hover:bg-purple-100 dark:text-purple-300 dark:hover:text-purple-100 dark:hover:bg-purple-800"
                    data-testid="edit-gm-name-button"
                  >
                    <Edit className="h-3 w-3" />
                  </Button>
                </DialogTrigger>
                <DialogContent className="bg-white dark:bg-[#1F2937] border-gray-300 dark:border-gray-600">
                  <DialogHeader>
                    <DialogTitle className="text-gray-900 dark:text-gray-100">Change Your Name</DialogTitle>
                  </DialogHeader>
                  <div className="space-y-4">
                    <div>
                      <label className="text-sm text-gray-700 dark:text-gray-300 mb-1 block">First Name</label>
                      <Input
                        value={newFirstName}
                        onChange={(e) => setNewFirstName(e.target.value)}
                        placeholder="Enter your first name"
                        className="bg-white dark:bg-[#374151] border-gray-300 dark:border-gray-600 text-gray-900 dark:text-gray-100"
                        data-testid="gm-first-name-input"
                      />
                    </div>
                    <div>
                      <label className="text-sm text-gray-700 dark:text-gray-300 mb-1 block">Last Name</label>
                      <Input
                        value={newLastName}
                        onChange={(e) => setNewLastName(e.target.value)}
                        placeholder="Enter your last name"
                        className="bg-white dark:bg-[#374151] border-gray-300 dark:border-gray-600 text-gray-900 dark:text-gray-100"
                        data-testid="gm-last-name-input"
                      />
                    </div>
                    <div className="flex space-x-2">
                      <Button 
                        onClick={handleNameSubmit}
                        disabled={updateNameMutation.isPending}
                        className="flex-1 bg-purple-600 hover:bg-purple-700"
                        data-testid="gm-save-name-button"
                      >
                        {updateNameMutation.isPending ? "Saving..." : "Save"}
                      </Button>
                      <Button 
                        variant="outline" 
                        onClick={() => setShowNameEdit(false)}
                        className="flex-1 border-gray-300 dark:border-gray-600 text-gray-900 dark:text-gray-100 hover:bg-gray-100 dark:hover:bg-gray-700"
                        data-testid="gm-cancel-name-button"
                      >
                        Cancel
                      </Button>
                    </div>
                  </div>
                </DialogContent>
              </Dialog>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-4">
          {onSwitchView && (
            <Button 
              variant="outline" 
              size="sm" 
              onClick={onSwitchView}
              data-testid="button-switch-view-gm"
            >
              Switch to Admin Interface
            </Button>
          )}
          <div className="flex items-center gap-2">
            <Label htmlFor="gm-panel-toggle" className="text-sm">
              GM Panel
            </Label>
            <Switch
              id="gm-panel-toggle"
              checked={isGMPanelVisible}
              onCheckedChange={setIsGMPanelVisible}
              data-testid="switch-gm-panel"
            />
            {isGMPanelVisible ? (
              <Eye className="w-4 h-4 text-purple-600" />
            ) : (
              <EyeOff className="w-4 h-4 text-gray-400" />
            )}
          </div>
        </div>
      </div>

      <div className="flex flex-1 overflow-hidden">
        {/* Game Board - Main Area */}
        <div className="flex-1 p-4">
          <Card className="h-full">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <span>Game Board</span>
                <span className="text-sm font-normal text-gray-500">
                  ({players.length} players connected)
                </span>
              </CardTitle>
            </CardHeader>
            <CardContent className="h-full">
              <GameBoard
                assets={assets}
                boardAssets={boardAssets}
                onAssetMoved={onAssetMoved}
                onAssetPlaced={onAssetPlaced}
                playerRole="admin"
                data-testid="game-board-gm"
              />
            </CardContent>
          </Card>
        </div>

        {/* GM Panel - Collapsible Side Panel */}
        {isGMPanelVisible && (
          <div className="w-80 border-l bg-gray-50 dark:bg-gray-900/50 flex flex-col">
            <Tabs value={selectedTab} onValueChange={setSelectedTab} className="flex-1 flex flex-col">
              <TabsList className="grid w-full grid-cols-4 m-2">
                <TabsTrigger value="game" className="text-xs">
                  <Dice6 className="w-4 h-4 mr-1" />
                  Game
                </TabsTrigger>
                <TabsTrigger value="assets" className="text-xs">
                  <Upload className="w-4 h-4 mr-1" />
                  Assets
                </TabsTrigger>
                <TabsTrigger value="players" className="text-xs">
                  <Users className="w-4 h-4 mr-1" />
                  Players
                </TabsTrigger>
                <TabsTrigger value="chat" className="text-xs">
                  <MessageCircle className="w-4 h-4 mr-1" />
                  Chat
                </TabsTrigger>
              </TabsList>

              <div className="flex-1 overflow-hidden">
                {/* Game Controls Tab */}
                <TabsContent value="game" className="h-full p-4 space-y-4 overflow-y-auto">
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-sm">Game Master Actions</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <GameControls
                        onDiceRolled={onDiceRolled}
                        currentPlayer={{ id: currentUser.id, name: currentPlayerName }}
                        data-testid="game-controls-gm"
                      />
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader>
                      <CardTitle className="text-sm">Quick Actions</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-2">
                      <Button
                        variant="outline"
                        size="sm"
                        className="w-full justify-start"
                        data-testid="button-clear-board"
                      >
                        Clear Board
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        className="w-full justify-start"
                        data-testid="button-save-state"
                      >
                        Save Game State
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        className="w-full justify-start"
                        data-testid="button-reset-dice"
                      >
                        Clear Dice History
                      </Button>
                    </CardContent>
                  </Card>
                </TabsContent>

                {/* Asset Management Tab */}
                <TabsContent value="assets" className="h-full p-4 space-y-4 overflow-y-auto">
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-sm">Upload Assets</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <ObjectUploader
                        maxNumberOfFiles={10}
                        maxFileSize={10485760}
                        onGetUploadParameters={handleGetUploadParameters}
                        onComplete={handleUploadComplete}
                        buttonClassName="w-full"
                      >
                        <Upload className="w-4 h-4 mr-2" />
                        Upload Game Assets
                      </ObjectUploader>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader>
                      <CardTitle className="text-sm">Asset Library</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <AssetLibrary
                        roomId={roomId}
                        assets={assets}
                        onAssetUploaded={onAssetUploaded}
                      />
                    </CardContent>
                  </Card>
                </TabsContent>

                {/* Player Management Tab */}
                <TabsContent value="players" className="h-full p-4 space-y-4 overflow-y-auto">
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-sm">Connected Players</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-2">
                        {players.map((player) => (
                          <div
                            key={player.id}
                            className="flex items-center justify-between p-2 rounded border"
                            data-testid={`player-${player.playerId}`}
                          >
                            <div className="flex items-center gap-2">
                              <div
                                className={`w-2 h-2 rounded-full ${
                                  player.isOnline ? 'bg-green-500' : 'bg-gray-400'
                                }`}
                              />
                              <span className="text-sm font-medium">
                                {player.playerId === currentUser.id ? 'You (GM)' : `Player ${player.playerId.slice(0, 8)}`}
                              </span>
                            </div>
                            <div className="flex items-center gap-1">
                              <span className={`text-xs px-2 py-1 rounded ${
                                player.role === 'admin' 
                                  ? 'bg-purple-100 text-purple-700 dark:bg-purple-900 dark:text-purple-300' 
                                  : 'bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300'
                              }`}>
                                {player.role === 'admin' ? 'GM' : 'Player'}
                              </span>
                            </div>
                          </div>
                        ))}
                        {players.length === 0 && (
                          <div className="text-center py-4 text-gray-500 text-sm">
                            No players connected
                          </div>
                        )}
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader>
                      <CardTitle className="text-sm">Room Settings</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <div className="flex items-center justify-between">
                        <Label htmlFor="private-dice" className="text-sm">
                          Private Dice Rolls
                        </Label>
                        <Switch id="private-dice" data-testid="switch-private-dice" />
                      </div>
                      <div className="flex items-center justify-between">
                        <Label htmlFor="lock-assets" className="text-sm">
                          Lock Assets
                        </Label>
                        <Switch id="lock-assets" data-testid="switch-lock-assets" />
                      </div>
                      <Separator />
                      <Button
                        variant="destructive"
                        size="sm"
                        className="w-full"
                        data-testid="button-end-session"
                      >
                        End Game Session
                      </Button>
                    </CardContent>
                  </Card>
                </TabsContent>

                {/* Chat Tab */}
                <TabsContent value="chat" className="h-full">
                  <div className="h-full p-4">
                    <ChatComponent 
                      roomId={roomId}
                      websocket={websocket}
                      currentUserId={currentUser.id}
                    />
                  </div>
                </TabsContent>
              </div>
            </Tabs>
          </div>
        )}
      </div>
    </div>
  );
}