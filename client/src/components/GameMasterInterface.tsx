import { useState } from "react";
import { Upload, Settings, Users, Dice6, Eye, EyeOff, Edit, MessageCircle, ArrowLeft, Hand, FolderOpen } from "lucide-react";
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
import { CardDeckManager } from "./CardDeckManager";
import { GameTemplateManager } from "./GameTemplateManager";
import { GameSystemManager } from "./GameSystemManager";
import { PlayerScoreboard } from "./PlayerScoreboard";
import { useToast } from "@/hooks/use-toast";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { authenticatedApiRequest } from "@/lib/authClient";
import { ThemeToggle } from "@/components/ThemeToggle";
import { useLocation } from "wouter";
import type { GameAsset, BoardAsset, RoomPlayerWithName } from "@shared/schema";

interface GameMasterInterfaceProps {
  roomId: string;
  assets: GameAsset[];
  boardAssets: BoardAsset[];
  players: RoomPlayerWithName[];
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
  const [showHandViewer, setShowHandViewer] = useState(false);
  
  // GM hand data - in a real implementation this would come from the server
  const [gmHand] = useState([
    { id: 'gm1', name: 'Event Card: Storm', imageUrl: null, faceUp: true },
    { id: 'gm2', name: 'Quest: Dragon Hunt', imageUrl: null, faceUp: true },
    { id: 'gm3', name: 'Hidden Plot Card', imageUrl: null, faceUp: false },
    { id: 'gm4', name: 'NPC: Mysterious Stranger', imageUrl: null, faceUp: true }
  ]);
  
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [, setLocation] = useLocation();

  const handleScoreUpdate = async (playerId: string, newScore: number) => {
    try {
      // Send WebSocket message for real-time updates
      if (websocket && websocket.readyState === WebSocket.OPEN) {
        websocket.send(JSON.stringify({
          type: 'player_score_updated',
          roomId,
          payload: {
            playerId,
            score: newScore
          }
        }));
      }

      // Also update via API for persistence
      await authenticatedApiRequest("PATCH", `/api/rooms/${roomId}/players/${playerId}/score`, {
        score: newScore
      });

      toast({
        title: "Score Updated",
        description: "Player score has been updated successfully.",
      });
    } catch (error) {
      console.error("Error updating score:", error);
      toast({
        title: "Error",
        description: "Failed to update player score. Please try again.",
        variant: "destructive",
      });
    }
  };

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
          <ThemeToggle />
          <GameTemplateManager roomId={roomId}>
            <Button
              variant="outline"
              size="sm"
              className="border-purple-300 dark:border-purple-600 text-purple-700 dark:text-purple-300 hover:bg-purple-100 dark:hover:bg-purple-800"
              data-testid="button-template-manager"
            >
              <FolderOpen className="w-4 h-4 mr-1" />
              Templates
            </Button>
          </GameTemplateManager>

          <Dialog>
            <DialogTrigger asChild>
              <Button
                variant="outline"
                size="sm"
                className="border-purple-300 dark:border-purple-600 text-purple-700 dark:text-purple-300 hover:bg-purple-100 dark:hover:bg-purple-800"
                data-testid="button-system-manager"
              >
                <Settings className="w-4 h-4 mr-1" />
                Game Systems
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-6xl max-h-[90vh] overflow-y-auto">
              <DialogHeader>
                <DialogTitle>Game Systems Manager</DialogTitle>
              </DialogHeader>
              <GameSystemManager roomId={roomId} currentUser={currentUser} />
            </DialogContent>
          </Dialog>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setLocation('/')}
            className="border-purple-300 dark:border-purple-600 text-purple-700 dark:text-purple-300 hover:bg-purple-100 dark:hover:bg-purple-800"
            data-testid="button-leave-room"
          >
            <ArrowLeft className="w-4 h-4 mr-1" />
            Leave Room
          </Button>
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
              <TabsList className="grid w-full grid-cols-6 m-2">
                <TabsTrigger value="game" className="text-xs">
                  <Dice6 className="w-4 h-4 mr-1" />
                  Game
                </TabsTrigger>
                <TabsTrigger value="hand" className="text-xs">
                  <Hand className="w-4 h-4 mr-1" />
                  Hand
                </TabsTrigger>
                <TabsTrigger value="assets" className="text-xs">
                  <Upload className="w-4 h-4 mr-1" />
                  Assets
                </TabsTrigger>
                <TabsTrigger value="cards" className="text-xs">
                  <Settings className="w-4 h-4 mr-1" />
                  Cards
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

                {/* GM Hand Tab */}
                <TabsContent value="hand" className="h-full p-4 space-y-4 overflow-y-auto">
                  <Card>
                    <CardHeader className="pb-3">
                      <div className="flex items-center justify-between">
                        <CardTitle className="text-sm flex items-center space-x-2">
                          <Hand className="w-4 h-4" />
                          <span>GM Hand</span>
                        </CardTitle>
                        <Button 
                          variant="outline" 
                          size="sm"
                          onClick={() => setShowHandViewer(true)}
                          className="text-xs"
                          data-testid="button-expand-gm-hand"
                        >
                          View Large
                        </Button>
                      </div>
                    </CardHeader>
                    <CardContent>
                      {gmHand.length > 0 ? (
                        <div className="space-y-3">
                          <div className="grid grid-cols-2 gap-2">
                            {gmHand.map((card) => (
                              <div key={card.id} className="relative">
                                <div className="w-full h-16 bg-gradient-to-br from-purple-600 to-purple-800 rounded-lg border border-gray-600 flex items-center justify-center text-white text-xs font-medium shadow-lg">
                                  {card.faceUp ? (
                                    <div className="text-center p-1">
                                      <div className="text-sm">🎴</div>
                                      <div className="text-[10px] leading-tight">{card.name.length > 15 ? card.name.substring(0, 15) + '...' : card.name}</div>
                                    </div>
                                  ) : (
                                    <div className="text-center">
                                      <div className="text-sm">🂠</div>
                                      <div className="text-[10px]">Hidden</div>
                                    </div>
                                  )}
                                </div>
                              </div>
                            ))}
                          </div>
                          <p className="text-xs text-gray-500 dark:text-gray-400">{gmHand.length} cards in GM hand</p>
                        </div>
                      ) : (
                        <div className="text-center py-6 text-gray-400">
                          <Hand className="w-6 h-6 mx-auto mb-2" />
                          <p className="text-sm">No cards in GM hand</p>
                          <p className="text-xs mt-1">Draw cards from decks</p>
                        </div>
                      )}
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader>
                      <CardTitle className="text-sm">Hand Actions</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-2">
                      <Button
                        variant="outline"
                        size="sm"
                        className="w-full justify-start text-xs"
                        data-testid="button-draw-card"
                      >
                        <Hand className="w-3 h-3 mr-2" />
                        Draw from Deck
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        className="w-full justify-start text-xs"
                        data-testid="button-shuffle-hand"
                      >
                        <Settings className="w-3 h-3 mr-2" />
                        Organize Hand
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        className="w-full justify-start text-xs"
                        data-testid="button-deal-cards"
                      >
                        <Users className="w-3 h-3 mr-2" />
                        Deal to Players
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

                {/* Card Management Tab */}
                <TabsContent value="cards" className="h-full p-4 space-y-4 overflow-y-auto">
                  <CardDeckManager
                    roomId={roomId}
                    assets={assets}
                    currentUserId={currentUser.id}
                    playerRole="admin"
                    onCardDealt={() => {}} // Placeholder for now
                  />
                </TabsContent>

                {/* Player Management Tab */}
                <TabsContent value="players" className="h-full p-4 space-y-4 overflow-y-auto">
                  <PlayerScoreboard
                    players={players}
                    currentUserId={currentUser.id}
                    isGameMaster={true}
                    onScoreUpdate={handleScoreUpdate}
                  />

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

      {/* Large GM Hand Viewer Dialog */}
      <Dialog open={showHandViewer} onOpenChange={setShowHandViewer}>
        <DialogContent className="max-w-4xl max-h-[80vh] bg-white dark:bg-[#1F2937] border-gray-300 dark:border-gray-600">
          <DialogHeader>
            <DialogTitle className="text-gray-900 dark:text-gray-100 flex items-center space-x-2">
              <Hand className="w-5 h-5" />
              <span>Game Master Hand - Large View</span>
            </DialogTitle>
          </DialogHeader>
          <div className="mt-4">
            {gmHand.length > 0 ? (
              <div className="grid grid-cols-4 gap-4 p-4 bg-gray-50 dark:bg-[#374151] rounded-lg max-h-[60vh] overflow-y-auto">
                {gmHand.map((card) => (
                  <div key={card.id} className="relative group">
                    <div className="w-32 h-40 bg-gradient-to-br from-purple-600 to-purple-800 rounded-lg border-2 border-gray-600 flex items-center justify-center text-white shadow-lg hover:shadow-xl transition-shadow cursor-pointer">
                      {card.faceUp ? (
                        <div className="text-center p-2">
                          <div className="text-4xl mb-2">🎴</div>
                          <div className="text-xs leading-tight font-medium">{card.name}</div>
                        </div>
                      ) : (
                        <div className="text-center">
                          <div className="text-4xl mb-2">🂠</div>
                          <div className="text-xs">Hidden</div>
                        </div>
                      )}
                    </div>
                    {/* Card actions on hover */}
                    <div className="absolute inset-0 bg-black/20 opacity-0 group-hover:opacity-100 transition-opacity rounded-lg flex items-center justify-center">
                      <div className="space-x-1">
                        <Button 
                          size="sm" 
                          variant="secondary" 
                          className="text-xs h-6 px-2"
                          data-testid={`button-play-gm-card-${card.id}`}
                        >
                          Play
                        </Button>
                        <Button 
                          size="sm" 
                          variant="outline" 
                          className="text-xs h-6 px-2"
                          data-testid={`button-deal-card-${card.id}`}
                        >
                          Deal
                        </Button>
                        {card.faceUp && (
                          <Button 
                            size="sm" 
                            variant="outline" 
                            className="text-xs h-6 px-2"
                            data-testid={`button-flip-gm-card-${card.id}`}
                          >
                            Flip
                          </Button>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-12 text-gray-500 dark:text-gray-400">
                <Hand className="w-16 h-16 mx-auto mb-4" />
                <p className="text-lg">No cards in GM hand</p>
                <p className="text-sm mt-2">Draw cards from decks to manage game state</p>
              </div>
            )}
            
            <div className="flex justify-between items-center mt-4 pt-4 border-t border-gray-300 dark:border-gray-600">
              <div className="text-sm text-gray-600 dark:text-gray-400">
                {gmHand.length} cards in GM hand
              </div>
              <div className="space-x-2">
                <Button 
                  variant="outline" 
                  onClick={() => setShowHandViewer(false)}
                  className="border-gray-300 dark:border-gray-600"
                  data-testid="button-close-gm-hand-viewer"
                >
                  Close
                </Button>
                <Button 
                  variant="outline"
                  className="border-gray-300 dark:border-gray-600"
                  data-testid="button-deal-all-cards"
                >
                  <Users className="w-4 h-4 mr-1" />
                  Deal to All Players
                </Button>
                <Button 
                  variant="outline"
                  className="border-gray-300 dark:border-gray-600"
                  data-testid="button-organize-gm-hand"
                >
                  <Settings className="w-4 h-4 mr-1" />
                  Organize by Type
                </Button>
              </div>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}