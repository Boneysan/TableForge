import { useState } from "react";
import { Upload, Settings, Users, Dice6, Eye, EyeOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { ObjectUploader } from "./ObjectUploader";
import { GameBoard } from "./GameBoard";
import { GameControls } from "./GameControls";
import { AssetLibrary } from "./AssetLibrary";
import type { GameAsset, BoardAsset, RoomPlayer } from "@shared/schema";

interface GameMasterInterfaceProps {
  roomId: string;
  assets: GameAsset[];
  boardAssets: BoardAsset[];
  players: RoomPlayer[];
  currentUser: { id: string; firstName?: string; lastName?: string };
  onAssetUploaded: () => void;
  onAssetPlaced: (assetId: string, x: number, y: number) => void;
  onAssetMoved: (assetId: string, x: number, y: number) => void;
  onDiceRolled: (diceType: string, diceCount: number, results: number[], total: number) => void;
}

export function GameMasterInterface({
  roomId,
  assets,
  boardAssets,
  players,
  currentUser,
  onAssetUploaded,
  onAssetPlaced,
  onAssetMoved,
  onDiceRolled,
}: GameMasterInterfaceProps) {
  const [isGMPanelVisible, setIsGMPanelVisible] = useState(true);
  const [selectedTab, setSelectedTab] = useState("game");

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

  const currentPlayerName = currentUser.firstName || currentUser.lastName 
    ? `${currentUser.firstName || ''} ${currentUser.lastName || ''}`.trim()
    : 'Game Master';

  return (
    <div className="h-screen flex flex-col">
      {/* Header with GM Controls Toggle */}
      <div className="flex items-center justify-between p-4 border-b bg-purple-50 dark:bg-purple-900/20">
        <div className="flex items-center gap-3">
          <Settings className="w-5 h-5 text-purple-600" />
          <h2 className="text-lg font-semibold text-purple-800 dark:text-purple-200">
            Game Master Console
          </h2>
        </div>
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
              <TabsList className="grid w-full grid-cols-3 m-2">
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
              </div>
            </Tabs>
          </div>
        )}
      </div>
    </div>
  );
}