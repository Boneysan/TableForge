import { useState } from 'react';
import { Eye, Move, RotateCw, Users, Dices, Book } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { GameBoard } from '@/components/GameBoard';
import { GameControls } from '@/components/GameControls';
import { GameRulesViewer } from '@/components/GameRulesViewer';
import type { GameRoom, GameAsset, BoardAsset, RoomPlayer } from '@shared/schema';

interface PlayerInterfaceProps {
  room: GameRoom;
  roomAssets: GameAsset[];
  boardAssets: BoardAsset[];
  roomPlayers: RoomPlayer[];
  currentPlayer: { id: string; name: string };
  onAssetMove: (assetId: string, x: number, y: number) => void;
  onAssetPlace: (assetId: string, x: number, y: number) => void;
  onDiceRoll: (diceType: string, count: number) => void;
  connected: boolean;
}

export function PlayerInterface({
  room,
  roomAssets,
  boardAssets,
  roomPlayers,
  currentPlayer,
  onAssetMove,
  onAssetPlace,
  onDiceRoll,
  connected,
}: PlayerInterfaceProps) {
  const [selectedAsset, setSelectedAsset] = useState<string | null>(null);

  return (
    <div className="space-y-6" data-testid="player-interface">
      {/* Player Header */}
      <div className="bg-gradient-to-r from-green-600 to-teal-600 rounded-lg p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Eye className="w-6 h-6 text-white" />
            <div>
              <h2 className="text-xl font-bold text-white">Player View</h2>
              <p className="text-green-100">Welcome to {room.name}</p>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <GameRulesViewer
              room={room}
              trigger={
                <Button
                  variant="outline"
                  size="sm"
                  className="bg-white/10 border-white/20 text-white hover:bg-white/20"
                  data-testid="button-view-rules-player"
                >
                  <Book className="w-4 h-4 mr-1" />
                  Rules
                </Button>
              }
            />
            <div className={`w-3 h-3 rounded-full ${connected ? 'bg-green-400' : 'bg-red-400'}`} />
            <span className="text-white text-sm">
              {connected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Game Board - Takes up most space */}
        <div className="lg:col-span-3">
          <Card className="h-[600px]">
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <span>Game Board</span>
                <Badge variant="secondary">{boardAssets.length} pieces</Badge>
              </CardTitle>
            </CardHeader>
            <CardContent className="h-full p-0">
              <GameBoard
                roomId={room.id}
                assets={roomAssets}
                boardAssets={boardAssets}
                onAssetMoved={onAssetMove}
                onAssetPlaced={onAssetPlace}
                playerRole="player"
                data-testid="game-board-player"
              />
            </CardContent>
          </Card>
        </div>

        {/* Sidebar - Game Controls and Info */}
        <div className="space-y-4">
          <Tabs defaultValue="controls" className="w-full">
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="controls" data-testid="tab-controls">
                <Dices className="w-4 h-4 mr-2" />
                Controls
              </TabsTrigger>
              <TabsTrigger value="players" data-testid="tab-players-view">
                <Users className="w-4 h-4 mr-2" />
                Players
              </TabsTrigger>
            </TabsList>

            <TabsContent value="controls" className="space-y-4">
              {/* Dice Controls */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Dice & Actions</CardTitle>
                </CardHeader>
                <CardContent>
                  <GameControls
                    onDiceRolled={onDiceRoll}
                    currentPlayer={currentPlayer}
                    data-testid="game-controls-player"
                  />
                </CardContent>
              </Card>

              {/* Asset Library - View Only */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Available Assets</CardTitle>
                </CardHeader>
                <CardContent>
                  {roomAssets.length === 0 ? (
                    <p className="text-gray-500 text-center py-4 text-sm">
                      No assets available yet. Wait for the Game Master to upload assets.
                    </p>
                  ) : (
                    <div className="grid grid-cols-2 gap-2">
                      {roomAssets.map((asset) => (
                        <div
                          key={asset.id}
                          className={`relative cursor-pointer group transition-all ${
                            selectedAsset === asset.id ? 'ring-2 ring-blue-500' : ''
                          }`}
                          onClick={() => setSelectedAsset(selectedAsset === asset.id ? null : asset.id)}
                          data-testid={`asset-thumbnail-${asset.id}`}
                        >
                          <div className="aspect-square bg-gray-100 rounded-lg overflow-hidden">
                            <img
                              src={asset.filePath.includes('storage.googleapis.com') && asset.filePath.includes('.private/uploads/')
                                ? `/api/image-proxy?url=${encodeURIComponent(asset.filePath)}`
                                : asset.filePath}
                              alt={asset.name}
                              className="w-full h-full object-cover group-hover:scale-105 transition-transform"
                            />
                          </div>
                          <div className="mt-1">
                            <p className="text-xs font-medium truncate">{asset.name}</p>
                            <Badge variant="outline" className="text-xs">
                              {asset.type}
                            </Badge>
                          </div>
                          {selectedAsset === asset.id && (
                            <div className="absolute inset-0 bg-blue-500 bg-opacity-20 rounded-lg flex items-center justify-center">
                              <Move className="w-6 h-6 text-blue-600" />
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}

                  {selectedAsset && (
                    <div className="mt-4 p-3 bg-blue-50 rounded-lg">
                      <p className="text-sm text-blue-700 font-medium mb-2">Selected Asset</p>
                      <p className="text-xs text-blue-600">
                        Click on the game board to place this asset, or drag existing pieces to move them.
                      </p>
                    </div>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="players" className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Room Players</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {roomPlayers.map((player) => (
                      <div key={player.id} className="flex items-center justify-between p-2 bg-gray-50 rounded" data-testid={`player-info-${player.playerId}`}>
                        <div className="flex items-center space-x-2">
                          <div className={`w-2 h-2 rounded-full ${player.isOnline ? 'bg-green-500' : 'bg-gray-400'}`} />
                          <span className="text-sm font-medium">
                            Player {player.playerId.slice(0, 8)}...
                          </span>
                        </div>
                        <div className="flex items-center space-x-2">
                          {player.role === 'admin' && (
                            <Badge variant="default" className="text-xs">GM</Badge>
                          )}
                          <span className="text-xs text-gray-500">
                            {player.isOnline ? 'Online' : 'Offline'}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* Game Info */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Game Info</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  <div>
                    <p className="text-sm font-medium">Room</p>
                    <p className="text-sm text-gray-600">{room.name}</p>
                  </div>
                  <div>
                    <p className="text-sm font-medium">Status</p>
                    <Badge variant={room.isActive ? 'default' : 'secondary'} className="text-xs">
                      {room.isActive ? 'Active' : 'Inactive'}
                    </Badge>
                  </div>
                  <div>
                    <p className="text-sm font-medium">Your Role</p>
                    <Badge variant="outline" className="text-xs">Player</Badge>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>
      </div>
    </div>
  );
}
