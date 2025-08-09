import { useState } from "react";
import { Eye, Dices, Users } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { GameRoom, GameAsset, BoardAsset, RoomPlayer, User } from "@shared/schema";

interface SimplePlayerInterfaceProps {
  room: GameRoom;
  roomAssets: GameAsset[];
  boardAssets: BoardAsset[];
  roomPlayers: RoomPlayer[];
  currentUser: User;
  onDiceRoll: (diceType: string, count: number) => void;
  connected: boolean;
}

export function SimplePlayerInterface({ 
  room, 
  roomAssets, 
  boardAssets, 
  roomPlayers, 
  currentUser,
  onDiceRoll,
  connected 
}: SimplePlayerInterfaceProps) {
  const [selectedDice, setSelectedDice] = useState<string>("d6");
  const [diceCount, setDiceCount] = useState<number>(1);

  const diceTypes = ["d4", "d6", "d8", "d10", "d12", "d20"];

  return (
    <div className="space-y-6" data-testid="simple-player-interface">
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
            <div className={`w-3 h-3 rounded-full ${connected ? 'bg-green-400' : 'bg-red-400'}`} />
            <span className="text-white text-sm">
              {connected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Game Board Area */}
        <div className="lg:col-span-2">
          <Card className="h-[500px]">
            <CardHeader>
              <CardTitle className="text-gray-100">Game Board</CardTitle>
            </CardHeader>
            <CardContent className="h-full bg-green-800 rounded-lg flex items-center justify-center">
              <div className="text-center text-white">
                <div className="text-4xl mb-4">🎲</div>
                <p className="text-lg">Interactive game board</p>
                <p className="text-sm text-gray-300 mt-2">
                  {boardAssets.length} pieces on board
                </p>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Player Controls */}
        <div className="space-y-4">
          {/* Players List */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2 text-gray-100">
                <Users className="w-4 h-4" />
                <span>Players ({roomPlayers.length})</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {roomPlayers.map((player) => (
                <div key={player.id} className="flex items-center justify-between p-2 bg-[#374151] rounded">
                  <span className="text-gray-100 text-sm">
                    Player {player.playerId}
                  </span>
                  <Badge variant={player.role === 'admin' ? 'default' : 'secondary'}>
                    {player.role === 'admin' ? 'GM' : 'Player'}
                  </Badge>
                </div>
              ))}
            </CardContent>
          </Card>

          {/* Dice Rolling */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2 text-gray-100">
                <Dices className="w-4 h-4" />
                <span>Dice</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <label className="text-sm text-gray-300 mb-2 block">Dice Type</label>
                <select 
                  value={selectedDice} 
                  onChange={(e) => setSelectedDice(e.target.value)}
                  className="w-full p-2 bg-[#374151] text-gray-100 rounded border border-gray-600"
                >
                  {diceTypes.map(dice => (
                    <option key={dice} value={dice}>{dice.toUpperCase()}</option>
                  ))}
                </select>
              </div>
              
              <div>
                <label className="text-sm text-gray-300 mb-2 block">Count</label>
                <input 
                  type="number" 
                  min="1" 
                  max="10" 
                  value={diceCount}
                  onChange={(e) => setDiceCount(Math.max(1, parseInt(e.target.value) || 1))}
                  className="w-full p-2 bg-[#374151] text-gray-100 rounded border border-gray-600"
                />
              </div>
              
              <Button 
                onClick={() => onDiceRoll(selectedDice, diceCount)}
                className="w-full bg-green-600 hover:bg-green-700"
                data-testid="roll-dice-button"
              >
                <Dices className="w-4 h-4 mr-2" />
                Roll {diceCount} {selectedDice.toUpperCase()}
              </Button>
            </CardContent>
          </Card>

          {/* Game Assets */}
          <Card>
            <CardHeader>
              <CardTitle className="text-gray-100">Available Assets</CardTitle>
            </CardHeader>
            <CardContent>
              {roomAssets.length > 0 ? (
                <div className="space-y-2">
                  {roomAssets.slice(0, 5).map((asset) => (
                    <div key={asset.id} className="p-2 bg-[#374151] rounded text-sm text-gray-100">
                      {asset.name}
                    </div>
                  ))}
                  {roomAssets.length > 5 && (
                    <p className="text-xs text-gray-400">+{roomAssets.length - 5} more assets</p>
                  )}
                </div>
              ) : (
                <p className="text-gray-400 text-sm">No assets uploaded yet</p>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}