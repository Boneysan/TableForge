import { useState } from "react";
import { Eye, Dices, Users, Edit } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { authenticatedApiRequest } from "@/lib/authClient";
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
  const [lastRoll, setLastRoll] = useState<{ results: number[]; total: number; diceType: string; count: number } | null>(null);
  const [showNameEdit, setShowNameEdit] = useState(false);
  const [newFirstName, setNewFirstName] = useState(currentUser.firstName || "");
  const [newLastName, setNewLastName] = useState(currentUser.lastName || "");
  
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const diceTypes = ["d4", "d6", "d8", "d10", "d12", "d20"];

  const handleRollDice = () => {
    const sides = parseInt(selectedDice.replace('d', ''));
    const results = Array.from({ length: diceCount }, () => Math.floor(Math.random() * sides) + 1);
    const total = results.reduce((sum, roll) => sum + roll, 0);
    
    // Update local state to show results immediately
    setLastRoll({ results, total, diceType: selectedDice, count: diceCount });
    
    // Send to server
    onDiceRoll(selectedDice, diceCount);
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

  const displayName = currentUser.firstName && currentUser.lastName 
    ? `${currentUser.firstName} ${currentUser.lastName}`
    : currentUser.firstName 
    ? currentUser.firstName
    : currentUser.email || "Player";

  return (
    <div className="space-y-6" data-testid="simple-player-interface">
      {/* Player Header */}
      <div className="bg-gradient-to-r from-green-600 to-teal-600 rounded-lg p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Eye className="w-6 h-6 text-white" />
            <div className="flex-1">
              <h2 className="text-xl font-bold text-white">Player View</h2>
              <div className="flex items-center space-x-2">
                <p className="text-green-100">Welcome {displayName}</p>
                <Dialog open={showNameEdit} onOpenChange={setShowNameEdit}>
                  <DialogTrigger asChild>
                    <Button 
                      variant="ghost" 
                      size="sm" 
                      className="h-6 w-6 p-0 text-green-100 hover:text-white hover:bg-green-700"
                      data-testid="edit-name-button"
                    >
                      <Edit className="h-3 w-3" />
                    </Button>
                  </DialogTrigger>
                  <DialogContent className="bg-[#1F2937] border-gray-600">
                    <DialogHeader>
                      <DialogTitle className="text-gray-100">Change Your Name</DialogTitle>
                    </DialogHeader>
                    <div className="space-y-4">
                      <div>
                        <label className="text-sm text-gray-300 mb-1 block">First Name</label>
                        <Input
                          value={newFirstName}
                          onChange={(e) => setNewFirstName(e.target.value)}
                          placeholder="Enter your first name"
                          className="bg-[#374151] border-gray-600 text-gray-100"
                          data-testid="first-name-input"
                        />
                      </div>
                      <div>
                        <label className="text-sm text-gray-300 mb-1 block">Last Name</label>
                        <Input
                          value={newLastName}
                          onChange={(e) => setNewLastName(e.target.value)}
                          placeholder="Enter your last name"
                          className="bg-[#374151] border-gray-600 text-gray-100"
                          data-testid="last-name-input"
                        />
                      </div>
                      <div className="flex space-x-2">
                        <Button 
                          onClick={handleNameSubmit}
                          disabled={updateNameMutation.isPending}
                          className="flex-1 bg-green-600 hover:bg-green-700"
                          data-testid="save-name-button"
                        >
                          {updateNameMutation.isPending ? "Saving..." : "Save"}
                        </Button>
                        <Button 
                          variant="outline" 
                          onClick={() => setShowNameEdit(false)}
                          className="flex-1 border-gray-600 text-gray-100 hover:bg-gray-700"
                          data-testid="cancel-name-button"
                        >
                          Cancel
                        </Button>
                      </div>
                    </div>
                  </DialogContent>
                </Dialog>
              </div>
              <p className="text-green-100 text-sm">Playing in {room.name}</p>
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
                    {(player as any).playerName || `Player ${player.playerId}`}
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
                onClick={handleRollDice}
                className="w-full bg-green-600 hover:bg-green-700"
                data-testid="roll-dice-button"
              >
                <Dices className="w-4 h-4 mr-2" />
                Roll {diceCount} {selectedDice.toUpperCase()}
              </Button>
              
              {lastRoll && (
                <div className="mt-4 p-3 bg-[#374151] rounded-lg border border-green-500">
                  <div className="text-center">
                    <div className="text-sm text-gray-300 mb-1">
                      {lastRoll.count} {lastRoll.diceType.toUpperCase()} Roll
                    </div>
                    <div className="flex justify-center space-x-2 mb-2">
                      {lastRoll.results.map((result, index) => (
                        <div key={index} className="w-8 h-8 bg-green-600 text-white rounded flex items-center justify-center text-sm font-bold">
                          {result}
                        </div>
                      ))}
                    </div>
                    <div className="text-lg font-bold text-green-400">
                      Total: {lastRoll.total}
                    </div>
                  </div>
                </div>
              )}
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