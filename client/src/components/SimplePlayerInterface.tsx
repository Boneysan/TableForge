import { useState } from "react";
import { Eye, Dices, Users, Edit, MessageCircle, ArrowLeft, Hand } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { authenticatedApiRequest } from "@/lib/authClient";
import { ChatComponent } from "./ChatComponent";
import { ThemeToggle } from "./ThemeToggle";
import { PlayerScoreboard } from "./PlayerScoreboard";
import { GameBoard } from "./GameBoard";
import { useLocation } from "wouter";
import type { GameRoom, GameAsset, BoardAsset, RoomPlayerWithName, User } from "@shared/schema";

interface SimplePlayerInterfaceProps {
  room: GameRoom;
  roomAssets: GameAsset[];
  boardAssets: BoardAsset[];
  roomPlayers: RoomPlayerWithName[];
  currentUser: User;
  websocket: WebSocket | null;
  onDiceRoll: (diceType: string, count: number) => void;
  connected: boolean;
}

export function SimplePlayerInterface({ 
  room, 
  roomAssets, 
  boardAssets, 
  roomPlayers, 
  currentUser,
  websocket,
  onDiceRoll,
  connected 
}: SimplePlayerInterfaceProps) {
  const [selectedDice, setSelectedDice] = useState<string>("d6");
  const [diceCount, setDiceCount] = useState<number>(1);
  const [lastRoll, setLastRoll] = useState<{ results: number[]; total: number; diceType: string; count: number } | null>(null);
  const [showNameEdit, setShowNameEdit] = useState(false);
  const [newFirstName, setNewFirstName] = useState(currentUser.firstName || "");
  const [newLastName, setNewLastName] = useState(currentUser.lastName || "");
  const [showHandViewer, setShowHandViewer] = useState(false);
  
  // Placeholder hand data - in a real implementation this would come from the server
  const [playerHand] = useState([
    { id: '1', name: 'Ace of Spades', imageUrl: null, faceUp: true },
    { id: '2', name: 'King of Hearts', imageUrl: null, faceUp: true },
    { id: '3', name: 'Hidden Card', imageUrl: null, faceUp: false }
  ]);
  
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [, setLocation] = useLocation();

  const handleScoreUpdate = async (playerId: string, newScore: number) => {
    try {
      // Players can only update their own score unless they're GM
      if (playerId !== currentUser.id) {
        toast({
          title: "Not Allowed",
          description: "Players can only update their own score.",
          variant: "destructive",
        });
        return;
      }

      // Send WebSocket message for real-time updates
      if (websocket && websocket.readyState === WebSocket.OPEN) {
        websocket.send(JSON.stringify({
          type: 'player_score_updated',
          roomId: room.id,
          payload: {
            playerId,
            score: newScore
          }
        }));
      }

      // Also update via API for persistence
      await authenticatedApiRequest("PATCH", `/api/rooms/${room.id}/players/${playerId}/score`, {
        score: newScore
      });

      toast({
        title: "Score Updated",
        description: "Your score has been updated successfully.",
      });
    } catch (error) {
      console.error("Error updating score:", error);
      toast({
        title: "Error",
        description: "Failed to update score. Please try again.",
        variant: "destructive",
      });
    }
  };

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
            <CardContent className="h-full p-0 overflow-auto">
              <GameBoard
                assets={roomAssets}
                boardAssets={boardAssets}
                onAssetMoved={() => {}} // Players can't move assets
                onAssetPlaced={() => {}} // Players can't place assets
                playerRole="player"
                roomId={room.id}
                roomBoardWidth={room.boardWidth}
                roomBoardHeight={room.boardHeight}
                data-testid="game-board-player"
              />
            </CardContent>
          </Card>
        </div>

        {/* Player Controls */}
        <div className="space-y-4">
          {/* Player Hand */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2 text-gray-100">
                <Hand className="w-4 h-4" />
                <span>Your Hand</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {/* Hand cards display */}
                {playerHand.length > 0 ? (
                  <div className="min-h-[120px] bg-[#374151] rounded-lg p-3">
                    <div className="flex flex-wrap gap-2">
                      {playerHand.map((card) => (
                        <div key={card.id} className="relative">
                          <div className="w-16 h-20 bg-gradient-to-br from-blue-600 to-blue-800 rounded-lg border border-gray-600 flex items-center justify-center text-white text-xs font-medium shadow-lg">
                            {card.faceUp ? (
                              <div className="text-center">
                                <div className="text-lg">🂡</div>
                                <div className="text-[10px] leading-tight">{card.name.split(' ')[0]}</div>
                              </div>
                            ) : (
                              <div className="text-center">
                                <div className="text-lg">🂠</div>
                                <div className="text-[10px]">Hidden</div>
                              </div>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                    <p className="text-xs text-gray-400 mt-2">{playerHand.length} cards in hand</p>
                  </div>
                ) : (
                  <div className="min-h-[120px] bg-[#374151] rounded-lg border-2 border-dashed border-gray-600 flex items-center justify-center">
                    <div className="text-center text-gray-400">
                      <Hand className="w-8 h-8 mx-auto mb-2" />
                      <p className="text-sm">No cards in hand</p>
                      <p className="text-xs mt-1">Cards dealt by GM will appear here</p>
                    </div>
                  </div>
                )}
                
                {/* Hand actions */}
                <div className="space-y-2">
                  <div className="flex space-x-2">
                    <Button 
                      variant="outline" 
                      size="sm" 
                      className="flex-1 border-gray-600 text-gray-300 hover:bg-gray-700"
                      data-testid="button-draw-from-deck"
                    >
                      <Hand className="w-3 h-3 mr-1" />
                      Draw Card
                    </Button>
                    <Button 
                      variant="outline" 
                      size="sm" 
                      className="flex-1 border-gray-600 text-gray-300 hover:bg-gray-700"
                      data-testid="button-organize-hand"
                    >
                      <Eye className="w-3 h-3 mr-1" />
                      Organize
                    </Button>
                  </div>
                  <Button 
                    variant="outline" 
                    size="sm" 
                    className="w-full border-gray-600 text-gray-300 hover:bg-gray-700"
                    onClick={() => setShowHandViewer(true)}
                    data-testid="button-expand-hand"
                  >
                    <Hand className="w-3 h-3 mr-1" />
                    View Large Hand
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Player Scoreboard */}
          <PlayerScoreboard
            players={roomPlayers}
            currentUserId={currentUser.id}
            isGameMaster={false}
            onScoreUpdate={handleScoreUpdate}
          />

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

          {/* Chat */}
          <div className="h-80 bg-[#1F2937] rounded-lg border border-gray-600 overflow-hidden">
            <ChatComponent 
              roomId={room.id}
              websocket={websocket}
              currentUserId={currentUser.id}
            />
          </div>
        </div>
      </div>

      {/* Large Hand Viewer Dialog */}
      <Dialog open={showHandViewer} onOpenChange={setShowHandViewer}>
        <DialogContent className="max-w-4xl max-h-[80vh] bg-white dark:bg-[#1F2937] border-gray-300 dark:border-gray-600">
          <DialogHeader>
            <DialogTitle className="text-gray-900 dark:text-gray-100 flex items-center space-x-2">
              <Hand className="w-5 h-5" />
              <span>Your Hand - Large View</span>
            </DialogTitle>
          </DialogHeader>
          <div className="mt-4">
            {playerHand.length > 0 ? (
              <div className="grid grid-cols-6 gap-4 p-4 bg-gray-50 dark:bg-[#374151] rounded-lg max-h-[60vh] overflow-y-auto">
                {playerHand.map((card) => (
                  <div key={card.id} className="relative group">
                    <div className="w-24 h-32 bg-gradient-to-br from-blue-600 to-blue-800 rounded-lg border-2 border-gray-600 flex items-center justify-center text-white shadow-lg hover:shadow-xl transition-shadow cursor-pointer">
                      {card.faceUp ? (
                        <div className="text-center">
                          <div className="text-3xl mb-1">🂡</div>
                          <div className="text-xs leading-tight font-medium">{card.name}</div>
                        </div>
                      ) : (
                        <div className="text-center">
                          <div className="text-3xl mb-1">🂠</div>
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
                          data-testid={`button-play-card-${card.id}`}
                        >
                          Play
                        </Button>
                        {card.faceUp && (
                          <Button 
                            size="sm" 
                            variant="outline" 
                            className="text-xs h-6 px-2"
                            data-testid={`button-flip-card-${card.id}`}
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
                <p className="text-lg">No cards in hand</p>
                <p className="text-sm mt-2">Cards dealt by the Game Master will appear here</p>
              </div>
            )}
            
            <div className="flex justify-between items-center mt-4 pt-4 border-t border-gray-300 dark:border-gray-600">
              <div className="text-sm text-gray-600 dark:text-gray-400">
                {playerHand.length} cards in hand
              </div>
              <div className="space-x-2">
                <Button 
                  variant="outline" 
                  onClick={() => setShowHandViewer(false)}
                  className="border-gray-300 dark:border-gray-600"
                  data-testid="button-close-hand-viewer"
                >
                  Close
                </Button>
                <Button 
                  variant="outline"
                  className="border-gray-300 dark:border-gray-600"
                  data-testid="button-organize-hand-large"
                >
                  <Eye className="w-4 h-4 mr-1" />
                  Sort by Value
                </Button>
                <Button 
                  variant="outline"
                  className="border-gray-300 dark:border-gray-600"
                  data-testid="button-draw-card-large"
                >
                  <Hand className="w-4 h-4 mr-1" />
                  Draw from Deck
                </Button>
              </div>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}