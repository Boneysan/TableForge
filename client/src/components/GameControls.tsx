import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Zap, Save, FolderOpen, Shuffle, Eye, Hand } from "lucide-react";
import { Button } from "@/components/ui/button";
import { DiceRoller } from "@/components/DiceRoller";
import type { DiceRoll } from "@shared/schema";

interface GameControlsProps {
  roomId: string;
  onDiceRolled: (diceType: string, diceCount: number, results: number[], total: number) => void;
}

export function GameControls({ roomId, onDiceRolled }: GameControlsProps) {
  const [handVisible, setHandVisible] = useState(true);

  // Fetch recent dice rolls
  const { data: diceRolls = [] } = useQuery({
    queryKey: ["/api/rooms", roomId, "dice-rolls"],
    refetchInterval: 5000, // Refresh every 5 seconds
  });

  const handleClearBoard = () => {
    if (confirm("Are you sure you want to clear the board? This action cannot be undone.")) {
      // TODO: Implement clear board functionality
      console.log("Clear board");
    }
  };

  const handleSaveGameState = () => {
    // TODO: Implement save game state
    console.log("Save game state");
  };

  const handleLoadGameState = () => {
    // TODO: Implement load game state
    console.log("Load game state");
  };

  const handleShuffleCards = () => {
    // TODO: Implement shuffle cards functionality
    console.log("Shuffle selected cards");
  };

  const toggleHandVisibility = () => {
    setHandVisible(!handVisible);
  };

  // Mock player hand - in a real app this would come from game state
  const playerHand = [
    { id: "1", name: "Lightning Bolt", type: "Spell" },
    { id: "2", name: "Warrior's Sword", type: "Equipment" },
    { id: "3", name: "Healing Potion", type: "Item" },
  ];

  return (
    <aside className="w-72 bg-[#374151] border-l border-gray-600 flex flex-col" data-testid="game-controls">
      {/* Dice Roller */}
      <DiceRoller onDiceRolled={onDiceRolled} diceRolls={diceRolls} />
      
      {/* Quick Actions */}
      <div className="p-4 border-b border-gray-600">
        <h3 className="text-lg font-semibold mb-3 flex items-center">
          <Zap className="mr-2 text-[#7C3AED]" />
          Quick Actions
        </h3>
        
        <div className="space-y-2">
          <Button
            variant="outline"
            onClick={handleClearBoard}
            className="w-full bg-[#4B5563] border-gray-600 text-gray-300 hover:bg-[#374151] justify-start"
            data-testid="button-clear-board"
          >
            <span className="text-red-400 mr-2">🗑️</span>
            Clear Board
          </Button>
          
          <Button
            variant="outline"
            onClick={handleSaveGameState}
            className="w-full bg-[#4B5563] border-gray-600 text-gray-300 hover:bg-[#374151] justify-start"
            data-testid="button-save-game"
          >
            <Save className="mr-2 text-[#10B981] w-4 h-4" />
            Save Game State
          </Button>
          
          <Button
            variant="outline"
            onClick={handleLoadGameState}
            className="w-full bg-[#4B5563] border-gray-600 text-gray-300 hover:bg-[#374151] justify-start"
            data-testid="button-load-game"
          >
            <FolderOpen className="mr-2 text-[#F59E0B] w-4 h-4" />
            Load Game State
          </Button>
          
          <Button
            variant="outline"
            onClick={handleShuffleCards}
            className="w-full bg-[#4B5563] border-gray-600 text-gray-300 hover:bg-[#374151] justify-start"
            data-testid="button-shuffle-cards"
          >
            <Shuffle className="mr-2 text-[#7C3AED] w-4 h-4" />
            Shuffle Selected Cards
          </Button>
        </div>
      </div>
      
      {/* Player Hand */}
      <div className="flex-1 p-4 overflow-y-auto">
        <h3 className="text-lg font-semibold mb-3 flex items-center justify-between">
          <span className="flex items-center">
            <Hand className="mr-2 text-[#10B981]" />
            Your Hand
          </span>
          <Button
            variant="outline"
            size="sm"
            onClick={toggleHandVisibility}
            className="bg-[#4B5563] border-gray-600 text-gray-300 hover:bg-[#374151]"
            data-testid="button-toggle-hand"
          >
            <Eye className="w-4 h-4" />
          </Button>
        </h3>
        
        {handVisible && (
          <div className="space-y-2">
            {playerHand.length === 0 ? (
              <div className="text-gray-500 text-sm italic text-center py-4">
                No cards in hand
              </div>
            ) : (
              playerHand.map((card) => (
                <div
                  key={card.id}
                  className="bg-[#4B5563] rounded-lg p-2 cursor-pointer hover:bg-[#2563EB] transition-colors"
                  onClick={() => console.log("Play card:", card.name)}
                  data-testid={`card-hand-${card.id}`}
                >
                  <div className="flex items-center space-x-2">
                    <div className="w-6 h-8 bg-gray-600 rounded"></div>
                    <div className="flex-1">
                      <div className="text-sm font-medium text-gray-100">{card.name}</div>
                      <div className="text-xs text-gray-400">{card.type}</div>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </aside>
  );
}
