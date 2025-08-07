import { useState } from "react";
import { Dice1, Dice2, Dice3, Dice4, Dice5, Dice6 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { DiceRoll } from "@shared/schema";

interface DiceRollerProps {
  onDiceRolled: (diceType: string, diceCount: number, results: number[], total: number) => void;
  diceRolls: DiceRoll[];
}

export function DiceRoller({ onDiceRolled, diceRolls }: DiceRollerProps) {
  const [customCount, setCustomCount] = useState(1);
  const [customSides, setCustomSides] = useState(6);
  const [isRolling, setIsRolling] = useState(false);

  const diceTypes = [
    { type: "d4", sides: 4, icon: "🔺" },
    { type: "d6", sides: 6, icon: "🎲" },
    { type: "d8", sides: 8, icon: "🔶" },
    { type: "d10", sides: 10, icon: "🔹" },
    { type: "d12", sides: 12, icon: "🔸" },
    { type: "d20", sides: 20, icon: "🎯" },
  ];

  const rollDice = async (sides: number, count: number = 1, diceType: string) => {
    setIsRolling(true);
    
    // Simulate rolling animation delay
    await new Promise(resolve => setTimeout(resolve, 500));
    
    const results: number[] = [];
    for (let i = 0; i < count; i++) {
      results.push(Math.floor(Math.random() * sides) + 1);
    }
    
    const total = results.reduce((sum, result) => sum + result, 0);
    onDiceRolled(diceType, count, results, total);
    setIsRolling(false);
  };

  const handleStandardDiceRoll = (diceType: string, sides: number) => {
    rollDice(sides, 1, diceType);
  };

  const handleCustomDiceRoll = () => {
    if (customCount < 1 || customCount > 10) {
      alert("Dice count must be between 1 and 10");
      return;
    }
    if (customSides < 2 || customSides > 100) {
      alert("Dice sides must be between 2 and 100");
      return;
    }
    rollDice(customSides, customCount, `d${customSides}`);
  };

  return (
    <div className="p-4 border-b border-gray-600">
      <h3 className="text-lg font-semibold mb-3 flex items-center">
        <Dice1 className="mr-2 text-[#F59E0B]" />
        Dice Roller
      </h3>
      
      {/* Standard Dice */}
      <div className="grid grid-cols-3 gap-2 mb-4">
        {diceTypes.map((dice) => (
          <Button
            key={dice.type}
            variant="outline"
            size="sm"
            onClick={() => handleStandardDiceRoll(dice.type, dice.sides)}
            disabled={isRolling}
            className="bg-[#4B5563] border-gray-600 text-gray-300 hover:bg-[#2563EB] text-center py-2 px-1 flex flex-col items-center"
            data-testid={`button-dice-${dice.type}`}
          >
            <span className="text-lg mb-1">{dice.icon}</span>
            <span className="text-xs">{dice.type}</span>
          </Button>
        ))}
      </div>
      
      {/* Custom Dice Roll */}
      <div className="flex space-x-2 mb-3">
        <Input
          type="number"
          placeholder="Count"
          min="1"
          max="10"
          value={customCount}
          onChange={(e) => setCustomCount(parseInt(e.target.value) || 1)}
          className="w-16 bg-[#4B5563] border-gray-600 text-gray-100 text-center"
          data-testid="input-custom-dice-count"
        />
        <span className="self-center text-gray-400">d</span>
        <Input
          type="number"
          placeholder="Sides"
          min="2"
          max="100"
          value={customSides}
          onChange={(e) => setCustomSides(parseInt(e.target.value) || 6)}
          className="w-16 bg-[#4B5563] border-gray-600 text-gray-100 text-center"
          data-testid="input-custom-dice-sides"
        />
        <Button
          onClick={handleCustomDiceRoll}
          disabled={isRolling}
          className="flex-1 bg-[#2563EB] hover:bg-blue-700 text-sm"
          data-testid="button-roll-custom"
        >
          {isRolling ? "Rolling..." : "Roll"}
        </Button>
      </div>
      
      {/* Dice Results */}
      <div className="bg-[#1F2937] p-3 rounded-lg">
        <div className="text-sm text-gray-400 mb-2">Recent Rolls:</div>
        <div className="space-y-1 max-h-20 overflow-y-auto">
          {diceRolls.length === 0 ? (
            <div className="text-sm text-gray-500 italic">No rolls yet</div>
          ) : (
            diceRolls.slice(0, 5).map((roll) => (
              <div key={roll.id} className="text-sm flex justify-between" data-testid={`dice-result-${roll.id}`}>
                <span className="text-gray-300">Player:</span>
                <span className="text-[#10B981] font-medium">
                  {roll.diceCount > 1 ? `${roll.diceCount}${roll.diceType}` : roll.diceType} = {roll.total}
                  {roll.diceCount > 1 && ` (${(roll.results as number[]).join(',')})`}
                </span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
