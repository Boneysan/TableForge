import { useState } from 'react';
import { Dice1, Dice2, Dice3, Dice4, Dice5, Dice6, Plus, Minus, RotateCcw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import type { DiceRoll } from '@shared/schema';

interface DiceRollerProps {
  onDiceRolled: (diceType: string, diceCount: number, results: number[], total: number) => void;
  diceRolls: DiceRoll[];
}

interface DiceSelection {
  type: string;
  sides: number;
  count: number;
  icon: string;
}

export function DiceRoller({ onDiceRolled, diceRolls }: DiceRollerProps) {
  const [customCount, setCustomCount] = useState(1);
  const [customSides, setCustomSides] = useState(6);
  const [isRolling, setIsRolling] = useState(false);
  const [selectedDice, setSelectedDice] = useState<DiceSelection[]>([]);

  const diceTypes = [
    { type: 'd4', sides: 4, icon: '🔺' },
    { type: 'd6', sides: 6, icon: '🎲' },
    { type: 'd8', sides: 8, icon: '🔶' },
    { type: 'd10', sides: 10, icon: '🔹' },
    { type: 'd12', sides: 12, icon: '🔸' },
    { type: 'd20', sides: 20, icon: '🎯' },
  ];

  const rollDice = async (sides: number, count = 1, diceType: string) => {
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

  const addDiceToSelection = (dice: { type: string; sides: number; icon: string }) => {
    const existing = selectedDice.find(d => d.type === dice.type);
    if (existing) {
      setSelectedDice(prev =>
        prev.map(d => d.type === dice.type ? { ...d, count: d.count + 1 } : d),
      );
    } else {
      setSelectedDice(prev => [...prev, { ...dice, count: 1 }]);
    }
  };

  const removeDiceFromSelection = (diceType: string) => {
    setSelectedDice(prev => {
      const existing = prev.find(d => d.type === diceType);
      if (existing && existing.count > 1) {
        return prev.map(d => d.type === diceType ? { ...d, count: d.count - 1 } : d);
      } else {
        return prev.filter(d => d.type !== diceType);
      }
    });
  };

  const clearSelection = () => {
    setSelectedDice([]);
  };

  const rollSelectedDice = async () => {
    if (selectedDice.length === 0) return;

    setIsRolling(true);

    // Simulate rolling animation delay
    await new Promise(resolve => setTimeout(resolve, 500));

    // Roll each type of dice
    const allResults: number[] = [];
    const rollDetails: string[] = [];

    for (const dice of selectedDice) {
      const results: number[] = [];
      for (let i = 0; i < dice.count; i++) {
        results.push(Math.floor(Math.random() * dice.sides) + 1);
      }
      allResults.push(...results);

      const diceTotal = results.reduce((sum, result) => sum + result, 0);
      rollDetails.push(`${dice.count}${dice.type}=${diceTotal}${dice.count > 1 ? `(${results.join(',')})` : ''}`);
    }

    const grandTotal = allResults.reduce((sum, result) => sum + result, 0);
    const combinedType = rollDetails.join(' + ');

    onDiceRolled(combinedType, allResults.length, allResults, grandTotal);
    setIsRolling(false);
  };

  const handleStandardDiceRoll = (diceType: string, sides: number) => {
    rollDice(sides, 1, diceType);
  };

  const handleCustomDiceRoll = () => {
    if (customCount < 1 || customCount > 10) {
      alert('Dice count must be between 1 and 10');
      return;
    }
    if (customSides < 2 || customSides > 100) {
      alert('Dice sides must be between 2 and 100');
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

      {/* Quick Roll - Standard Dice */}
      <div className="mb-4">
        <h4 className="text-sm font-medium text-gray-300 mb-2">Quick Roll</h4>
        <div className="grid grid-cols-3 gap-2">
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
      </div>

      {/* Multiple Dice Selection */}
      <div className="mb-4">
        <div className="flex items-center justify-between mb-2">
          <h4 className="text-sm font-medium text-gray-300">Multi-Dice Roll</h4>
          {selectedDice.length > 0 && (
            <Button
              variant="ghost"
              size="sm"
              onClick={clearSelection}
              className="text-gray-400 hover:text-gray-200 p-1"
              data-testid="button-clear-selection"
            >
              <RotateCcw className="w-3 h-3 mr-1" />
              Clear
            </Button>
          )}
        </div>

        {/* Add dice to selection */}
        <div className="grid grid-cols-3 gap-2 mb-3">
          {diceTypes.map((dice) => (
            <Button
              key={`add-${dice.type}`}
              variant="outline"
              size="sm"
              onClick={() => addDiceToSelection(dice)}
              disabled={isRolling}
              className="bg-[#374151] border-gray-600 text-gray-300 hover:bg-[#10B981] text-center py-2 px-1 flex items-center justify-center"
              data-testid={`button-add-${dice.type}`}
            >
              <Plus className="w-3 h-3 mr-1" />
              <span className="text-xs">{dice.type}</span>
            </Button>
          ))}
        </div>

        {/* Selected dice display */}
        {selectedDice.length > 0 && (
          <div className="bg-[#1F2937] p-3 rounded-lg mb-3">
            <div className="text-xs text-gray-400 mb-2">Selected Dice:</div>
            <div className="flex flex-wrap gap-1 mb-3">
              {selectedDice.map((dice) => (
                <div key={dice.type} className="flex items-center">
                  <Badge
                    variant="secondary"
                    className="bg-[#10B981] text-white text-xs px-2 py-1 flex items-center gap-1"
                    data-testid={`badge-selected-${dice.type}`}
                  >
                    {dice.count}{dice.type}
                    <button
                      onClick={() => removeDiceFromSelection(dice.type)}
                      className="ml-1 hover:text-red-300"
                      data-testid={`button-remove-${dice.type}`}
                    >
                      <Minus className="w-3 h-3" />
                    </button>
                  </Badge>
                </div>
              ))}
            </div>
            <Button
              onClick={rollSelectedDice}
              disabled={isRolling || selectedDice.length === 0}
              className="w-full bg-[#10B981] hover:bg-green-600 text-white"
              data-testid="button-roll-selected"
            >
              {isRolling ? 'Rolling...' : `Roll All (${selectedDice.reduce((sum, d) => sum + d.count, 0)} dice)`}
            </Button>
          </div>
        )}
      </div>

      {/* Custom Dice Roll */}
      <div className="mb-4">
        <h4 className="text-sm font-medium text-gray-300 mb-2">Custom Dice</h4>
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
          {isRolling ? 'Rolling...' : 'Roll'}
          </Button>
        </div>
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
