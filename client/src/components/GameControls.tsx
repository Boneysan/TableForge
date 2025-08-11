import { useState } from 'react';
import { Dice1, Dice2, Dice3, Dice4, Dice5, Dice6 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';

interface GameControlsProps {
  onDiceRolled: (diceType: string, diceCount: number, results: number[], total: number) => void;
  currentPlayer: { id: string; name: string };
  'data-testid'?: string;
}

export function GameControls({
  onDiceRolled,
  currentPlayer,
  'data-testid': testId,
}: GameControlsProps) {
  const [selectedDie, setSelectedDie] = useState<string>('d6');
  const [diceCount, setDiceCount] = useState<number>(1);

  const diceOptions = [
    { value: 'd4', label: 'd4', sides: 4 },
    { value: 'd6', label: 'd6', sides: 6 },
    { value: 'd8', label: 'd8', sides: 8 },
    { value: 'd10', label: 'd10', sides: 10 },
    { value: 'd12', label: 'd12', sides: 12 },
    { value: 'd20', label: 'd20', sides: 20 },
  ];

  const handleRollDice = () => {
    const sides = parseInt(selectedDie.substring(1));
    const results = Array.from({ length: diceCount }, () =>
      Math.floor(Math.random() * sides) + 1,
    );
    const total = results.reduce((sum, roll) => sum + roll, 0);

    onDiceRolled(selectedDie, diceCount, results, total);
  };

  const getDiceIcon = (value: number) => {
    switch (value) {
      case 1: return <Dice1 className="w-4 h-4" />;
      case 2: return <Dice2 className="w-4 h-4" />;
      case 3: return <Dice3 className="w-4 h-4" />;
      case 4: return <Dice4 className="w-4 h-4" />;
      case 5: return <Dice5 className="w-4 h-4" />;
      case 6: return <Dice6 className="w-4 h-4" />;
      default: return <Dice1 className="w-4 h-4" />;
    }
  };

  return (
    <div className="space-y-4" data-testid={testId}>
      {/* Dice Rolling */}
      <div className="space-y-3">
        <div className="space-y-2">
          <label className="text-sm font-medium">Dice Type</label>
          <Select value={selectedDie} onValueChange={setSelectedDie}>
            <SelectTrigger data-testid="select-dice-type">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {diceOptions.map((option) => (
                <SelectItem key={option.value} value={option.value}>
                  {option.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-2">
          <label className="text-sm font-medium">Number of Dice</label>
          <Select
            value={diceCount.toString()}
            onValueChange={(value) => setDiceCount(parseInt(value))}
          >
            <SelectTrigger data-testid="select-dice-count">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {[1, 2, 3, 4, 5, 6].map((num) => (
                <SelectItem key={num} value={num.toString()}>
                  {num}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <Button
          onClick={handleRollDice}
          className="w-full"
          data-testid="button-roll-dice"
        >
          {getDiceIcon(diceCount)}
          <span className="ml-2">Roll {diceCount}{selectedDie}</span>
        </Button>
      </div>

      {/* Player Info */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Current Player</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm font-medium">{currentPlayer.name}</p>
        </CardContent>
      </Card>
    </div>
  );
}
