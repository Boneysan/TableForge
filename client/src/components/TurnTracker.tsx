import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { 
  Clock, 
  Users, 
  SkipForward, 
  RotateCcw, 
  Play, 
  Pause, 
  Square,
  Timer
} from "lucide-react";

interface Player {
  id: string;
  name: string;
  isActive?: boolean;
}

interface TurnTrackerProps {
  players: Player[];
  currentTurnIndex: number;
  roundNumber: number;
  isTimerActive: boolean;
  timeRemaining: number;
  turnDuration: number;
  onNextTurn: () => void;
  onPreviousTurn: () => void;
  onSetTimer: (seconds: number) => void;
  onStartTimer: () => void;
  onPauseTimer: () => void;
  onStopTimer: () => void;
  playerRole: 'admin' | 'player';
}

export function TurnTracker({
  players,
  currentTurnIndex,
  roundNumber,
  isTimerActive,
  timeRemaining,
  turnDuration,
  onNextTurn,
  onPreviousTurn,
  onSetTimer,
  onStartTimer,
  onPauseTimer,
  onStopTimer,
  playerRole
}: TurnTrackerProps) {
  const [customTime, setCustomTime] = useState(turnDuration);
  const [showTimeInput, setShowTimeInput] = useState(false);

  const currentPlayer = players[currentTurnIndex];
  
  const formatTime = (seconds: number): string => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  const getTimeColor = () => {
    if (timeRemaining <= 10) return "text-red-500";
    if (timeRemaining <= 30) return "text-yellow-500";
    return "text-green-500";
  };

  const handleSetCustomTime = () => {
    onSetTimer(customTime);
    setShowTimeInput(false);
  };

  return (
    <Card className="w-full">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm flex items-center gap-2">
          <Users className="w-4 h-4" />
          Turn Tracker
          <Badge variant="outline" className="ml-auto">
            Round {roundNumber}
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Current Player */}
        <div className="text-center p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
          <div className="text-xs text-gray-500 dark:text-gray-400 mb-1">
            Current Turn
          </div>
          <div className="font-semibold text-lg">
            {currentPlayer?.name || "No players"}
          </div>
          <div className="text-xs text-gray-500">
            Player {currentTurnIndex + 1} of {players.length}
          </div>
        </div>

        {/* Timer Section */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Timer className="w-4 h-4" />
              <span className="text-sm font-medium">Timer</span>
            </div>
            <div className={`text-lg font-mono font-bold ${getTimeColor()}`}>
              {formatTime(timeRemaining)}
            </div>
          </div>

          {/* Timer Controls - Admin Only */}
          {playerRole === 'admin' && (
            <div className="flex gap-2">
              <Button
                size="sm"
                variant="outline"
                onClick={isTimerActive ? onPauseTimer : onStartTimer}
                className="flex-1"
                data-testid="button-timer-toggle"
              >
                {isTimerActive ? (
                  <>
                    <Pause className="w-3 h-3 mr-1" />
                    Pause
                  </>
                ) : (
                  <>
                    <Play className="w-3 h-3 mr-1" />
                    Start
                  </>
                )}
              </Button>
              
              <Button
                size="sm"
                variant="outline"
                onClick={onStopTimer}
                data-testid="button-timer-stop"
              >
                <Square className="w-3 h-3" />
              </Button>
              
              <Button
                size="sm"
                variant="outline"
                onClick={() => setShowTimeInput(!showTimeInput)}
                data-testid="button-timer-settings"
              >
                <Clock className="w-3 h-3" />
              </Button>
            </div>
          )}

          {/* Time Input */}
          {showTimeInput && playerRole === 'admin' && (
            <div className="space-y-2 p-2 border rounded">
              <Label htmlFor="custom-time" className="text-xs">
                Turn Duration (seconds)
              </Label>
              <div className="flex gap-2">
                <Input
                  id="custom-time"
                  type="number"
                  min="10"
                  max="3600"
                  value={customTime}
                  onChange={(e) => setCustomTime(parseInt(e.target.value) || 60)}
                  className="h-8"
                  data-testid="input-turn-duration"
                />
                <Button
                  size="sm"
                  onClick={handleSetCustomTime}
                  data-testid="button-set-timer"
                >
                  Set
                </Button>
              </div>
            </div>
          )}
        </div>

        {/* Turn Controls - Admin Only */}
        {playerRole === 'admin' && (
          <div className="space-y-2">
            <div className="flex gap-2">
              <Button
                size="sm"
                variant="outline"
                onClick={onPreviousTurn}
                className="flex-1"
                disabled={players.length === 0}
                data-testid="button-previous-turn"
              >
                <RotateCcw className="w-3 h-3 mr-1" />
                Previous
              </Button>
              
              <Button
                size="sm"
                onClick={onNextTurn}
                className="flex-1"
                disabled={players.length === 0}
                data-testid="button-next-turn"
              >
                <SkipForward className="w-3 h-3 mr-1" />
                Next Turn
              </Button>
            </div>
          </div>
        )}

        {/* Player List */}
        <div className="space-y-1">
          <div className="text-xs text-gray-500 dark:text-gray-400 mb-2">
            Turn Order
          </div>
          {players.length === 0 ? (
            <div className="text-center text-gray-500 text-sm py-4">
              No players in turn order
            </div>
          ) : (
            players.map((player, index) => (
              <div
                key={player.id}
                className={`flex items-center justify-between p-2 rounded text-sm ${
                  index === currentTurnIndex
                    ? 'bg-blue-100 dark:bg-blue-900/30 border-l-4 border-blue-500'
                    : 'bg-gray-50 dark:bg-gray-800/50'
                }`}
                data-testid={`turn-order-player-${index}`}
              >
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 rounded-full bg-gray-300 dark:bg-gray-600 flex items-center justify-center text-xs font-bold">
                    {index + 1}
                  </div>
                  <span className={index === currentTurnIndex ? 'font-semibold' : ''}>
                    {player.name}
                  </span>
                </div>
                
                {index === currentTurnIndex && (
                  <Badge variant="default" className="text-xs">
                    Active
                  </Badge>
                )}
              </div>
            ))
          )}
        </div>

        {/* Game State Info */}
        <div className="pt-2 border-t text-xs text-gray-500 dark:text-gray-400">
          <div className="flex justify-between">
            <span>Round: {roundNumber}</span>
            <span>Players: {players.length}</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}