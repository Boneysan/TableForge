import React, { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import {
  Trophy,
  Plus,
  Minus,
  Edit2,
  Check,
  X,
  Crown,
  Medal,
  Award,
  Users,
} from 'lucide-react';
import type { RoomPlayerWithName } from '@shared/schema';

interface PlayerScoreboardProps {
  players: RoomPlayerWithName[];
  currentUserId: string;
  isGameMaster: boolean;
  onScoreUpdate?: (playerId: string, newScore: number) => void;
}

export function PlayerScoreboard({
  players,
  currentUserId,
  isGameMaster,
  onScoreUpdate,
}: PlayerScoreboardProps) {
  const [editingScores, setEditingScores] = useState<Record<string, number>>({});
  const [tempScores, setTempScores] = useState<Record<string, string>>({});

  // Sort players by score (highest first)
  const sortedPlayers = [...players].sort((a, b) => b.score - a.score);

  const handleScoreEdit = (playerId: string, currentScore: number) => {
    setEditingScores(prev => ({ ...prev, [playerId]: currentScore }));
    setTempScores(prev => ({ ...prev, [playerId]: currentScore.toString() }));
  };

  const handleScoreConfirm = (playerId: string) => {
    const newScore = parseInt(tempScores[playerId]) || 0;
    if (onScoreUpdate) {
      onScoreUpdate(playerId, newScore);
    }
    setEditingScores(prev => {
      const newState = { ...prev };
      delete newState[playerId];
      return newState;
    });
    setTempScores(prev => {
      const newState = { ...prev };
      delete newState[playerId];
      return newState;
    });
  };

  const handleScoreCancel = (playerId: string) => {
    setEditingScores(prev => {
      const newState = { ...prev };
      delete newState[playerId];
      return newState;
    });
    setTempScores(prev => {
      const newState = { ...prev };
      delete newState[playerId];
      return newState;
    });
  };

  const handleQuickScoreChange = (playerId: string, delta: number) => {
    const player = players.find(p => p.playerId === playerId);
    if (player && onScoreUpdate) {
      onScoreUpdate(playerId, player.score + delta);
    }
  };

  const getRankIcon = (index: number) => {
    switch (index) {
      case 0:
        return <Crown className="w-5 h-5 text-yellow-500" />;
      case 1:
        return <Medal className="w-5 h-5 text-gray-400" />;
      case 2:
        return <Award className="w-5 h-5 text-amber-600" />;
      default:
        return null;
    }
  };

  const getRankBadgeVariant = (index: number) => {
    switch (index) {
      case 0:
        return 'default';
      case 1:
        return 'secondary';
      case 2:
        return 'outline';
      default:
        return 'outline';
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Trophy className="w-5 h-5" />
          Player Scoreboard
          <Badge variant="outline" className="ml-auto">
            <Users className="w-3 h-3 mr-1" />
            {players.length}
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-2">
          {sortedPlayers.length === 0 ? (
            <div className="text-center py-4 text-muted-foreground">
              No players in this game yet
            </div>
          ) : (
            sortedPlayers.map((player, index) => {
              const isEditing = editingScores.hasOwnProperty(player.playerId);
              const isCurrentUser = player.playerId === currentUserId;

              return (
                <div
                  key={player.playerId}
                  className={`flex items-center justify-between p-3 rounded-lg border transition-colors ${
                    isCurrentUser
                      ? 'bg-primary/5 border-primary/20'
                      : 'bg-muted/30 hover:bg-muted/50'
                  }`}
                  data-testid={`scoreboard-player-${player.playerId}`}
                >
                  <div className="flex items-center space-x-3">
                    <div className="flex items-center space-x-2">
                      {getRankIcon(index)}
                      <Badge variant={getRankBadgeVariant(index)} className="text-xs">
                        #{index + 1}
                      </Badge>
                    </div>

                    <Avatar className="w-8 h-8">
                      <AvatarImage src={''} alt={player.playerName} />
                      <AvatarFallback className="text-xs">
                        {player.playerName.split(' ').map(n => n[0]).join('').toUpperCase()}
                      </AvatarFallback>
                    </Avatar>

                    <div>
                      <p className="font-medium text-sm">
                        {player.playerName}
                        {isCurrentUser && (
                          <Badge variant="outline" className="ml-2 text-xs">You</Badge>
                        )}
                        {player.role === 'admin' && (
                          <Badge variant="default" className="ml-2 text-xs">GM</Badge>
                        )}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {player.isOnline ? 'Online' : 'Offline'}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2">
                    {isEditing ? (
                      <div className="flex items-center space-x-1">
                        <Input
                          type="number"
                          value={tempScores[player.playerId] || ''}
                          onChange={(e) => setTempScores(prev => ({
                            ...prev,
                            [player.playerId]: e.target.value,
                          }))}
                          className="w-16 h-8 text-center"
                          data-testid={`input-score-${player.playerId}`}
                        />
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => handleScoreConfirm(player.playerId)}
                          className="h-8 w-8 p-0"
                          data-testid={`button-confirm-score-${player.playerId}`}
                        >
                          <Check className="w-3 h-3" />
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => handleScoreCancel(player.playerId)}
                          className="h-8 w-8 p-0"
                          data-testid={`button-cancel-score-${player.playerId}`}
                        >
                          <X className="w-3 h-3" />
                        </Button>
                      </div>
                    ) : (
                      <>
                        <div className="text-right">
                          <div className="font-bold text-lg">{player.score}</div>
                          <div className="text-xs text-muted-foreground">points</div>
                        </div>

                        {isGameMaster && (
                          <div className="flex flex-col space-y-1">
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => handleQuickScoreChange(player.playerId, 1)}
                              className="h-6 w-6 p-0"
                              data-testid={`button-increase-score-${player.playerId}`}
                            >
                              <Plus className="w-3 h-3" />
                            </Button>
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => handleQuickScoreChange(player.playerId, -1)}
                              className="h-6 w-6 p-0"
                              data-testid={`button-decrease-score-${player.playerId}`}
                            >
                              <Minus className="w-3 h-3" />
                            </Button>
                          </div>
                        )}

                        {isGameMaster && (
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => handleScoreEdit(player.playerId, player.score)}
                            className="h-8 w-8 p-0"
                            data-testid={`button-edit-score-${player.playerId}`}
                          >
                            <Edit2 className="w-3 h-3" />
                          </Button>
                        )}
                      </>
                    )}
                  </div>
                </div>
              );
            })
          )}
        </div>

        {isGameMaster && players.length > 0 && (
          <div className="mt-4 pt-4 border-t">
            <div className="text-xs text-muted-foreground text-center">
              Game Master: Use +/- buttons for quick adjustments or edit icon for custom scores
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
