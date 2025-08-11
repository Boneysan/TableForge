import { useState } from 'react';
import { Book, ExternalLink, ChevronDown, ChevronRight } from 'lucide-react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { ScrollArea } from '@/components/ui/scroll-area';
import type { GameRoom } from '@shared/schema';

interface GameRulesViewerProps {
  room: GameRoom;
  trigger?: React.ReactNode;
}

interface GameSystemInfo {
  name?: string;
  description?: string;
  rules?: {
    quickStart?: string;
    fullRules?: string;
    sections?: {
      title: string;
      content: string;
    }[];
  };
  playerCount?: {
    min: number;
    max: number;
  };
  playTime?: string;
  difficulty?: string;
  tags?: string[];
}

export function GameRulesViewer({ room, trigger }: GameRulesViewerProps) {
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set());

  // Extract game system info from room's gameState
  const gameSystemInfo: GameSystemInfo = room.gameState as GameSystemInfo || {};

  const toggleSection = (sectionTitle: string) => {
    const newExpanded = new Set(expandedSections);
    if (newExpanded.has(sectionTitle)) {
      newExpanded.delete(sectionTitle);
    } else {
      newExpanded.add(sectionTitle);
    }
    setExpandedSections(newExpanded);
  };

  const hasRules = gameSystemInfo.rules || gameSystemInfo.description;

  return (
    <Dialog>
      <DialogTrigger asChild>
        {trigger || (
          <Button variant="outline" size="sm" className="gap-2" data-testid="button-view-rules">
            <Book className="w-4 h-4" />
            Game Rules
          </Button>
        )}
      </DialogTrigger>
      <DialogContent className="max-w-4xl max-h-[80vh]" data-testid="game-rules-dialog">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Book className="w-5 h-5" />
            Game Rules - {gameSystemInfo.name || room.name}
          </DialogTitle>
        </DialogHeader>

        <ScrollArea className="max-h-[70vh] pr-4">
          {!hasRules ? (
            <div className="text-center py-8 text-muted-foreground">
              <Book className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p className="text-lg font-medium mb-2">No Rules Available</p>
              <p>The game master hasn't set up rules for this game yet.</p>
            </div>
          ) : (
            <div className="space-y-6">
              {/* Game Info Section */}
              {(gameSystemInfo.playerCount || gameSystemInfo.playTime || gameSystemInfo.difficulty || gameSystemInfo.tags) && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-lg">Game Information</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      {gameSystemInfo.playerCount && (
                        <div>
                          <p className="text-sm font-medium text-muted-foreground">Players</p>
                          <p className="text-lg">{gameSystemInfo.playerCount.min}-{gameSystemInfo.playerCount.max}</p>
                        </div>
                      )}
                      {gameSystemInfo.playTime && (
                        <div>
                          <p className="text-sm font-medium text-muted-foreground">Play Time</p>
                          <p className="text-lg">{gameSystemInfo.playTime}</p>
                        </div>
                      )}
                      {gameSystemInfo.difficulty && (
                        <div>
                          <p className="text-sm font-medium text-muted-foreground">Difficulty</p>
                          <p className="text-lg">{gameSystemInfo.difficulty}</p>
                        </div>
                      )}
                    </div>
                    {gameSystemInfo.tags && gameSystemInfo.tags.length > 0 && (
                      <div>
                        <p className="text-sm font-medium text-muted-foreground mb-2">Categories</p>
                        <div className="flex flex-wrap gap-2">
                          {gameSystemInfo.tags.map((tag, index) => (
                            <Badge key={index} variant="secondary">{tag}</Badge>
                          ))}
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>
              )}

              {/* Description Section */}
              {gameSystemInfo.description && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-lg">Game Overview</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-muted-foreground leading-relaxed whitespace-pre-wrap">
                      {gameSystemInfo.description}
                    </p>
                  </CardContent>
                </Card>
              )}

              {/* Quick Start Rules */}
              {gameSystemInfo.rules?.quickStart && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-lg">Quick Start Guide</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="prose prose-sm max-w-none dark:prose-invert">
                      <div className="whitespace-pre-wrap text-muted-foreground leading-relaxed">
                        {gameSystemInfo.rules.quickStart}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Rule Sections */}
              {gameSystemInfo.rules?.sections && gameSystemInfo.rules.sections.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-lg">Detailed Rules</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    {gameSystemInfo.rules.sections.map((section, index) => (
                      <Collapsible
                        key={index}
                        open={expandedSections.has(section.title)}
                        onOpenChange={() => toggleSection(section.title)}
                      >
                        <CollapsibleTrigger asChild>
                          <Button
                            variant="ghost"
                            className="w-full justify-between p-3 h-auto"
                            data-testid={`button-expand-${section.title.toLowerCase().replace(/\s+/g, '-')}`}
                          >
                            <span className="font-medium text-left">{section.title}</span>
                            {expandedSections.has(section.title) ? (
                              <ChevronDown className="w-4 h-4" />
                            ) : (
                              <ChevronRight className="w-4 h-4" />
                            )}
                          </Button>
                        </CollapsibleTrigger>
                        <CollapsibleContent className="px-3 pb-3">
                          <div className="prose prose-sm max-w-none dark:prose-invert">
                            <div className="whitespace-pre-wrap text-muted-foreground leading-relaxed">
                              {section.content}
                            </div>
                          </div>
                        </CollapsibleContent>
                      </Collapsible>
                    ))}
                  </CardContent>
                </Card>
              )}

              {/* Full Rules */}
              {gameSystemInfo.rules?.fullRules && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-lg">Complete Rules</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="prose prose-sm max-w-none dark:prose-invert">
                      <div className="whitespace-pre-wrap text-muted-foreground leading-relaxed">
                        {gameSystemInfo.rules.fullRules}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          )}
        </ScrollArea>
      </DialogContent>
    </Dialog>
  );
}
