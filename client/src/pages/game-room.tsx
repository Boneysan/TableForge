import { useParams } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Dice1, Users, Upload } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { GameBoard } from "@/components/GameBoard";
import { AssetLibrary } from "@/components/AssetLibrary";
import { GameControls } from "@/components/GameControls";
import { useWebSocket } from "@/hooks/useWebSocket";
import { useToast } from "@/hooks/use-toast";
import type { GameRoom, GameAsset, BoardAsset, RoomPlayer } from "@shared/schema";

export default function GameRoom() {
  const { roomId } = useParams<{ roomId: string }>();
  const { toast } = useToast();
  const [currentPlayer] = useState({ id: "mock-player-id", name: "Player 1" });

  // Fetch room data
  const { data: room, isLoading: roomLoading } = useQuery({
    queryKey: ["/api/rooms", roomId],
    enabled: !!roomId,
  });

  const { data: assets = [], refetch: refetchAssets } = useQuery({
    queryKey: ["/api/rooms", roomId, "assets"],
    enabled: !!roomId,
  });

  const { data: boardAssets = [], refetch: refetchBoardAssets } = useQuery({
    queryKey: ["/api/rooms", roomId, "board-assets"],
    enabled: !!roomId,
  });

  // WebSocket for real-time updates
  const { sendMessage, connected } = useWebSocket({
    onMessage: (message) => {
      switch (message.type) {
        case 'asset_moved':
          refetchBoardAssets();
          break;
        case 'asset_flipped':
          refetchBoardAssets();
          break;
        case 'dice_rolled':
          toast({
            title: "Dice Rolled",
            description: `${message.payload.diceCount}d${message.payload.diceType.substring(1)} = ${message.payload.total}`,
          });
          break;
        case 'player_joined':
          toast({
            title: "Player Joined",
            description: `${message.payload.player.name} joined the room`,
          });
          break;
        case 'player_left':
          toast({
            title: "Player Left",
            description: "A player left the room",
          });
          break;
      }
    }
  });

  // Join room on connection
  useEffect(() => {
    if (connected && roomId) {
      sendMessage({
        type: 'join_room',
        roomId,
        payload: { player: currentPlayer }
      });
    }
  }, [connected, roomId, sendMessage, currentPlayer]);

  const handleAssetUploaded = () => {
    refetchAssets();
    toast({
      title: "Asset Uploaded",
      description: "Your asset has been uploaded successfully",
    });
  };

  const handleAssetPlaced = (assetId: string, x: number, y: number) => {
    // The GameBoard component will handle the API call and WebSocket message
  };

  const handleAssetMoved = (assetId: string, x: number, y: number) => {
    sendMessage({
      type: 'asset_moved',
      roomId,
      payload: { assetId, positionX: x, positionY: y }
    });
  };

  const handleAssetFlipped = (assetId: string, isFlipped: boolean) => {
    sendMessage({
      type: 'asset_flipped',
      roomId,
      payload: { assetId, isFlipped }
    });
  };

  const handleDiceRolled = (diceType: string, diceCount: number, results: number[], total: number) => {
    sendMessage({
      type: 'dice_rolled',
      roomId,
      payload: {
        playerId: currentPlayer.id,
        diceType,
        diceCount,
        results,
        total
      }
    });
  };

  if (roomLoading) {
    return (
      <div className="min-h-screen bg-[#1F2937] text-gray-100 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-[#2563EB] mx-auto mb-4"></div>
          <div>Loading room...</div>
        </div>
      </div>
    );
  }

  if (!room) {
    return (
      <div className="min-h-screen bg-[#1F2937] text-gray-100 flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl font-bold mb-4">Room Not Found</h1>
          <p className="text-gray-400">The room you're looking for doesn't exist.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-screen bg-[#1F2937] text-gray-100 overflow-hidden">
      {/* Header */}
      <header className="bg-[#374151] border-b border-gray-600 px-6 py-3 flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <Dice1 className="text-[#2563EB] text-2xl" />
            <h1 className="text-xl font-bold">Virtual Tabletop</h1>
          </div>
          <div className="text-sm text-gray-300">
            Room: <span className="text-[#10B981] font-medium" data-testid="text-room-name">{room.name}</span>
          </div>
        </div>
        
        <div className="flex items-center space-x-4">
          {/* Connection Status */}
          <Badge 
            variant={connected ? "default" : "destructive"}
            className={connected ? "bg-[#10B981]" : ""}
            data-testid="badge-connection-status"
          >
            {connected ? "Connected" : "Disconnected"}
          </Badge>

          {/* Mock players */}
          <div className="flex items-center space-x-3">
            <Badge className="bg-[#4B5563] text-gray-100" data-testid="badge-player-1">
              <div className="w-2 h-2 bg-[#10B981] rounded-full mr-1"></div>
              {currentPlayer.name}
            </Badge>
          </div>
          
          <Button 
            variant="outline" 
            size="sm"
            className="border-gray-600 text-gray-300 hover:bg-[#4B5563]"
            data-testid="button-invite-players"
          >
            <Users className="w-4 h-4 mr-2" />
            Invite Players
          </Button>
        </div>
      </header>

      <div className="flex h-[calc(100vh-64px)]">
        {/* Asset Library */}
        <AssetLibrary
          roomId={roomId!}
          assets={assets}
          onAssetUploaded={handleAssetUploaded}
        />

        {/* Game Board */}
        <GameBoard
          roomId={roomId!}
          assets={assets}
          boardAssets={boardAssets}
          onAssetPlaced={handleAssetPlaced}
          onAssetMoved={handleAssetMoved}
          onAssetFlipped={handleAssetFlipped}
        />

        {/* Game Controls */}
        <GameControls
          roomId={roomId!}
          onDiceRolled={handleDiceRolled}
        />
      </div>
    </div>
  );
}
