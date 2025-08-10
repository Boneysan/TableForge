import { useParams } from "wouter";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useWebSocket } from "@/hooks/useWebSocket";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/useAuth";

import { SimplePlayerInterface } from "@/components/SimplePlayerInterface";
import { GameMasterInterface } from "@/components/GameMasterInterface";
import { AdminInterface } from "@/components/AdminInterface";
import { ViewSelector } from "@/components/ViewSelector";
import { ThemeToggle } from "@/components/ThemeToggle";
import { authenticatedApiRequest } from "@/lib/authClient";
import type { GameRoom, GameAsset, BoardAsset, RoomPlayer, RoomPlayerWithName, User } from "@shared/schema";

export default function GameRoom() {
  const { roomId } = useParams<{ roomId: string }>();
  const { toast } = useToast();
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [userRole, setUserRole] = useState<'admin' | 'player' | null>(null);
  const [selectedView, setSelectedView] = useState<'admin' | 'gamemaster' | 'player' | null>(null);
  const currentPlayer = { id: (user as User)?.id || "unknown", name: (user as User)?.firstName || (user as User)?.email || "Player" };
  
  // Check if this is a "join" navigation (from home page join button) - check on component mount
  const [wasJoiningRoom] = useState(() => sessionStorage.getItem('joining-room') === 'true');
  
  // Debug logging
  console.log('wasJoiningRoom:', wasJoiningRoom, 'userRole:', userRole, 'selectedView:', selectedView);

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

  const { data: roomPlayers = [] } = useQuery<RoomPlayerWithName[]>({
    queryKey: ["/api/rooms", roomId, "players"],
    enabled: !!roomId,
  });

  // WebSocket for real-time updates
  const { sendMessage, connected, websocket } = useWebSocket({
    onMessage: (message) => {
      switch (message.type) {
        case 'asset_moved':
          refetchBoardAssets();
          break;
        case 'asset_flipped':
          refetchBoardAssets();
          break;
        case 'dice_rolled':
          console.log('Dice roll received via WebSocket:', message.payload);
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
        case 'player_score_updated':
          // Refetch room players to get updated scores
          queryClient.invalidateQueries({ queryKey: ["/api/rooms", roomId, "players"] });
          toast({
            title: "Score Updated",
            description: `${message.payload.playerName}'s score: ${message.payload.score}`,
          });
          break;
      }
    }
  });

  // Join room and get user role
  useEffect(() => {
    const joinRoomAndGetRole = async () => {
      if (roomId && user) {
        try {
          // Join the room first
          const joinResponse = await authenticatedApiRequest("POST", `/api/rooms/${roomId}/join`);
          const joinData = await joinResponse.json();
          
          // Get user role
          const roleResponse = await authenticatedApiRequest("GET", `/api/rooms/${roomId}/role`);
          const roleData = await roleResponse.json();
          
          setUserRole(roleData.role);
          
          // Clear the joining flag after successfully joining
          sessionStorage.removeItem('joining-room');
        } catch (error) {
          console.error("Error joining room or getting role:", error);
          sessionStorage.removeItem('joining-room');
          toast({
            title: "Error",
            description: "Failed to join room. Please try again.",
            variant: "destructive",
          });
        }
      }
    };

    joinRoomAndGetRole();
  }, [roomId, user, toast]);

  // Join room on WebSocket connection
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
  };

  const handleAssetPlaced = (assetId: string, x: number, y: number) => {
    // The GameBoard component will handle the API call and WebSocket message
  };

  const handleAssetMoved = (assetId: string, x: number, y: number) => {
    // Use the actual room UUID, not the room name/param
    const actualRoomId = (room as GameRoom)?.id || roomId;
    sendMessage({
      type: 'asset_moved',
      roomId: actualRoomId,
      payload: { assetId, positionX: x, positionY: y }
    });
  };

  const handleDiceRolled = (diceType: string, diceCount: number, results: number[], total: number) => {
    // Use the actual room UUID, not the room name/param
    const actualRoomId = (room as GameRoom)?.id || roomId;
    console.log('Sending dice roll:', { diceType, diceCount, results, total, actualRoomId });
    sendMessage({
      type: 'dice_rolled',
      roomId: actualRoomId,
      payload: {
        playerId: currentPlayer.id,
        diceType,
        diceCount,
        results,
        total
      }
    });
  };

  // Wrapper function to match PlayerInterface props
  const handleDiceRoll = (diceType: string, count: number) => {
    // Simple dice roll implementation for PlayerInterface
    const results = Array.from({ length: count }, () => Math.floor(Math.random() * parseInt(diceType.replace('d', ''))) + 1);
    const total = results.reduce((sum, roll) => sum + roll, 0);
    handleDiceRolled(diceType, count, results, total);
  };

  if (roomLoading || userRole === null) {
    return (
      <div className="min-h-screen bg-[#1F2937] text-gray-100 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-[#2563EB] mx-auto mb-4"></div>
          <div>Loading room...</div>
        </div>
      </div>
    );
  }

  // If joining room, force player interface regardless of role
  if (wasJoiningRoom && userRole === 'admin') {
    return (
      <div className="container mx-auto px-4 py-6">
        <div className="mb-4 p-3 bg-green-600 text-white rounded-lg">
          <p>Joined as Player (using Join Room button)</p>
        </div>
        <SimplePlayerInterface
          room={room as GameRoom}
          roomAssets={assets as GameAsset[]}
          boardAssets={boardAssets as BoardAsset[]}
          roomPlayers={roomPlayers}
          currentUser={user as User}
          websocket={websocket}
          onDiceRoll={handleDiceRoll}
          connected={connected}
        />
      </div>
    );
  }

  // Show view selector for admins who haven't chosen a view yet (unless they joined via button)
  if (userRole === 'admin' && selectedView === null && !wasJoiningRoom) {
    return (
      <ViewSelector
        onSelectView={setSelectedView}
        currentUser={user as User}
      />
    );
  }

  // Default player interface for regular players
  if (userRole === 'player' && selectedView === null) {
    return (
      <div className="container mx-auto px-4 py-6">
        <SimplePlayerInterface
          room={room as GameRoom}
          roomAssets={assets as GameAsset[]}
          boardAssets={boardAssets as BoardAsset[]}
          roomPlayers={roomPlayers}
          currentUser={user as User}
          websocket={websocket}
          onDiceRoll={handleDiceRoll}
          connected={connected}
        />
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
    <div className="min-h-screen bg-background text-foreground">
      {/* Global Theme Toggle - Always visible */}
      <div className="absolute top-4 right-4 z-50">
        <ThemeToggle />
      </div>

      {userRole === 'admin' && selectedView === 'admin' && (
        <AdminInterface
          roomId={roomId || ''}
          assets={assets as GameAsset[]}
          boardAssets={boardAssets as BoardAsset[]}
          players={roomPlayers}
          currentUser={user as User}
          onAssetUploaded={refetchAssets}
          onSwitchView={() => setSelectedView('gamemaster')}
        />
      )}

      {userRole === 'admin' && selectedView === 'gamemaster' && (
        <GameMasterInterface
          roomId={roomId || ''}
          assets={assets as GameAsset[]}
          boardAssets={boardAssets as BoardAsset[]}
          players={roomPlayers}
          currentUser={user as User}
          websocket={websocket}
          onAssetUploaded={refetchAssets}
          onAssetPlaced={handleAssetPlaced}
          onAssetMoved={handleAssetMoved}
          onDiceRolled={handleDiceRolled}
          onSwitchView={() => setSelectedView('admin')}
        />
      )}

      {selectedView === 'player' && (
        <div className="container mx-auto px-4 py-6">
          <SimplePlayerInterface
            room={room as GameRoom}
            roomAssets={assets as GameAsset[]}
            boardAssets={boardAssets as BoardAsset[]}
            roomPlayers={roomPlayers}
            currentUser={user as User}
            websocket={websocket}
            onDiceRoll={handleDiceRoll}
            connected={connected}
          />
        </div>
      )}
    </div>
  );
}
