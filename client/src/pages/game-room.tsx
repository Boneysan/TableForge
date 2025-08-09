import { useParams } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useWebSocket } from "@/hooks/useWebSocket";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/useAuth";
import { AdminInterface } from "@/components/AdminInterface";
import { PlayerInterface } from "@/components/PlayerInterface";
import { authenticatedApiRequest } from "@/lib/authClient";
import type { GameRoom, GameAsset, BoardAsset, RoomPlayer, User } from "@shared/schema";

export default function GameRoom() {
  const { roomId } = useParams<{ roomId: string }>();
  const { toast } = useToast();
  const { user } = useAuth();
  const [userRole, setUserRole] = useState<'admin' | 'player' | null>(null);
  const currentPlayer = { id: (user as User)?.id || "unknown", name: (user as User)?.firstName || (user as User)?.email || "Player" };

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

  const { data: roomPlayers = [] } = useQuery<RoomPlayer[]>({
    queryKey: ["/api/rooms", roomId, "players"],
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
        } catch (error) {
          console.error("Error joining room or getting role:", error);
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
    sendMessage({
      type: 'asset_moved',
      roomId,
      payload: { assetId, positionX: x, positionY: y }
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
    <div className="min-h-screen bg-[#1F2937] text-gray-100">

      <div className="container mx-auto px-4 py-6">
        {userRole === 'admin' ? (
          <AdminInterface
            room={room}
            roomAssets={assets}
            roomPlayers={roomPlayers}
            onAssetUploaded={handleAssetUploaded}
          />
        ) : (
          <PlayerInterface
            room={room}
            roomAssets={assets}
            boardAssets={boardAssets}
            roomPlayers={roomPlayers}
            currentPlayer={currentPlayer}
            onAssetMove={handleAssetMoved}
            onAssetPlace={handleAssetPlaced}
            onDiceRoll={(type: string, count: number) => {
              const results = Array.from({ length: count }, () => Math.floor(Math.random() * parseInt(type.substring(1))) + 1);
              const total = results.reduce((sum, roll) => sum + roll, 0);
              handleDiceRolled(type, count, results, total);
            }}
            connected={connected}
          />
        )}
      </div>
    </div>
  );
}
