import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dice1, Plus, Users, Clock } from "lucide-react";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { GameRoom } from "@shared/schema";

export default function Home() {
  const [, setLocation] = useLocation();
  const [roomName, setRoomName] = useState("");
  const [joinRoomId, setJoinRoomId] = useState("");
  const { toast } = useToast();

  // Mock user ID - in a real app this would come from authentication
  const userId = "mock-user-id";

  const { data: userRooms, isLoading } = useQuery({
    queryKey: ["/api/user", userId, "rooms"],
    enabled: !!userId,
  });

  const createRoomMutation = useMutation({
    mutationFn: async (data: { name: string; userId: string }) => {
      const response = await apiRequest("POST", "/api/rooms", data);
      return response.json();
    },
    onSuccess: (room: GameRoom) => {
      queryClient.invalidateQueries({ queryKey: ["/api/user", userId, "rooms"] });
      setLocation(`/room/${room.id}`);
      toast({
        title: "Room Created",
        description: `Successfully created room "${room.name}"`,
      });
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to create room. Please try again.",
        variant: "destructive",
      });
    },
  });

  const handleCreateRoom = () => {
    if (!roomName.trim()) {
      toast({
        title: "Error",
        description: "Please enter a room name",
        variant: "destructive",
      });
      return;
    }
    createRoomMutation.mutate({ name: roomName, userId });
  };

  const handleJoinRoom = () => {
    if (!joinRoomId.trim()) {
      toast({
        title: "Error",
        description: "Please enter a room ID",
        variant: "destructive",
      });
      return;
    }
    setLocation(`/room/${joinRoomId}`);
  };

  return (
    <div className="min-h-screen bg-[#1F2937] text-gray-100">
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="flex items-center justify-center space-x-3 mb-4">
            <Dice1 className="text-[#2563EB] text-4xl" />
            <h1 className="text-4xl font-bold">Virtual Tabletop</h1>
          </div>
          <p className="text-gray-300 text-lg">
            Create or join a virtual tabletop for board games with real-time multiplayer support
          </p>
        </div>

        <div className="grid md:grid-cols-2 gap-8 max-w-4xl mx-auto">
          {/* Create Room */}
          <Card className="bg-[#374151] border-gray-600">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2 text-gray-100">
                <Plus className="w-5 h-5 text-[#2563EB]" />
                <span>Create New Room</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label htmlFor="room-name" className="text-gray-300">Room Name</Label>
                <Input
                  id="room-name"
                  type="text"
                  placeholder="Enter room name..."
                  value={roomName}
                  onChange={(e) => setRoomName(e.target.value)}
                  className="bg-[#4B5563] border-gray-600 text-gray-100 placeholder-gray-400"
                  data-testid="input-room-name"
                />
              </div>
              <Button
                onClick={handleCreateRoom}
                disabled={createRoomMutation.isPending}
                className="w-full bg-[#2563EB] hover:bg-blue-700"
                data-testid="button-create-room"
              >
                {createRoomMutation.isPending ? "Creating..." : "Create Room"}
              </Button>
            </CardContent>
          </Card>

          {/* Join Room */}
          <Card className="bg-[#374151] border-gray-600">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2 text-gray-100">
                <Users className="w-5 h-5 text-[#10B981]" />
                <span>Join Existing Room</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label htmlFor="room-id" className="text-gray-300">Room ID</Label>
                <Input
                  id="room-id"
                  type="text"
                  placeholder="Enter room ID..."
                  value={joinRoomId}
                  onChange={(e) => setJoinRoomId(e.target.value)}
                  className="bg-[#4B5563] border-gray-600 text-gray-100 placeholder-gray-400"
                  data-testid="input-room-id"
                />
              </div>
              <Button
                onClick={handleJoinRoom}
                className="w-full bg-[#10B981] hover:bg-green-700"
                data-testid="button-join-room"
              >
                Join Room
              </Button>
            </CardContent>
          </Card>
        </div>

        {/* User's Rooms */}
        {userRooms && userRooms.length > 0 && (
          <div className="mt-12 max-w-4xl mx-auto">
            <h2 className="text-2xl font-bold mb-6 flex items-center space-x-2">
              <Clock className="w-6 h-6 text-[#F59E0B]" />
              <span>Your Recent Rooms</span>
            </h2>
            <div className="grid gap-4">
              {userRooms.map((room: GameRoom) => (
                <Card
                  key={room.id}
                  className="bg-[#374151] border-gray-600 hover:bg-[#4B5563] transition-colors cursor-pointer"
                  onClick={() => setLocation(`/room/${room.id}`)}
                  data-testid={`card-room-${room.id}`}
                >
                  <CardContent className="flex items-center justify-between p-4">
                    <div>
                      <h3 className="font-semibold text-gray-100">{room.name}</h3>
                      <p className="text-sm text-gray-400">
                        Created {new Date(room.createdAt).toLocaleDateString()}
                      </p>
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      className="border-gray-600 text-gray-300 hover:bg-[#4B5563]"
                      data-testid={`button-enter-room-${room.id}`}
                    >
                      Enter Room
                    </Button>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        )}

        {isLoading && (
          <div className="text-center mt-8">
            <div className="text-gray-400">Loading your rooms...</div>
          </div>
        )}
      </div>
    </div>
  );
}
