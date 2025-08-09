import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { useAuth } from "@/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dice1, Plus, Users, Clock, Trash2, LogOut, User as UserIcon } from "lucide-react";
import { signOutUser } from "@/lib/firebase";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { authenticatedApiRequest } from "@/lib/authClient";
import { useToast } from "@/hooks/use-toast";
import type { GameRoom, User } from "@shared/schema";

export default function Home() {
  const [, setLocation] = useLocation();
  const [roomName, setRoomName] = useState("");
  const [joinRoomInput, setJoinRoomInput] = useState("");
  const { toast } = useToast();
  const { user, isLoading: isAuthLoading } = useAuth();

  const userId = (user as User)?.id;

  if (isAuthLoading) {
    return (
      <div className="min-h-screen bg-[#1F2937] flex items-center justify-center">
        <div className="text-gray-400">Loading...</div>
      </div>
    );
  }

  const { data: userRooms = [], isLoading } = useQuery<GameRoom[]>({
    queryKey: ["/api/user", userId, "rooms"],
    enabled: !!userId,
  });

  const createRoomMutation = useMutation({
    mutationFn: async (data: { name: string }) => {
      const response = await authenticatedApiRequest("POST", "/api/rooms", data);
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
    onError: (error: any) => {
      let description = "Failed to create room. Please try again.";
      if (error?.message?.includes("unique constraint") || error?.message?.includes("duplicate")) {
        description = "A room with this name already exists. Please choose a different name.";
      }
      toast({
        title: "Error",
        description,
        variant: "destructive",
      });
    },
  });

  const deleteRoomMutation = useMutation({
    mutationFn: async (roomId: string) => {
      const response = await authenticatedApiRequest("DELETE", `/api/rooms/${roomId}`);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/user", userId, "rooms"] });
      toast({
        title: "Room Deleted",
        description: "Room has been deleted successfully",
      });
    },
    onError: () => {
      toast({
        title: "Error", 
        description: "Failed to delete room. Please try again.",
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
    createRoomMutation.mutate({ name: roomName });
    setRoomName("");
  };

  const handleJoinRoom = () => {
    if (!joinRoomInput.trim()) {
      toast({
        title: "Error",
        description: "Please enter a room name or ID",
        variant: "destructive",
      });
      return;
    }
    setLocation(`/room/${encodeURIComponent(joinRoomInput.trim())}`);
  };

  const handleDeleteRoom = (e: React.MouseEvent, roomId: string) => {
    e.stopPropagation(); // Prevent card click navigation
    if (confirm("Are you sure you want to delete this room? This action cannot be undone.")) {
      deleteRoomMutation.mutate(roomId);
    }
  };

  return (
    <div className="min-h-screen bg-[#1F2937] text-gray-100">
      <div className="container mx-auto px-4 py-8">
        {/* Header with User Info */}
        <div className="flex justify-between items-center mb-8">
          <div className="flex items-center space-x-3">
            <Dice1 className="text-[#2563EB] text-4xl" />
            <h1 className="text-4xl font-bold">Virtual Tabletop</h1>
          </div>
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2 text-gray-300">
              <UserIcon className="w-5 h-5" />
              <span>{(user as User)?.firstName || (user as User)?.email || 'User'}</span>
            </div>
            <Button 
              onClick={() => window.location.href = '/api/logout'}
              variant="ghost"
              size="sm"
              className="text-gray-300 hover:text-white"
              data-testid="button-logout"
            >
              <LogOut className="w-4 h-4 mr-2" />
              Logout
            </Button>
          </div>
        </div>

        {/* Subtitle */}
        <div className="text-center mb-12">
          <p className="text-gray-300 text-lg">
            Create rooms as a Game Master or join existing rooms as a Player for real-time multiplayer gaming
          </p>
        </div>

        <div className="grid md:grid-cols-2 gap-8 max-w-4xl mx-auto">
          {/* Create Room */}
          <Card className="bg-[#374151] border-gray-600">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2 text-gray-100">
                <Plus className="w-5 h-5 text-[#2563EB]" />
                <span>Create New Room (Game Master)</span>
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
                <span>Join Existing Room (Player)</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label htmlFor="room-input" className="text-gray-300">Room Name or ID</Label>
                <Input
                  id="room-input"
                  type="text"
                  placeholder="Enter room name or ID..."
                  value={joinRoomInput}
                  onChange={(e) => setJoinRoomInput(e.target.value)}
                  className="bg-[#4B5563] border-gray-600 text-gray-100 placeholder-gray-400"
                  data-testid="input-room-input"
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
                    <div className="flex-1" onClick={() => setLocation(`/room/${room.id}`)}>
                      <h3 className="font-semibold text-gray-100">{room.name}</h3>
                      <p className="text-sm text-gray-400">
                        Created {new Date(room.createdAt).toLocaleDateString()}
                      </p>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setLocation(`/room/${room.id}`)}
                        className="border-gray-600 text-gray-300 hover:bg-[#2563EB] hover:text-white"
                        data-testid={`button-enter-room-${room.id}`}
                      >
                        Enter
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={(e) => handleDeleteRoom(e, room.id)}
                        disabled={deleteRoomMutation.isPending}
                        className="border-red-600 text-red-400 hover:bg-red-600 hover:text-white"
                        data-testid={`button-delete-room-${room.id}`}
                      >
                        <Trash2 className="w-4 h-4" />
                      </Button>
                    </div>
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
