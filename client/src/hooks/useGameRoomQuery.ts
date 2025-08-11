/**
 * Centralized React Query hooks for game room data
 * 
 * Provides consistent query patterns with:
 * - Stable query keys
 * - Standard error handling
 * - Optimistic updates integration
 * - WebSocket invalidation support
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { queryKeys } from "@/lib/queryKeys";
import { useOptimisticUpdates } from "./useOptimisticUpdates";
import { useToast } from "./use-toast";
import type { 
  GameRoom, 
  CardDeck, 
  CardPile, 
  GameAsset, 
  RoomPlayerWithName,
  ChatMessage 
} from "@shared/schema";

// Room data hooks
export function useGameRoom(roomId: string) {
  return useQuery({
    queryKey: queryKeys.rooms.byId(roomId),
    enabled: !!roomId,
    staleTime: 5 * 60 * 1000, // 5 minutes
  });
}

export function useRoomPlayers(roomId: string) {
  return useQuery({
    queryKey: queryKeys.rooms.players(roomId),
    enabled: !!roomId,
    staleTime: 30 * 1000, // 30 seconds
  });
}

export function useRoomAssets(roomId: string) {
  return useQuery({
    queryKey: queryKeys.rooms.assets(roomId),
    enabled: !!roomId,
    staleTime: 5 * 60 * 1000, // 5 minutes
  });
}

export function useBoardAssets(roomId: string) {
  return useQuery({
    queryKey: queryKeys.rooms.boardAssets(roomId),
    enabled: !!roomId,
    staleTime: 10 * 1000, // 10 seconds - more frequent updates for real-time positioning
  });
}

// Deck and pile hooks
export function useRoomDecks(roomId: string) {
  return useQuery({
    queryKey: queryKeys.decks.all(roomId),
    enabled: !!roomId,
    staleTime: 30 * 1000, // 30 seconds
  });
}

export function useDeck(roomId: string, deckId: string) {
  return useQuery({
    queryKey: queryKeys.decks.byId(roomId, deckId),
    enabled: !!roomId && !!deckId,
    staleTime: 10 * 1000, // 10 seconds
  });
}

export function useRoomPiles(roomId: string) {
  return useQuery({
    queryKey: queryKeys.piles.all(roomId),
    enabled: !!roomId,
    staleTime: 30 * 1000, // 30 seconds
  });
}

export function usePile(roomId: string, pileId: string) {
  return useQuery({
    queryKey: queryKeys.piles.byId(roomId, pileId),
    enabled: !!roomId && !!pileId,
    staleTime: 10 * 1000, // 10 seconds
  });
}

// Chat hooks
export function useChatMessages(roomId: string) {
  return useQuery({
    queryKey: queryKeys.chat.messages(roomId),
    enabled: !!roomId,
    staleTime: 1000, // 1 second - real-time chat
  });
}

// Mutation hooks with optimistic updates
export function useCreateDeck(roomId: string) {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (data: { 
      name: string; 
      description: string; 
      deckOrder: string[];
      cardBackId?: string;
    }) => {
      const response = await apiRequest("POST", `/api/rooms/${roomId}/decks`, data);
      return response.json();
    },
    onSuccess: (newDeck) => {
      // Optimistically add the deck
      queryClient.setQueryData(
        queryKeys.decks.all(roomId), 
        (oldDecks: CardDeck[] | undefined) => oldDecks ? [...oldDecks, newDeck] : [newDeck]
      );
      
      toast({ title: "Deck created successfully!" });
    },
    onError: () => {
      toast({ title: "Failed to create deck", variant: "destructive" });
    },
  });
}

export function useShuffleDeck(roomId: string) {
  const queryClient = useQueryClient();
  const { optimisticDeckShuffle } = useOptimisticUpdates(roomId);
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (deckId: string) => {
      // Apply optimistic update
      const rollback = optimisticDeckShuffle(deckId);
      
      try {
        const response = await apiRequest("POST", `/api/rooms/${roomId}/decks/${deckId}/shuffle`);
        return response.json();
      } catch (error) {
        rollback(); // Rollback on error
        throw error;
      }
    },
    onSuccess: (data, deckId) => {
      // Invalidate to get real data
      queryClient.invalidateQueries({ queryKey: queryKeys.decks.byId(roomId, deckId) });
      toast({ title: "Deck shuffled!" });
    },
    onError: () => {
      toast({ title: "Failed to shuffle deck", variant: "destructive" });
    },
  });
}

export function useDrawCards(roomId: string) {
  const queryClient = useQueryClient();
  const { optimisticCardDraw } = useOptimisticUpdates(roomId);
  const { toast } = useToast();

  return useMutation({
    mutationFn: async ({ deckId, count = 1, playerId }: {
      deckId: string;
      count?: number;
      playerId: string;
    }) => {
      // Apply optimistic update
      const rollback = optimisticCardDraw(deckId, count);
      
      try {
        const response = await apiRequest("POST", `/api/rooms/${roomId}/decks/${deckId}/draw`, {
          playerId,
          count,
        });
        return response.json();
      } catch (error) {
        rollback(); // Rollback on error
        throw error;
      }
    },
    onSuccess: (data, variables) => {
      // Invalidate relevant queries
      queryClient.invalidateQueries({ queryKey: queryKeys.decks.byId(roomId, variables.deckId) });
      queryClient.invalidateQueries({ queryKey: queryKeys.piles.all(roomId) });
      
      toast({ 
        title: `Drew ${variables.count || 1} card${(variables.count || 1) > 1 ? 's' : ''}!`,
        description: "Cards added to your hand"
      });
    },
    onError: () => {
      toast({ title: "Failed to draw cards", variant: "destructive" });
    },
  });
}

export function useCreatePile(roomId: string) {
  const queryClient = useQueryClient();
  const { optimisticPileCreate } = useOptimisticUpdates(roomId);
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (data: {
      name: string;
      positionX: number;
      positionY: number;
      pileType: "custom" | "deck" | "discard" | "hand";
      visibility: "public" | "owner" | "gm";
      ownerId?: string;
    }) => {
      // Apply optimistic update
      const rollback = optimisticPileCreate(data);
      
      try {
        const response = await apiRequest("POST", `/api/rooms/${roomId}/piles`, data);
        return response.json();
      } catch (error) {
        rollback(); // Rollback on error
        throw error;
      }
    },
    onSuccess: (newPile) => {
      // Replace optimistic pile with real one
      queryClient.setQueryData(
        queryKeys.piles.all(roomId),
        (oldPiles: CardPile[] | undefined) => {
          if (!oldPiles) return [newPile];
          return oldPiles.map(pile => 
            pile.id.startsWith('temp-') ? newPile : pile
          );
        }
      );
      
      toast({ title: "Card pile created successfully!" });
    },
    onError: () => {
      toast({ title: "Failed to create pile", variant: "destructive" });
    },
  });
}

export function useMoveAsset(roomId: string) {
  const queryClient = useQueryClient();
  const { optimisticAssetMove } = useOptimisticUpdates(roomId);
  const { toast } = useToast();

  return useMutation({
    mutationFn: async ({ assetId, positionX, positionY, rotation }: {
      assetId: string;
      positionX: number;
      positionY: number;
      rotation?: number;
    }) => {
      // Apply optimistic update
      const rollback = optimisticAssetMove(assetId, { x: positionX, y: positionY }, rotation);
      
      try {
        const response = await apiRequest("PUT", `/api/rooms/${roomId}/board-assets/${assetId}`, {
          positionX,
          positionY,
          rotation,
        });
        return response.json();
      } catch (error) {
        rollback(); // Rollback on error
        throw error;
      }
    },
    onSuccess: () => {
      // Let optimistic update stand, will be confirmed by WebSocket
    },
    onError: () => {
      toast({ title: "Failed to move asset", variant: "destructive" });
    },
  });
}