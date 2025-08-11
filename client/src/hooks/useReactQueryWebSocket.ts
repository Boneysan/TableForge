/**
 * Enhanced WebSocket hook with React Query integration
 *
 * Features:
 * - Automatic query invalidation on socket events
 * - Optimistic updates for card/token interactions
 * - Stable query key patterns
 * - Room-scoped state management
 */

import { useQueryClient } from '@tanstack/react-query';
import { useWebSocket } from './useWebSocket';
import { queryKeys, queryKeyMatchers } from '@/lib/queryKeys';
import { useCallback, useRef } from 'react';

// Import the shared WebSocketMessage type
import type { WebSocketMessage } from '@shared/schema';

export interface UseReactQueryWebSocketOptions {
  roomId?: string;
  onMessage?: (message: WebSocketMessage) => void;
  onConnect?: () => void;
  onDisconnect?: () => void;
  enableOptimisticUpdates?: boolean;
}

export function useReactQueryWebSocket({
  roomId,
  onMessage,
  onConnect,
  onDisconnect,
  enableOptimisticUpdates = true,
}: UseReactQueryWebSocketOptions = {}) {
  const queryClient = useQueryClient();
  const optimisticUpdatesRef = useRef(new Map<string, any>());

  // Enhanced message handler with query invalidation
  const handleMessage = useCallback((message: WebSocketMessage) => {
    console.log('📡 [WebSocket] Received message:', message.type, message.payload);

    // Call user-provided message handler first
    onMessage?.(message);

    // Handle query invalidation based on message type
    if (roomId) {
      handleQueryInvalidation(message, roomId);
    }
  }, [onMessage, roomId]);

  // Query invalidation logic based on WebSocket message types
  const handleQueryInvalidation = useCallback((message: WebSocketMessage, roomId: string) => {
    const { type, payload } = message;

    switch (type) {
      // Room state changes
      case 'ROOM_UPDATED':
      case 'BOARD_RESIZED':
        queryClient.invalidateQueries({ queryKey: queryKeys.rooms.byId(roomId) });
        queryClient.invalidateQueries({ queryKey: queryKeys.rooms.state(roomId) });
        break;

      // Player events
      case 'PLAYER_JOINED':
      case 'PLAYER_LEFT':
      case 'PLAYER_SCORE_UPDATED':
        queryClient.invalidateQueries({ queryKey: queryKeys.rooms.players(roomId) });
        break;

      // Asset events
      case 'ASSET_UPLOADED':
      case 'ASSET_DELETED':
        queryClient.invalidateQueries({ queryKey: queryKeys.rooms.assets(roomId) });
        break;

      // Board asset events
      case 'BOARD_ASSET_MOVED':
      case 'BOARD_ASSET_UPDATED':
      case 'BOARD_ASSET_DELETED':
        queryClient.invalidateQueries({ queryKey: queryKeys.rooms.boardAssets(roomId) });
        // Update optimistically if enabled
        if (enableOptimisticUpdates && payload.assetId) {
          updateBoardAssetOptimistically(roomId, payload);
        }
        break;

      // Deck events
      case 'DECK_CREATED':
      case 'DECK_DELETED':
      case 'DECK_UPDATED':
        queryClient.invalidateQueries({ queryKey: queryKeys.decks.all(roomId) });
        if (payload.deckId) {
          queryClient.invalidateQueries({ queryKey: queryKeys.decks.byId(roomId, payload.deckId) });
        }
        break;

      case 'DECK_SHUFFLED':
        if (payload.deckId) {
          queryClient.invalidateQueries({ queryKey: queryKeys.decks.cards(roomId, payload.deckId) });
          // Optimistic update for shuffle animation
          if (enableOptimisticUpdates) {
            updateDeckOptimistically(roomId, payload.deckId, { shuffled: true });
          }
        }
        break;

      // Card pile events
      case 'PILE_CREATED':
      case 'PILE_DELETED':
      case 'PILE_UPDATED':
        queryClient.invalidateQueries({ queryKey: queryKeys.piles.all(roomId) });
        if (payload.pileId) {
          queryClient.invalidateQueries({ queryKey: queryKeys.piles.byId(roomId, payload.pileId) });
        }
        break;

      case 'CARD_MOVED':
      case 'CARDS_DEALT':
      case 'CARD_DRAWN':
        // Invalidate both source and destination piles/decks
        if (payload.sourcePileId) {
          queryClient.invalidateQueries({ queryKey: queryKeys.piles.cards(roomId, payload.sourcePileId) });
        }
        if (payload.destinationPileId) {
          queryClient.invalidateQueries({ queryKey: queryKeys.piles.cards(roomId, payload.destinationPileId) });
        }
        if (payload.deckId) {
          queryClient.invalidateQueries({ queryKey: queryKeys.decks.cards(roomId, payload.deckId) });
        }

        // Optimistic updates for card movements
        if (enableOptimisticUpdates) {
          updateCardMovementOptimistically(roomId, payload);
        }
        break;

      // Chat events
      case 'CHAT_MESSAGE':
        queryClient.invalidateQueries({ queryKey: queryKeys.chat.messages(roomId) });
        // Optimistic chat update
        if (enableOptimisticUpdates && payload.message) {
          addChatMessageOptimistically(roomId, payload.message);
        }
        break;

      // Dice events
      case 'DICE_ROLLED':
        queryClient.invalidateQueries({ queryKey: queryKeys.dice.rolls(roomId) });
        // Optimistic dice result
        if (enableOptimisticUpdates && payload.result) {
          addDiceRollOptimistically(roomId, payload.result);
        }
        break;

      // Game system events
      case 'SYSTEM_APPLIED':
        // Invalidate room assets and any system-related queries
        queryClient.invalidateQueries({ queryKey: queryKeys.rooms.assets(roomId) });
        queryClient.invalidateQueries({ queryKey: queryKeys.decks.all(roomId) });
        break;

      default:
        console.log(`📡 [WebSocket] Unhandled message type: ${type}`);
    }
  }, [queryClient, enableOptimisticUpdates]);

  // Optimistic update functions
  const updateBoardAssetOptimistically = useCallback((roomId: string, payload: any) => {
    const queryKey = queryKeys.rooms.boardAssets(roomId);

    queryClient.setQueryData(queryKey, (oldData: any[]) => {
      if (!oldData) return oldData;

      return oldData.map(asset =>
        asset.id === payload.assetId
          ? { ...asset, ...payload.updates }
          : asset,
      );
    });

    // Store for potential rollback
    const updateId = `board-asset-${payload.assetId}-${Date.now()}`;
    optimisticUpdatesRef.current.set(updateId, { queryKey, payload });

    // Auto-cleanup optimistic update after 5 seconds
    setTimeout(() => {
      optimisticUpdatesRef.current.delete(updateId);
    }, 5000);
  }, [queryClient]);

  const updateDeckOptimistically = useCallback((roomId: string, deckId: string, updates: any) => {
    const queryKey = queryKeys.decks.byId(roomId, deckId);

    queryClient.setQueryData(queryKey, (oldData: any) => {
      if (!oldData) return oldData;
      return { ...oldData, ...updates, lastModified: Date.now() };
    });
  }, [queryClient]);

  const updateCardMovementOptimistically = useCallback((roomId: string, payload: any) => {
    // This is complex - for now, we'll rely on server invalidation
    // Future enhancement: implement proper optimistic card movement
    console.log('🃏 [Optimistic] Card movement:', payload);
  }, []);

  const addChatMessageOptimistically = useCallback((roomId: string, message: any) => {
    const queryKey = queryKeys.chat.messages(roomId);

    queryClient.setQueryData(queryKey, (oldData: any[]) => {
      if (!oldData) return [message];
      return [...oldData, { ...message, optimistic: true }];
    });
  }, [queryClient]);

  const addDiceRollOptimistically = useCallback((roomId: string, result: any) => {
    const queryKey = queryKeys.dice.rolls(roomId);

    queryClient.setQueryData(queryKey, (oldData: any[]) => {
      if (!oldData) return [result];
      return [result, ...oldData.slice(0, 49)]; // Keep last 50 rolls
    });
  }, [queryClient]);

  // Enhanced connect handler
  const handleConnect = useCallback(() => {
    console.log('📡 [WebSocket] Connected with React Query integration');
    onConnect?.();

    // Invalidate stale data on reconnect
    if (roomId) {
      queryClient.invalidateQueries(queryKeyMatchers.room(roomId));
    }
  }, [onConnect, queryClient, roomId]);

  // Enhanced disconnect handler
  const handleDisconnect = useCallback(() => {
    console.log('📡 [WebSocket] Disconnected - clearing optimistic updates');
    onDisconnect?.();

    // Clear optimistic updates on disconnect
    optimisticUpdatesRef.current.clear();
  }, [onDisconnect]);

  // Use the base WebSocket hook
  const { connected, error, sendMessage, disconnect } = useWebSocket({
    onMessage: handleMessage,
    onConnect: handleConnect,
    onDisconnect: handleDisconnect,
  });

  // Enhanced sendMessage with optimistic updates
  const sendMessageWithOptimistic = useCallback((message: any) => {
    // Send the message
    sendMessage(message);

    // Apply optimistic updates for certain message types
    if (enableOptimisticUpdates && roomId) {
      applyOptimisticUpdateForOutgoingMessage(roomId, message);
    }
  }, [sendMessage, enableOptimisticUpdates, roomId]);

  const applyOptimisticUpdateForOutgoingMessage = useCallback((roomId: string, message: any) => {
    // Handle optimistic updates for outgoing messages
    switch (message.type) {
      case 'SEND_CHAT_MESSAGE':
        if (message.payload?.message) {
          addChatMessageOptimistically(roomId, {
            ...message.payload.message,
            id: `temp-${Date.now()}`,
            optimistic: true,
          });
        }
        break;

      case 'MOVE_BOARD_ASSET':
        if (message.payload) {
          updateBoardAssetOptimistically(roomId, message.payload);
        }
        break;

      // Add more optimistic updates as needed
    }
  }, [addChatMessageOptimistically, updateBoardAssetOptimistically]);

  return {
    connected,
    error,
    sendMessage: sendMessageWithOptimistic,
    disconnect,
    // Utility functions for manual cache management
    invalidateRoom: (roomId: string) => {
      queryClient.invalidateQueries(queryKeyMatchers.room(roomId));
    },
    clearOptimisticUpdates: () => {
      optimisticUpdatesRef.current.clear();
    },
  };
}
