/**
 * Hook for managing optimistic updates in React Query
 *
 * Provides helpers for:
 * - Deck/pile operations
 * - Card movements
 * - Token positioning
 * - Chat messages
 */

import { useQueryClient } from '@tanstack/react-query';
import { useCallback, useRef } from 'react';
import { queryKeys } from '@/lib/queryKeys';
import type { CardDeck, CardPile, GameAsset, BoardAsset } from '@shared/schema';

export interface OptimisticUpdate {
  queryKey: readonly string[];
  rollback: () => void;
  timestamp: number;
}

export function useOptimisticUpdates(roomId: string) {
  const queryClient = useQueryClient();
  const optimisticUpdatesRef = useRef(new Map<string, OptimisticUpdate>());

  // Helper to create rollback function
  const createRollback = useCallback((queryKey: readonly string[], previousData: any) => {
    return () => {
      queryClient.setQueryData(queryKey, previousData);
    };
  }, [queryClient]);

  // Helper to auto-cleanup optimistic updates
  const scheduleCleanup = useCallback((updateId: string, delay = 5000) => {
    setTimeout(() => {
      optimisticUpdatesRef.current.delete(updateId);
    }, delay);
  }, []);

  // Optimistic deck shuffle
  const optimisticDeckShuffle = useCallback((deckId: string) => {
    const queryKey = queryKeys.decks.byId(roomId, deckId);
    const updateId = `deck-shuffle-${deckId}-${Date.now()}`;

    const previousData = queryClient.getQueryData(queryKey);
    const rollback = createRollback(queryKey, previousData);

    queryClient.setQueryData(queryKey, (oldData: CardDeck | undefined) => {
      if (!oldData) return oldData;
      return {
        ...oldData,
        lastModifiedAt: new Date(),
        isShuffled: true,
      };
    });

    optimisticUpdatesRef.current.set(updateId, {
      queryKey,
      rollback,
      timestamp: Date.now(),
    });

    scheduleCleanup(updateId);
    return rollback;
  }, [queryClient, roomId, createRollback, scheduleCleanup]);

  // Optimistic card draw
  const optimisticCardDraw = useCallback((deckId: string, count: number) => {
    const deckQueryKey = queryKeys.decks.byId(roomId, deckId);
    const updateId = `card-draw-${deckId}-${Date.now()}`;

    const previousData = queryClient.getQueryData(deckQueryKey);
    const rollback = createRollback(deckQueryKey, previousData);

    queryClient.setQueryData(deckQueryKey, (oldData: CardDeck | undefined) => {
      if (!oldData) return oldData;

      // CardDeck doesn't have cardCount, use deckOrder length instead
      const currentCardCount = oldData.deckOrder ? Array.isArray(oldData.deckOrder) ? oldData.deckOrder.length : 0 : 0;
      const remainingCards = Math.max(0, currentCardCount - count);
      return {
        ...oldData,
        lastModifiedAt: new Date(),
      };
    });

    optimisticUpdatesRef.current.set(updateId, {
      queryKey: deckQueryKey,
      rollback,
      timestamp: Date.now(),
    });

    scheduleCleanup(updateId);
    return rollback;
  }, [queryClient, roomId, createRollback, scheduleCleanup]);

  // Optimistic asset movement
  const optimisticAssetMove = useCallback((
    assetId: string,
    newPosition: { x: number; y: number },
    rotation?: number,
  ) => {
    const queryKey = queryKeys.rooms.boardAssets(roomId);
    const updateId = `asset-move-${assetId}-${Date.now()}`;

    const previousData = queryClient.getQueryData(queryKey);
    const rollback = createRollback(queryKey, previousData);

    queryClient.setQueryData(queryKey, (oldData: BoardAsset[]) => {
      if (!oldData) return oldData;

      // BoardAsset uses GameAsset fields
      return oldData.map(asset =>
        asset.assetId === assetId
          ? {
              ...asset,
              positionX: newPosition.x,
              positionY: newPosition.y,
              rotation: rotation ?? asset.rotation,
            }
          : asset,
      );
    });

    optimisticUpdatesRef.current.set(updateId, {
      queryKey,
      rollback,
      timestamp: Date.now(),
    });

    scheduleCleanup(updateId, 2000); // Shorter cleanup for movements
    return rollback;
  }, [queryClient, roomId, createRollback, scheduleCleanup]);

  // Optimistic pile creation
  const optimisticPileCreate = useCallback((pile: Partial<CardPile>) => {
    const queryKey = queryKeys.piles.all(roomId);
    const updateId = `pile-create-${Date.now()}`;

    const previousData = queryClient.getQueryData(queryKey);
    const rollback = createRollback(queryKey, previousData);

    const optimisticPile: CardPile = {
      id: `temp-${Date.now()}`,
      roomId,
      name: pile.name || 'New Pile',
      positionX: pile.positionX || 0,
      positionY: pile.positionY || 0,
      pileType: pile.pileType as any || 'custom',
      visibility: pile.visibility as any || 'public',
      cardCount: 0,
      createdAt: new Date(),
      createdBy: pile.ownerId || '',
      lastModifiedAt: null,
      lastModifiedBy: null,
      ownerId: pile.ownerId || null,
      cardOrder: [],
      version: 1,
      ...pile,
    };

    queryClient.setQueryData(queryKey, (oldData: CardPile[] | undefined) => {
      if (!oldData) return [optimisticPile];
      return [...oldData, optimisticPile];
    });

    optimisticUpdatesRef.current.set(updateId, {
      queryKey,
      rollback,
      timestamp: Date.now(),
    });

    scheduleCleanup(updateId);
    return rollback;
  }, [queryClient, roomId, createRollback, scheduleCleanup]);

  // Clear all optimistic updates for a room
  const clearOptimisticUpdates = useCallback(() => {
    optimisticUpdatesRef.current.forEach(update => {
      update.rollback();
    });
    optimisticUpdatesRef.current.clear();
  }, []);

  // Rollback specific optimistic update
  const rollbackOptimisticUpdate = useCallback((updateId: string) => {
    const update = optimisticUpdatesRef.current.get(updateId);
    if (update) {
      update.rollback();
      optimisticUpdatesRef.current.delete(updateId);
    }
  }, []);

  // Get count of pending optimistic updates
  const getOptimisticUpdateCount = useCallback(() => {
    return optimisticUpdatesRef.current.size;
  }, []);

  return {
    // Optimistic update functions
    optimisticDeckShuffle,
    optimisticCardDraw,
    optimisticAssetMove,
    optimisticPileCreate,

    // Management functions
    clearOptimisticUpdates,
    rollbackOptimisticUpdate,
    getOptimisticUpdateCount,
  };
}
