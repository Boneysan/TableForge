/**
 * Centralized query key management for React Query
 * 
 * Provides stable, hierarchical query keys that enable:
 * - Precise cache invalidation
 * - Consistent patterns across components
 * - Easy debugging and cache inspection
 */

export const queryKeys = {
  // Authentication
  auth: {
    user: () => ['auth', 'user'] as const,
  },

  // Game Rooms
  rooms: {
    all: () => ['rooms'] as const,
    byId: (roomId: string) => ['rooms', roomId] as const,
    players: (roomId: string) => ['rooms', roomId, 'players'] as const,
    assets: (roomId: string) => ['rooms', roomId, 'assets'] as const,
    boardAssets: (roomId: string) => ['rooms', roomId, 'board-assets'] as const,
    state: (roomId: string) => ['rooms', roomId, 'state'] as const,
  },

  // Decks and Piles
  decks: {
    all: (roomId: string) => ['rooms', roomId, 'decks'] as const,
    byId: (roomId: string, deckId: string) => ['rooms', roomId, 'decks', deckId] as const,
    cards: (roomId: string, deckId: string) => ['rooms', roomId, 'decks', deckId, 'cards'] as const,
  },

  piles: {
    all: (roomId: string) => ['rooms', roomId, 'piles'] as const,
    byId: (roomId: string, pileId: string) => ['rooms', roomId, 'piles', pileId] as const,
    cards: (roomId: string, pileId: string) => ['rooms', roomId, 'piles', pileId, 'cards'] as const,
  },

  // Game Systems
  systems: {
    all: () => ['systems'] as const,
    byId: (systemId: string) => ['systems', systemId] as const,
    assets: (systemId: string) => ['systems', systemId, 'assets'] as const,
  },

  // Chat
  chat: {
    messages: (roomId: string) => ['rooms', roomId, 'chat', 'messages'] as const,
  },

  // Dice
  dice: {
    rolls: (roomId: string) => ['rooms', roomId, 'dice', 'rolls'] as const,
  },

  // Object Storage
  storage: {
    uploadUrl: () => ['storage', 'upload-url'] as const,
  },
} as const;

/**
 * Helper functions for query key matching
 */
export const queryKeyMatchers = {
  // Match all room-related queries
  room: (roomId: string) => ({ predicate: (query: any) => 
    query.queryKey[0] === 'rooms' && query.queryKey[1] === roomId 
  }),
  
  // Match specific resource types within a room
  roomDecks: (roomId: string) => ({ predicate: (query: any) => 
    query.queryKey[0] === 'rooms' && 
    query.queryKey[1] === roomId && 
    query.queryKey[2] === 'decks' 
  }),
  
  roomPiles: (roomId: string) => ({ predicate: (query: any) => 
    query.queryKey[0] === 'rooms' && 
    query.queryKey[1] === roomId && 
    query.queryKey[2] === 'piles' 
  }),
  
  roomAssets: (roomId: string) => ({ predicate: (query: any) => 
    query.queryKey[0] === 'rooms' && 
    query.queryKey[1] === roomId && 
    (query.queryKey[2] === 'assets' || query.queryKey[2] === 'board-assets')
  }),
  
  // Match all queries for a specific deck
  deck: (roomId: string, deckId: string) => ({ predicate: (query: any) => 
    query.queryKey[0] === 'rooms' && 
    query.queryKey[1] === roomId && 
    query.queryKey[2] === 'decks' && 
    query.queryKey[3] === deckId 
  }),
  
  // Match all queries for a specific pile
  pile: (roomId: string, pileId: string) => ({ predicate: (query: any) => 
    query.queryKey[0] === 'rooms' && 
    query.queryKey[1] === roomId && 
    query.queryKey[2] === 'piles' && 
    query.queryKey[3] === pileId 
  }),
};

/**
 * Type-safe query key extraction
 */
export type AuthQueryKey = ReturnType<typeof queryKeys.auth[keyof typeof queryKeys.auth]>;
export type RoomQueryKey = ReturnType<typeof queryKeys.rooms[keyof typeof queryKeys.rooms]>;
export type DeckQueryKey = ReturnType<typeof queryKeys.decks[keyof typeof queryKeys.decks]>;
export type PileQueryKey = ReturnType<typeof queryKeys.piles[keyof typeof queryKeys.piles]>;
export type SystemQueryKey = ReturnType<typeof queryKeys.systems[keyof typeof queryKeys.systems]>;