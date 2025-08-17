// Test Fixtures - Mock data for testing
export const mockUser = {
  uid: 'test-user-123',
  email: 'test@example.com',
  displayName: 'Test User',
  emailVerified: true,
  providerId: 'firebase',
  createdAt: new Date().toISOString(),
  lastLoginAt: new Date().toISOString()
};

export const mockUsers = [
  mockUser,
  {
    uid: 'test-user-456',
    email: 'player2@example.com',
    displayName: 'Player Two',
    emailVerified: true,
    providerId: 'firebase',
    createdAt: new Date().toISOString(),
    lastLoginAt: new Date().toISOString()
  }
];

export const mockGameRoom = {
  id: 'test-room-123',
  name: 'Test Game Room',
  description: 'A test room for unit testing',
  createdBy: mockUser.uid,
  isActive: true,
  maxPlayers: 6,
  currentPlayers: 2,
  gameSystemId: 'test-system-123',
  settings: {
    isPublic: false,
    allowSpectators: true,
    autoSave: true
  },
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString()
};

export const mockAssets = [
  {
    id: 'asset-1',
    name: 'Test Card',
    type: 'card',
    url: '/test-assets/card-1.png',
    thumbnailUrl: '/test-assets/card-1-thumb.png',
    metadata: {
      width: 300,
      height: 420,
      category: 'playing-cards'
    },
    roomId: mockGameRoom.id,
    uploadedBy: mockUser.uid,
    createdAt: new Date().toISOString()
  },
  {
    id: 'asset-2',
    name: 'Test Token',
    type: 'token',
    url: '/test-assets/token-1.png',
    thumbnailUrl: '/test-assets/token-1-thumb.png',
    metadata: {
      width: 100,
      height: 100,
      category: 'tokens'
    },
    roomId: mockGameRoom.id,
    uploadedBy: mockUser.uid,
    createdAt: new Date().toISOString()
  }
];

export const mockPlayers = [
  {
    playerId: mockUser.uid,
    name: mockUser.displayName,
    role: 'gm',
    isOnline: true,
    joinedAt: new Date().toISOString(),
    lastActivity: new Date().toISOString(),
    color: '#ff6b6b'
  },
  {
    playerId: 'test-user-456',
    name: 'Player Two',
    role: 'player',
    isOnline: true,
    joinedAt: new Date().toISOString(),
    lastActivity: new Date().toISOString(),
    color: '#4ecdc4'
  },
  {
    playerId: 'test-user-789',
    name: 'Player Three',
    role: 'player',
    isOnline: false,
    joinedAt: new Date().toISOString(),
    lastActivity: new Date(Date.now() - 3600000).toISOString(), // 1 hour ago
    color: '#45b7d1'
  }
];

export const mockWebSocketEvents = {
  authSuccess: {
    type: 'auth:success' as const,
    data: { user: mockUser },
    timestamp: new Date().toISOString(),
    correlationId: 'test-auth-123'
  },
  roomJoined: {
    type: 'room:joined' as const,
    data: { 
      roomId: mockGameRoom.id, 
      players: mockPlayers 
    },
    timestamp: new Date().toISOString(),
    correlationId: 'test-room-123'
  },
  assetMoved: {
    type: 'asset:moved' as const,
    data: {
      assetId: 'asset-1',
      position: { x: 100, y: 200 },
      playerId: mockUser.uid
    },
    timestamp: new Date().toISOString(),
    correlationId: 'test-move-123'
  }
};

export const mockApiResponses = {
  success: {
    data: mockGameRoom,
    timestamp: new Date().toISOString(),
    correlationId: 'test-api-123'
  },
  error: {
    error: 'VALIDATION_ERROR',
    message: 'Invalid input data',
    code: 'E001',
    timestamp: new Date().toISOString(),
    correlationId: 'test-error-123'
  },
  paginated: {
    data: mockAssets,
    pagination: {
      page: 1,
      limit: 10,
      total: mockAssets.length,
      hasNext: false,
      hasPrevious: false
    },
    timestamp: new Date().toISOString(),
    correlationId: 'test-paginated-123'
  }
};

export const mockDatabaseQueries = {
  success: {
    data: mockGameRoom,
    success: true as const
  },
  error: {
    error: {
      code: 'DB_CONNECTION_ERROR',
      message: 'Database connection failed'
    },
    success: false as const
  }
};

// Mock board assets for GameBoard component testing
export const mockBoardAssets = [
  {
    id: 'board-asset-1',
    assetId: 'asset-1',
    roomId: 'test-room-123',
    x: 100,
    y: 150,
    width: 60,
    height: 90,
    rotation: 0,
    scale: 1,
    zIndex: 1,
    isFlipped: false,
    ownedBy: mockUser.uid,
    name: 'Test Token',
    type: 'token',
    url: '/test-assets/token-1.png'
  },
  {
    id: 'board-asset-2', 
    assetId: 'asset-2',
    roomId: 'test-room-123',
    x: 250,
    y: 200,
    width: 60,
    height: 90,
    rotation: 45,
    scale: 1,
    zIndex: 2,
    isFlipped: false,
    ownedBy: 'test-user-456', // mockUsers[1].uid
    name: 'Test Card',
    type: 'card',
    url: '/test-assets/card-1.png'
  },
  {
    id: 'board-asset-3',
    assetId: 'asset-3', 
    roomId: 'test-room-123',
    x: 400,
    y: 300,
    width: 120,
    height: 120,
    rotation: 0,
    scale: 1,
    zIndex: 0,
    isFlipped: false,
    ownedBy: null,
    name: 'Test Tile',
    type: 'tile',
    url: '/test-assets/tile-1.png'
  }
];
