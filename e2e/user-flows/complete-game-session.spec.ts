// End-to-End Tests for Complete User Journey
import { test, expect } from '@playwright/test';

test.describe('Complete Game Session Flow', () => {
  test('should support full game lifecycle from login to gameplay', async ({ page }) => {
    // Step 1: Navigate to application
    await page.goto('/');
    
    // Verify home page loads
    await expect(page).toHaveTitle(/TableForge|Vorpal Board/);
    
    // Step 2: Authentication
    await page.click('[data-testid="sign-in-button"]');
    
    // Mock authentication for E2E testing
    await page.evaluate(() => {
      // Simulate Firebase auth success
      window.localStorage.setItem('auth-token', 'e2e-test-token');
      window.dispatchEvent(new CustomEvent('auth-state-change', {
        detail: {
          user: {
            uid: 'e2e-user-123',
            email: 'e2e@test.com',
            displayName: 'E2E Test User'
          }
        }
      }));
    });

    // Wait for authentication to complete
    await expect(page.locator('[data-testid="user-menu"]')).toBeVisible();
    
    // Step 3: Create new room
    await page.click('[data-testid="create-room-button"]');
    
    // Fill room creation form
    await page.fill('[data-testid="room-name-input"]', 'E2E Test Game Room');
    await page.fill('[data-testid="room-description"]', 'Automated test room');
    await page.selectOption('[data-testid="max-players"]', '6');
    await page.check('[data-testid="allow-spectators"]');
    
    await page.click('[data-testid="create-room-submit"]');

    // Verify room creation and redirect
    await expect(page).toHaveURL(/\/room\/.+/);
    await expect(page.locator('[data-testid="room-name"]')).toContainText('E2E Test Game Room');

    // Step 4: Switch to Admin Interface
    await page.click('[data-testid="admin-interface-button"]');
    await expect(page.locator('[data-testid="admin-interface"]')).toBeVisible();

    // Step 5: Upload game assets
    await page.click('[data-testid="tab-assets"]');
    
    // Mock file upload
    const fileInput = page.locator('input[type="file"]');
    await fileInput.setInputFiles('./tests/fixtures/test-card.png');

    // Wait for upload completion
    await expect(page.locator('[data-testid="upload-success"]')).toBeVisible();
    await expect(page.locator('[data-testid^="asset-"]')).toBeVisible();

    // Step 6: Switch to Game Master view
    await page.click('[data-testid="switch-to-gm"]');
    await expect(page.locator('[data-testid="gm-interface"]')).toBeVisible();

    // Step 7: Place assets on game board
    const assetLibrary = page.locator('[data-testid="asset-library"]');
    const gameBoard = page.locator('[data-testid="game-board"]');
    
    // Drag asset from library to board
    const firstAsset = assetLibrary.locator('[data-testid^="asset-"]').first();
    await firstAsset.dragTo(gameBoard, {
      targetPosition: { x: 300, y: 200 }
    });

    // Verify asset appears on board
    await expect(gameBoard.locator('[data-testid^="board-asset-"]')).toBeVisible();

    // Step 8: Asset manipulation
    const boardAsset = gameBoard.locator('[data-testid^="board-asset-"]').first();
    
    // Move asset to different position
    await boardAsset.dragTo(gameBoard, {
      targetPosition: { x: 500, y: 400 }
    });

    // Right-click for context menu
    await boardAsset.click({ button: 'right' });
    await expect(page.locator('[data-testid="asset-context-menu"]')).toBeVisible();

    // Flip asset
    await page.click('[data-testid="flip-asset"]');
    await expect(boardAsset).toHaveClass(/flipped/);

    // Step 9: Dice rolling functionality
    await page.click('[data-testid="dice-panel-toggle"]');
    await expect(page.locator('[data-testid="dice-roller"]')).toBeVisible();
    
    await page.selectOption('[data-testid="dice-type"]', 'd20');
    await page.fill('[data-testid="dice-count"]', '2');
    await page.click('[data-testid="roll-dice"]');

    // Verify dice results
    await expect(page.locator('[data-testid="dice-results"]')).toBeVisible();
    await expect(page.locator('[data-testid="dice-total"]')).toBeVisible();

    // Step 10: Chat functionality
    await page.fill('[data-testid="chat-input"]', 'This is an E2E test message');
    await page.press('[data-testid="chat-input"]', 'Enter');

    await expect(page.locator('[data-testid="chat-messages"]'))
      .toContainText('This is an E2E test message');

    // Step 11: Save game state
    await page.click('[data-testid="save-game-button"]');
    await expect(page.locator('[data-testid="save-success-toast"]')).toBeVisible();

    // Step 12: Game settings
    await page.click('[data-testid="settings-button"]');
    await expect(page.locator('[data-testid="settings-modal"]')).toBeVisible();
    
    await page.check('[data-testid="auto-save-enabled"]');
    await page.selectOption('[data-testid="board-theme"]', 'dark');
    await page.click('[data-testid="save-settings"]');

    // Step 13: Verify settings persistence
    await page.reload();
    await page.click('[data-testid="settings-button"]');
    await expect(page.locator('[data-testid="auto-save-enabled"]')).toBeChecked();
    await expect(page.locator('[data-testid="board-theme"]')).toHaveValue('dark');
  });

  test('should handle multiplayer interactions', async ({ browser }) => {
    // Create two browser contexts for multiplayer testing
    const context1 = await browser.newContext();
    const context2 = await browser.newContext();
    
    const page1 = await context1.newPage();
    const page2 = await context2.newPage();

    // Player 1: Create room and authenticate
    await page1.goto('/');
    await page1.evaluate(() => {
      window.localStorage.setItem('auth-token', 'player1-token');
      window.dispatchEvent(new CustomEvent('auth-state-change', {
        detail: { user: { uid: 'player1', displayName: 'Player One' } }
      }));
    });

    await page1.click('[data-testid="create-room-button"]');
    await page1.fill('[data-testid="room-name-input"]', 'Multiplayer Test Room');
    await page1.click('[data-testid="create-room-submit"]');

    // Get room URL for player 2
    const roomUrl = page1.url();

    // Player 2: Join the same room
    await page2.goto(roomUrl);
    await page2.evaluate(() => {
      window.localStorage.setItem('auth-token', 'player2-token');
      window.dispatchEvent(new CustomEvent('auth-state-change', {
        detail: { user: { uid: 'player2', displayName: 'Player Two' } }
      }));
    });

    // Verify both players see each other in player list
    await expect(page1.locator('[data-testid="player-list"]'))
      .toContainText('Player Two');
    await expect(page2.locator('[data-testid="player-list"]'))
      .toContainText('Player One');

    // Player 1: Place an asset
    await page1.click('[data-testid="admin-interface-button"]');
    // ... upload asset and place on board

    // Player 1: Move asset
    const gameBoard1 = page1.locator('[data-testid="game-board"]');
    const asset1 = gameBoard1.locator('[data-testid^="board-asset-"]').first();
    await asset1.dragTo(gameBoard1, { targetPosition: { x: 400, y: 300 } });

    // Player 2: Verify they see the asset movement
    const gameBoard2 = page2.locator('[data-testid="game-board"]');
    const asset2 = gameBoard2.locator('[data-testid^="board-asset-"]').first();
    
    // Check asset position synchronized
    await expect(asset2).toHaveCSS('transform', /translate\(400px, 300px\)/);

    // Player 2: Send chat message
    await page2.fill('[data-testid="chat-input"]', 'Hello from Player 2!');
    await page2.press('[data-testid="chat-input"]', 'Enter');

    // Player 1: See the chat message
    await expect(page1.locator('[data-testid="chat-messages"]'))
      .toContainText('Hello from Player 2!');

    // Cleanup
    await context1.close();
    await context2.close();
  });

  test('should handle connection resilience', async ({ page }) => {
    // Navigate and authenticate
    await page.goto('/');
    await page.evaluate(() => {
      window.localStorage.setItem('auth-token', 'resilience-test-token');
      window.dispatchEvent(new CustomEvent('auth-state-change', {
        detail: { user: { uid: 'resilience-user', displayName: 'Resilience User' } }
      }));
    });

    // Create room
    await page.click('[data-testid="create-room-button"]');
    await page.fill('[data-testid="room-name-input"]', 'Connection Test Room');
    await page.click('[data-testid="create-room-submit"]');

    // Verify initial connection
    await expect(page.locator('[data-testid="connection-status"]')).toContainText('Connected');

    // Simulate network interruption
    await page.evaluate(() => {
      // Mock WebSocket disconnect
      window.dispatchEvent(new CustomEvent('websocket-disconnect'));
    });

    // Verify reconnection attempt
    await expect(page.locator('[data-testid="connection-status"]')).toContainText('Reconnecting');

    // Simulate reconnection
    await page.evaluate(() => {
      window.dispatchEvent(new CustomEvent('websocket-reconnect'));
    });

    // Verify connection restored
    await expect(page.locator('[data-testid="connection-status"]')).toContainText('Connected');
  });
});

test.describe('Admin Interface E2E Tests', () => {
  test('should manage game systems', async ({ page }) => {
    // Navigate to admin panel
    await page.goto('/admin');
    
    // Authenticate as admin
    await page.evaluate(() => {
      window.localStorage.setItem('auth-token', 'admin-token');
      window.dispatchEvent(new CustomEvent('auth-state-change', {
        detail: { 
          user: { 
            uid: 'admin-user', 
            displayName: 'Admin User',
            customClaims: { admin: true }
          } 
        }
      }));
    });

    // Navigate to game systems
    await page.click('[data-testid="game-systems-tab"]');
    await expect(page.locator('[data-testid="systems-list"]')).toBeVisible();

    // Create new game system
    await page.click('[data-testid="create-system-button"]');
    await page.fill('[data-testid="system-name"]', 'Test Card Game System');
    await page.fill('[data-testid="system-description"]', 'E2E test system for card games');
    await page.selectOption('[data-testid="system-category"]', 'card-game');
    await page.check('[data-testid="system-public"]');
    
    await page.click('[data-testid="save-system"]');

    // Verify system appears in list
    await expect(page.locator('[data-testid="systems-list"]'))
      .toContainText('Test Card Game System');

    // Upload system assets
    await page.click('[data-testid="system-assets-tab"]');
    const fileInput = page.locator('input[type="file"]');
    await fileInput.setInputFiles([
      './tests/fixtures/card-back.png',
      './tests/fixtures/card-front.png'
    ]);

    await expect(page.locator('[data-testid="asset-upload-success"]')).toBeVisible();

    // Configure system settings
    await page.click('[data-testid="system-settings-tab"]');
    await page.fill('[data-testid="deck-size"]', '52');
    await page.check('[data-testid="allow-shuffle"]');
    await page.check('[data-testid="show-card-counts"]');
    
    // Publish system
    await page.click('[data-testid="publish-system"]');
    await expect(page.locator('[data-testid="system-status"]')).toContainText('Published');
    
    // Verify system is available for room creation
    await page.goto('/');
    await page.click('[data-testid="create-room-button"]');
    await expect(page.locator('[data-testid="game-system-select"]'))
      .toContainText('Test Card Game System');
  });
});

test.describe('Performance and Load Testing', () => {
  test('should handle rapid asset movements', async ({ page }) => {
    await page.goto('/');
    
    // Setup authentication and room
    await page.evaluate(() => {
      window.localStorage.setItem('auth-token', 'performance-token');
      window.dispatchEvent(new CustomEvent('auth-state-change', {
        detail: { user: { uid: 'perf-user', displayName: 'Performance User' } }
      }));
    });

    await page.click('[data-testid="create-room-button"]');
    await page.fill('[data-testid="room-name-input"]', 'Performance Test Room');
    await page.click('[data-testid="create-room-submit"]');

    // Place multiple assets for testing
    const gameBoard = page.locator('[data-testid="game-board"]');
    
    // Measure performance of rapid movements
    const startTime = Date.now();
    
    for (let i = 0; i < 20; i++) {
      const asset = gameBoard.locator('[data-testid^="board-asset-"]').first();
      await asset.dragTo(gameBoard, {
        targetPosition: { x: 100 + (i * 10), y: 100 + (i * 10) }
      });
    }
    
    const endTime = Date.now();
    const duration = endTime - startTime;
    
    // Verify performance is acceptable (should complete in reasonable time)
    expect(duration).toBeLessThan(10000); // 10 seconds max for 20 movements
  });

  test('should handle large asset libraries', async ({ page }) => {
    await page.goto('/');
    
    // Simulate large asset library
    await page.evaluate(() => {
      // Mock large number of assets
      window.mockAssets = Array.from({ length: 500 }, (_, i) => ({
        id: `asset-${i}`,
        name: `Test Asset ${i}`,
        type: 'card',
        url: `/mock-assets/asset-${i}.png`
      }));
    });

    // Measure rendering performance
    const startTime = await page.evaluate(() => performance.now());
    
    await page.click('[data-testid="asset-library-toggle"]');
    await expect(page.locator('[data-testid="asset-library"]')).toBeVisible();
    
    const endTime = await page.evaluate(() => performance.now());
    const renderTime = endTime - startTime;
    
    // Verify reasonable render time for large asset library
    expect(renderTime).toBeLessThan(2000); // 2 seconds max
  });
});
