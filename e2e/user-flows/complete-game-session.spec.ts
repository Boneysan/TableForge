// End-to-End Tests for Complete User Journey
import { test, expect } from '@playwright/test';

test.describe('Complete Game Session Flow', () => {
  test('should support full game lifecycle', async ({ page }) => {
    // Step 1: Authentication
    await page.goto('/');
    await page.click('[data-testid="sign-in-button"]');
    
    // Mock Firebase auth for E2E
    await page.evaluate(() => {
      (window as any).mockUser = {
        uid: 'e2e-user-123',
        email: 'e2e@test.com',
        displayName: 'E2E Test User'
      };
    });

    // Wait for authentication to complete
    await expect(page.locator('[data-testid="user-menu"]')).toBeVisible();

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
      (window as any).mockAssets = Array.from({ length: 500 }, (_, i) => ({
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
