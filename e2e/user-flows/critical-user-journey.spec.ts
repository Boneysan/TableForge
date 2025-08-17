/**
 * Critical User Journey Tests - Phase 2 Week 3
 * End-to-end testing of complete user workflows
 */

import { test, expect } from '@playwright/test';
import { createTestPage, E2EUtils } from '../utils/test-utils';

test.describe('Critical User Journey: Complete Game Session', () => {
  let utils: E2EUtils;
  let testUsers: any[];

  test.beforeEach(async ({ page }) => {
    utils = await createTestPage(page);
    testUsers = E2EUtils.getTestUsers();
  });

  test('should complete full game session lifecycle', async ({ page }) => {
    test.setTimeout(120000); // Extended timeout for full workflow

    const user = testUsers.find(u => u.role === 'user');
    if (!user) {
      test.skip(true, 'No test user available');
    }

    // Step 1: User Authentication
    await test.step('User authenticates successfully', async () => {
      await page.goto('/');
      await utils.authenticateUser(user);
      
      // Verify authentication
      await expect(page.locator('[data-testid="user-menu"]')).toContainText(user.displayName);
    });

    // Step 2: Room Creation
    let roomId: string;
    await test.step('User creates a new game room', async () => {
      roomId = await utils.createGameRoom('E2E Test Game Room');
      
      // Verify room creation
      expect(roomId).toBeTruthy();
      await expect(page).toHaveURL(`/room/${roomId}`);
      await expect(page.locator('[data-testid="room-title"]')).toContainText('E2E Test Game Room');
    });

    // Step 3: Asset Management
    await test.step('User uploads and manages game assets', async () => {
      // Switch to admin/GM view for asset management
      await utils.switchToGMView();
      
      // Navigate to asset management
      await page.click('[data-testid="admin-interface-button"]');
      await page.click('[data-testid="tab-assets"]');

      // Create a mock file for testing
      const fileInput = page.locator('input[type="file"]');
      await fileInput.setInputFiles([{
        name: 'test-card.png',
        mimeType: 'image/png',
        buffer: Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChAGA3zBsKQAAAABJRU5ErkJggg==', 'base64')
      }]);

      // Wait for upload success
      await expect(page.locator('[data-testid="upload-success"]')).toBeVisible({ timeout: 10000 });
      
      // Verify asset appears in list
      await expect(page.locator('[data-testid^="asset-"]')).toBeVisible();
    });

    // Step 4: Board Interaction
    await test.step('User places and manipulates assets on game board', async () => {
      // Switch back to game view
      await page.click('[data-testid="switch-to-game-view"]');
      
      // Drag asset to board
      const asset = page.locator('[data-testid^="asset-"]').first();
      const board = page.locator('[data-testid="game-board"]');
      
      await asset.dragTo(board, {
        targetPosition: { x: 200, y: 200 }
      });

      // Verify asset is placed on board
      await expect(page.locator('[data-testid^="board-asset-"]')).toBeVisible();
      
      // Move asset around the board
      const boardAsset = page.locator('[data-testid^="board-asset-"]').first();
      await boardAsset.dragTo(board, {
        targetPosition: { x: 400, y: 300 }
      });

      // Right-click for context menu
      await boardAsset.click({ button: 'right' });
      await expect(page.locator('[data-testid="asset-context-menu"]')).toBeVisible();
      
      // Flip asset
      await page.click('[data-testid="flip-asset"]');
      await expect(page.locator('[data-testid="asset-flipped"]')).toBeVisible();
    });

    // Step 5: Chat Functionality
    await test.step('User uses chat system', async () => {
      const testMessage = 'Hello from E2E test!';
      await utils.sendChatMessage(testMessage);
      
      // Verify message appears in chat
      await expect(page.locator('[data-testid="chat-messages"]')).toContainText(testMessage);
      
      // Test different message types
      await utils.sendChatMessage('/roll 1d20');
      await expect(page.locator('[data-testid="chat-messages"]')).toContainText('rolled');
    });

    // Step 6: Dice Rolling
    await test.step('User rolls dice', async () => {
      const results = await utils.rollDice('d20', 2);
      
      // Verify dice results
      expect(results).toHaveLength(2);
      results.forEach(result => {
        expect(result).toBeGreaterThanOrEqual(1);
        expect(result).toBeLessThanOrEqual(20);
      });
      
      // Verify dice results appear in chat
      await expect(page.locator('[data-testid="chat-messages"]')).toContainText('rolled');
    });

    // Step 7: Game State Persistence
    await test.step('Game state is saved and persisted', async () => {
      // Trigger save
      await page.click('[data-testid="save-game"]');
      await expect(page.locator('[data-testid="save-success"]')).toBeVisible();
      
      // Reload page to test persistence
      await page.reload();
      await page.waitForLoadState('networkidle');
      
      // Verify assets are still on board
      await expect(page.locator('[data-testid^="board-asset-"]')).toBeVisible();
      
      // Verify chat history is preserved
      const testMessage = 'Hello from E2E test!';
      await expect(page.locator('[data-testid="chat-messages"]')).toContainText(testMessage);
    });

    // Step 8: Cleanup
    await test.step('User leaves room', async () => {
      await page.click('[data-testid="leave-room"]');
      await expect(page).toHaveURL('/');
    });
  });

  test('should handle game session with multiple asset types', async ({ page }) => {
    const user = testUsers.find(u => u.role === 'user');
    if (!user) {
      test.skip(true, 'No test user available');
    }

    await utils.authenticateUser(user);
    await utils.createGameRoom('Multi-Asset Test Room');

    await test.step('Upload different asset types', async () => {
      await utils.switchToGMView();
      await page.click('[data-testid="admin-interface-button"]');
      await page.click('[data-testid="tab-assets"]');

      // Upload multiple asset types
      const assetTypes = [
        { name: 'card.png', type: 'card' },
        { name: 'dice.png', type: 'dice' },
        { name: 'token.png', type: 'token' }
      ];

      for (const asset of assetTypes) {
        const fileInput = page.locator('input[type="file"]');
        await fileInput.setInputFiles([{
          name: asset.name,
          mimeType: 'image/png',
          buffer: Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChAGA3zBsKQAAAABJRU5ErkJggg==', 'base64')
        }]);

        await expect(page.locator('[data-testid="upload-success"]')).toBeVisible();
      }

      // Verify all assets uploaded
      const assetCount = await page.locator('[data-testid^="asset-"]').count();
      expect(assetCount).toBeGreaterThanOrEqual(assetTypes.length);
    });

    await test.step('Interact with different asset types', async () => {
      await page.click('[data-testid="switch-to-game-view"]');
      
      const board = page.locator('[data-testid="game-board"]');
      const assets = page.locator('[data-testid^="asset-"]');
      
      // Place multiple assets on board
      const assetCount = await assets.count();
      for (let i = 0; i < Math.min(assetCount, 3); i++) {
        const asset = assets.nth(i);
        await asset.dragTo(board, {
          targetPosition: { x: 150 + (i * 100), y: 150 + (i * 50) }
        });
        
        // Verify asset is placed
        await expect(page.locator('[data-testid^="board-asset-"]').nth(i)).toBeVisible();
      }

      // Test different interactions on each asset type
      const boardAssets = page.locator('[data-testid^="board-asset-"]');
      const boardAssetCount = await boardAssets.count();
      
      for (let i = 0; i < boardAssetCount; i++) {
        const boardAsset = boardAssets.nth(i);
        
        // Right-click for context menu
        await boardAsset.click({ button: 'right' });
        await expect(page.locator('[data-testid="asset-context-menu"]')).toBeVisible();
        
        // Test different actions based on asset type
        if (await page.locator('[data-testid="shuffle-deck"]').isVisible()) {
          // Card-specific action
          await page.click('[data-testid="shuffle-deck"]');
        } else if (await page.locator('[data-testid="roll-dice"]').isVisible()) {
          // Dice-specific action
          await page.click('[data-testid="roll-dice"]');
        } else {
          // Generic action
          await page.click('[data-testid="flip-asset"]');
        }
        
        // Close context menu
        await page.keyboard.press('Escape');
      }
    });
  });

  test('should handle errors gracefully', async ({ page }) => {
    const user = testUsers.find(u => u.role === 'user');
    if (!user) {
      test.skip(true, 'No test user available');
    }

    await test.step('Handle network errors during asset upload', async () => {
      await utils.authenticateUser(user);
      await utils.createGameRoom('Error Test Room');
      await utils.switchToGMView();
      
      // Intercept upload request to simulate network error
      await page.route('/api/assets/upload', route => {
        route.fulfill({ status: 500, body: 'Server Error' });
      });

      await page.click('[data-testid="admin-interface-button"]');
      await page.click('[data-testid="tab-assets"]');

      const fileInput = page.locator('input[type="file"]');
      await fileInput.setInputFiles([{
        name: 'error-test.png',
        mimeType: 'image/png',
        buffer: Buffer.from('test')
      }]);

      // Verify error is displayed
      await expect(page.locator('[data-testid="upload-error"]')).toBeVisible();
    });

    await test.step('Handle WebSocket disconnection', async () => {
      // Simulate WebSocket disconnection
      await page.evaluate(() => {
        if ((window as any).wsConnection) {
          (window as any).wsConnection.close();
        }
      });

      // Verify reconnection attempt
      await expect(page.locator('[data-testid="connection-status"]')).toContainText('Reconnecting');
      
      // Wait for reconnection
      await utils.waitForWebSocketConnection();
      await expect(page.locator('[data-testid="connection-status"]')).toContainText('Connected');
    });
  });
});
