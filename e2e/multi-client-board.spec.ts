/**
 * End-to-end tests for multi-client board interactions using Playwright
 */

import { test, expect, type Page, type BrowserContext } from '@playwright/test';

// Helper functions
async function loginUser(page: Page, userName: string = 'Test User') {
  // Mock authentication - in real app, this would go through actual auth flow
  await page.goto('/');
  
  // Wait for auth to complete or simulate login
  await page.waitForSelector('[data-testid="user-menu"]', { timeout: 10000 });
  
  // Verify user is logged in
  const userMenu = page.locator('[data-testid="user-menu"]');
  await expect(userMenu).toBeVisible();
}

async function createGameRoom(page: Page, roomName: string) {
  await page.click('[data-testid="create-room-button"]');
  
  await page.fill('[data-testid="room-name-input"]', roomName);
  await page.selectOption('[data-testid="game-system-select"]', 'test-system');
  
  await page.click('[data-testid="create-room-submit"]');
  
  // Wait for room creation and redirect
  await page.waitForSelector('[data-testid="game-board"]');
  
  // Get room ID from URL
  const url = page.url();
  const roomId = url.split('/rooms/')[1];
  return roomId;
}

async function joinGameRoom(page: Page, roomId: string) {
  await page.goto(`/rooms/${roomId}`);
  await page.waitForSelector('[data-testid="game-board"]');
}

async function addAssetToBoard(page: Page, assetName: string) {
  // Open asset library
  await page.click('[data-testid="asset-library-button"]');
  
  // Search for asset
  await page.fill('[data-testid="asset-search"]', assetName);
  
  // Select first asset
  const firstAsset = page.locator('[data-testid^="asset-item-"]').first();
  await firstAsset.click();
  
  // Add to board
  await page.click('[data-testid="add-to-board-button"]');
  
  // Wait for asset to appear on board
  await page.waitForSelector('[data-testid^="board-asset-"]');
}

test.describe('Multi-Client Board Interactions', () => {
  let hostContext: BrowserContext;
  let playerContext: BrowserContext;
  let hostPage: Page;
  let playerPage: Page;
  let roomId: string;

  test.beforeAll(async ({ browser }) => {
    // Create separate browser contexts for host and player
    hostContext = await browser.newContext();
    playerContext = await browser.newContext();
    
    hostPage = await hostContext.newPage();
    playerPage = await playerContext.newPage();
  });

  test.afterAll(async () => {
    await hostContext.close();
    await playerContext.close();
  });

  test.beforeEach(async () => {
    // Login both users
    await loginUser(hostPage, 'Host User');
    await loginUser(playerPage, 'Player User');
    
    // Host creates room
    roomId = await createGameRoom(hostPage, `Test Room ${Date.now()}`);
    
    // Player joins room
    await joinGameRoom(playerPage, roomId);
    
    // Wait for both clients to be connected
    await Promise.all([
      hostPage.waitForSelector('[data-testid="online-indicator"]'),
      playerPage.waitForSelector('[data-testid="online-indicator"]'),
    ]);
  });

  test.describe('Real-time Asset Movement', () => {
    test('should sync asset movements between clients', async () => {
      // Host adds an asset to the board
      await addAssetToBoard(hostPage, 'Test Token');
      
      // Player should see the asset appear
      await playerPage.waitForSelector('[data-testid^="board-asset-"]');
      const playerAsset = playerPage.locator('[data-testid^="board-asset-"]').first();
      await expect(playerAsset).toBeVisible();
      
      // Get initial position
      const initialPosition = await hostPage.locator('[data-testid^="board-asset-"]').first().boundingBox();
      
      // Host moves the asset
      const hostAsset = hostPage.locator('[data-testid^="board-asset-"]').first();
      await hostAsset.dragTo(hostPage.locator('[data-testid="game-board"]'), {
        targetPosition: { x: 200, y: 300 },
      });
      
      // Player should see the movement
      await playerPage.waitForTimeout(500); // Allow time for sync
      
      const newPosition = await playerPage.locator('[data-testid^="board-asset-"]').first().boundingBox();
      expect(newPosition!.x).not.toBe(initialPosition!.x);
      expect(newPosition!.y).not.toBe(initialPosition!.y);
    });

    test('should handle simultaneous movements gracefully', async () => {
      // Add two assets
      await addAssetToBoard(hostPage, 'Token A');
      await addAssetToBoard(hostPage, 'Token B');
      
      // Wait for assets to appear on both clients
      await Promise.all([
        hostPage.waitForSelector('[data-testid^="board-asset-"]:nth-child(2)'),
        playerPage.waitForSelector('[data-testid^="board-asset-"]:nth-child(2)'),
      ]);
      
      // Both clients move different assets simultaneously
      const [hostAsset1, hostAsset2] = await hostPage.locator('[data-testid^="board-asset-"]').all();
      const [playerAsset1, playerAsset2] = await playerPage.locator('[data-testid^="board-asset-"]').all();
      
      await Promise.all([
        hostAsset1.dragTo(hostPage.locator('[data-testid="game-board"]'), {
          targetPosition: { x: 100, y: 100 },
        }),
        playerAsset2.dragTo(playerPage.locator('[data-testid="game-board"]'), {
          targetPosition: { x: 300, y: 300 },
        }),
      ]);
      
      // Allow time for synchronization
      await Promise.all([
        hostPage.waitForTimeout(1000),
        playerPage.waitForTimeout(1000),
      ]);
      
      // Both clients should see both movements
      const hostAssets = await hostPage.locator('[data-testid^="board-asset-"]').all();
      const playerAssets = await playerPage.locator('[data-testid^="board-asset-"]').all();
      
      expect(hostAssets).toHaveLength(2);
      expect(playerAssets).toHaveLength(2);
      
      // Positions should be synchronized
      for (let i = 0; i < 2; i++) {
        const hostPos = await hostAssets[i].boundingBox();
        const playerPos = await playerAssets[i].boundingBox();
        
        expect(Math.abs(hostPos!.x - playerPos!.x)).toBeLessThan(5);
        expect(Math.abs(hostPos!.y - playerPos!.y)).toBeLessThan(5);
      }
    });

    test('should show other users cursors and selections', async () => {
      await addAssetToBoard(hostPage, 'Cursor Test Token');
      
      // Player selects an asset
      const playerAsset = playerPage.locator('[data-testid^="board-asset-"]').first();
      await playerAsset.click();
      
      // Host should see player's selection indicator
      await hostPage.waitForSelector('[data-testid="user-selection-indicator"]');
      const selectionIndicator = hostPage.locator('[data-testid="user-selection-indicator"]');
      await expect(selectionIndicator).toBeVisible();
      
      // Indicator should show player's name/color
      await expect(selectionIndicator).toContainText('Player User');
    });
  });

  test.describe('Deck and Card Management', () => {
    test('should sync deck creation and card operations', async () => {
      // Host creates a deck
      await hostPage.click('[data-testid="create-deck-button"]');
      await hostPage.fill('[data-testid="deck-name-input"]', 'Test Deck');
      await hostPage.click('[data-testid="deck-create-submit"]');
      
      // Player should see the new deck
      await playerPage.waitForSelector('[data-testid^="deck-"]');
      const playerDeck = playerPage.locator('[data-testid^="deck-"]').first();
      await expect(playerDeck).toBeVisible();
      await expect(playerDeck).toContainText('Test Deck');
      
      // Host shuffles deck
      const hostDeck = hostPage.locator('[data-testid^="deck-"]').first();
      await hostDeck.click({ button: 'right' });
      await hostPage.click('[data-testid="shuffle-deck-option"]');
      
      // Player should see shuffle animation/indicator
      await playerPage.waitForSelector('[data-testid="deck-shuffling-indicator"]', { timeout: 2000 });
      
      // Host draws a card
      await hostDeck.click({ button: 'right' });
      await hostPage.click('[data-testid="draw-card-option"]');
      
      // Player should see card count decrease
      await playerPage.waitForFunction(
        () => {
          const deck = document.querySelector('[data-testid^="deck-"]');
          const countText = deck?.textContent || '';
          return countText.includes('cards: ') && !countText.includes('cards: 52');
        },
        undefined,
        { timeout: 3000 }
      );
    });

    test('should handle card visibility and permissions', async () => {
      // Create deck with cards
      await hostPage.click('[data-testid="create-deck-button"]');
      await hostPage.fill('[data-testid="deck-name-input"]', 'Permission Test Deck');
      await hostPage.click('[data-testid="deck-create-submit"]');
      
      // Draw card to hand
      const hostDeck = hostPage.locator('[data-testid^="deck-"]').first();
      await hostDeck.click({ button: 'right' });
      await hostPage.click('[data-testid="draw-to-hand-option"]');
      
      // Host should see card in their hand
      await hostPage.waitForSelector('[data-testid="player-hand"]');
      const hostHand = hostPage.locator('[data-testid="player-hand"]');
      await expect(hostHand.locator('[data-testid^="hand-card-"]')).toHaveCount(1);
      
      // Player should NOT see host's hand contents (only card backs)
      const playerHandArea = playerPage.locator('[data-testid="other-player-hand-host"]');
      if (await playerHandArea.isVisible()) {
        const cardBacks = playerHandArea.locator('[data-testid^="card-back-"]');
        await expect(cardBacks).toHaveCount(1);
        
        // Should not see actual card content
        const cardFronts = playerHandArea.locator('[data-testid^="card-front-"]');
        await expect(cardFronts).toHaveCount(0);
      }
    });
  });

  test.describe('Chat and Communication', () => {
    test('should sync chat messages between users', async () => {
      // Open chat panel
      await Promise.all([
        hostPage.click('[data-testid="chat-toggle-button"]'),
        playerPage.click('[data-testid="chat-toggle-button"]'),
      ]);
      
      // Host sends a message
      const hostChatInput = hostPage.locator('[data-testid="chat-input"]');
      await hostChatInput.fill('Hello from host!');
      await hostChatInput.press('Enter');
      
      // Player should see the message
      await playerPage.waitForSelector('[data-testid="chat-message"]:has-text("Hello from host!")');
      const playerChatMessage = playerPage.locator('[data-testid="chat-message"]').last();
      await expect(playerChatMessage).toContainText('Hello from host!');
      await expect(playerChatMessage).toContainText('Host User');
      
      // Player responds
      const playerChatInput = playerPage.locator('[data-testid="chat-input"]');
      await playerChatInput.fill('Hi from player!');
      await playerChatInput.press('Enter');
      
      // Host should see the response
      await hostPage.waitForSelector('[data-testid="chat-message"]:has-text("Hi from player!")');
      const hostChatMessage = hostPage.locator('[data-testid="chat-message"]').last();
      await expect(hostChatMessage).toContainText('Hi from player!');
      await expect(hostChatMessage).toContainText('Player User');
    });

    test('should show typing indicators', async () => {
      await Promise.all([
        hostPage.click('[data-testid="chat-toggle-button"]'),
        playerPage.click('[data-testid="chat-toggle-button"]'),
      ]);
      
      // Player starts typing
      const playerChatInput = playerPage.locator('[data-testid="chat-input"]');
      await playerChatInput.focus();
      await playerChatInput.type('Starting to type...', { delay: 100 });
      
      // Host should see typing indicator
      await hostPage.waitForSelector('[data-testid="typing-indicator"]');
      const typingIndicator = hostPage.locator('[data-testid="typing-indicator"]');
      await expect(typingIndicator).toContainText('Player User is typing');
      
      // Player sends message
      await playerChatInput.press('Enter');
      
      // Typing indicator should disappear
      await expect(typingIndicator).toBeHidden({ timeout: 3000 });
    });
  });

  test.describe('Dice Rolling and Random Events', () => {
    test('should sync dice rolls between clients', async () => {
      // Host rolls dice
      await hostPage.click('[data-testid="dice-panel-toggle"]');
      await hostPage.click('[data-testid="roll-d20-button"]');
      
      // Both clients should see the roll result
      await Promise.all([
        hostPage.waitForSelector('[data-testid="dice-result"]'),
        playerPage.waitForSelector('[data-testid="dice-result"]'),
      ]);
      
      const hostResult = await hostPage.locator('[data-testid="dice-result"]').textContent();
      const playerResult = await playerPage.locator('[data-testid="dice-result"]').textContent();
      
      expect(hostResult).toBe(playerResult);
      expect(hostResult).toMatch(/\d+/); // Should contain a number
      
      // Should show who rolled
      await expect(hostPage.locator('[data-testid="dice-roller-name"]')).toContainText('Host User');
      await expect(playerPage.locator('[data-testid="dice-roller-name"]')).toContainText('Host User');
    });

    test('should handle multiple simultaneous dice rolls', async () => {
      // Both users roll dice at the same time
      await Promise.all([
        hostPage.click('[data-testid="dice-panel-toggle"]'),
        playerPage.click('[data-testid="dice-panel-toggle"]'),
      ]);
      
      await Promise.all([
        hostPage.click('[data-testid="roll-d6-button"]'),
        playerPage.click('[data-testid="roll-d8-button"]'),
      ]);
      
      // Should see both results
      await hostPage.waitForSelector('[data-testid="dice-result"]:nth-child(2)');
      await playerPage.waitForSelector('[data-testid="dice-result"]:nth-child(2)');
      
      const hostResults = await hostPage.locator('[data-testid="dice-result"]').count();
      const playerResults = await playerPage.locator('[data-testid="dice-result"]').count();
      
      expect(hostResults).toBeGreaterThanOrEqual(2);
      expect(playerResults).toBeGreaterThanOrEqual(2);
    });
  });

  test.describe('Undo/Redo and State Management', () => {
    test('should sync undo/redo operations', async () => {
      // Add asset and move it
      await addAssetToBoard(hostPage, 'Undo Test Token');
      const asset = hostPage.locator('[data-testid^="board-asset-"]').first();
      
      // Get initial position
      const initialPos = await asset.boundingBox();
      
      // Move asset
      await asset.dragTo(hostPage.locator('[data-testid="game-board"]'), {
        targetPosition: { x: 200, y: 200 },
      });
      
      // Wait for sync
      await playerPage.waitForTimeout(500);
      
      // Host undoes the move
      await hostPage.click('[data-testid="undo-button"]');
      
      // Both clients should see the asset back at original position
      await hostPage.waitForTimeout(500);
      await playerPage.waitForTimeout(500);
      
      const hostPos = await hostPage.locator('[data-testid^="board-asset-"]').first().boundingBox();
      const playerPos = await playerPage.locator('[data-testid^="board-asset-"]').first().boundingBox();
      
      expect(Math.abs(hostPos!.x - initialPos!.x)).toBeLessThan(10);
      expect(Math.abs(playerPos!.x - initialPos!.x)).toBeLessThan(10);
    });

    test('should handle conflict resolution for simultaneous edits', async () => {
      await addAssetToBoard(hostPage, 'Conflict Test Token');
      
      // Both users try to move the same asset simultaneously
      const hostAsset = hostPage.locator('[data-testid^="board-asset-"]').first();
      const playerAsset = playerPage.locator('[data-testid^="board-asset-"]').first();
      
      await Promise.all([
        hostAsset.dragTo(hostPage.locator('[data-testid="game-board"]'), {
          targetPosition: { x: 100, y: 100 },
        }),
        playerAsset.dragTo(playerPage.locator('[data-testid="game-board"]'), {
          targetPosition: { x: 300, y: 300 },
        }),
      ]);
      
      // Wait for conflict resolution
      await Promise.all([
        hostPage.waitForTimeout(2000),
        playerPage.waitForTimeout(2000),
      ]);
      
      // Assets should be at the same position (conflict resolved)
      const hostPos = await hostPage.locator('[data-testid^="board-asset-"]').first().boundingBox();
      const playerPos = await playerPage.locator('[data-testid^="board-asset-"]').first().boundingBox();
      
      expect(Math.abs(hostPos!.x - playerPos!.x)).toBeLessThan(5);
      expect(Math.abs(hostPos!.y - playerPos!.y)).toBeLessThan(5);
    });
  });

  test.describe('Connection Handling', () => {
    test('should handle temporary disconnections gracefully', async () => {
      // Add asset and move it
      await addAssetToBoard(hostPage, 'Disconnect Test Token');
      
      // Simulate network disconnection for player
      await playerPage.context().setOffline(true);
      
      // Host moves asset while player is offline
      const hostAsset = hostPage.locator('[data-testid^="board-asset-"]').first();
      await hostAsset.dragTo(hostPage.locator('[data-testid="game-board"]'), {
        targetPosition: { x: 250, y: 250 },
      });
      
      // Player reconnects
      await playerPage.context().setOffline(false);
      
      // Player should sync to current state
      await playerPage.waitForSelector('[data-testid="online-indicator"]');
      await playerPage.waitForTimeout(2000); // Allow sync time
      
      const playerPos = await playerPage.locator('[data-testid^="board-asset-"]').first().boundingBox();
      const hostPos = await hostPage.locator('[data-testid^="board-asset-"]').first().boundingBox();
      
      expect(Math.abs(playerPos!.x - hostPos!.x)).toBeLessThan(10);
      expect(Math.abs(playerPos!.y - hostPos!.y)).toBeLessThan(10);
    });

    test('should show connection status to users', async () => {
      // Both users should show online status
      await expect(hostPage.locator('[data-testid="online-indicator"]')).toBeVisible();
      await expect(playerPage.locator('[data-testid="online-indicator"]')).toBeVisible();
      
      // Disconnect player
      await playerPage.context().setOffline(true);
      
      // Player should show offline status
      await expect(playerPage.locator('[data-testid="offline-indicator"]')).toBeVisible({ timeout: 5000 });
      
      // Reconnect
      await playerPage.context().setOffline(false);
      
      // Should show online again
      await expect(playerPage.locator('[data-testid="online-indicator"]')).toBeVisible({ timeout: 10000 });
    });
  });

  test.describe('Performance and Stress Testing', () => {
    test('should handle many assets without performance degradation', async () => {
      const assetCount = 20;
      
      // Add many assets
      for (let i = 0; i < assetCount; i++) {
        await addAssetToBoard(hostPage, `Performance Token ${i}`);
        
        // Small delay to avoid overwhelming the system
        if (i % 5 === 0) {
          await hostPage.waitForTimeout(200);
        }
      }
      
      // Player should see all assets
      await playerPage.waitForFunction(
        (count) => {
          return document.querySelectorAll('[data-testid^="board-asset-"]').length >= count;
        },
        assetCount,
        { timeout: 10000 }
      );
      
      const hostAssets = await hostPage.locator('[data-testid^="board-asset-"]').count();
      const playerAssets = await playerPage.locator('[data-testid^="board-asset-"]').count();
      
      expect(hostAssets).toBe(assetCount);
      expect(playerAssets).toBe(assetCount);
      
      // Performance check: moving an asset should still be responsive
      const startTime = Date.now();
      const lastAsset = hostPage.locator('[data-testid^="board-asset-"]').last();
      await lastAsset.dragTo(hostPage.locator('[data-testid="game-board"]'), {
        targetPosition: { x: 400, y: 400 },
      });
      const endTime = Date.now();
      
      // Movement should complete within reasonable time
      expect(endTime - startTime).toBeLessThan(3000);
    }, 30000); // Longer timeout for stress test

    test('should maintain sync with rapid operations', async () => {
      await addAssetToBoard(hostPage, 'Rapid Test Token');
      
      const asset = hostPage.locator('[data-testid^="board-asset-"]').first();
      
      // Perform many rapid movements
      for (let i = 0; i < 10; i++) {
        await asset.dragTo(hostPage.locator('[data-testid="game-board"]'), {
          targetPosition: { x: 50 + i * 20, y: 50 + i * 20 },
        });
        await hostPage.waitForTimeout(100);
      }
      
      // Allow time for final sync
      await playerPage.waitForTimeout(2000);
      
      // Final positions should be synchronized
      const hostPos = await hostPage.locator('[data-testid^="board-asset-"]').first().boundingBox();
      const playerPos = await playerPage.locator('[data-testid^="board-asset-"]').first().boundingBox();
      
      expect(Math.abs(hostPos!.x - playerPos!.x)).toBeLessThan(10);
      expect(Math.abs(hostPos!.y - playerPos!.y)).toBeLessThan(10);
    });
  });
});