/**
 * Multiplayer Interaction E2E Tests - Phase 2 Week 3
 * End-to-end testing of multi-client real-time interactions
 */

import { test, expect, Browser, BrowserContext, Page } from '@playwright/test';
import { createTestPage, E2EUtils } from '../utils/test-utils';

test.describe('Multiplayer Interaction E2E Tests', () => {
  let browser2: Browser;
  let context2: BrowserContext;
  let page2: Page;
  let utils1: E2EUtils;
  let utils2: E2EUtils;
  let testUsers: any[];
  let roomId: string;

  test.beforeEach(async ({ browser, page }) => {
    // Set up first client
    utils1 = await createTestPage(page);
    testUsers = E2EUtils.getTestUsers();

    // Set up second client
    browser2 = await browser.browserType().launch();
    context2 = await browser2.newContext();
    page2 = await context2.newPage();
    utils2 = await createTestPage(page2);

    // Create a shared room for testing
    await page.goto('/');
    await utils1.authenticateUser(testUsers[0]);
    roomId = await utils1.createGameRoom('Multiplayer Test Room');
  });

  test.afterEach(async () => {
    await context2?.close();
    await browser2?.close();
  });

  test('should handle multi-client room joining and synchronization', async ({ page }) => {
    await test.step('Second client joins the same room', async () => {
      // Authenticate second user
      await page2.goto('/');
      await utils2.authenticateUser(testUsers[1]);
      
      // Join the room
      await page2.goto(`/room/${roomId}`);
      
      // Verify room loaded for both clients
      await expect(page.locator('[data-testid="room-title"]')).toContainText('Multiplayer Test Room');
      await expect(page2.locator('[data-testid="room-title"]')).toContainText('Multiplayer Test Room');
    });

    await test.step('Verify user presence synchronization', async () => {
      // Check player list on both clients
      await expect(page.locator('[data-testid="player-list"]')).toContainText(testUsers[0].name);
      await expect(page.locator('[data-testid="player-list"]')).toContainText(testUsers[1].name);
      
      await expect(page2.locator('[data-testid="player-list"]')).toContainText(testUsers[0].name);
      await expect(page2.locator('[data-testid="player-list"]')).toContainText(testUsers[1].name);
      
      // Verify player count
      await expect(page.locator('[data-testid="player-count"]')).toContainText('2 players');
      await expect(page2.locator('[data-testid="player-count"]')).toContainText('2 players');
    });

    await test.step('Test real-time cursor synchronization', async () => {
      // Move cursor on first client
      await page.mouse.move(300, 200);
      
      // Verify cursor appears on second client
      await expect(page2.locator('[data-testid="remote-cursor-user1"]')).toBeVisible({ timeout: 2000 });
      
      // Move cursor on second client
      await page2.mouse.move(400, 300);
      
      // Verify cursor appears on first client
      await expect(page.locator('[data-testid="remote-cursor-user2"]')).toBeVisible({ timeout: 2000 });
    });
  });

  test('should synchronize asset movements between clients', async ({ page }) => {
    // Set up both clients in the room
    await page2.goto('/');
    await utils2.authenticateUser(testUsers[1]);
    await page2.goto(`/room/${roomId}`);

    await test.step('First client adds an asset to the board', async () => {
      // Upload and place asset from first client
      const assetId = await utils1.uploadTestAsset('multiplayer-card.png', 'image/png');
      await utils1.dragAssetToBoard(assetId, 200, 150);
      
      // Verify asset appears on both clients
      await expect(page.locator('[data-testid="board-asset"]')).toBeVisible();
      await expect(page2.locator('[data-testid="board-asset"]')).toBeVisible({ timeout: 3000 });
    });

    await test.step('Second client moves the asset', async () => {
      // Second client drags the asset
      const asset = page2.locator('[data-testid="board-asset"]');
      await asset.dragTo(page2.locator('[data-testid="game-board"]'), {
        targetPosition: { x: 400, y: 300 }
      });
      
      // Verify movement synchronized to first client
      await expect(page.locator('[data-testid="board-asset"]')).toHaveAttribute(
        'style', 
        /transform:\s*translate\(400px,\s*300px\)/,
        { timeout: 3000 }
      );
    });

    await test.step('Verify asset state persistence across clients', async () => {
      // First client modifies asset properties
      await page.locator('[data-testid="board-asset"]').click({ button: 'right' });
      await page.click('[data-testid="rotate-asset"]');
      
      // Verify rotation synchronized to second client
      await expect(page2.locator('[data-testid="board-asset"]')).toHaveAttribute(
        'style',
        /transform:.*rotate\(90deg\)/,
        { timeout: 3000 }
      );
    });
  });

  test('should handle real-time chat synchronization', async ({ page }) => {
    await page2.goto('/');
    await utils2.authenticateUser(testUsers[1]);
    await page2.goto(`/room/${roomId}`);

    await test.step('Exchange messages between clients', async () => {
      // First client sends message
      await utils1.sendChatMessage('Hello from client 1!');
      
      // Verify message appears on second client
      await expect(page2.locator('[data-testid="chat-messages"]')).toContainText('Hello from client 1!');
      
      // Second client responds
      await utils2.sendChatMessage('Hello back from client 2!');
      
      // Verify response appears on first client
      await expect(page.locator('[data-testid="chat-messages"]')).toContainText('Hello back from client 2!');
    });

    await test.step('Test typing indicators', async () => {
      // Start typing on first client
      const chatInput = page.locator('[data-testid="chat-input"]');
      await chatInput.focus();
      await chatInput.type('Testing typing indicator', { delay: 100 });
      
      // Verify typing indicator on second client
      await expect(page2.locator('[data-testid="typing-indicator"]')).toContainText(`${testUsers[0].name} is typing...`);
      
      // Send the message
      await page.keyboard.press('Enter');
      
      // Verify typing indicator disappears
      await expect(page2.locator('[data-testid="typing-indicator"]')).not.toBeVisible();
    });

    await test.step('Test message reactions and emoji responses', async () => {
      // First client adds reaction to message
      const lastMessage = page.locator('[data-testid="chat-message"]').last();
      await lastMessage.hover();
      await page.click('[data-testid="add-reaction"]');
      await page.click('[data-testid="emoji-thumbs-up"]');
      
      // Verify reaction appears on second client
      await expect(page2.locator('[data-testid="message-reactions"]').last()).toContainText('👍 1');
      
      // Second client adds same reaction
      const lastMessage2 = page2.locator('[data-testid="chat-message"]').last();
      await lastMessage2.hover();
      await page2.click('[data-testid="reaction-thumbs-up"]');
      
      // Verify reaction count updated on first client
      await expect(page.locator('[data-testid="message-reactions"]').last()).toContainText('👍 2');
    });
  });

  test('should handle collaborative dice rolling', async ({ page }) => {
    await page2.goto('/');
    await utils2.authenticateUser(testUsers[1]);
    await page2.goto(`/room/${roomId}`);

    await test.step('First client rolls dice', async () => {
      const result1 = await utils1.rollDice('d6', 2);
      const total1 = result1.reduce((sum, val) => sum + val, 0);
      
      // Verify dice result appears on both clients
      await expect(page.locator('[data-testid="dice-results"]')).toContainText(`rolled ${total1}`);
      await expect(page2.locator('[data-testid="dice-results"]')).toContainText(`rolled ${total1}`);
    });

    await test.step('Second client rolls dice', async () => {
      await utils2.rollDice('d20', 1);
      
      // Verify both results visible on both clients
      await expect(page.locator('[data-testid="dice-history"]')).toContainText(`${testUsers[1].name} rolled`);
      await expect(page2.locator('[data-testid="dice-history"]')).toContainText(`${testUsers[1].name} rolled`);
    });

    await test.step('Test group dice roll', async () => {
      // First client initiates group roll
      await page.click('[data-testid="group-dice-roll"]');
      await page.selectOption('[data-testid="dice-type"]', 'd10');
      await page.fill('[data-testid="dice-count"]', '1');
      await page.click('[data-testid="start-group-roll"]');
      
      // Verify group roll notification on second client
      await expect(page2.locator('[data-testid="group-roll-notification"]')).toBeVisible();
      
      // Second client joins the group roll
      await page2.click('[data-testid="join-group-roll"]');
      
      // Verify group results displayed on both clients
      await expect(page.locator('[data-testid="group-roll-results"]')).toBeVisible();
      await expect(page2.locator('[data-testid="group-roll-results"]')).toBeVisible();
    });
  });

  test('should handle turn-based gameplay mechanics', async ({ page }) => {
    await page2.goto('/');
    await utils2.authenticateUser(testUsers[1]);
    await page2.goto(`/room/${roomId}`);

    await test.step('Initialize turn-based game', async () => {
      // First client starts turn-based mode
      await page.click('[data-testid="game-settings"]');
      await page.check('[data-testid="enable-turn-order"]');
      await page.click('[data-testid="start-turns"]');
      
      // Verify turn order established
      await expect(page.locator('[data-testid="current-turn"]')).toContainText(testUsers[0].name);
      await expect(page2.locator('[data-testid="current-turn"]')).toContainText(testUsers[0].name);
    });

    await test.step('Test turn progression', async () => {
      // First client ends turn
      await page.click('[data-testid="end-turn"]');
      
      // Verify turn passed to second client
      await expect(page.locator('[data-testid="current-turn"]')).toContainText(testUsers[1].name);
      await expect(page2.locator('[data-testid="current-turn"]')).toContainText(testUsers[1].name);
      
      // Verify turn restrictions
      await expect(page.locator('[data-testid="not-your-turn"]')).toBeVisible();
      await expect(page2.locator('[data-testid="your-turn"]')).toBeVisible();
    });

    await test.step('Test turn timer synchronization', async () => {
      // Set turn timer
      await page2.click('[data-testid="game-settings"]');
      await page2.fill('[data-testid="turn-timer"]', '30');
      await page2.click('[data-testid="apply-settings"]');
      
      // Verify timer appears on both clients
      await expect(page.locator('[data-testid="turn-timer-display"]')).toBeVisible();
      await expect(page2.locator('[data-testid="turn-timer-display"]')).toBeVisible();
      
      // Verify timer countdown synchronization
      await page.waitForTimeout(2000);
      const timer1 = await page.locator('[data-testid="turn-timer-display"]').textContent();
      const timer2 = await page2.locator('[data-testid="turn-timer-display"]').textContent();
      
      // Timers should be within 1 second of each other
      const time1 = parseInt(timer1 || '0');
      const time2 = parseInt(timer2 || '0');
      expect(Math.abs(time1 - time2)).toBeLessThanOrEqual(1);
    });
  });

  test('should handle conflict resolution and concurrent edits', async ({ page }) => {
    await page2.goto('/');
    await utils2.authenticateUser(testUsers[1]);
    await page2.goto(`/room/${roomId}`);

    await test.step('Test concurrent asset editing', async () => {
      // Both clients add assets simultaneously
      const asset1Promise = utils1.uploadTestAsset('conflict-test-1.png', 'image/png');
      const asset2Promise = utils2.uploadTestAsset('conflict-test-2.png', 'image/png');
      
      const [assetId1, assetId2] = await Promise.all([asset1Promise, asset2Promise]);
      
      // Both clients try to place assets at same position
      const position = { x: 250, y: 200 };
      await Promise.all([
        utils1.dragAssetToBoard(assetId1, position.x, position.y),
        utils2.dragAssetToBoard(assetId2, position.x, position.y)
      ]);
      
      // Verify conflict resolution - assets should be offset
      const assets = page.locator('[data-testid="board-asset"]');
      await expect(assets).toHaveCount(2);
      
      // Verify assets are not overlapping exactly
      const positions = await assets.evaluateAll(elements => 
        elements.map(el => {
          const transform = el.style.transform;
          const match = transform.match(/translate\((\d+)px,\s*(\d+)px\)/);
          return match && match[1] && match[2] ? { x: parseInt(match[1]), y: parseInt(match[2]) } : null;
        })
      );
      
      expect(positions[0]).not.toEqual(positions[1]);
    });

    await test.step('Test optimistic updates and rollback', async () => {
      // First client starts moving an asset
      const asset = page.locator('[data-testid="board-asset"]').first();
      await asset.hover();
      
      // Simulate network interruption during move
      await page.route('/api/room/*/assets/*/move', route => {
        route.abort('failed');
      });
      
      // Attempt to move asset
      await asset.dragTo(page.locator('[data-testid="game-board"]'), {
        targetPosition: { x: 500, y: 400 }
      });
      
      // Verify optimistic update shows locally
      await expect(asset).toHaveAttribute('style', /transform:\s*translate\(500px,\s*400px\)/);
      
      // Wait for rollback
      await page.waitForTimeout(2000);
      
      // Verify rollback occurred
      await expect(asset).not.toHaveAttribute('style', /transform:\s*translate\(500px,\s*400px\)/);
    });
  });

  test('should handle client disconnection and reconnection', async ({ page }) => {
    await page2.goto('/');
    await utils2.authenticateUser(testUsers[1]);
    await page2.goto(`/room/${roomId}`);

    await test.step('Test graceful disconnection handling', async () => {
      // Verify both clients connected
      await expect(page.locator('[data-testid="player-count"]')).toContainText('2 players');
      await expect(page2.locator('[data-testid="player-count"]')).toContainText('2 players');
      
      // Simulate network disconnection for second client
      await page2.context().setOffline(true);
      
      // Verify disconnection reflected on first client
      await expect(page.locator('[data-testid="player-count"]')).toContainText('1 player', { timeout: 5000 });
      await expect(page.locator('[data-testid="player-status-offline"]')).toBeVisible();
    });

    await test.step('Test reconnection and state synchronization', async () => {
      // First client makes changes while second is offline
      const assetId = await utils1.uploadTestAsset('offline-change.png', 'image/png');
      await utils1.dragAssetToBoard(assetId, 300, 250);
      await utils1.sendChatMessage('Message sent while offline');
      
      // Reconnect second client
      await page2.context().setOffline(false);
      await page2.reload();
      await utils2.authenticateUser(testUsers[1]);
      await page2.goto(`/room/${roomId}`);
      
      // Verify state synchronized
      await expect(page2.locator('[data-testid="board-asset"]')).toBeVisible({ timeout: 5000 });
      await expect(page2.locator('[data-testid="chat-messages"]')).toContainText('Message sent while offline');
      
      // Verify both clients show correct player count
      await expect(page.locator('[data-testid="player-count"]')).toContainText('2 players');
      await expect(page2.locator('[data-testid="player-count"]')).toContainText('2 players');
    });
  });

  test('should handle multiplayer performance with many concurrent actions', async ({ page }) => {
    await page2.goto('/');
    await utils2.authenticateUser(testUsers[1]);
    await page2.goto(`/room/${roomId}`);

    await test.step('Test high-frequency asset movements', async () => {
      // Add multiple assets
      const assetIds = await Promise.all([
        utils1.uploadTestAsset('perf-test-1.png', 'image/png'),
        utils1.uploadTestAsset('perf-test-2.png', 'image/png'),
        utils2.uploadTestAsset('perf-test-3.png', 'image/png')
      ]);
      
      // Place assets on board
      await utils1.dragAssetToBoard(assetIds[0], 100, 100);
      await utils1.dragAssetToBoard(assetIds[1], 200, 100);
      await utils2.dragAssetToBoard(assetIds[2], 300, 100);
      
      // Perform rapid movements on both clients
      const movements = Array.from({ length: 10 }, (_, i) => ({
        x: 100 + (i * 20),
        y: 150 + (i * 10)
      }));
      
      const startTime = Date.now();
      
      // Concurrent rapid movements
      await Promise.all([
        // Client 1 moves first asset rapidly
        (async () => {
          for (const pos of movements) {
            const asset = page.locator('[data-testid="board-asset"]').first();
            await asset.dragTo(page.locator('[data-testid="game-board"]'), {
              targetPosition: pos
            });
            await page.waitForTimeout(50);
          }
        })(),
        // Client 2 moves second asset rapidly
        (async () => {
          for (const pos of movements) {
            const asset = page2.locator('[data-testid="board-asset"]').nth(1);
            await asset.dragTo(page2.locator('[data-testid="game-board"]'), {
              targetPosition: { x: pos.x + 100, y: pos.y }
            });
            await page2.waitForTimeout(50);
          }
        })()
      ]);
      
      const endTime = Date.now();
      const duration = endTime - startTime;
      
      // Verify performance acceptable (should complete within reasonable time)
      expect(duration).toBeLessThan(10000); // 10 seconds max
      
      // Verify final state synchronized
      await page.waitForTimeout(1000);
      const assets1 = await page.locator('[data-testid="board-asset"]').count();
      const assets2 = await page2.locator('[data-testid="board-asset"]').count();
      expect(assets1).toBe(assets2);
    });

    await test.step('Test chat message flood handling', async () => {
      // Send rapid messages from both clients
      const messages = Array.from({ length: 20 }, (_, i) => `Stress test message ${i + 1}`);
      
      await Promise.all([
        // Client 1 sends messages
        (async () => {
          for (let i = 0; i < 10; i++) {
            await utils1.sendChatMessage(`Client 1: ${messages[i]}`);
            await page.waitForTimeout(100);
          }
        })(),
        // Client 2 sends messages
        (async () => {
          for (let i = 10; i < 20; i++) {
            await utils2.sendChatMessage(`Client 2: ${messages[i]}`);
            await page2.waitForTimeout(100);
          }
        })()
      ]);
      
      // Verify all messages received on both clients
      await page.waitForTimeout(2000);
      
      const chatMessages1 = await page.locator('[data-testid="chat-message"]').count();
      const chatMessages2 = await page2.locator('[data-testid="chat-message"]').count();
      
      expect(chatMessages1).toBeGreaterThanOrEqual(20);
      expect(chatMessages2).toBeGreaterThanOrEqual(20);
      expect(chatMessages1).toBe(chatMessages2);
    });
  });
});
