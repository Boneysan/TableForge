/**
 * E2E Test Utilities - Phase 2 Week 3
 * Common utilities and helpers for end-to-end testing
 */

import { Page, expect } from '@playwright/test';

export interface TestUser {
  id: string;
  email: string;
  displayName: string;
  role: 'user' | 'admin';
}

export interface TestAsset {
  id: string;
  name: string;
  type: 'card' | 'dice' | 'board' | 'token';
  url: string;
}

// Extend Window interface for WebSocket state
declare global {
  interface Window {
    wsConnectionState?: string;
  }
}

export class E2EUtils {
  constructor(private page: Page) {}

  /**
   * Authenticate user for E2E tests
   */
  async authenticateUser(user: TestUser): Promise<void> {
    // Navigate to login if not already there
    if (!this.page.url().includes('/login')) {
      await this.page.goto('/');
      
      // Check if user is already authenticated
      const isAuthenticated = await this.page.locator('[data-testid="user-menu"]').isVisible();
      if (isAuthenticated) {
        await this.logoutUser();
      }
    }

    // Mock authentication for E2E testing
    await this.page.evaluate((testUser) => {
      // Store user data in localStorage for mock auth
      localStorage.setItem('e2e-test-user', JSON.stringify(testUser));
      
      // Dispatch custom event to trigger auth state change
      window.dispatchEvent(new CustomEvent('e2e-auth-change', {
        detail: { user: testUser }
      }));
    }, user);

    // Wait for authentication to complete
    await this.page.waitForSelector('[data-testid="user-menu"]', { timeout: 10000 });
    
    // Verify user is authenticated
    const userMenu = this.page.locator('[data-testid="user-menu"]');
    await expect(userMenu).toContainText(user.displayName);
  }

  /**
   * Logout current user
   */
  async logoutUser(): Promise<void> {
    const userMenu = this.page.locator('[data-testid="user-menu"]');
    if (await userMenu.isVisible()) {
      await userMenu.click();
      await this.page.click('[data-testid="logout-button"]');
      
      // Wait for logout to complete
      await this.page.waitForSelector('[data-testid="sign-in-button"]', { timeout: 5000 });
    }
  }

  /**
   * Create a new game room
   */
  async createGameRoom(roomName: string): Promise<string> {
    await this.page.click('[data-testid="create-room-button"]');
    await this.page.fill('[data-testid="room-name-input"]', roomName);
    await this.page.click('[data-testid="create-room-submit"]');

    // Wait for navigation to room
    await this.page.waitForURL(/\/room\/.+/, { timeout: 10000 });
    
    // Extract room ID from URL
    const url = this.page.url();
    const roomId = url.match(/\/room\/(.+)$/)?.[1];
    if (!roomId) {
      throw new Error('Failed to extract room ID from URL');
    }

    return roomId;
  }

  /**
   * Join an existing room by ID
   */
  async joinRoom(roomId: string): Promise<void> {
    await this.page.goto(`/room/${roomId}`);
    
    // Wait for room to load
    await this.page.waitForSelector('[data-testid="game-board"]', { timeout: 10000 });
  }

  /**
   * Upload a test asset
   */
  async uploadAsset(filePath: string, assetName?: string): Promise<void> {
    // Navigate to admin interface
    await this.page.click('[data-testid="admin-interface-button"]');
    await this.page.click('[data-testid="tab-assets"]');

    // Upload file
    const fileInput = this.page.locator('input[type="file"]');
    await fileInput.setInputFiles(filePath);

    // Wait for upload to complete
    await this.page.waitForSelector('[data-testid="upload-success"]', { timeout: 15000 });

    if (assetName) {
      // Verify asset appears with correct name
      await expect(this.page.locator(`[data-testid="asset-${assetName}"]`)).toBeVisible();
    }
  }

  /**
   * Upload a test asset with mock data - returns asset ID
   */
  async uploadTestAsset(filename: string, mimeType: string): Promise<string> {
    const mockAssetData = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChAGA3zBsKQAAAABJRU5ErkJggg==', 'base64');
    
    // Create file input
    const fileInput = this.page.locator('[data-testid="asset-upload-input"]');
    await fileInput.setInputFiles([{
      name: filename,
      mimeType,
      buffer: mockAssetData
    }]);

    // Wait for upload to complete and get asset ID
    await this.page.waitForSelector('[data-testid="upload-success"]', { timeout: 10000 });
    
    // Return a mock asset ID based on filename
    return `test-asset-${filename.replace(/\./g, '-')}`;
  }

  /**
   * Drag and drop an asset to the board
   */
  async dragAssetToBoard(assetId: string, targetX: number, targetY: number): Promise<void> {
    const asset = this.page.locator(`[data-testid="asset-${assetId}"]`);
    const board = this.page.locator('[data-testid="game-board"]');

    // Get board position for offset calculation
    const boardBox = await board.boundingBox();
    if (!boardBox) {
      throw new Error('Could not get board bounding box');
    }

    await asset.dragTo(board, {
      targetPosition: { x: targetX, y: targetY }
    });

    // Wait for asset to appear on board
    await this.page.waitForSelector(`[data-testid="board-asset-${assetId}"]`, { timeout: 5000 });
  }

  /**
   * Send a chat message
   */
  async sendChatMessage(message: string): Promise<void> {
    await this.page.fill('[data-testid="chat-input"]', message);
    await this.page.press('[data-testid="chat-input"]', 'Enter');

    // Wait for message to appear in chat
    await expect(this.page.locator('[data-testid="chat-messages"]')).toContainText(message);
  }

  /**
   * Roll dice
   */
  async rollDice(diceType: string = 'd20', count: number = 1): Promise<number[]> {
    await this.page.click('[data-testid="dice-roller"]');
    await this.page.selectOption('[data-testid="dice-type"]', diceType);
    await this.page.fill('[data-testid="dice-count"]', count.toString());
    await this.page.click('[data-testid="roll-dice"]');

    // Wait for results
    await this.page.waitForSelector('[data-testid="dice-result"]', { timeout: 5000 });

    // Extract results
    const resultText = await this.page.locator('[data-testid="dice-result"]').textContent();
    const results = resultText?.match(/\d+/g)?.map(Number) || [];
    
    return results;
  }

  /**
   * Switch between player and GM view
   */
  async switchToGMView(): Promise<void> {
    await this.page.click('[data-testid="switch-to-gm"]');
    await expect(this.page.locator('[data-testid="gm-controls"]')).toBeVisible();
  }

  async switchToPlayerView(): Promise<void> {
    await this.page.click('[data-testid="switch-to-player"]');
    await expect(this.page.locator('[data-testid="player-controls"]')).toBeVisible();
  }

  /**
   * Wait for WebSocket connection
   */
  async waitForWebSocketConnection(): Promise<void> {
    await this.page.waitForFunction(() => {
      return window.wsConnectionState === 'connected';
    }, { timeout: 10000 });
  }

  /**
   * Verify asset synchronization between clients
   */
  async verifyAssetPosition(assetId: string, expectedX: number, expectedY: number, tolerance: number = 5): Promise<void> {
    const asset = this.page.locator(`[data-testid="board-asset-${assetId}"]`);
    await expect(asset).toBeVisible();

    // Get actual position
    const transform = await asset.evaluate((el) => {
      const style = window.getComputedStyle(el);
      return style.transform;
    });

    // Parse transform matrix to get position
    const matrixMatch = transform.match(/matrix\(([^)]+)\)/);
    if (matrixMatch && matrixMatch[1]) {
      const values = matrixMatch[1].split(',').map(Number);
      const actualX = values[4];
      const actualY = values[5];

      // Check within tolerance
      if (actualX !== undefined && actualY !== undefined) {
        expect(Math.abs(actualX - expectedX)).toBeLessThan(tolerance);
        expect(Math.abs(actualY - expectedY)).toBeLessThan(tolerance);
      }
    }
  }

  /**
   * Get test users from environment
   */
  static getTestUsers(): TestUser[] {
    const usersJson = process.env['E2E_TEST_USERS'];
    return usersJson ? JSON.parse(usersJson) : [];
  }

  /**
   * Get test assets from environment
   */
  static getTestAssets(): TestAsset[] {
    const assetsJson = process.env['E2E_TEST_ASSETS'];
    return assetsJson ? JSON.parse(assetsJson) : [];
  }

  /**
   * Take screenshot with timestamp
   */
  async takeTimestampedScreenshot(name: string): Promise<void> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    await this.page.screenshot({ 
      path: `test-results/screenshots/${name}-${timestamp}.png`,
      fullPage: true
    });
  }

  /**
   * Assert no console errors
   */
  async assertNoConsoleErrors(): Promise<void> {
    const consoleErrors: string[] = [];
    
    this.page.on('console', (msg) => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });

    // Wait a moment for any async errors
    await this.page.waitForTimeout(1000);

    if (consoleErrors.length > 0) {
      throw new Error(`Console errors detected: ${consoleErrors.join(', ')}`);
    }
  }
}

/**
 * Create a new page with common setup
 */
export async function createTestPage(page: Page): Promise<E2EUtils> {
  // Set up console error monitoring
  const consoleErrors: string[] = [];
  page.on('console', (msg) => {
    if (msg.type() === 'error') {
      consoleErrors.push(msg.text());
    }
  });

  // Set up network monitoring for debugging
  page.on('response', (response) => {
    if (!response.ok() && response.status() !== 404) {
      console.log(`HTTP ${response.status()}: ${response.url()}`);
    }
  });

  return new E2EUtils(page);
}
