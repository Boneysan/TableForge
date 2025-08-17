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

  test('should manage game system categories', async ({ page }) => {
    await page.goto('/admin');
    await page.click('[data-testid="game-systems-tab"]');

    // Test category filtering
    await page.selectOption('[data-testid="category-filter"]', 'card-game');
    await expect(page.locator('[data-testid="systems-list"] [data-category="card-game"]'))
      .toBeVisible();

    // Test search functionality
    await page.fill('[data-testid="system-search"]', 'Test Card Game');
    await expect(page.locator('[data-testid="systems-list"]'))
      .toContainText('Test Card Game');

    // Test system editing
    await page.locator('[data-testid="edit-system-button"]').first().click();
    await page.fill('[data-testid="system-name"]', 'Updated Test Card Game');
    await page.click('[data-testid="save-system"]');

    await expect(page.locator('[data-testid="systems-list"]'))
      .toContainText('Updated Test Card Game');
  });

  test('should handle asset management within systems', async ({ page }) => {
    await page.goto('/admin');
    await page.click('[data-testid="game-systems-tab"]');

    // Select existing system
    await page.locator('[data-testid="system-item"]').first().click();
    await page.click('[data-testid="system-assets-tab"]');

    // Upload multiple assets
    const fileInput = page.locator('input[type="file"]').first();
    await fileInput.setInputFiles([
      './tests/fixtures/test-card.png',
      './tests/fixtures/test-token.png',
      './tests/fixtures/test-map.png'
    ]);

    // Verify all assets uploaded
    await expect(page.locator('[data-testid="asset-item"]')).toHaveCount(3);

    // Test asset organization
    await page.locator('[data-testid="asset-item"]').first().click();
    await page.fill('[data-testid="asset-name"]', 'Custom Card Asset');
    await page.selectOption('[data-testid="asset-category"]', 'cards');
    await page.click('[data-testid="save-asset"]');

    // Test asset deletion
    await page.locator('[data-testid="delete-asset"]').first().click();
    await page.click('[data-testid="confirm-delete"]');
    await expect(page.locator('[data-testid="asset-item"]')).toHaveCount(2);
  });

  test('should validate system publishing workflow', async ({ page }) => {
    await page.goto('/admin');
    await page.click('[data-testid="game-systems-tab"]');

    // Create system for publishing test
    await page.click('[data-testid="create-system-button"]');
    await page.fill('[data-testid="system-name"]', 'Publishing Test System');
    await page.fill('[data-testid="system-description"]', 'System for testing publishing workflow');
    await page.selectOption('[data-testid="system-category"]', 'board-game');
    await page.click('[data-testid="save-system"]');

    // Verify system starts as draft
    await expect(page.locator('[data-testid="system-status"]'))
      .toContainText('Draft');

    // Upload required assets
    await page.click('[data-testid="system-assets-tab"]');
    const fileInput = page.locator('input[type="file"]').first();
    await fileInput.setInputFiles('./tests/fixtures/test-map.png');

    // Test publishing validation
    await page.click('[data-testid="publish-system"]');
    
    // Should show validation errors if requirements not met
    await expect(page.locator('[data-testid="validation-errors"]'))
      .toBeVisible();

    // Complete required fields
    await page.click('[data-testid="system-details-tab"]');
    await page.fill('[data-testid="system-rules"]', 'Basic game rules for testing');
    await page.fill('[data-testid="system-min-players"]', '2');
    await page.fill('[data-testid="system-max-players"]', '6');

    // Publish successfully
    await page.click('[data-testid="publish-system"]');
    await expect(page.locator('[data-testid="system-status"]'))
      .toContainText('Published');

    // Test unpublishing
    await page.click('[data-testid="unpublish-system"]');
    await page.click('[data-testid="confirm-unpublish"]');
    await expect(page.locator('[data-testid="system-status"]'))
      .toContainText('Draft');
  });

  test('should handle system permissions and access control', async ({ page }) => {
    await page.goto('/admin');
    await page.click('[data-testid="game-systems-tab"]');

    // Test system ownership
    await page.locator('[data-testid="system-item"]').first().click();
    await page.click('[data-testid="system-permissions-tab"]');

    // Add collaborator
    await page.fill('[data-testid="add-collaborator-email"]', 'collaborator@test.com');
    await page.selectOption('[data-testid="collaborator-role"]', 'editor');
    await page.click('[data-testid="add-collaborator"]');

    await expect(page.locator('[data-testid="collaborators-list"]'))
      .toContainText('collaborator@test.com');

    // Test role modification
    await page.selectOption('[data-testid="collaborator-role"]', 'viewer');
    await page.click('[data-testid="update-role"]');

    // Test collaborator removal
    await page.click('[data-testid="remove-collaborator"]');
    await page.click('[data-testid="confirm-remove"]');
    await expect(page.locator('[data-testid="collaborators-list"]'))
      .not.toContainText('collaborator@test.com');
  });

  test('should support system templates and cloning', async ({ page }) => {
    await page.goto('/admin');
    await page.click('[data-testid="game-systems-tab"]');

    // Test system cloning
    await page.locator('[data-testid="system-item"]').first().click();
    await page.click('[data-testid="clone-system"]');

    await page.fill('[data-testid="clone-name"]', 'Cloned Test System');
    await page.click('[data-testid="confirm-clone"]');

    // Verify cloned system appears
    await expect(page.locator('[data-testid="systems-list"]'))
      .toContainText('Cloned Test System');

    // Test template creation
    await page.click('[data-testid="create-template"]');
    await page.fill('[data-testid="template-name"]', 'Card Game Template');
    await page.fill('[data-testid="template-description"]', 'Template for card-based games');
    await page.click('[data-testid="save-template"]');

    // Verify template is available
    await page.click('[data-testid="templates-tab"]');
    await expect(page.locator('[data-testid="templates-list"]'))
      .toContainText('Card Game Template');

    // Test creating system from template
    await page.click('[data-testid="use-template"]');
    await page.fill('[data-testid="system-name"]', 'System from Template');
    await page.click('[data-testid="create-from-template"]');

    await expect(page.locator('[data-testid="systems-list"]'))
      .toContainText('System from Template');
  });
});
