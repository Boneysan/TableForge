// e2e/admin-flows/room-management.spec.ts
import { test, expect } from '@playwright/test';

test.describe('Room Management Interface', () => {
  test('should display and manage active rooms', async ({ page }) => {
    await page.goto('/admin');
    await page.click('[data-testid="rooms-tab"]');

    // View rooms list
    await expect(page.locator('[data-testid="rooms-table"]')).toBeVisible();

    // Test room search and filtering
    await page.fill('[data-testid="room-search"]', 'Test Room');
    await expect(page.locator('[data-testid="room-row"]'))
      .toContainText('Test Room');

    // Filter by room status
    await page.selectOption('[data-testid="status-filter"]', 'active');
    await expect(page.locator('[data-testid="active-rooms-count"]')).toBeVisible();

    // View room details
    await page.locator('[data-testid="view-room"]').first().click();
    await expect(page.locator('[data-testid="room-details-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="room-players-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="room-assets-count"]')).toBeVisible();
  });

  test('should handle room moderation actions', async ({ page }) => {
    await page.goto('/admin');
    await page.click('[data-testid="rooms-tab"]');

    // Access room moderation
    await page.locator('[data-testid="moderate-room"]').first().click();

    // Test room suspension
    await page.click('[data-testid="suspend-room"]');
    await page.fill('[data-testid="suspension-reason"]', 'Inappropriate content');
    await page.click('[data-testid="confirm-suspension"]');

    await expect(page.locator('[data-testid="room-status"]'))
      .toContainText('Suspended');

    // Test room restoration
    await page.click('[data-testid="restore-room"]');
    await page.click('[data-testid="confirm-restoration"]');

    await expect(page.locator('[data-testid="room-status"]'))
      .toContainText('Active');

    // Test force room closure
    await page.click('[data-testid="close-room"]');
    await page.fill('[data-testid="closure-message"]', 'Server maintenance');
    await page.click('[data-testid="confirm-closure"]');

    await expect(page.locator('[data-testid="room-status"]'))
      .toContainText('Closed');
  });

  test('should monitor room performance metrics', async ({ page }) => {
    await page.goto('/admin');
    await page.click('[data-testid="rooms-tab"]');
    await page.click('[data-testid="performance-metrics"]');

    // View performance dashboard
    await expect(page.locator('[data-testid="metrics-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="avg-response-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="concurrent-users"]')).toBeVisible();
    await expect(page.locator('[data-testid="bandwidth-usage"]')).toBeVisible();

    // Test performance alerts
    await page.click('[data-testid="performance-alerts"]');
    await expect(page.locator('[data-testid="alerts-list"]')).toBeVisible();

    // Configure alert thresholds
    await page.click('[data-testid="configure-alerts"]');
    await page.fill('[data-testid="response-time-threshold"]', '500');
    await page.fill('[data-testid="memory-usage-threshold"]', '80');
    await page.click('[data-testid="save-thresholds"]');

    await expect(page.locator('[data-testid="alert-config-success"]')).toBeVisible();
  });
});
