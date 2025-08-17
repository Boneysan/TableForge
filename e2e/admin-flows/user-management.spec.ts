// e2e/admin-flows/user-management.spec.ts
import { test, expect } from '@playwright/test';

test.describe('User Management Interface', () => {
  test('should manage user accounts and permissions', async ({ page }) => {
    await page.goto('/admin');
    await page.click('[data-testid="users-tab"]');

    // View user list
    await expect(page.locator('[data-testid="users-table"]')).toBeVisible();
    const userRows = page.locator('[data-testid="user-row"]');
    await expect(userRows).toHaveCount(await userRows.count());

    // Search users
    await page.fill('[data-testid="user-search"]', 'test@example.com');
    await expect(page.locator('[data-testid="user-row"]'))
      .toContainText('test@example.com');

    // Edit user permissions
    await page.locator('[data-testid="edit-user"]').first().click();
    await page.selectOption('[data-testid="user-role"]', 'moderator');
    await page.click('[data-testid="save-user"]');

    await expect(page.locator('[data-testid="user-role-badge"]'))
      .toContainText('Moderator');
  });

  test('should handle user suspension and activation', async ({ page }) => {
    await page.goto('/admin');
    await page.click('[data-testid="users-tab"]');

    // Suspend user
    await page.locator('[data-testid="user-actions"]').first().click();
    await page.click('[data-testid="suspend-user"]');
    await page.fill('[data-testid="suspension-reason"]', 'Policy violation');
    await page.click('[data-testid="confirm-suspension"]');

    await expect(page.locator('[data-testid="user-status"]'))
      .toContainText('Suspended');

    // Reactivate user
    await page.click('[data-testid="reactivate-user"]');
    await page.click('[data-testid="confirm-reactivation"]');

    await expect(page.locator('[data-testid="user-status"]'))
      .toContainText('Active');
  });

  test('should display user activity analytics', async ({ page }) => {
    await page.goto('/admin');
    await page.click('[data-testid="analytics-tab"]');

    // View user statistics
    await expect(page.locator('[data-testid="total-users"]')).toBeVisible();
    await expect(page.locator('[data-testid="active-users"]')).toBeVisible();
    await expect(page.locator('[data-testid="new-registrations"]')).toBeVisible();

    // View activity chart
    await expect(page.locator('[data-testid="activity-chart"]')).toBeVisible();

    // Filter by date range
    await page.click('[data-testid="date-filter"]');
    await page.selectOption('[data-testid="date-range"]', 'last-7-days');
    await page.click('[data-testid="apply-filter"]');

    await expect(page.locator('[data-testid="filtered-results"]')).toBeVisible();
  });
});
