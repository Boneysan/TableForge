/**
 * Admin Interface E2E Tests - Phase 2 Week 3
 * End-to-end testing of admin-specific functionality
 */

import { test, expect } from '@playwright/test';
import { createTestPage, E2EUtils } from '../utils/test-utils';

test.describe('Admin Interface E2E Tests', () => {
  let utils: E2EUtils;
  let testUsers: any[];

  test.beforeEach(async ({ page }) => {
    utils = await createTestPage(page);
    testUsers = E2EUtils.getTestUsers();
  });

  test('should complete admin user management workflow', async ({ page }) => {
    const adminUser = testUsers.find(u => u.role === 'admin');
    if (!adminUser) {
      test.skip(true, 'No admin user available');
    }

    await test.step('Admin authenticates and accesses admin interface', async () => {
      await page.goto('/');
      await utils.authenticateUser(adminUser);
      
      // Navigate to admin interface
      await page.click('[data-testid="admin-menu"]');
      await page.click('[data-testid="admin-dashboard"]');
      
      await expect(page).toHaveURL('/admin');
      await expect(page.locator('[data-testid="admin-dashboard-title"]')).toBeVisible();
    });

    await test.step('Admin manages user accounts', async () => {
      // Navigate to user management
      await page.click('[data-testid="users-tab"]');
      
      // Verify user list loads
      await expect(page.locator('[data-testid="users-table"]')).toBeVisible();
      
      // Test user search functionality
      await page.fill('[data-testid="user-search"]', 'e2e');
      await expect(page.locator('[data-testid="user-row"]')).toBeVisible();
      
      // Test user role change
      const userRow = page.locator('[data-testid="user-row"]').first();
      await userRow.locator('[data-testid="edit-user"]').click();
      
      await page.selectOption('[data-testid="user-role-select"]', 'moderator');
      await page.click('[data-testid="save-user"]');
      
      // Verify success notification
      await expect(page.locator('[data-testid="save-success"]')).toBeVisible();
    });

    await test.step('Admin manages game rooms', async () => {
      // Navigate to room management
      await page.click('[data-testid="rooms-tab"]');
      
      // Verify room list
      await expect(page.locator('[data-testid="rooms-table"]')).toBeVisible();
      
      // Create new room
      await page.click('[data-testid="create-room-button"]');
      await page.fill('[data-testid="room-name-input"]', 'Admin Created Room');
      await page.fill('[data-testid="room-description"]', 'Room created by admin');
      await page.selectOption('[data-testid="room-privacy"]', 'public');
      await page.click('[data-testid="create-room-submit"]');
      
      // Verify room creation
      await expect(page.locator('[data-testid="room-created-success"]')).toBeVisible();
      await expect(page.locator('[data-testid="rooms-table"]')).toContainText('Admin Created Room');
    });

    await test.step('Admin manages game systems', async () => {
      // Navigate to game systems management
      await page.click('[data-testid="systems-tab"]');
      
      // Create new game system
      await page.click('[data-testid="create-system-button"]');
      await page.fill('[data-testid="system-name"]', 'E2E Test System');
      await page.fill('[data-testid="system-description"]', 'Game system created for E2E testing');
      await page.selectOption('[data-testid="system-category"]', 'card-game');
      
      // Upload system configuration
      const configInput = page.locator('[data-testid="system-config-upload"]');
      await configInput.setInputFiles([{
        name: 'system-config.json',
        mimeType: 'application/json',
        buffer: Buffer.from(JSON.stringify({
          name: 'E2E Test System',
          version: '1.0.0',
          assets: ['cards', 'dice', 'board']
        }))
      }]);
      
      await page.click('[data-testid="save-system"]');
      
      // Verify system creation
      await expect(page.locator('[data-testid="system-created-success"]')).toBeVisible();
      await expect(page.locator('[data-testid="systems-list"]')).toContainText('E2E Test System');
    });
  });

  test('should handle admin analytics and monitoring', async ({ page }) => {
    const adminUser = testUsers.find(u => u.role === 'admin');
    if (!adminUser) {
      test.skip(true, 'No admin user available');
    }

    await utils.authenticateUser(adminUser);
    await page.goto('/admin');

    await test.step('Admin views analytics dashboard', async () => {
      await page.click('[data-testid="analytics-tab"]');
      
      // Verify analytics widgets load
      await expect(page.locator('[data-testid="active-users-widget"]')).toBeVisible();
      await expect(page.locator('[data-testid="active-rooms-widget"]')).toBeVisible();
      await expect(page.locator('[data-testid="usage-chart"]')).toBeVisible();
      
      // Test date range filter
      await page.click('[data-testid="date-range-picker"]');
      await page.click('[data-testid="last-7-days"]');
      
      // Verify chart updates
      await expect(page.locator('[data-testid="usage-chart"]')).toBeVisible();
    });

    await test.step('Admin monitors system health', async () => {
      await page.click('[data-testid="monitoring-tab"]');
      
      // Verify system status indicators
      await expect(page.locator('[data-testid="server-status"]')).toContainText('Healthy');
      await expect(page.locator('[data-testid="database-status"]')).toContainText('Connected');
      await expect(page.locator('[data-testid="websocket-status"]')).toContainText('Active');
      
      // Test performance metrics
      await expect(page.locator('[data-testid="response-time-metric"]')).toBeVisible();
      await expect(page.locator('[data-testid="memory-usage-metric"]')).toBeVisible();
      
      // Test system logs
      await page.click('[data-testid="view-logs"]');
      await expect(page.locator('[data-testid="system-logs"]')).toBeVisible();
      
      // Filter logs by level
      await page.selectOption('[data-testid="log-level-filter"]', 'error');
      await expect(page.locator('[data-testid="filtered-logs"]')).toBeVisible();
    });

    await test.step('Admin manages content moderation', async () => {
      await page.click('[data-testid="moderation-tab"]');
      
      // Verify moderation queue
      await expect(page.locator('[data-testid="moderation-queue"]')).toBeVisible();
      
      // Test content review
      const reportedItem = page.locator('[data-testid="reported-item"]').first();
      if (await reportedItem.isVisible()) {
        await reportedItem.click();
        
        // Review content details
        await expect(page.locator('[data-testid="content-details"]')).toBeVisible();
        
        // Take moderation action
        await page.click('[data-testid="approve-content"]');
        await expect(page.locator('[data-testid="moderation-success"]')).toBeVisible();
      }
      
      // Test automated moderation rules
      await page.click('[data-testid="moderation-rules"]');
      await page.click('[data-testid="add-rule"]');
      
      await page.fill('[data-testid="rule-name"]', 'E2E Test Rule');
      await page.selectOption('[data-testid="rule-type"]', 'keyword-filter');
      await page.fill('[data-testid="rule-keywords"]', 'spam,inappropriate');
      await page.click('[data-testid="save-rule"]');
      
      await expect(page.locator('[data-testid="rule-created-success"]')).toBeVisible();
    });
  });

  test('should handle admin asset management', async ({ page }) => {
    const adminUser = testUsers.find(u => u.role === 'admin');
    if (!adminUser) {
      test.skip(true, 'No admin user available');
    }

    await utils.authenticateUser(adminUser);
    await page.goto('/admin');

    await test.step('Admin manages global asset library', async () => {
      await page.click('[data-testid="assets-tab"]');
      
      // Upload multiple assets
      const fileInput = page.locator('[data-testid="bulk-asset-upload"]');
      await fileInput.setInputFiles([
        {
          name: 'admin-card-1.png',
          mimeType: 'image/png',
          buffer: Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChAGA3zBsKQAAAABJRU5ErkJggg==', 'base64')
        },
        {
          name: 'admin-dice-1.png',
          mimeType: 'image/png',
          buffer: Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChAGA3zBsKQAAAABJRU5ErkJggg==', 'base64')
        }
      ]);

      // Wait for uploads to complete
      await expect(page.locator('[data-testid="bulk-upload-success"]')).toBeVisible();
      
      // Verify assets appear in library
      await expect(page.locator('[data-testid="asset-library"]')).toContainText('admin-card-1.png');
      await expect(page.locator('[data-testid="asset-library"]')).toContainText('admin-dice-1.png');
    });

    await test.step('Admin organizes assets into collections', async () => {
      // Create new collection
      await page.click('[data-testid="create-collection"]');
      await page.fill('[data-testid="collection-name"]', 'E2E Test Collection');
      await page.fill('[data-testid="collection-description"]', 'Collection for E2E testing');
      await page.click('[data-testid="save-collection"]');
      
      // Add assets to collection
      const assetItem = page.locator('[data-testid^="asset-item-"]').first();
      await assetItem.locator('[data-testid="add-to-collection"]').click();
      await page.selectOption('[data-testid="collection-select"]', 'E2E Test Collection');
      await page.click('[data-testid="confirm-add"]');
      
      // Verify collection
      await page.click('[data-testid="view-collections"]');
      await expect(page.locator('[data-testid="collections-list"]')).toContainText('E2E Test Collection');
    });

    await test.step('Admin manages asset permissions', async () => {
      // Select asset to modify permissions
      const assetItem = page.locator('[data-testid^="asset-item-"]').first();
      await assetItem.locator('[data-testid="manage-permissions"]').click();
      
      // Verify permission dialog
      await expect(page.locator('[data-testid="permissions-dialog"]')).toBeVisible();
      
      // Set asset as public
      await page.check('[data-testid="public-access"]');
      await page.uncheck('[data-testid="require-approval"]');
      await page.click('[data-testid="save-permissions"]');
      
      // Verify permission update
      await expect(page.locator('[data-testid="permissions-updated"]')).toBeVisible();
    });
  });

  test('should handle admin security and access control', async ({ page }) => {
    const adminUser = testUsers.find(u => u.role === 'admin');
    if (!adminUser) {
      test.skip(true, 'No admin user available');
    }

    await utils.authenticateUser(adminUser);
    await page.goto('/admin');

    await test.step('Admin manages user permissions and roles', async () => {
      await page.click('[data-testid="security-tab"]');
      
      // View role management
      await page.click('[data-testid="role-management"]');
      
      // Create custom role
      await page.click('[data-testid="create-role"]');
      await page.fill('[data-testid="role-name"]', 'Test Moderator');
      await page.fill('[data-testid="role-description"]', 'Custom role for testing');
      
      // Set permissions
      await page.check('[data-testid="permission-moderate-chat"]');
      await page.check('[data-testid="permission-manage-rooms"]');
      await page.uncheck('[data-testid="permission-manage-users"]');
      
      await page.click('[data-testid="save-role"]');
      
      // Verify role creation
      await expect(page.locator('[data-testid="role-created-success"]')).toBeVisible();
      await expect(page.locator('[data-testid="roles-list"]')).toContainText('Test Moderator');
    });

    await test.step('Admin configures security settings', async () => {
      await page.click('[data-testid="security-settings"]');
      
      // Configure session settings
      await page.fill('[data-testid="session-timeout"]', '3600');
      await page.check('[data-testid="require-email-verification"]');
      await page.check('[data-testid="enable-two-factor"]');
      
      // Configure content filtering
      await page.check('[data-testid="enable-content-filter"]');
      await page.selectOption('[data-testid="filter-level"]', 'strict');
      
      // Configure rate limiting
      await page.fill('[data-testid="api-rate-limit"]', '100');
      await page.fill('[data-testid="upload-rate-limit"]', '10');
      
      await page.click('[data-testid="save-security-settings"]');
      
      // Verify settings saved
      await expect(page.locator('[data-testid="security-settings-saved"]')).toBeVisible();
    });

    await test.step('Admin reviews audit logs', async () => {
      await page.click('[data-testid="audit-logs"]');
      
      // Verify audit log table
      await expect(page.locator('[data-testid="audit-logs-table"]')).toBeVisible();
      
      // Filter logs by user
      await page.fill('[data-testid="audit-user-filter"]', adminUser.email);
      await page.click('[data-testid="apply-filter"]');
      
      // Verify filtered results
      await expect(page.locator('[data-testid="filtered-audit-logs"]')).toBeVisible();
      
      // Export audit logs
      await page.click('[data-testid="export-logs"]');
      await page.selectOption('[data-testid="export-format"]', 'csv');
      await page.click('[data-testid="confirm-export"]');
      
      // Verify export initiated
      await expect(page.locator('[data-testid="export-initiated"]')).toBeVisible();
    });
  });

  test('should handle admin backup and maintenance operations', async ({ page }) => {
    const adminUser = testUsers.find(u => u.role === 'admin');
    if (!adminUser) {
      test.skip(true, 'No admin user available');
    }

    await utils.authenticateUser(adminUser);
    await page.goto('/admin');

    await test.step('Admin manages system backups', async () => {
      await page.click('[data-testid="maintenance-tab"]');
      
      // View backup status
      await expect(page.locator('[data-testid="last-backup-date"]')).toBeVisible();
      await expect(page.locator('[data-testid="backup-size"]')).toBeVisible();
      
      // Initiate manual backup
      await page.click('[data-testid="create-backup"]');
      await page.fill('[data-testid="backup-description"]', 'E2E test backup');
      await page.click('[data-testid="confirm-backup"]');
      
      // Verify backup initiated
      await expect(page.locator('[data-testid="backup-initiated"]')).toBeVisible();
      
      // Configure automatic backups
      await page.click('[data-testid="backup-schedule"]');
      await page.selectOption('[data-testid="backup-frequency"]', 'daily');
      await page.fill('[data-testid="backup-time"]', '02:00');
      await page.click('[data-testid="save-schedule"]');
      
      // Verify schedule saved
      await expect(page.locator('[data-testid="schedule-saved"]')).toBeVisible();
    });

    await test.step('Admin performs maintenance tasks', async () => {
      // Database optimization
      await page.click('[data-testid="database-maintenance"]');
      await page.click('[data-testid="optimize-database"]');
      
      // Verify optimization started
      await expect(page.locator('[data-testid="optimization-started"]')).toBeVisible();
      
      // Clear cache
      await page.click('[data-testid="clear-cache"]');
      await page.click('[data-testid="confirm-clear-cache"]');
      
      // Verify cache cleared
      await expect(page.locator('[data-testid="cache-cleared"]')).toBeVisible();
      
      // Update system configuration
      await page.click('[data-testid="system-config"]');
      await page.fill('[data-testid="max-room-size"]', '50');
      await page.fill('[data-testid="max-upload-size"]', '10485760'); // 10MB
      await page.click('[data-testid="save-config"]');
      
      // Verify configuration saved
      await expect(page.locator('[data-testid="config-saved"]')).toBeVisible();
    });
  });

  test('should handle admin error scenarios', async ({ page }) => {
    const adminUser = testUsers.find(u => u.role === 'admin');
    if (!adminUser) {
      test.skip(true, 'No admin user available');
    }

    await utils.authenticateUser(adminUser);
    await page.goto('/admin');

    await test.step('Handle insufficient permissions gracefully', async () => {
      // Simulate permission revocation
      await page.evaluate(() => {
        localStorage.setItem('user-permissions', JSON.stringify(['basic-access']));
      });

      await page.reload();
      
      // Verify restricted access message
      await expect(page.locator('[data-testid="access-restricted"]')).toBeVisible();
    });

    await test.step('Handle server errors during admin operations', async () => {
      // Intercept admin API calls to simulate errors
      await page.route('/api/admin/**', route => {
        route.fulfill({ status: 500, body: 'Internal Server Error' });
      });

      await page.click('[data-testid="users-tab"]');
      
      // Verify error handling
      await expect(page.locator('[data-testid="admin-error"]')).toBeVisible();
      await expect(page.locator('[data-testid="admin-error"]')).toContainText('Unable to load user data');
    });
  });
});
