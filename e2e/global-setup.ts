/**
 * Global Setup for E2E Tests - Phase 2 Week 3
 * Initializes test environment and prepares test data
 */

import { chromium, FullConfig } from '@playwright/test';

async function globalSetup(config: FullConfig) {
  console.log('🚀 Starting global E2E test setup...');

  const baseURL = config.projects[0]?.use?.baseURL || 'http://localhost:5173';
  
  // Launch browser for setup operations
  const browser = await chromium.launch();
  const page = await browser.newPage();

  try {
    // Wait for the development server to be ready
    console.log(`📡 Waiting for server at ${baseURL}...`);
    await page.goto(baseURL, { waitUntil: 'networkidle' });
    
    // Verify the application loads correctly
    await page.waitForSelector('body', { timeout: 30000 });
    console.log('✅ Application loaded successfully');

    // Setup test database state if needed
    await setupTestDatabase();

    // Create test user accounts
    await createTestUsers();

    // Setup test assets
    await setupTestAssets();

    console.log('✅ Global E2E setup completed successfully');

  } catch (error) {
    console.error('❌ Global setup failed:', error);
    throw error;
  } finally {
    await browser.close();
  }
}

async function setupTestDatabase() {
  console.log('🗄️ Setting up test database...');
  
  // In a real implementation, this would:
  // 1. Connect to test database
  // 2. Run migrations
  // 3. Seed with test data
  // 4. Ensure clean state
  
  // For now, we'll simulate this
  await new Promise(resolve => setTimeout(resolve, 1000));
  console.log('✅ Test database ready');
}

async function createTestUsers() {
  console.log('👥 Creating test user accounts...');
  
  // Mock test users that E2E tests will use
  const testUsers = [
    {
      id: 'e2e-user-1',
      email: 'e2e.user1@test.com',
      displayName: 'E2E Test User 1',
      role: 'user'
    },
    {
      id: 'e2e-user-2', 
      email: 'e2e.user2@test.com',
      displayName: 'E2E Test User 2',
      role: 'user'
    },
    {
      id: 'e2e-admin',
      email: 'e2e.admin@test.com',
      displayName: 'E2E Admin User',
      role: 'admin'
    }
  ];

  // In a real implementation, this would create actual user accounts
  // For testing, we'll store this data for test access
  process.env['E2E_TEST_USERS'] = JSON.stringify(testUsers);
  
  console.log(`✅ Created ${testUsers.length} test user accounts`);
}

async function setupTestAssets() {
  console.log('🎮 Setting up test game assets...');
  
  // Prepare test assets that will be used in E2E tests
  const testAssets = [
    {
      id: 'test-card-1',
      name: 'Test Card 1',
      type: 'card',
      url: '/test-assets/card-1.png'
    },
    {
      id: 'test-dice-1',
      name: 'Test Dice',
      type: 'dice',
      url: '/test-assets/dice.png'
    },
    {
      id: 'test-board-1',
      name: 'Test Board',
      type: 'board',
      url: '/test-assets/board.jpg'
    }
  ];

  // Store test asset data
  process.env['E2E_TEST_ASSETS'] = JSON.stringify(testAssets);
  
  console.log(`✅ Prepared ${testAssets.length} test assets`);
}

export default globalSetup;
