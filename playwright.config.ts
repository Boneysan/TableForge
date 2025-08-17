import { defineConfig, devices } from '@playwright/test';

/**
 * Phase 2 Week 3: End-to-End Testing Configuration
 * Enhanced E2E testing setup with comprehensive browser support and test utilities
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  
  reporter: [
    ['html', { outputFolder: 'test-results/e2e-report' }],
    ['json', { outputFile: 'test-results/e2e-results.json' }],
    ['junit', { outputFile: 'test-results/e2e-junit.xml' }],
    ['line']
  ],
  
  use: {
    baseURL: process.env.E2E_BASE_URL || 'http://localhost:5173',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    
    // Enhanced timeouts for complex interactions
    actionTimeout: 15000,
    navigationTimeout: 30000,
    
    // Configure viewport for consistent testing
    viewport: { width: 1280, height: 720 },
    
    // Ignore HTTPS errors for local testing
    ignoreHTTPSErrors: true
  },

  projects: [
    // Desktop browsers
    {
      name: 'chromium',
      use: { 
        ...devices['Desktop Chrome'],
        channel: 'chrome'
      },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
    },
    
    // Mobile devices for responsive testing
    {
      name: 'Mobile Chrome',
      use: { ...devices['Pixel 5'] },
    },
    {
      name: 'Mobile Safari',
      use: { ...devices['iPhone 12'] },
    },

    // Additional browser testing
    {
      name: 'Microsoft Edge',
      use: { 
        ...devices['Desktop Edge'], 
        channel: 'msedge' 
      },
    },
  ],

  webServer: [
    {
      command: 'npm run dev',
      port: 5173,
      reuseExistingServer: !process.env.CI,
      timeout: 120000,
      env: {
        NODE_ENV: 'test'
      }
    }
  ],

  // Global setup and teardown
  globalSetup: './e2e/global-setup.ts',
  globalTeardown: './e2e/global-teardown.ts',

  // Enhanced timeouts
  timeout: 60000,
  expect: {
    timeout: 10000
  },

  // Output directory for test artifacts
  outputDir: 'test-results/e2e-artifacts',

  // Maximum number of failures before stopping
  maxFailures: process.env.CI ? 10 : undefined
});