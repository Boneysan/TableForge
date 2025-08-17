# E2E Tests Directory

This directory contains end-to-end tests for the TableForge application.

## Test Files

E2E tests are located in the root `e2e/` directory and configured with Playwright.
This directory is reserved for future additional E2E test organization.

## Current E2E Tests

- `e2e/multi-client-board.spec.ts` - Multi-client board interaction tests

## Running E2E Tests

```bash
# Run all E2E tests
npm run test:e2e

# Run E2E tests in headed mode (visible browser)
npm run test:e2e:headed

# Debug E2E tests
npm run test:e2e:debug
```

## Configuration

E2E tests are configured in `playwright.config.ts` at the project root.
