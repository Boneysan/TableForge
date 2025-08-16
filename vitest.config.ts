import { defineConfig } from 'vitest/config';
import { resolve } from 'path';

export default defineConfig({
  test: {
    globals: true,
    environment: 'happy-dom',
    setupFiles: ['./tests/setup.ts'],
    include: ['**/*.{test,spec}.{js,mjs,cjs,ts,mts,cts,jsx,tsx}'],
    exclude: ['**/node_modules/**', '**/e2e/**', '**/performance/**'],
    
    // Enhanced coverage configuration
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov'],
      reportsDirectory: './coverage',
      exclude: [
        'coverage/**',
        'dist/**',
        '**/*.d.ts',
        'e2e/**',
        'performance/**',
        '**/*.config.*',
        'scripts/**'
      ],
      thresholds: {
        global: {
          branches: 90,
          functions: 90,
          lines: 90,
          statements: 90
        },
        // Per-file thresholds for critical components
        './server/auth/': {
          branches: 95,
          functions: 95,
          lines: 95,
          statements: 95
        },
        './server/middleware/security.ts': {
          branches: 100,
          functions: 100,
          lines: 100,
          statements: 100
        }
      }
    },
    
    // Test timeout configuration
    testTimeout: 10000,
    hookTimeout: 10000,
    
    // Parallel execution
    threads: true,
    maxThreads: 4,
    
    // Reporter configuration
    reporter: ['verbose', 'json', 'html'],
    outputFile: {
      json: './test-results/results.json',
      html: './test-results/report.html'
    }
  },
  
  resolve: {
    alias: {
      '@': resolve('./client/src'),
      '@shared': resolve('./shared'),
      '@server': resolve('./server'),
      '@tests': resolve('./tests')
    }
  }
});