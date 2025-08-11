#!/bin/bash

# Pre-deployment validation script
set -e

echo "🚀 Running pre-deployment validations..."

# Type checking
echo "🔧 TypeScript type checking..."
npx tsc --noEmit

# Linting
echo "🔍 ESLint validation..."
npx eslint . --ext .ts,.tsx,.js,.jsx --max-warnings 0

# Code formatting check
echo "📝 Prettier format validation..."
npx prettier --check . --log-level warn

# Run all tests
echo "🧪 Running full test suite..."
npx vitest run --coverage --reporter=verbose

# Build verification
echo "🏗️  Build verification..."
npm run build

# E2E tests (if server is running)
if curl -f -s http://localhost:5173/health >/dev/null 2>&1; then
  echo "🎭 Running E2E tests..."
  npx playwright test --reporter=line
else
  echo "⚠️  Skipping E2E tests (server not running)"
fi

echo "✅ All pre-deployment validations passed!"
echo "🎯 Ready for deployment"