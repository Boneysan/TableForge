#!/bin/bash

# Comprehensive linting and formatting script
set -e

echo "🔧 Running comprehensive code quality checks and fixes..."

# Format all files with Prettier
echo "📝 Formatting code with Prettier..."
npx prettier --write . --log-level warn

# Fix ESLint issues
echo "🔍 Fixing ESLint issues..."
npx eslint . --ext .ts,.tsx,.js,.jsx --fix --max-warnings 0

# Run TypeScript type checking
echo "🔧 Running TypeScript type checking..."
npx tsc --noEmit

# Run tests to ensure nothing is broken
echo "🧪 Running tests to verify fixes..."
npx vitest run --reporter=basic

echo "✅ All code quality checks and fixes completed successfully!"
echo "📊 Summary:"
echo "   - Code formatted with Prettier"
echo "   - ESLint issues resolved"
echo "   - TypeScript types validated"
echo "   - Tests passing"