# Testing Infrastructure Documentation

This document outlines the comprehensive testing setup for Vorpal Board, including unit tests, integration tests, end-to-end tests, and static analysis tools.

## Test Structure

```
tests/
├── setup.ts              # Global test setup and mocks
├── unit/                  # Unit tests
│   ├── schema.test.ts     # Database schema validation tests
│   ├── hooks/             # React hooks tests
│   │   └── useCommandStack.test.ts
│   └── utils/             # Utility function tests
│       └── moveLogic.test.ts
├── integration/           # Integration tests
│   ├── api.test.ts        # API endpoint tests with Supertest
│   └── websocket.test.ts  # WebSocket functionality tests
└── README.md

e2e/                       # End-to-end tests (separate directory)
└── multi-client-board.spec.ts  # Multi-client interactions with Playwright
```

## Testing Tools

### Unit Testing (Vitest)
- **Framework**: Vitest with happy-dom environment
- **Mocking**: Built-in vi mocks for WebSocket, localStorage, etc.
- **Coverage**: V8 provider with 80% threshold targets
- **Features**: 
  - React Testing Library integration
  - Component testing with jsdom simulation
  - Hook testing with renderHook utilities

### Integration Testing (Supertest)
- **API Testing**: Supertest for HTTP endpoint testing
- **WebSocket Testing**: Socket.io test client for real-time features
- **Database Testing**: Uses test database with cleanup between tests
- **Authentication**: Mock authentication tokens for protected routes

### End-to-End Testing (Playwright)
- **Multi-Browser**: Chrome, Firefox, Safari testing
- **Multi-Client**: Tests collaborative features with separate browser contexts
- **Mobile Testing**: Mobile Chrome and Safari support
- **Visual Testing**: Screenshots and video capture on failures

### Static Analysis
- **ESLint**: TypeScript-specific rules and React best practices
- **Prettier**: Code formatting with consistent style
- **TypeScript**: Strict type checking with --noEmit
- **Husky**: Pre-commit hooks for automated quality checks

## Running Tests

### Unit Tests
```bash
npm run test              # Run all tests in watch mode
npm run test:unit         # Run unit tests once
npm run test:coverage     # Run with coverage report
npm run test:watch        # Run in watch mode
```

### Integration Tests
```bash
npm run test:integration  # Run integration tests
```

### End-to-End Tests
```bash
npm run test:e2e          # Run E2E tests headless
npm run test:e2e:ui       # Run E2E tests with UI
```

### Code Quality
```bash
npm run lint              # Run ESLint
npm run lint:fix          # Fix linting issues
npm run format            # Format code with Prettier
npm run format:check      # Check formatting
npm run type-check        # TypeScript type checking
```

## Test Categories

### Schema Validation Tests
- Tests all Drizzle schemas and Zod validators
- Validates required fields, data types, and constraints
- Tests edge cases like null values and array validation
- Ensures database schema integrity

### Hook Tests
- Tests React hooks in isolation with renderHook
- Mocks external dependencies like WebSocket connections
- Tests state management and side effects
- Validates error handling and edge cases

### Move Logic Tests
- Tests core game mechanics like asset movement
- Collision detection and grid snapping
- Position calculations and bounds checking
- Distance calculations and asset finding

### API Integration Tests
- Tests all REST API endpoints with authentication
- Validates request/response formats and error handling
- Tests rate limiting and security measures
- Database integration with proper cleanup

### WebSocket Integration Tests
- Tests real-time collaboration features
- Room management and user connections
- Asset movement synchronization
- Chat and communication features
- Error handling and reconnection logic

### Multi-Client E2E Tests
- Tests collaborative features between multiple users
- Asset movement synchronization across clients
- Deck and card management in multiplayer scenarios
- Chat and communication in real-time
- Connection handling and offline/online states

## Coverage Targets

The testing infrastructure maintains high code coverage standards:

- **Branches**: 80% minimum
- **Functions**: 80% minimum  
- **Lines**: 80% minimum
- **Statements**: 80% minimum

Coverage excludes:
- Configuration files
- Test files themselves
- Build artifacts
- Third-party dependencies

## Continuous Integration

### Pre-commit Hooks
Automated checks run before each commit:
1. ESLint with auto-fix
2. Prettier formatting
3. TypeScript type checking
4. Unit test execution

### Quality Gates
All tests must pass for:
- Code quality (linting and formatting)
- Type safety (TypeScript compilation)
- Unit test coverage (80% threshold)
- Integration test execution

## Test Data Management

### Unit Tests
- Use mocked data and dependencies
- No external API calls or database connections
- Isolated test environment with predictable state

### Integration Tests
- Use test database with automated cleanup
- Mock authentication with controlled user contexts
- Reset state between test suites

### E2E Tests
- Use development server with real database
- Create/cleanup test data for each scenario
- Test with realistic user workflows

## Performance Testing

### Load Testing
- WebSocket connection stress tests
- High-frequency asset movement simulation
- Multiple concurrent user scenarios

### Memory Testing
- Long-running test scenarios
- Memory leak detection in collaborative features
- Resource cleanup verification

## Security Testing

### Authentication Testing
- Invalid token rejection
- Authorization boundary testing
- Session management validation

### Input Validation
- Malformed request handling
- SQL injection prevention
- XSS protection verification

## Best Practices

### Test Organization
- Group related tests in describe blocks
- Use descriptive test names that explain expected behavior
- Follow Arrange-Act-Assert pattern
- Keep tests focused and isolated

### Mock Strategy
- Mock external dependencies at module boundaries
- Use factory functions for test data creation
- Maintain realistic mock implementations
- Reset mocks between tests

### Assertion Strategy
- Use specific assertions over generic ones
- Test both positive and negative cases
- Verify error conditions and edge cases
- Use async/await for asynchronous operations

This comprehensive testing infrastructure ensures code quality, prevents regressions, and validates the complex collaborative features of the Vorpal Board platform.