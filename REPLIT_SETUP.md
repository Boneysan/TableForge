# TableForge - Replit Import & Setup Guide

## 🚀 Quick Start for Replit

This guide helps you import and run the TableForge project in Replit with all Phase 1 Type Safety enhancements.

### 📋 Prerequisites

- Replit account
- Node.js 18+ (automatically provided in Replit)
- PostgreSQL database (Neon DB recommended)

### 🔧 Step 1: Import to Replit

1. **Import from GitHub:**
   ```
   https://github.com/Boneysan/TableForge
   ```

2. **Select Node.js template** when prompted

3. **Replit will automatically detect:**
   - `package.json` for dependencies
   - TypeScript configuration
   - Build scripts

### 📦 Step 2: Install Dependencies

Replit should auto-install, but if needed:

```bash
npm install
```

**Key Dependencies for Type Safety & Testing:**
- `typescript: 5.6.3` - TypeScript compiler
- `tsx: ^4.19.1` - TypeScript executor
- `@typescript-eslint/*` - TypeScript ESLint rules
- `vitest: ^3.2.4` - Testing framework with TypeScript support
- `@testing-library/react` - React component testing utilities
- `@testing-library/jest-dom` - Jest DOM matchers for testing
- `@playwright/test` - End-to-end testing framework
- `happy-dom` - Lightweight DOM implementation for testing
- `jsdom` - DOM testing environment
- `supertest` - HTTP assertion library for API testing
- `k6` - Performance and load testing tool

### 🔐 Step 3: Environment Setup

Create `.env` file (Replit Secrets tab):

```env
# Database
DATABASE_URL=your_postgresql_connection_string
DIRECT_URL=your_direct_database_connection

# Authentication
JWT_SECRET=your_jwt_secret_key
SESSION_SECRET=your_session_secret

# Firebase (optional)
FIREBASE_PROJECT_ID=your_firebase_project
FIREBASE_PRIVATE_KEY=your_firebase_private_key
FIREBASE_CLIENT_EMAIL=your_firebase_client_email

# Storage (optional)
GCS_BUCKET_NAME=your_gcs_bucket
GCS_PROJECT_ID=your_gcs_project

# Development
NODE_ENV=development
PORT=3000
```

### 🛠️ Step 4: Replit Configuration

**`.replit` file** (should be auto-created):
```toml
run = "npm run dev"
entrypoint = "server/index.ts"

[nix]
channel = "stable-22_11"

[deployment]
run = ["sh", "-c", "npm run build && npm start"]

[[ports]]
localPort = 3000
externalPort = 80

[env]
NODE_ENV = "development"
```

**`replit.nix` file** (for system dependencies):
```nix
{ pkgs }: {
  deps = [
    pkgs.nodejs-18_x
    pkgs.nodePackages.npm
    pkgs.nodePackages.typescript
    pkgs.postgresql
  ];
}
```

### 🎯 Step 5: Phase 1 & 2 Validation

**Phase 1 - Type Safety Validation:**
```bash
# 1. Check TypeScript compilation
npm run type-check

# 2. Lint TypeScript code
npm run lint

# 3. Run Phase 1 status check
npm run phase1:status

# 4. Run type safety tests
npx tsx tests/unit/type-safety.test.ts

# 5. Simple validation (no dependencies)
node tests/unit/type-safety-simple.test.js
```

**Phase 2 - Testing Infrastructure Validation:**
```bash
# 6. Run comprehensive test suite
npm test

# 7. Run unit tests with coverage
npm run test:unit

# 8. Run integration tests
npm run test:integration

# 9. Run E2E tests (headless)
npm run test:e2e

# 10. Run performance tests
npm run test:performance

# 11. Run security tests
npm run test:security

# 12. Generate coverage report
npm run test:coverage
```

### 📁 Step 6: Project Structure Overview

```
TableForge/
├── 📋 Type Definitions (Phase 1 Complete)
│   ├── shared/types/
│   │   ├── api.ts           # API response types
│   │   ├── websocket.ts     # WebSocket event types
│   │   └── requests.ts      # Request types
│   ├── server/types/
│   │   └── database.ts      # Database query types
│   ├── server/middleware/
│   │   └── types.ts         # Middleware types
│   └── server/repositories/
│       └── types.ts         # Repository pattern types
│
├── 🧪 Testing Infrastructure (Phase 2 Complete)
│   ├── tests/
│   │   ├── unit/                      # Unit tests (95% coverage target)
│   │   │   ├── components/           # React component tests
│   │   │   ├── hooks/               # Custom hooks tests
│   │   │   ├── utils/               # Utility function tests
│   │   │   ├── middleware/          # Server middleware tests
│   │   │   └── services/            # Service layer tests
│   │   ├── integration/             # Integration tests (85% coverage target)
│   │   │   ├── api/                # API endpoint tests
│   │   │   ├── database/           # Database operation tests
│   │   │   ├── websocket/          # WebSocket integration tests
│   │   │   └── auth/               # Authentication flow tests
│   │   ├── e2e/                    # End-to-end tests (100% critical flows)
│   │   │   ├── user-flows/         # Complete user journey tests
│   │   │   ├── admin-flows/        # Admin interface tests
│   │   │   └── game-flows/         # Game session tests
│   │   ├── performance/            # Performance and load tests
│   │   │   ├── load/              # Load testing scenarios
│   │   │   ├── stress/            # Stress testing scenarios
│   │   │   └── benchmarks/        # Performance benchmarks
│   │   ├── security/               # Security testing
│   │   │   ├── penetration/       # Penetration testing
│   │   │   └── vulnerability/     # Vulnerability scanning
│   │   ├── fixtures/               # Test data & mocks
│   │   └── utils/                  # Testing utilities & helpers
│   ├── vitest.config.ts             # Enhanced test configuration
│   ├── playwright.config.ts         # E2E test configuration
│   └── scripts/
│       ├── type-check.ts            # Type validation script
│       ├── phase1-status.ts         # Phase 1 completion checker
│       └── phase2-status.ts         # Phase 2 completion checker
│
├── 🚀 Application Code
│   ├── server/              # Backend (Express + TypeScript)
│   ├── client/              # Frontend (React + TypeScript)
│   └── shared/              # Shared utilities & types
│
└── 📚 Documentation
    └── docs/implementation/
        ├── phase1-type-safety.md     # Complete Phase 1 guide
        └── phase2-testing.md         # Complete Phase 2 guide
```

### 🔍 Step 7: Development Workflow

**Start Development Server:**
```bash
npm run dev
```

**Type Safety Checks (Phase 1):**
```bash
# Quick type check
npm run type-check

# Detailed type analysis
npm run type-check:detailed

# ESLint validation
npm run lint

# Auto-fix linting issues
npm run lint:fix
```

**Testing Workflow (Phase 2):**
```bash
# Run all tests
npm test

# Unit tests only
npm run test:unit

# Integration tests only
npm run test:integration

# E2E tests (requires server running)
npm run test:e2e

# Performance tests
npm run test:performance

# Security tests
npm run test:security

# Coverage reports
npm run test:coverage
```

**React Component Testing (Phase 2):**
```bash
# Test React components with React Testing Library
npm run test:components

# Test with coverage
npm run test:unit -- --coverage

# Watch mode for component development
npm run test:unit -- --watch

# Test specific component
npm run test:unit -- AdminInterface.test.tsx
```

**Custom Hooks Testing (Phase 2):**
```bash
# Test custom hooks with React Testing Library
npm run test:hooks

# Test specific hook
npm run test:unit -- useWebSocket.test.ts

# Test hooks with coverage analysis
npm run test:unit -- hooks/ --coverage

# Watch mode for hook development
npm run test:unit -- hooks/ --watch

# Debug hook state changes
npm run test:unit -- hooks/ --reporter=verbose
```

**WebSocket Testing Patterns:**
```bash
# Test WebSocket functionality
npm run test:unit -- useWebSocket.test.ts

# Test with real-time message simulation
npm run test:unit -- useWebSocket.test.ts --reporter=verbose

# Test connection resilience
npm run test:integration -- websocket/

# Performance test WebSocket load
npm run test:performance -- websocket-load.js
```

**Database Setup:**
```bash
# Push schema to database
npm run db:push
```

**Continuous Testing:**
```bash
# Watch mode for development
npm run test:watch

# Type safety tests specifically
npx tsx tests/unit/type-safety.test.ts
```

### 🎨 Step 8: Replit-Specific Tips

**1. Console Access:**
- Use Replit Console (bottom panel) for commands
- Shell tab for full terminal access

**2. Environment Variables:**
- Use Secrets tab instead of `.env` file
- Secrets are automatically injected

**3. Database Connection:**
- Replit provides free PostgreSQL instances
- Or connect to external Neon/Supabase database

**4. Port Configuration:**
- Default port 3000 is auto-configured
- Replit handles port forwarding automatically

**5. Hot Reload:**
- TypeScript files auto-compile on save
- Server restarts automatically with `npm run dev`

### 🚨 Troubleshooting

**TypeScript Errors:**
```bash
# Clear TypeScript cache
rm -rf node_modules/.cache

# Reinstall dependencies
rm -rf node_modules package-lock.json
npm install
```

**Testing Issues:**
```bash
# Clear test cache
npm run test:clear-cache

# Reset test database
npm run test:db:reset

# Debug failing tests
npm run test:debug
```

**Port Issues:**
```bash
# Kill existing processes
pkill -f "node"
npm run dev
```

**Database Connection:**
```bash
# Test database connection
node -e "console.log(process.env.DATABASE_URL)"
```

**Performance Test Issues:**
```bash
# Check if k6 is available (for performance tests)
k6 version

# Install k6 if needed (Replit might require manual install)
curl https://github.com/grafana/k6/releases/download/v0.45.0/k6-v0.45.0-linux-amd64.tar.gz -L | tar xvz --strip-components 1
```

### ✅ Phase 1 & 2 Validation Checklist

**Phase 1 - Type Safety (Complete):**
- [ ] `npm install` - Dependencies installed
- [ ] `npm run type-check` - TypeScript strict compilation passes
- [ ] `npm run lint` - ESLint validation passes
- [ ] `npm run phase1:status` - Phase 1 status shows 100% complete
- [ ] `npx tsx tests/unit/type-safety.test.ts` - All type safety tests pass
- [ ] `npm run dev` - Development server starts without errors

**Phase 2 - Testing Infrastructure (Complete):**
- [ ] `npm test` - All tests run successfully
- [ ] `npm run test:unit` - Unit tests achieve 95% coverage
- [ ] `npm run test:integration` - Integration tests pass
- [ ] `npm run test:coverage` - Coverage reports generate successfully
- [ ] `vitest --version` - Vitest testing framework available
- [ ] `npx playwright --version` - Playwright E2E framework available
- [ ] Test directory structure exists under `tests/`
- [ ] `npm run test:hooks` - Custom hooks tests pass
- [ ] `npm run test:components` - React component tests pass

### 🎯 Testing Best Practices for Replit

**Custom Hooks Testing Guidelines:**
```typescript
// ✅ Good: Mock external dependencies
(globalThis as any).WebSocket = MockWebSocket;

// ✅ Good: Test async hook behavior
await act(async () => {
  await new Promise(resolve => setTimeout(resolve, 20));
});

// ✅ Good: Test hook cleanup
const { unmount } = renderHook(() => useWebSocket());
unmount(); // Verify no memory leaks

// ✅ Good: Test error scenarios
expect(result.current.error).toBeTruthy();
```

**WebSocket Testing Patterns:**
```typescript
// ✅ Realistic mock that simulates connection behavior
class MockWebSocket {
  constructor(url: string) {
    setTimeout(() => {
      if (url.includes('invalid')) {
        this.onerror?.(new Event('error'));
      } else {
        this.onopen?.(new Event('open'));
      }
    }, 10);
  }
}

// ✅ Test message flow
const testMessage: WebSocketMessage = {
  type: 'asset_moved',
  payload: { assetId: 'test', positionX: 100, positionY: 200 }
};

// ✅ Test reconnection logic
expect(result.current.connected).toBe(false);
await act(async () => {
  await new Promise(resolve => setTimeout(resolve, 150));
});
expect(result.current.connected).toBe(true);
```

**Component Testing Integration:**
```typescript
// ✅ Combine hook and component testing
const { result } = renderHook(() => useWebSocket({ onMessage }));
const { rerender } = render(<GameBoard websocket={result.current} />);

// ✅ Test real game scenarios
fireEvent.dragEnd(screen.getByTestId('game-asset'));
expect(result.current.sendMessage).toHaveBeenCalledWith({
  type: 'asset_moved',
  payload: expect.objectContaining({ positionX: 200, positionY: 150 })
});
```

### 🎯 Expected Output

**Successful Phase 1 Setup:**
```
🧪 Running Phase 1 Type Safety Tests...

📋 Phase 1 Type Safety - API Response Types
  ✅ should create valid ApiResponse with typed data
  ✅ should create valid ErrorResponse
  ✅ should create valid PaginatedResponse

📋 Phase 1 Type Safety - Database Query Types
  ✅ should create valid successful QueryResult
  ✅ should create valid error QueryResult

📋 Phase 1 Type Safety - Repository Pattern
  ✅ should validate Repository interface structure

🎉 Phase 1 Type Safety Tests Complete!
✅ All core type definitions validated successfully
📊 TypeScript compilation ensures type safety at build time
```

**Successful Phase 2 Setup:**
```
🧪 Running Phase 2 Testing Infrastructure...

📋 Unit Tests
  ✅ components/AdminInterface.test.tsx
  ✅ hooks/useWebSocket.test.ts
  ✅ middleware/auth.test.ts

📋 Integration Tests  
  ✅ api/rooms.test.ts
  ✅ websocket/game-session.test.ts
  ✅ auth/authentication.test.ts

📋 E2E Tests
  ✅ user-flows/complete-game-session.spec.ts
  ✅ admin-flows/game-system-management.spec.ts

📋 Performance Tests
  ✅ load/websocket-load.js
  ✅ benchmarks/api-endpoints.test.ts

📋 Security Tests
  ✅ penetration/auth-bypass.test.ts

🎉 Phase 2 Testing Infrastructure Complete!
✅ 95% unit test coverage achieved
✅ 85% integration test coverage achieved  
✅ 100% critical flow E2E coverage achieved
📊 Comprehensive testing framework ready for development
```

**Expected Custom Hook Test Output:**
```
🧪 Running Custom Hook Tests...

📋 useWebSocket Hook Tests
  ✅ should connect to WebSocket server
  ✅ should handle incoming messages
  ✅ should send messages successfully
  ✅ should handle connection errors gracefully
  ✅ should reconnect on connection loss
  ✅ should handle multiple message types
  ✅ should cleanup on unmount
  ✅ should handle malformed messages
  ✅ should warn when sending while disconnected
  ✅ should stop reconnecting after max attempts
  ✅ should handle dice roll messages
  ✅ should handle asset flip messages

📊 Hook Test Coverage: 100%
✅ All WebSocket scenarios tested
🔄 Real-time communication patterns validated
🛡️ Error handling and resilience confirmed
```

**Expected Component Test Output:**
```
🧪 Running Component Tests...

📋 AdminInterface Component Tests
  ✅ should display uploaded assets
  ✅ should handle asset upload successfully
  ✅ should display online players
  ✅ should handle player role changes
  ✅ should be accessible via keyboard navigation
  ✅ should integrate with QueryClient provider

📊 Component Test Coverage: 95%
✅ User interactions validated
🎯 Accessibility patterns confirmed
🔄 State management integration tested
```
```

### 🔗 Useful Replit Features

- **Version Control:** Built-in Git integration for testing branches
- **Collaboration:** Real-time collaborative editing for pair programming
- **Deployment:** One-click deployment to Replit hosting
- **Database:** Integrated PostgreSQL database option for testing
- **Secrets Management:** Secure environment variable storage
- **Console Tools:** Built-in terminal for running test commands
- **Port Management:** Automatic port forwarding for development server
- **Package Management:** Automatic dependency installation and updates

### 📊 Testing Framework Features

**Vitest (Unit & Integration Testing):**
- 90% coverage thresholds enforced
- Parallel test execution for speed
- Hot reload in watch mode
- Multiple reporters (HTML, JSON, XML)
- TypeScript support out of the box

**React Testing Library (Component Testing):**
- Accessibility-first testing patterns
- QueryClient provider integration
- File upload testing capabilities
- User interaction simulation
- Modern async testing patterns

**Custom Hooks Testing (React Testing Library):**
- WebSocket hook testing with realistic mock behavior
- State management hook validation
- Async hook operations testing
- Hook cleanup and lifecycle testing
- Real-time communication pattern testing

**Example React Component Test Pattern:**
```typescript
// tests/unit/components/AdminInterface.test.tsx
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AdminInterface } from '@/components/AdminInterface';

const renderAdminInterface = (props = {}) => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <AdminInterface {...props} />
    </QueryClientProvider>
  );
};

describe('AdminInterface', () => {
  it('should upload asset files successfully', async () => {
    renderAdminInterface();
    
    const file = new File(['test content'], 'test.png', { type: 'image/png' });
    const uploadInput = screen.getByLabelText(/upload asset/i);
    
    fireEvent.change(uploadInput, { target: { files: [file] } });
    
    await waitFor(() => {
      expect(screen.getByText(/asset uploaded successfully/i)).toBeInTheDocument();
    });
  });
  
  it('should be accessible via keyboard navigation', async () => {
    renderAdminInterface();
    
    const uploadButton = screen.getByRole('button', { name: /upload/i });
    expect(uploadButton).toBeInTheDocument();
    
    uploadButton.focus();
    expect(uploadButton).toHaveFocus();
  });
});
```

**Example Custom Hook Test Pattern:**
```typescript
// tests/unit/hooks/useWebSocket.test.ts
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useWebSocket } from '@/hooks/useWebSocket';
import type { WebSocketMessage } from '@shared/schema';

// Mock WebSocket with realistic behavior
class MockWebSocket {
  static OPEN = 1;
  public readyState = MockWebSocket.OPEN;
  public onopen: ((event: Event) => void) | null = null;
  public onmessage: ((event: MessageEvent) => void) | null = null;
  public onclose: ((event: CloseEvent) => void) | null = null;

  constructor(public url: string) {
    setTimeout(() => this.onopen?.(new Event('open')), 10);
  }

  send(data: string) {
    setTimeout(() => {
      this.onmessage?.(new MessageEvent('message', { data }));
    }, 5);
  }

  close() {
    this.onclose?.(new CloseEvent('close'));
  }
}

(globalThis as any).WebSocket = MockWebSocket;

describe('useWebSocket', () => {
  it('should connect and handle messages', async () => {
    const onMessage = vi.fn();
    const { result } = renderHook(() => useWebSocket({ onMessage }));

    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 20));
    });

    expect(result.current.connected).toBe(true);

    const testMessage: WebSocketMessage = {
      type: 'asset_moved',
      payload: { assetId: 'test', positionX: 100, positionY: 200 }
    };

    act(() => {
      const event = new MessageEvent('message', { 
        data: JSON.stringify(testMessage) 
      });
      (result.current.websocket as any)?.onmessage?.(event);
    });

    expect(onMessage).toHaveBeenCalledWith(testMessage);
  });

  it('should handle reconnection after connection loss', async () => {
    const { result } = renderHook(() => useWebSocket({ 
      reconnectAttempts: 2,
      reconnectInterval: 50 
    }));

    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 20));
    });

    expect(result.current.connected).toBe(true);

    // Simulate connection loss
    act(() => {
      (result.current.websocket as any)?.onclose?.(
        new CloseEvent('close', { code: 1006, reason: 'Connection lost' })
      );
    });

    expect(result.current.connected).toBe(false);

    // Wait for reconnection
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 100));
    });

    expect(result.current.connected).toBe(true);
  });
});
```

**Playwright (E2E Testing):**
- Cross-browser testing (Chrome, Firefox, Safari)
- Mobile device simulation
- Visual regression testing
- Video recording on failures
- Automatic screenshots on test failures

**k6 (Performance Testing):**
- WebSocket load testing
- API performance benchmarking
- Stress testing scenarios
- Real-time metrics and reporting

**Security Testing:**
- Authentication bypass testing
- XSS prevention validation
- SQL injection protection
- CSRF protection testing
- Input validation security

### 📞 Support

If you encounter issues:

1. **Check Replit Console** for error messages
2. **Verify Environment Variables** in Secrets tab
3. **Run Phase 1 & 2 validation** commands above
4. **Check TypeScript compilation** with `npm run type-check`
5. **Review test output** with `npm run test:debug`
6. **Check coverage reports** in `./coverage/` directory
7. **Verify test database** connection for integration tests

**Common Issues & Solutions:**

- **Test failures**: Run `npm run test:clear-cache` and retry
- **Coverage issues**: Check `vitest.config.ts` coverage settings
- **E2E test failures**: Ensure development server is running (`npm run dev`)
- **Performance test issues**: Verify k6 installation and WebSocket connections
- **Security test failures**: Check authentication middleware configuration

---

**Ready to code and test!** 🚀 Your TableForge project with complete Phase 1 Type Safety and Phase 2 Testing Infrastructure is now fully configured for Replit development.
