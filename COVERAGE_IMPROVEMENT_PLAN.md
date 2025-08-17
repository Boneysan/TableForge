# Coverage Improvement Plan - Phase 2 Week 4

## Current Coverage Status
- **Line Coverage**: 0.09% (Target: 95%)
- **Branch Coverage**: 8.33% (Target: 90%)
- **Function Coverage**: 8.24% (Target: 90%)
- **Statement Coverage**: 0.09% (Target: 90%)

## Coverage Gap Analysis

### High Priority Files (0% Coverage - Core Business Logic)
1. **Server Middleware**: `server/middleware/errorHandler.ts` ✅ (16 tests complete)
2. **Server Auth**: `server/auth/middleware.ts`, `tokenValidator.ts`, `roomAuth.ts`
3. **Server Utils**: `server/utils/logger.ts`
4. **Client Hooks**: `client/src/hooks/useWebSocket.tsx` ✅, `useCommandStack.ts` (partial)
5. **Shared Utilities**: `shared/sanitization.ts`, `shared/validators.ts`

### Medium Priority Files (Partial Coverage)
1. **Client Components**: `GameBoard.tsx`, `AdminInterface.tsx` (partial coverage)
2. **Server Routes**: Core route handlers 
3. **Database Layer**: Connection and query utilities

### Low Priority Files (Framework/Config)
1. **UI Components**: `client/src/components/ui/*` (framework components)
2. **Build Config**: Various config files
3. **Static Assets**: CSS, images, etc.

## Implementation Strategy

### Phase 1: Fix Existing Tests (Critical)
- [x] Fix `useCommandStack.test.ts` (4 failing tests)
- [x] Fix `GameBoard.test.tsx` (9 failing tests - missing fixtures)
- [x] Fix `AdminInterface.test.tsx` (1 failing test - selector issue)
- [x] Fix `schema.test.ts` (10 failing tests - schema imports)
- [x] Fix `moveLogic.test.ts` (1 failing test - collision logic)

### Phase 2: Add Critical Business Logic Tests
- [ ] `shared/sanitization.ts` - Input sanitization (security critical)
- [ ] `shared/validators.ts` - Data validation logic
- [ ] `server/auth/tokenValidator.ts` - Authentication security
- [ ] `server/utils/logger.ts` - Logging functionality

### Phase 3: Add Client-Side Logic Tests  
- [ ] `client/src/hooks/useAuth.ts` - Authentication state
- [ ] `client/src/hooks/useGameRoomQuery.ts` - Data fetching
- [ ] `client/src/lib/utils.ts` - Utility functions

### Phase 4: Integration Points
- [ ] `server/routes/*` - API endpoint logic
- [ ] `server/websocket/*` - Real-time functionality
- [ ] Database repositories and connections

## Execution Plan

### Step 1: Fix Broken Tests (Immediate)
```bash
# Fix the 25 currently failing tests
npm run test:unit -- --reporter=verbose
```

### Step 2: Add High-Impact Tests
Focus on files with the highest business logic density:
- Authentication and security modules
- Data validation and sanitization  
- Core business logic utilities

### Step 3: Measure and Iterate
```bash
# Run coverage after each batch of new tests
npm run test:unit -- --coverage
```

### Target Milestones
- **Week 4 Day 1**: Fix all broken tests (25 → 0 failures)
- **Week 4 Day 2**: Achieve 30% line coverage  
- **Week 4 Day 3**: Achieve 60% line coverage
- **Week 4 Day 4**: Achieve 85% line coverage
- **Week 4 Day 5**: Achieve 95% line coverage target

## Quality Gates
- All tests must pass before adding new ones
- Each new test file should achieve >90% coverage of its target module
- Integration tests should cover end-to-end scenarios
- Performance tests should validate <100ms response times

## Success Metrics
- [x] Complete testing infrastructure (k6, autocannon, security, reporting)
- [ ] 95% line coverage for unit tests
- [ ] 85% API endpoint coverage for integration tests  
- [ ] 100% critical user flow coverage for E2E tests
- [ ] All endpoints <100ms (95th percentile)
- [ ] Zero critical security vulnerabilities

---

**Next Action**: Fix the 25 failing unit tests to establish a solid foundation for coverage improvement.
