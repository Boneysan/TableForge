# E2E Admin Interface Tests

This directory contains comprehensive End-to-End tests for the admin interface of the Vorpal Board platform.

## Test Structure

### Game System Management (`game-system-management.spec.ts`)
Tests the complete lifecycle of game system creation, management, and publishing:
- ✅ **Core Requirements (Phase 2 Spec)**: System creation, asset upload, publishing workflow
- ✅ **Enhanced Coverage**: Category management, search functionality, system editing
- ✅ **Asset Management**: Multiple asset uploads, organization, deletion
- ✅ **Publishing Workflow**: Validation, requirements checking, status management
- ✅ **Permissions**: Access control, collaborator management, role assignment
- ✅ **Templates**: System cloning, template creation, template-based system creation

### User Management (`user-management.spec.ts`)
Tests user account administration and moderation:
- ✅ **User Administration**: Account viewing, search, permission management
- ✅ **Moderation Actions**: User suspension, reactivation, role changes
- ✅ **Analytics**: User activity tracking, registration metrics, filtering

### Room Management (`room-management.spec.ts`)
Tests room oversight and performance monitoring:
- ✅ **Room Overview**: Active rooms display, search, filtering
- ✅ **Moderation**: Room suspension, restoration, forced closure
- ✅ **Performance**: Metrics dashboard, alerts configuration, threshold management

## Test Features

### Authentication & Authorization
All tests assume admin-level authentication is handled by the test setup. Tests verify:
- Admin interface accessibility
- Role-based feature visibility
- Permission-based action availability

### Data Management
Tests interact with:
- Game systems and categories
- User accounts and permissions
- Room states and configurations
- Asset uploads and organization

### Real-time Features
E2E tests validate:
- Live status updates
- Real-time metrics display
- Immediate UI feedback for actions

## Running Tests

```bash
# Run all admin interface tests
npx playwright test e2e/admin-flows/

# Run specific test suites
npx playwright test e2e/admin-flows/game-system-management.spec.ts
npx playwright test e2e/admin-flows/user-management.spec.ts
npx playwright test e2e/admin-flows/room-management.spec.ts

# Run with headed browser (for debugging)
npx playwright test e2e/admin-flows/ --headed

# Generate test report
npx playwright test e2e/admin-flows/ --reporter=html
```

## Test Data

Tests utilize fixtures from `tests/fixtures/`:
- `card-back.png` - Card back images for game systems
- `card-front.png` - Card front images for game systems
- `test-card.png` - General card assets
- `test-token.png` - Token assets
- `test-map.png` - Map/board assets

## Assertions & Validations

### UI Element Testing
- Element visibility and interaction
- Form field validation
- Button state management
- Modal dialog behavior

### Data Integrity
- System creation and updates
- Asset upload verification
- Status change validation
- Permission assignment verification

### Performance Validation
- Response time measurements
- Resource usage monitoring
- Alert threshold configuration
- Dashboard metric display

## Phase 2 Compliance

These tests implement the complete **Section 4.2 Admin Interface E2E Tests** from the Phase 2 testing specification:

✅ **Exact Specification Match**: Core test matches Phase 2 requirements exactly  
✅ **Enhanced Coverage**: Additional test scenarios for comprehensive validation  
✅ **TypeScript Integration**: Full type safety and error-free execution  
✅ **Production Ready**: Suitable for CI/CD integration and automated testing

The admin interface E2E tests provide complete validation of administrative features, ensuring the platform maintains quality and security standards for game system management, user administration, and room oversight.
