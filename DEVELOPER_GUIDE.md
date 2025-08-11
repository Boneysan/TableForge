# Vorpal Board Developer Guide

## Overview

Vorpal Board is a comprehensive multiplayer virtual tabletop gaming platform built with React, TypeScript, Express.js, and PostgreSQL. This guide will help you set up, develop, and contribute to the project.

## Quick Start

### Prerequisites

- Node.js 18+ with npm
- PostgreSQL database (Neon serverless recommended)
- Firebase project with authentication enabled
- Google Cloud Storage bucket (optional, for file uploads)

### Automated Setup

Run the development setup script:

```bash
chmod +x scripts/dev-setup.sh
./scripts/dev-setup.sh
```

This script will:
- Check Node.js and npm versions
- Install all dependencies
- Create necessary directories
- Setup environment files
- Run database migrations
- Verify the TypeScript build

### Manual Setup

1. **Clone and Install Dependencies**
   ```bash
   npm install
   ```

2. **Environment Configuration**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Required Environment Variables**
   ```env
   # Database
   DATABASE_URL=postgresql://username:password@hostname:port/database

   # Firebase Configuration
   VITE_FIREBASE_API_KEY=your-api-key
   VITE_FIREBASE_PROJECT_ID=your-project-id  
   VITE_FIREBASE_APP_ID=your-app-id
   FIREBASE_SERVICE_ACCOUNT_KEY={"type":"service_account",...}

   # Optional: Object Storage
   OTLP_ENDPOINT=http://localhost:4318/v1/traces
   OTLP_AUTH_TOKEN=your-token
   ```

4. **Database Setup**
   ```bash
   npm run db:push
   ```

5. **Start Development Server**
   ```bash
   npm run dev
   ```

## Project Structure

```
vorpal-board/
├── client/                 # React frontend
│   ├── src/
│   │   ├── components/     # Reusable UI components
│   │   ├── pages/         # Application pages
│   │   ├── hooks/         # Custom React hooks
│   │   ├── lib/           # Utility functions
│   │   └── types/         # TypeScript type definitions
├── server/                # Express.js backend
│   ├── auth/              # Authentication middleware
│   ├── docs/              # API documentation
│   ├── middleware/        # Express middleware
│   ├── observability/     # Monitoring and metrics
│   ├── routes/            # API route handlers
│   ├── utils/             # Server utilities
│   └── websocket/         # WebSocket handlers
├── shared/                # Shared code between client/server
│   ├── schema.ts          # Database schema and types
│   ├── validators.ts      # Validation schemas
│   └── config.ts          # Shared configuration
├── scripts/               # Development and deployment scripts
├── tests/                 # Test files
├── migrations/            # Database migration files
└── docs/                  # Project documentation
```

## Development Workflow

### Daily Development

1. **Start the Development Server**
   ```bash
   npm run dev
   ```
   This starts both the frontend (Vite) and backend (Express) servers.

2. **Available URLs**
   - Main application: http://localhost:5000
   - API documentation: http://localhost:5000/docs
   - Health check: http://localhost:5000/api/observability/status
   - Metrics: http://localhost:5000/api/observability/metrics

3. **Hot Reloading**
   - Frontend changes are automatically reloaded
   - Backend changes restart the server automatically
   - Database schema changes require running `npm run db:push`

### Database Development

1. **Schema Changes**
   - Edit `shared/schema.ts` to modify the database schema
   - Run `npm run db:push` to apply changes to the development database
   - Use `npm run db:studio` to open Drizzle Studio for visual database management

2. **Sample Data**
   ```bash
   chmod +x scripts/seed-data.sh
   ./scripts/seed-data.sh
   ```
   This creates realistic sample data including demo users, rooms, and game systems.

3. **Database Operations**
   ```bash
   npm run db:push      # Apply schema changes
   npm run db:pull      # Pull schema from database
   npm run db:studio    # Open database studio
   npm run db:drop      # Drop all tables (destructive)
   ```

### API Development

1. **Adding New Endpoints**
   - Add route handlers in `server/routes.ts` or `server/routes/`
   - Update the OpenAPI specification in `server/docs/openapi.yaml`
   - Add appropriate middleware for authentication, validation, and rate limiting

2. **Interactive API Testing**
   - Visit http://localhost:5000/docs for Swagger UI
   - Use the "Authorize" button to authenticate with Firebase
   - Test endpoints directly from the documentation

3. **API Documentation**
   - Swagger UI: http://localhost:5000/docs
   - ReDoc: http://localhost:5000/docs/redoc
   - Raw OpenAPI: http://localhost:5000/docs/openapi.json

### Frontend Development

1. **Component Development**
   - Components use shadcn/ui for consistent design
   - Custom components go in `client/src/components/`
   - Page components go in `client/src/pages/`

2. **State Management**
   - TanStack React Query for server state
   - Local component state for UI state
   - WebSocket integration for real-time updates

3. **Routing**
   - Uses Wouter for lightweight routing
   - Routes defined in `client/src/App.tsx`
   - Protected routes require authentication

## Testing

### Running Tests

```bash
npm run test          # Run all tests
npm run test:unit     # Unit tests only
npm run test:e2e      # End-to-end tests
npm run test:coverage # Coverage report
```

### Writing Tests

1. **Unit Tests**
   - Use Vitest for unit and integration tests
   - Test files: `*.test.ts` or `*.spec.ts`
   - Mock external dependencies

2. **End-to-End Tests**
   - Use Playwright for E2E tests
   - Test files in `tests/e2e/`
   - Test complete user workflows

3. **API Tests**
   - Test API endpoints with Supertest
   - Include authentication and authorization tests
   - Test error conditions and edge cases

## Code Quality

### Linting and Formatting

```bash
npm run lint          # Run ESLint
npm run lint:fix      # Fix linting issues
npm run format        # Format code with Prettier
npm run type-check    # TypeScript type checking
```

### Pre-commit Hooks

The project uses Husky for pre-commit hooks that automatically:
- Run linting and fix auto-fixable issues
- Format code with Prettier
- Run type checking
- Run affected tests

### Code Style Guidelines

1. **TypeScript**
   - Strict mode enabled
   - Explicit type annotations for function parameters and returns
   - Use interfaces for object shapes, types for unions
   - Prefer `const` assertions and `as const` for readonly arrays

2. **React**
   - Functional components with hooks
   - Custom hooks for shared logic
   - Props interfaces for component contracts
   - Use React.memo() for performance-critical components

3. **Database**
   - Use Drizzle ORM for type-safe queries
   - Keep schema definitions in `shared/schema.ts`
   - Use transactions for multi-step operations
   - Index frequently queried columns

## Architecture

### Authentication

The platform supports multiple authentication methods:

1. **Firebase Authentication** (Primary)
   - Google OAuth integration
   - JWT token validation
   - Automatic user profile creation

2. **Replit Authentication** (Development)
   - Automatic fallback in Replit environment
   - Session-based authentication

### Real-time Communication

1. **WebSocket Server**
   - Located at `/ws` endpoint
   - Authentication required for connection
   - Room-based message routing
   - Automatic reconnection handling

2. **Event Types**
   - `room_join` - User joins a room
   - `card_move` - Card/token movement
   - `chat_message` - Real-time chat
   - `dice_roll` - Dice rolling results
   - `board_update` - Board state changes

### Database Architecture

1. **Core Entities**
   - `users` - User profiles and authentication
   - `game_rooms` - Game session management
   - `game_assets` - Uploaded game content
   - `board_assets` - Positioned game pieces
   - `card_piles` - Card collections and hands
   - `chat_messages` - In-game communication

2. **Relationships**
   - Users can own multiple rooms
   - Rooms contain assets and board pieces
   - Assets can be system-wide or room-specific
   - Card piles belong to rooms and optionally players

### File Upload System

1. **Security Features**
   - Content-type validation
   - File size limits (configurable)
   - Filename sanitization
   - Malware scanning integration ready

2. **Storage Pipeline**
   - Client requests upload URL
   - Server generates presigned URL
   - Client uploads directly to cloud storage
   - Server processes and validates uploaded file

## Observability

### Monitoring

1. **Metrics Collection**
   - Prometheus-compatible metrics at `/api/observability/metrics`
   - Real-time system health monitoring
   - Custom business metrics (rooms, users, moves)

2. **Distributed Tracing**
   - OpenTelemetry integration
   - End-to-end request tracing
   - Performance bottleneck identification

3. **Logging**
   - Structured JSON logging with Pino
   - Correlation IDs for request tracking
   - Different log levels for development/production

### Health Checks

- System status: `/api/observability/status`
- Metrics health: `/api/observability/health/metrics`
- Database connectivity validation
- External service dependency checks

## Deployment

### Development Deployment

1. **Replit Deployment**
   - Automatic deployment on code changes
   - Environment variables via Replit Secrets
   - Built-in PostgreSQL database

2. **Local Development**
   - Docker Compose for local services (optional)
   - Local PostgreSQL installation
   - Environment variable configuration

### Production Deployment

1. **Database**
   - Use Neon or similar PostgreSQL service
   - Enable connection pooling
   - Set up automated backups
   - Monitor query performance

2. **Application**
   - Build production bundle: `npm run build`
   - Set NODE_ENV=production
   - Configure proper CORS origins
   - Enable rate limiting

3. **Monitoring**
   - Configure observability endpoints
   - Set up Grafana dashboards
   - Enable alerting for critical metrics
   - Log aggregation setup

## Common Tasks

### Adding a New Game Feature

1. **Database Schema**
   ```typescript
   // In shared/schema.ts
   export const newFeature = pgTable('new_feature', {
     id: varchar('id').primaryKey(),
     roomId: varchar('room_id').notNull(),
     // ... other fields
   });
   ```

2. **API Endpoint**
   ```typescript
   // In server/routes.ts
   app.post('/api/rooms/:roomId/new-feature', 
     hybridAuthMiddleware,
     async (req, res) => {
       // Implementation
     }
   );
   ```

3. **Frontend Component**
   ```typescript
   // In client/src/components/NewFeature.tsx
   export function NewFeature() {
     const { data } = useQuery({
       queryKey: ['/api/rooms', roomId, 'new-feature'],
     });
     // Implementation
   }
   ```

4. **WebSocket Integration**
   ```typescript
   // In server/websocket/
   // Add real-time event handling
   ```

### Debugging Common Issues

1. **Database Connection Issues**
   ```bash
   # Check environment variables
   echo $DATABASE_URL
   
   # Test connection
   npm run db:studio
   ```

2. **Authentication Problems**
   ```bash
   # Check Firebase configuration
   curl http://localhost:5000/api/test-firebase-admin
   
   # Test authentication
   curl -H "Authorization: Bearer YOUR_TOKEN" \
        http://localhost:5000/api/auth/user
   ```

3. **WebSocket Connection Issues**
   ```bash
   # Check WebSocket endpoint
   curl -i -N -H "Connection: Upgrade" \
        -H "Upgrade: websocket" \
        -H "Sec-WebSocket-Key: SGVsbG8sIHdvcmxkIQ==" \
        -H "Sec-WebSocket-Version: 13" \
        http://localhost:5000/ws
   ```

## Contributing

### Development Process

1. **Feature Development**
   - Create feature branch from main
   - Implement feature with tests
   - Update documentation
   - Submit pull request

2. **Code Review**
   - Ensure all tests pass
   - Check code style compliance
   - Verify API documentation updates
   - Test database migrations

3. **Quality Gates**
   - All tests must pass
   - No TypeScript errors
   - ESLint and Prettier compliance
   - API documentation up to date

### Getting Help

1. **Documentation**
   - API documentation: http://localhost:5000/docs
   - System architecture: `IMPLEMENTATION_SUMMARY.md`
   - Observability guide: `OBSERVABILITY.md`

2. **Troubleshooting**
   - Check system health: `/api/observability/status`
   - Review application logs
   - Verify environment configuration
   - Test database connectivity

3. **Development Tools**
   - Database studio: `npm run db:studio`
   - API testing: Swagger UI at `/docs`
   - Log monitoring: Server console output
   - Performance profiling: `/api/observability/metrics`

## Best Practices

### Performance

1. **Database Queries**
   - Use appropriate indexes
   - Implement pagination for large datasets
   - Use database transactions for consistency
   - Monitor slow queries

2. **Real-time Features**
   - Implement reconnection logic
   - Use room-based message filtering
   - Handle connection state gracefully
   - Throttle high-frequency events

3. **File Uploads**
   - Validate file types and sizes
   - Use progressive upload for large files
   - Implement retry logic
   - Clean up failed uploads

### Security

1. **Authentication**
   - Always validate JWT tokens
   - Implement proper session management
   - Use HTTPS in production
   - Rate limit authentication endpoints

2. **Authorization**
   - Check user permissions for room operations
   - Validate resource ownership
   - Implement admin-only endpoints securely
   - Sanitize user inputs

3. **Data Protection**
   - Use environment variables for secrets
   - Implement proper CORS policies
   - Sanitize file uploads
   - Log security events

This developer guide provides a comprehensive foundation for working with Vorpal Board. For specific implementation details, refer to the API documentation and codebase comments.