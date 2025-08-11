# Overview

Vorpal Board is a comprehensive multiplayer virtual tabletop gaming platform designed for browser-based real-time tabletop gaming with digital components. It supports rules-agnostic gameplay with advanced features for managing cards, tokens, dice, and boards. The platform aims to provide a robust and flexible environment for diverse tabletop gaming experiences, offering a powerful tool for GMs and players to create and play digital versions of tabletop games without asset duplication across game rooms. The business vision is to become the leading digital tabletop platform, enabling a new era of collaborative online gaming.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Frontend Architecture
- **Framework**: React with TypeScript (Vite)
- **UI Components**: Shadcn/ui (Radix UI)
- **Styling**: Tailwind CSS with custom CSS variables
- **Routing**: Wouter
- **State Management**: TanStack React Query system with centralized query key factory, optimistic updates with rollback capabilities, and WebSocket invalidation integration. Query architecture includes stable query keys, cache invalidation, optimistic mutations with conflict resolution, and standardized error handling.
- **Real-time Communication**: Advanced WebSocket system integrated with React Query for seamless state synchronization and optimistic UI updates.

## Backend Architecture
- **Runtime**: Node.js with Express.js
- **Language**: TypeScript (ES modules)
- **API Design**: RESTful API with integrated WebSocket server for real-time game state synchronization.
- **File Uploads**: Uppy integration for client-side handling.
- **Concurrency Control**: Hybrid optimistic concurrency and server-authoritative state control for card move management, including a move ledger system with idempotency and conflict prevention.
- **Logging**: Enterprise-grade structured logging with Pino, including correlation IDs, context-aware loggers, security event tracking, and performance monitoring. Comprehensive WebSocket logging with room/user context.
- **Error Handling**: Standardized error envelope format with central error middleware for consistent API error responses, converting Zod validation errors, database constraints, and Firebase auth errors.
- **Input Validation**: Fail-closed validation for all HTTP routes and WebSocket events using shared Zod schemas with typed error responses and security-first request processing.
- **Rate Limiting**: Tiered rate limiting with per-IP and per-user limits for auth, asset upload, room operations, and WebSocket connections.
- **Security Headers**: Production-ready CORS configuration with strict origin validation and enterprise Helmet security with CSP.

## Data Storage Solutions
- **Primary Database**: PostgreSQL (Neon serverless)
- **ORM**: Drizzle ORM (schema-first approach) with comprehensive indexing (84 indexes across 13 tables) and migration management.
- **File Storage**: Google Cloud Storage for game assets with secure upload pipeline including content-type validation, file size limits, extension allowlist, server-side signed URL generation, and comprehensive metadata sanitization. ObjectStorageService includes secure upload URL generation, file processing, and content validation pipeline.

## Authentication and Authorization
- **Authentication**: Enterprise-grade Firebase ID token validation for both HTTP and WebSocket connections with explicit trust boundaries and server-side re-validation. Performance-optimized Firebase token validation with intelligent caching. Automatic Replit Auth fallback for development.
- **Authorization**: Room-scoped authorization with granular permission system for board modifications, chat, dice rolling, and asset management. WebSocket security includes authentication validation and room membership verification for every socket event.
- **Architecture**: Modular auth system with tokenValidator, roomAuth, middleware, and socketAuth for comprehensive security coverage.
- **Logging**: Comprehensive authentication event logging and suspicious activity monitoring.

## Core Features
- **Interfaces**: Three-interface system: ViewSelector, Admin Interface, Game Master Console, and Player Interface.
- **Real-Time Communication**: WebSocket server for room-based connections and state synchronization.
- **File Upload System**: ObjectUploader with Google Cloud Storage and ACL security, supporting bulk uploads with progress tracking and retry logic. Includes comprehensive orphaned file cleanup.
- **Card/Deck System**: Server-side shuffling, pile management, ownership, dealing, visual deck spots, named deck creation, custom card back selection, and full deck lifecycle management.
- **Game System Management**: Creation and editing of custom game systems with categorized asset uploads (Cards, Tokens, Maps, Rules) and comprehensive metadata management. Game system assets are permanent and shared across rooms.
- **Token System**: Rotation, z-order, snap-to-grid, lock/unlock.
- **Board System**: Multi-layer board system (background, game assets, overlay) with z-indexing, GM-controlled synchronized board resizing, and configurable grid system.
- **Measurement Tools**: Ruler functionality and distance calculations.
- **Annotation System**: Freehand drawing, sticky notes, text annotations.
- **Asset Pipeline**: Library, upload, and builder tabs with search, filtering, tagging, and bulk operations.
- **Turn & Timer System**: Turn order management, round counting, configurable timers.
- **Game Template System**: Save/load/browse functionality.
- **Chat System**: Real-time text chat with message history.
- **Player Hand System**: Compact and large views for player and GM hands with card actions and real game data.
- **Theme System**: Site-wide dark/light/system theme support with persistence.
- **Navigation System**: Universal "Leave Room" buttons and GM view switching.
- **Room Deletion System**: Safely cleans up room-specific data while preserving game system assets.

# External Dependencies

## Cloud Services
- **Firebase**: Google OAuth authentication.
- **Google Cloud Storage**: File storage for game assets.
- **Neon Database**: Serverless PostgreSQL hosting.
- **Replit Sidecar**: Authentication mechanism for Google Cloud services in development.

## Frontend Libraries
- **Firebase SDK**: Client-side authentication.
- **Radix UI**: Unstyled, accessible UI primitives.
- **TanStack React Query**: Server state management.
- **Uppy**: File upload handling.
- **Wouter**: Lightweight routing.
- **React Hook Form**: Form state management.

## Backend Libraries
- **Firebase Admin SDK**: Server-side Firebase authentication.
- **Drizzle ORM**: Type-safe database toolkit.
- **WebSocket (ws)**: Real-time communication.
- **Express.js**: Web application framework.
- **Zod**: Runtime type validation.