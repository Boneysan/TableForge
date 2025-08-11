# Overview

Vorpal Board is a comprehensive multiplayer virtual tabletop gaming platform designed for browser-based real-time tabletop gaming with digital components. It supports rules-agnostic gameplay with advanced features for managing cards, tokens, dice, and boards. The platform aims to provide a robust and flexible environment for diverse tabletop gaming experiences, offering a powerful tool for GMs and players to create and play digital versions of tabletop games without asset duplication across game rooms.

## Recent Changes (August 11, 2025)
- **Schema-Validated Configuration System**: Implemented comprehensive Zod-based environment validation with fail-fast startup and clear error messages
- **Enhanced Security Architecture**: Added rate limiting (general/API/auth tiers), CORS handling, Helmet security headers, and suspicious request monitoring
- **Environment Separation**: Created proper server/client configuration separation with validation scripts and comprehensive error handling
- **Security Middleware System**: Implemented tiered rate limiting, request validation, security logging, and health check endpoints
- **Configuration Management**: Added environment validation utilities, secure secret generation, and comprehensive configuration documentation
- **🛡️ ENTERPRISE-GRADE AUTHENTICATION HARDENING**: Implemented comprehensive Firebase ID token validation for both HTTP and WebSocket connections with explicit trust boundaries between client and server authentication states
- **🔐 Advanced Room Authorization**: Created room-scoped authorization with granular permission system for board modifications, chat, dice rolling, and asset management
- **🔒 WebSocket Security**: Secured all real-time operations with authentication validation and room membership verification for every socket event
- **⚡ Memoized Token Validation**: Added performance-optimized Firebase token validation with intelligent caching and automatic re-validation
- **🏗️ Robust Auth Architecture**: Built modular auth system with tokenValidator.ts, roomAuth.ts, middleware.ts, and socketAuth.ts for comprehensive security coverage
- **🔐 COMPREHENSIVE INPUT VALIDATION SYSTEM**: Implemented fail-closed validation for all HTTP routes and WebSocket events using shared Zod schemas with typed error responses
- **✅ Validation Middleware Framework**: Created reusable validation middleware with proper error handling and type safety for body, params, query, and WebSocket messages
- **🛡️ Security-First Request Processing**: All API endpoints now validate inputs before processing with standardized error responses and proper TypeScript typing
- **🚦 ADVANCED RATE LIMITING SYSTEM**: Implemented tiered rate limiting with per-IP and per-user limits for auth, asset upload, room operations, and WebSocket connections
- **🌐 PRODUCTION-READY CORS CONFIGURATION**: Strict origin validation with environment-specific policies, explicit domain whitelisting, and comprehensive error handling
- **🛡️ ENTERPRISE HELMET SECURITY**: Configured CSP with strict img-src, connect-src policies, security headers, and violation reporting for comprehensive protection
- **Fixed Empty Deck Issue**: Resolved problem where created decks showed 0 cards in the Game Master Console Cards tab
- **Enhanced Drag & Drop**: Implemented complete drag-and-drop functionality from Asset Library to GameBoard with proper grid snapping
- **Image Display Fix**: All game assets now display correctly using image proxy for private Google Cloud Storage URLs
- **CRITICAL System Apply Fix**: Fixed system apply logic that was incorrectly checking for ANY existing system assets instead of ALL expected assets, causing incomplete transfers
- **Asset Transfer Completion**: "Wrong Party" system now properly transfers all 155 cards (21 Party Themes + 134 Party Guests) when applied to rooms
- **CardDeckManager Filter Fix**: Fixed filtering bug that prevented image assets from being recognized as valid cards for deck creation
- **Deck Creation Logic Fix**: Corrected deck creation to use proper asset ID arrays instead of invalid number references
- **Asset Deduplication**: Added logic to prevent duplicate asset creation during partial system applications
- **System Asset Creation Fixed**: Resolved asset upload failure with new `/api/systems/:systemId/assets` endpoint
- **BulkUploader Enhanced**: Added immediate database record creation callbacks during upload process
- **Google Cloud Storage Cleanup**: Implemented comprehensive orphaned file cleanup system with admin interface
- **Admin Dashboard Cleanup**: Added "Cleanup Orphaned Files" button with authentication and toast notifications

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Frontend Architecture
- **Framework**: React with TypeScript (Vite)
- **UI Components**: Shadcn/ui (Radix UI)
- **Styling**: Tailwind CSS with custom CSS variables
- **Routing**: Wouter
- **State Management**: TanStack React Query for server state
- **Real-time Communication**: Custom WebSocket hook

## Backend Architecture
- **Runtime**: Node.js with Express.js
- **Language**: TypeScript (ES modules)
- **API Design**: RESTful API with integrated WebSocket server for real-time game state synchronization
- **File Uploads**: Uppy integration for client-side handling

## Data Storage Solutions
- **Primary Database**: PostgreSQL (Neon serverless)
- **ORM**: Drizzle ORM (schema-first approach)
- **File Storage**: Google Cloud Storage for game assets
- **Schema Structure**: Comprehensive tables for users, game rooms, assets, board elements, players, and dice roll history. Assets are designed for reuse across multiple game rooms without duplication, maintaining a `systemId` and `isSystemAsset` flag.

## Authentication and Authorization
- **🛡️ Enterprise-Grade Firebase Authentication**: Comprehensive Firebase ID token validation with explicit trust boundaries and server-side re-validation for every request
- **🔐 Room-Scoped Authorization**: Granular permission system with role-based access control for board modifications, chat, dice rolling, and asset management
- **⚡ Performance-Optimized Validation**: Memoized Firebase token validation with intelligent caching and automatic refresh handling
- **🔒 WebSocket Security**: Full authentication and authorization for real-time operations with room membership validation for every socket event
- **🏗️ Modular Auth Architecture**: Comprehensive auth system with tokenValidator, roomAuth, middleware, and socketAuth modules for complete security coverage
- **🔄 Hybrid Fallback**: Automatic Replit Auth fallback for development environments with seamless Firebase integration
- **📊 Security Logging**: Comprehensive authentication event logging and suspicious activity monitoring

## Core Features
- **Three-Interface System**: ViewSelector, Admin Interface, Game Master Console, and Player Interface.
- **Real-Time Communication**: WebSocket server for room-based connections and state synchronization.
- **File Upload System**: ObjectUploader with Google Cloud Storage and ACL security, supporting bulk uploads with progress tracking and retry logic.
- **Enhanced Card/Deck System**: Server-side shuffling, pile management, ownership, dealing, and visual deck spots on the game board with real-time positioning.
- **Game System Management**: Creation and editing of custom game systems with categorized asset uploads (Cards, Tokens, Maps, Rules) and comprehensive metadata management. Game system assets are permanent and shared across rooms.
- **Enhanced Token System**: Rotation, z-order, snap-to-grid, lock/unlock.
- **Multi-layer Board System**: Background, game assets, overlay layers with z-indexing. GM-controlled synchronized board resizing.
- **Grid System**: Configurable grid, snap-to-grid, visibility controls.
- **Measurement Tools**: Ruler functionality and distance calculations.
- **Annotation System**: Freehand drawing, sticky notes, text annotations.
- **Asset Pipeline**: Library, upload, and builder tabs with search, filtering, tagging, and bulk operations.
- **Complete Deck Management System**: Named deck creation, custom card back selection, visual card selection interface, deck preview displays, and full deck lifecycle management. Supports authentic card back display on main deck spots.
- **Turn & Timer System**: Turn order management, round counting, configurable timers.
- **Game Template System**: Save/load/browse functionality for game templates.
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