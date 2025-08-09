# Overview

This is a comprehensive multiplayer virtual tabletop gaming platform called "Vorpal Board" designed for browser-based real-time tabletop gaming with digital components. The platform supports rules-agnostic gameplay with advanced features for cards, tokens, dice, and board management. The application features a React frontend with a Node.js/Express backend, real-time WebSocket communication, PostgreSQL database storage via Drizzle ORM, Google Cloud Storage for file uploads, and hybrid authentication supporting both Firebase Google OAuth and Replit Auth with automatic fallback.

## Recent Changes (January 2025)
- **Authentication System Completed**: Implemented robust hybrid authentication with Firebase Google OAuth and Replit Auth fallback
- **Domain Resolution**: Resolved Firebase unauthorized domain issues in development environment with automatic fallback mechanism
- **Production Ready**: Authentication works seamlessly in both development and production environments
- **UI Authentication Flow**: Fixed authentication state detection to properly show authenticated vs non-authenticated interfaces
- **Full Game Room Features**: Users can now create rooms, join rooms, and access all multiplayer features after authentication
- **Role-Based Interfaces Completed (Jan 9, 2025)**: Successfully implemented admin and player interfaces with proper role detection
- **Database Constraint Fix**: Added unique constraint to roomPlayers table and fixed conflict resolution for reliable room joining
- **File Upload System**: Integrated ObjectUploader component with 10MB limit supporting PNG/JPG/PDF formats
- **Game Components**: Built comprehensive GameBoard and GameControls with dice rolling, asset placement, and real-time interaction
- **Three-View System Completed (Jan 9, 2025)**: Successfully implemented ViewSelector with three distinct interfaces:
  - ViewSelector: Choice screen for game masters to select their preferred interface
  - Admin Interface: Upload-focused management page with blue header and file management tools
  - Game Master Console: Interactive gameplay interface with purple header and collapsible GM panel
- **Room Joining by Name**: Added unique constraint to room names and support for joining by either room name or UUID
- **Player-First Experience Completed**: Join existing room button now routes directly to player interface for immediate gameplay
- **Player Interface Implementation**: Built complete SimplePlayerInterface with dice rolling, player list, and game board functionality
- **Database Foreign Key Fix**: Fixed dice rolling errors by ensuring proper room UUID usage instead of room names in WebSocket messages
- **Name Change System**: Added ability for both players and game masters to change their display names with real-time updates
- **Player List Enhancement**: Fixed player list to show actual user names instead of raw user IDs with proper database joins
- **Real-Time Chat System Completed (Jan 9, 2025)**: Implemented comprehensive chat functionality across all interfaces:
  - Chat component integrated in Game Master Console (Chat tab in GM panel)
  - Chat sidebar added to Player Interface for seamless communication
  - Database storage with message history and user name display
  - Real-time WebSocket messaging across all connected users
  - Message timestamps and proper user identification
- **Expanded Scope (Jan 9, 2025)**: Received comprehensive "Vorpal Board-class" specification with advanced tabletop features including:
  - Advanced card/deck management with face-up/down states and ownership rules
  - Enhanced token/tile system with rotation, z-order, and snap-to-grid
  - Multi-layer board system with background maps and overlays
  - Comprehensive asset pipeline with bulk imports and card builder
  - Advanced real-time state management with conflict resolution
  - Measurement tools, annotations, and board manipulation features
  - Security features including server-side shuffles and audit trails
  - Commercial features with subscription plans and usage caps

# User Preferences

Preferred communication style: Simple, everyday language.

# Project Roadmap (Based on Vorpal Board Specification)

## Phase 1: Core Foundation (Current - Mostly Complete)
✓ Basic room creation and joining
✓ User authentication and role management
✓ Basic file upload system
✓ Simple dice rolling
✓ Basic player interface and game master console
✓ Real-time WebSocket communication
✓ Player name management
✓ Real-time text chat system across all interfaces

## Phase 2: Enhanced Game Objects (Next Priority)
- Card system with decks, piles, and face-up/down states
- Enhanced token system with rotation and z-order
- Snap-to-grid functionality
- Card/token ownership and visibility rules
- Server-authoritative shuffling

## Phase 3: Advanced Board Features
- Multi-layer board system (background + overlay layers)
- Measurement tools and rulers
- Annotation system (drawing, sticky notes)
- Fog of war and hide/reveal functionality
- Search and filtering for game objects

## Phase 4: Asset Pipeline Enhancement
- Bulk import system (ZIP files)
- Web-based card builder with cropping
- Asset tagging and versioning
- Thumbnail generation
- Asset library permissions (private/shared)

## Phase 5: Advanced Real-time Features
- Optimistic UI with conflict resolution
- Undo/redo system with action logs
- Turn tracker and timer system
- Auto-save checkpoints
- Session save/restore

## Phase 6: Commercial & Security Features
- Subscription plans and billing
- Advanced ACL system
- Anti-cheat measures
- Audit trails and tamper detection
- Usage caps and quotas

## Phase 7: Polish & Advanced Features
- Accessibility improvements
- Macro/automation system
- Module marketplace
- Advanced moderation tools
- Performance optimizations

# System Architecture

## Frontend Architecture
- **Framework**: React with TypeScript using Vite as the build tool
- **UI Components**: Shadcn/ui component library built on Radix UI primitives
- **Styling**: Tailwind CSS with custom CSS variables for theming
- **Routing**: Wouter for client-side routing (lightweight React router)
- **State Management**: TanStack React Query for server state management
- **Real-time Communication**: Custom WebSocket hook for multiplayer features

## Backend Architecture
- **Runtime**: Node.js with Express.js framework
- **Language**: TypeScript with ES modules
- **API Design**: RESTful API with real-time WebSocket support
- **WebSocket Server**: Built-in WebSocket server for multiplayer game state synchronization
- **File Uploads**: Uppy integration for client-side file handling

## Data Storage Solutions
- **Primary Database**: PostgreSQL accessed via Neon serverless
- **ORM**: Drizzle ORM with schema-first approach
- **File Storage**: Google Cloud Storage for game assets
- **Schema Structure**: 
  - Users and authentication
  - Game rooms with state management
  - Game assets (files) linked to rooms
  - Board assets (positioned game pieces)
  - Room players for multiplayer sessions
  - Dice roll history

## Authentication and Authorization
- **Hybrid Authentication System**: Primary Firebase Google OAuth with automatic Replit Auth fallback
- **Development Environment Support**: Automatic domain detection and fallback for Replit development domains
- **Production Ready**: Firebase Google OAuth for production with proper domain authorization
- **Smart Fallback**: When Firebase fails due to domain issues, automatically redirects to Replit Auth
- **File Access Control**: Custom ACL (Access Control List) system for object storage
- **Room-based Permissions**: Players can only access assets and board state for rooms they've joined
- **Secure API Endpoints**: All protected routes support both Firebase ID tokens and Replit Auth verification

## External Dependencies

### Cloud Services
- **Firebase**: Google OAuth authentication service with free tier (50k MAU)
- **Google Cloud Storage**: File storage with custom ACL policies for secure asset management
- **Neon Database**: Serverless PostgreSQL hosting
- **Replit Sidecar**: Authentication mechanism for Google Cloud services

### Frontend Libraries
- **Firebase SDK**: Client-side authentication with Google OAuth and ID token management
- **Radix UI**: Comprehensive set of unstyled, accessible UI primitives
- **TanStack React Query**: Server state management with caching and synchronization
- **Uppy**: File upload handling with progress tracking and cloud integration
- **Wouter**: Lightweight routing library
- **React Hook Form**: Form state management with validation

### Backend Libraries
- **Firebase Admin SDK**: Server-side Firebase authentication and token verification
- **Drizzle ORM**: Type-safe database toolkit with migrations
- **WebSocket (ws)**: Real-time bidirectional communication
- **Express.js**: Web application framework
- **Zod**: Runtime type validation for API schemas

### Development Tools
- **Vite**: Fast build tool with HMR (Hot Module Replacement)
- **TypeScript**: Static typing across the entire application
- **ESBuild**: Fast JavaScript bundler for production builds
- **Tailwind CSS**: Utility-first CSS framework