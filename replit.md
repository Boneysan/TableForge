# Overview

This is a comprehensive multiplayer virtual tabletop gaming platform called "Vorpal Board" designed for browser-based real-time tabletop gaming with digital components. The platform supports rules-agnostic gameplay with advanced features for cards, tokens, dice, and board management. The application features a React frontend with a Node.js/Express backend, real-time WebSocket communication, PostgreSQL database storage via Drizzle ORM, Google Cloud Storage for file uploads, and hybrid authentication supporting both Firebase Google OAuth and Replit Auth with automatic fallback.

## Recent Changes (January 2025)
- **COMPREHENSIVE IMPLEMENTATION COMPLETED (Jan 9, 2025)**: Successfully implemented the complete Vorpal Board specification including all advanced features:
- **DARK MODE THEME SYSTEM COMPLETED (Jan 9, 2025)**: Integrated comprehensive site-wide dark mode with ThemeProvider, theme toggles on all interfaces, and proper CSS variable support
- **NAVIGATION SYSTEM COMPLETED (Jan 9, 2025)**: Added consistent navigation controls across all interfaces with Leave Room buttons and proper GM view switching

### Phase 1-3 Core Features ✅ COMPLETE
- **Authentication System**: Robust hybrid authentication with Firebase Google OAuth and Replit Auth fallback
- **Room Management**: Full room creation, joining by name/UUID, host controls, and reconnection handling
- **Three-Interface System**: ViewSelector, Admin Interface (blue), Game Master Console (purple), and Player Interface
- **Real-Time Communication**: WebSocket server with room-based connections and state synchronization
- **File Upload System**: ObjectUploader with Google Cloud Storage, 10MB limits, ACL security

### Advanced Game Objects ✅ COMPLETE
- **Enhanced Card/Deck System**: Complete CardDeckManager with face-up/down states, server-side shuffling, pile management, ownership rules, and dealing system
- **Enhanced Token System**: Rotation controls, z-order management, snap-to-grid, lock/unlock functionality
- **Database Schema**: Comprehensive tables for cardDecks, cardPiles, deckCards with full relationships
- **API Integration**: Complete REST endpoints with authentication for all card operations

### Advanced Board Features ✅ COMPLETE
- **Multi-layer Board System**: Background layer, game assets layer, overlay layers with proper z-indexing
- **Grid System**: GridOverlay component with configurable grid size, snap-to-grid functionality, visibility controls
- **Measurement Tools**: MeasurementTool component with ruler functionality, distance calculations, multiple measurement support
- **Annotation System**: AnnotationSystem with freehand drawing, sticky notes, text annotations, color controls, and deletion

### Asset Pipeline ✅ COMPLETE
- **AssetPipeline Component**: Library, upload, and builder tabs with comprehensive functionality
- **Search & Filtering**: Category, tag, and visibility-based filtering with bulk operations
- **Asset Organization**: Tag system with color coding, metadata management, thumbnail generation
- **Bulk Operations**: Multi-select with tag, duplicate, and delete actions

### Turn & Timer System ✅ COMPLETE
- **TurnTracker Component**: Full turn order management, round counting, active player highlighting
- **Timer System**: Configurable turn timers with start/pause/stop controls, visual countdown warnings
- **Player Management**: Real-time updates, name changes, role detection, connection status

### Real-Time Features ✅ COMPLETE
- **Chat System**: Real-time text chat across all interfaces with message history and timestamps
- **State Synchronization**: WebSocket message handling for all game actions with proper authentication
- **Player Updates**: Real-time player list updates, name changes, and connection management

### Navigation System ✅ COMPLETE
- **Universal Leave Room Buttons**: All interfaces (Player, Admin, Game Master) have navigation back to home page
- **GM View Switching**: Direct switching between Admin Interface and Game Master Console without ViewSelector
- **Consistent UX**: Theme toggles and navigation controls positioned consistently across all interfaces
- **Proper Routing**: wouter-based navigation with clean URL management and state preservation

### Theme System ✅ COMPLETE
- **Comprehensive Dark Mode**: Site-wide dark/light/system theme support with localStorage persistence
- **Universal Theme Controls**: Theme toggle buttons integrated into all interfaces (Home, Admin, Game Master, Player)
- **CSS Variables**: All components use theme-aware CSS variables for consistent styling
- **ThemeProvider**: Context-based theme management with automatic system preference detection
- **Cross-Interface Consistency**: Theme preferences persist across all views and page transitions

### Database & Security ✅ COMPLETE
- **Complete Schema**: All tables implemented with proper relationships and constraints
- **API Security**: Hybrid authentication middleware on all protected endpoints
- **Data Integrity**: Foreign key constraints, cascade deletes, and validation
- **Real-time Persistence**: All game state changes saved and synchronized

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