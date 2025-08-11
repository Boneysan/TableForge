# Overview

Vorpal Board is a comprehensive multiplayer virtual tabletop gaming platform designed for browser-based real-time tabletop gaming with digital components. It supports rules-agnostic gameplay with advanced features for managing cards, tokens, dice, and boards. The platform aims to provide a robust and flexible environment for diverse tabletop gaming experiences.

## Recent Changes (August 2025)
- **Fixed Application Startup Issues (August 9, 2025)**: Resolved critical TypeScript errors in useAuth hook preventing app startup
- **Database Schema Validated**: Confirmed database connectivity and schema integrity
- **Authentication System Stabilized**: Fixed Firebase auth state management and token handling
- **Enhanced Admin Dashboard**: Added comprehensive room creator information display showing both usernames and UUIDs for better user identification
- **Improved Database Queries**: Enhanced admin room queries with JOIN operations to fetch creator details from both Firebase and Replit user accounts
- **Streamlined Router Configuration**: Simplified authentication-based routing for better reliability and user experience
- **Create Game System Feature (August 9, 2025)**: Added comprehensive game system creation with categorized asset uploads (Cards, Tokens, Maps, Rules), accessible from home page and admin dashboard
- **Enhanced Tag Input System (August 10, 2025)**: Implemented sophisticated tagging interface with preset suggestions organized by Game Types, Mechanics, Themes, Player Count, Complexity, and Time duration. Supports bulk tag entry via comma-separated lists, semicolon-separated lists, and vertical lists (newline-separated). Smart paste detection automatically processes multiple tags from clipboard.
- **Game System Edit Feature (August 10, 2025)**: Added comprehensive editing capabilities for existing game systems. Users can now update system details, modify tags, add/remove assets by category, and delete systems. Edit functionality accessible from admin dashboard with full CRUD operations.
- **Complete Deck Creation & Management System (August 10, 2025)**: Implemented full deck creation workflow with naming, card back selection, and visual card management. Features include: named deck creation with descriptions, custom card back selection from uploaded assets, visual card selection interface with click-to-toggle, deck preview displays with card count and custom back indicators, and complete deck lifecycle management from creation to deletion.
- **Upload System Fixes (August 10, 2025)**: Resolved upload failures by standardizing endpoint to `/api/objects/upload`, fixing authentication token parsing, and enhancing error handling. Upload system now successfully handles 10 files per batch with 10MB file limit and proper Firebase authentication.
- **Moveable Deck Spots on Game Board (August 10, 2025)**: Implemented visual deck spots that appear directly on the game board for each created deck. GMs can drag and reposition deck spots during gameplay with real-time position updates. Features include: automatic deck spot creation when decks are made, color-coded pile types (blue for main decks, red for discard, gray for custom), card count displays, snap-to-grid functionality, and PATCH API endpoint for position updates. Each deck automatically gets a corresponding moveable spot on the board.
- **GM-Controlled Synchronized Board Sizing (August 10, 2025)**: Implemented synchronized board resizing where only GMs can control board dimensions for all players. Features include: preset size options (Small 600×400 to Huge 1600×1200), custom size input with validation (200-3000 pixels), real-time board dimension updates synchronized across all users, scrollable board containers for larger boards, role-based access control (only GMs see resize controls), and database persistence of board dimensions in gameRooms schema. Board size changes are instantly synchronized to all players in the room.
- **Bulk Upload System (August 10, 2025)**: Implemented comprehensive bulk upload system for handling large file batches (100+ files). Features include: automatic batching of large uploads into manageable chunks (50 files per batch), progress tracking across all batches with visual indicators, intelligent retry logic for failed uploads, performance optimization to avoid server overload, specialized interface for card uploads supporting up to 500 files, dual upload options (standard up to 50 files, bulk up to 500 files), and real-time status updates showing successful and failed upload counts. System automatically processes files in sequential batches to maintain server stability while providing complete progress visibility.
- **Fixed Bulk Upload Asset Accumulation Bug (August 10, 2025)**: Resolved critical issue where bulk uploaded assets weren't properly accumulating across batches in the frontend state. The BulkUploader component was calling handleUploadComplete for each batch, but the handler was designed for single uploads and wasn't properly accumulating assets across multiple batches. Fixed by implementing proper batch tracking and ensuring each batch adds to the existing asset state rather than treating each batch as a separate upload. Now bulk uploads properly accumulate all assets before saving to database.
- **Bulk Upload System Fully Operational (August 10, 2025)**: Successfully resolved the root cause of callback system failures in BulkUploader. Fixed event handler setup using useEffect to properly trigger startBulkUpload on upload events. The complete workflow now functions end-to-end: files upload to cloud storage, onBatchComplete and onAllComplete callbacks execute successfully, assets accumulate properly in frontend state, and database persistence works correctly. Verified with successful 5-file bulk upload that increased asset count from 21 to 26 cards with proper database save confirmation.
- **Game System Application & Image Display Fixed (August 10, 2025)**: Completed end-to-end system application workflow from creation to room deployment. Fixed critical applySystemToRoom function by implementing proper asset copying logic, resolved foreign key constraints by creating assets before deck references, and fixed coordinate data types using Math.floor for integer positions. Successfully applied "Wrong Party" game system with 155 cards, 2 complete decks ("Party Themes" and "Party Guests"), and 4 card piles to game room. Resolved image display issues by implementing proper Google Cloud Storage URL proxying through /api/image-proxy endpoint in all frontend components (AssetLibrary, ThemedDeckCard, CardDeck, EnhancedToken, PlayerInterface). Images now load correctly with authentication handling.
- **Asset Library Display Issue Resolved (August 10, 2025)**: Fixed critical issue where Asset Library showed "No cards uploaded yet" despite having 155 assets loaded. Root cause was asset categorization logic that expected specific type values ('card', 'token', etc.) but assets had MIME types ('image/jpeg'). Updated categorization logic to properly classify image files based on file extensions and MIME types. Fixed TypeScript error preventing app startup. Asset Library now correctly displays all 155 card images with working thumbnails in Game Master interface. Image proxy system confirmed fully operational with proper authentication and URL processing.
- **Card Back Images on Game Board (August 11, 2025)**: Successfully implemented authentic card back display on main deck spots. Main decks now show their actual uploaded card back images instead of solid colors, with semi-transparent overlays showing card counts. Features include proper deck name matching (removing " - Main/Discard" suffixes), fallback handling for failed image loads, and maintained drag functionality. Enhanced visual authenticity while preserving all existing gameplay features.
- **Real GM Hand System (August 11, 2025)**: Replaced test data with real GM hand functionality connected to actual game data. GM hands are now managed through CardPile system with pileType "hand" and ownerId matching GM user ID. Features include: fetching GM hand data from card piles, displaying real card images with proper image proxy authentication, automatic GM hand pile creation when needed, real card thumbnails in both compact and large hand viewers, proper card count tracking, and integration with existing card management infrastructure. GM can now have actual game cards in their hand instead of placeholder data.
- **Enhanced Room Deletion System (August 11, 2025)**: Fixed room deletion foreign key constraint errors and implemented game system asset preservation. Fixed deletion order to handle card decks referencing game assets as card backs. Room deletion now preserves original game system assets to maintain system integrity and reusability, while safely cleaning up room-specific data like card piles, decks, board assets, and dice rolls. Enhanced return cards system to detect and repair missing cards automatically when triggered.
- **System Asset Architecture Overhaul (August 11, 2025)**: Implemented efficient asset reuse system where game systems maintain permanent assets that are shared across multiple rooms instead of duplicating them. Added systemId and isSystemAsset fields to game_assets schema. Game system application now reuses existing system assets rather than creating copies, eliminating storage bloat and improving performance. Room deletion preserves system assets while only removing room-specific data. This architecture allows unlimited room creation from the same game system without asset duplication.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Frontend Architecture
- **Framework**: React with TypeScript (Vite build tool)
- **UI Components**: Shadcn/ui (built on Radix UI)
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
- **Schema Structure**: Comprehensive tables for users, game rooms, assets, board elements, players, and dice roll history.

## Authentication and Authorization
- **Hybrid Authentication**: Primary Firebase Google OAuth with automatic Replit Auth fallback.
- **Environment Support**: Automatic domain detection for Replit development and production environments.
- **Access Control**: Custom ACL for object storage and room-based permissions.
- **Security**: All protected API routes verify Firebase ID tokens or Replit Auth.

## Core Features
- **Three-Interface System**: ViewSelector, Admin Interface, Game Master Console, and Player Interface.
- **Real-Time Communication**: WebSocket server for room-based connections and state synchronization.
- **File Upload System**: ObjectUploader with Google Cloud Storage and ACL security.
- **Enhanced Card/Deck System**: Server-side shuffling, pile management, ownership, dealing.
- **Enhanced Token System**: Rotation, z-order, snap-to-grid, lock/unlock.
- **Multi-layer Board System**: Background, game assets, overlay layers with z-indexing.
- **Grid System**: Configurable grid, snap-to-grid, visibility controls.
- **Measurement Tools**: Ruler functionality and distance calculations.
- **Annotation System**: Freehand drawing, sticky notes, text annotations.
- **Asset Pipeline**: Library, upload, and builder tabs with search, filtering, tagging, and bulk operations.
- **Complete Deck Management System**: Two-tab interface (Assets/Card Decks) with named deck creation, custom card back selection, visual card selection interface, deck preview displays, and full deck lifecycle management.
- **Moveable Deck Spots**: Visual deck representations directly on the game board that GMs can drag and reposition during gameplay. Each deck automatically creates a corresponding board spot with real-time position synchronization.
- **Turn & Timer System**: Turn order management, round counting, configurable timers.
- **Game Template System**: Save/load/browse functionality for game templates, accessible from Admin and GM interfaces.
- **Game System Creation**: Dedicated page for creating custom game systems with categorized asset uploads (Cards, Tokens, Maps, Rules) and comprehensive metadata management.
- **Chat System**: Real-time text chat with message history.
- **Player Hand System**: Compact and large views for player and GM hands with card actions.
- **Theme System**: Site-wide dark/light/system theme support with persistence and universal controls.
- **Navigation System**: Universal "Leave Room" buttons and GM view switching for consistent UX.

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

## Development Tools
- **Vite**: Fast build tool.
- **TypeScript**: Static typing.
- **ESBuild**: Fast JavaScript bundler.
- **Tailwind CSS**: Utility-first CSS framework.