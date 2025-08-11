# Overview

Vorpal Board is a comprehensive multiplayer virtual tabletop gaming platform designed for browser-based real-time tabletop gaming with digital components. It supports rules-agnostic gameplay with advanced features for managing cards, tokens, dice, and boards. The platform aims to provide a robust and flexible environment for diverse tabletop gaming experiences, offering a powerful tool for GMs and players to create and play digital versions of tabletop games without asset duplication across game rooms.

## Recent Changes (August 11, 2025)
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
- **Hybrid Authentication**: Primary Firebase Google OAuth with automatic Replit Auth fallback.
- **Environment Support**: Automatic domain detection for Replit environments.
- **Access Control**: Custom ACL for object storage and room-based permissions.
- **Security**: All protected API routes verify Firebase ID tokens or Replit Auth.

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