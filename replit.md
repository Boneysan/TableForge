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