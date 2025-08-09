# Overview

This is a multiplayer tabletop gaming application that allows users to create and join game rooms where they can share game assets (cards, tokens, maps), place them on a shared game board, and interact in real-time. The application features a React frontend with a Node.js/Express backend, real-time WebSocket communication, PostgreSQL database storage via Drizzle ORM, Google Cloud Storage for file uploads, and hybrid authentication supporting both Firebase Google OAuth and Replit Auth with automatic fallback.

## Recent Changes (January 2025)
- **Authentication System Completed**: Implemented robust hybrid authentication with Firebase Google OAuth and Replit Auth fallback
- **Domain Resolution**: Resolved Firebase unauthorized domain issues in development environment with automatic fallback mechanism
- **Production Ready**: Authentication works seamlessly in both development and production environments

# User Preferences

Preferred communication style: Simple, everyday language.

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