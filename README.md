# Vorpal Board

A comprehensive multiplayer virtual tabletop gaming platform designed for browser-based real-time tabletop gaming with digital components.

## Overview

Vorpal Board supports rules-agnostic gameplay with advanced features for managing cards, tokens, dice, and boards. The platform provides a robust and flexible environment for diverse tabletop gaming experiences, offering powerful tools for Game Masters and players to create and play digital versions of tabletop games without asset duplication across game rooms.

## Features

### Core Gaming Features
- **Real-time Multiplayer**: WebSocket-based real-time communication for synchronized gameplay
- **Advanced Card Management**: Complete deck system with shuffling, dealing, and pile management
- **Token System**: Rotation, z-order, snap-to-grid, and lock/unlock functionality
- **Multi-layer Board System**: Background, game assets, and overlay layers with z-indexing
- **Measurement Tools**: Ruler functionality and distance calculations
- **Annotation System**: Freehand drawing, sticky notes, and text annotations

### Game System Management
- **Custom Game System Creation**: Build and edit game systems with categorized asset uploads
- **Asset Library**: Comprehensive asset management with search, filtering, and tagging
- **Template System**: Save, load, and browse game templates
- **Bulk Upload**: Support for large card sets and asset collections

### Interface & Controls
- **Three-Interface System**: Admin Interface, Game Master Console, and Player Interface
- **Responsive Design**: Works seamlessly across different screen sizes
- **Theme System**: Dark/light/system theme support with persistence
- **Drag & Drop**: Intuitive asset placement with grid snapping

## Tech Stack

### Frontend
- **React** with TypeScript (Vite build system)
- **Shadcn/ui** components (Radix UI primitives)
- **Tailwind CSS** for styling
- **Wouter** for routing
- **TanStack React Query** for server state management

### Backend
- **Node.js** with Express.js
- **TypeScript** with ES modules
- **WebSocket** server for real-time communication
- **PostgreSQL** database with Drizzle ORM
- **Google Cloud Storage** for asset storage

### Authentication & Security
- **Firebase** Google OAuth (primary)
- **Replit Auth** (fallback)
- **Custom ACL** for object storage
- **Room-based permissions**

## Getting Started

### Prerequisites
- Node.js 18+ 
- PostgreSQL database
- Google Cloud Storage bucket
- Firebase project (for authentication)

### Installation

1. Install dependencies:
```bash
npm install
```

2. Set up environment variables (create `.env` file):
```
DATABASE_URL=your_postgresql_connection_string
GOOGLE_APPLICATION_CREDENTIALS=path/to/service-account.json
FIREBASE_PROJECT_ID=your_firebase_project_id
```

3. Run database migrations:
```bash
npm run db:push
```

4. Start the development server:
```bash
npm run dev
```

The application will be available at `http://localhost:5000`.

### Project Structure

```
├── client/          # React frontend application
├── server/          # Express.js backend
├── shared/          # Shared TypeScript schemas and types
├── components.json  # Shadcn/ui configuration
├── drizzle.config.ts # Database configuration
├── package.json     # Dependencies and scripts
└── vite.config.ts   # Vite build configuration
```

## Database Schema

The application uses PostgreSQL with the following main entities:
- **Users**: Player profiles and authentication
- **Game Rooms**: Virtual game spaces
- **Game Systems**: Reusable game templates and rules
- **Game Assets**: Cards, tokens, and other game pieces
- **Card Decks & Piles**: Organized card collections
- **Board Assets**: Positioned game elements

## API Endpoints

### Authentication
- `GET /api/auth/user` - Get current user
- `POST /api/auth/logout` - Sign out

### Game Management
- `GET /api/rooms` - List user's rooms
- `POST /api/rooms` - Create new room
- `GET /api/systems` - List game systems
- `POST /api/rooms/:id/apply-system` - Apply system to room

### Asset Management
- `POST /api/assets` - Upload new asset
- `GET /api/rooms/:id/assets` - Get room assets
- `POST /api/systems/:id/assets` - Upload system assets

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Recent Updates

- Fixed critical system apply logic for complete asset transfers
- Enhanced card deck management with proper filtering
- Improved drag-and-drop functionality with grid snapping
- Added comprehensive asset deduplication system
- Implemented Google Cloud Storage cleanup utilities

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions, please open an issue in the GitHub repository.