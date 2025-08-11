#!/bin/bash

# Vorpal Board Database Seeding Script
# Seeds the database with realistic sample data for development

set -e  # Exit on any error

echo "🌱 Vorpal Board Database Seeding"
echo "================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if database is accessible
print_status "Checking database connection..."

if [ -z "${DATABASE_URL:-}" ]; then
    if [ -f ".env" ] && grep -q "DATABASE_URL" .env; then
        source .env
    else
        print_error "DATABASE_URL not found. Please configure your database connection."
        exit 1
    fi
fi

# Test database connection using node
cat > /tmp/db-test.js << 'EOF'
const { Pool } = require('@neondatabase/serverless');
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

async function testConnection() {
  try {
    const client = await pool.connect();
    await client.query('SELECT 1');
    console.log('✓ Database connection successful');
    client.release();
    process.exit(0);
  } catch (error) {
    console.error('✗ Database connection failed:', error.message);
    process.exit(1);
  }
}

testConnection();
EOF

if ! node /tmp/db-test.js; then
    print_error "Cannot connect to database. Please check your DATABASE_URL configuration."
    rm -f /tmp/db-test.js
    exit 1
fi

rm -f /tmp/db-test.js
print_success "Database connection verified"

# Create seeding script
print_status "Creating database seed script..."

cat > /tmp/seed-script.js << 'EOF'
const { Pool } = require('@neondatabase/serverless');
const { drizzle } = require('drizzle-orm/neon-serverless');
const ws = require('ws');

// Configure WebSocket for Neon
const neonConfig = require('@neondatabase/serverless').neonConfig;
neonConfig.webSocketConstructor = ws;

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const db = drizzle({ client: pool });

// Import schema (assuming it's available)
let schema;
try {
  schema = require('../shared/schema');
} catch (error) {
  console.error('Could not import schema:', error.message);
  console.error('Make sure to build the project first: npm run build');
  process.exit(1);
}

const {
  users,
  gameRooms,
  gameAssets,
  gameTemplates,
  gameSystems,
  cardDecks,
  cardPiles,
  boardAssets,
  chatMessages,
  diceRolls,
  sessions
} = schema;

// Sample data
const sampleUsers = [
  {
    id: 'user-demo-gm-001',
    email: 'gamemaster@demo.local',
    firstName: 'Demo',
    lastName: 'GameMaster',
    profileImageUrl: null,
  },
  {
    id: 'user-demo-player-001',
    email: 'player1@demo.local', 
    firstName: 'Alice',
    lastName: 'Player',
    profileImageUrl: null,
  },
  {
    id: 'user-demo-player-002',
    email: 'player2@demo.local',
    firstName: 'Bob', 
    lastName: 'Adventurer',
    profileImageUrl: null,
  },
  {
    id: 'user-demo-player-003',
    email: 'player3@demo.local',
    firstName: 'Carol',
    lastName: 'Mage',
    profileImageUrl: null,
  }
];

const sampleGameSystems = [
  {
    id: 'system-demo-dnd',
    name: 'D&D 5e Demo System',
    description: 'Dungeons & Dragons 5th Edition demo game system with basic assets',
    version: '1.0.0',
    isPublic: true,
    createdBy: 'user-demo-gm-001',
  },
  {
    id: 'system-demo-poker',
    name: 'Poker Demo System', 
    description: 'Standard poker game system with playing cards',
    version: '1.0.0',
    isPublic: true,
    createdBy: 'user-demo-gm-001',
  }
];

const sampleRooms = [
  {
    id: 'room-demo-adventure',
    name: 'The Dragon\'s Lair',
    description: 'A classic dungeon crawl adventure for 3-4 players',
    createdBy: 'user-demo-gm-001',
    isPublic: true,
    maxPlayers: 4,
    currentPlayers: 3,
    status: 'active',
    gameSystemId: 'system-demo-dnd',
    boardConfig: {
      width: 1200,
      height: 800,
      gridSize: 25,
      backgroundColor: '#2d5016'
    }
  },
  {
    id: 'room-demo-poker',
    name: 'Friday Night Poker',
    description: 'Casual poker game for friends',
    createdBy: 'user-demo-gm-001', 
    isPublic: false,
    maxPlayers: 6,
    currentPlayers: 4,
    status: 'active',
    gameSystemId: 'system-demo-poker',
    boardConfig: {
      width: 1000,
      height: 600,
      gridSize: 0,
      backgroundColor: '#1e5631'
    }
  },
  {
    id: 'room-demo-finished',
    name: 'Completed Campaign',
    description: 'A completed D&D campaign for reference',
    createdBy: 'user-demo-gm-001',
    isPublic: true,
    maxPlayers: 5,
    currentPlayers: 0,
    status: 'completed',
    gameSystemId: 'system-demo-dnd',
    boardConfig: {
      width: 1500,
      height: 1000,
      gridSize: 25,
      backgroundColor: '#2d5016'
    }
  }
];

const sampleAssets = [
  // D&D Assets
  {
    id: 'asset-demo-fighter-token',
    name: 'Fighter Token',
    filePath: '/demo-assets/fighter-token.png',
    assetType: 'token',
    systemId: 'system-demo-dnd',
    isSystemAsset: true,
    tags: ['character', 'fighter', 'warrior'],
    metadata: { size: 'medium', category: 'player-character' },
    createdBy: 'user-demo-gm-001'
  },
  {
    id: 'asset-demo-wizard-token', 
    name: 'Wizard Token',
    filePath: '/demo-assets/wizard-token.png',
    assetType: 'token',
    systemId: 'system-demo-dnd',
    isSystemAsset: true,
    tags: ['character', 'wizard', 'spellcaster'],
    metadata: { size: 'medium', category: 'player-character' },
    createdBy: 'user-demo-gm-001'
  },
  {
    id: 'asset-demo-dragon-token',
    name: 'Red Dragon',
    filePath: '/demo-assets/red-dragon.png',
    assetType: 'token',
    systemId: 'system-demo-dnd', 
    isSystemAsset: true,
    tags: ['monster', 'dragon', 'large'],
    metadata: { size: 'large', category: 'monster' },
    createdBy: 'user-demo-gm-001'
  },
  {
    id: 'asset-demo-dungeon-map',
    name: 'Dungeon Map',
    filePath: '/demo-assets/dungeon-map.jpg',
    assetType: 'board',
    systemId: 'system-demo-dnd',
    isSystemAsset: true,
    tags: ['map', 'dungeon', 'battlemap'],
    metadata: { gridSize: 25, category: 'battlemap' },
    createdBy: 'user-demo-gm-001'
  },
  // Poker Assets
  {
    id: 'asset-demo-card-back',
    name: 'Poker Card Back',
    filePath: '/demo-assets/card-back-blue.png', 
    assetType: 'card',
    systemId: 'system-demo-poker',
    isSystemAsset: true,
    tags: ['card-back', 'poker'],
    metadata: { category: 'card-back' },
    createdBy: 'user-demo-gm-001'
  }
];

const sampleTemplates = [
  {
    id: 'template-demo-dnd-starter',
    name: 'D&D Starter Template',
    description: 'Basic D&D setup with common tokens and a simple map',
    category: 'D&D',
    tags: ['dnd', 'starter', 'dungeon'],
    isPublic: true,
    createdBy: 'user-demo-gm-001',
    templateData: {
      gameSystem: 'system-demo-dnd',
      assets: ['asset-demo-fighter-token', 'asset-demo-wizard-token', 'asset-demo-dungeon-map'],
      boardConfig: {
        width: 1200,
        height: 800,
        gridSize: 25,
        backgroundColor: '#2d5016'
      }
    }
  }
];

const sampleChatMessages = [
  {
    id: 'chat-demo-001',
    roomId: 'room-demo-adventure',
    userId: 'user-demo-gm-001',
    message: 'Welcome to The Dragon\'s Lair! Please introduce your characters.',
    messageType: 'chat',
    metadata: {}
  },
  {
    id: 'chat-demo-002', 
    roomId: 'room-demo-adventure',
    userId: 'user-demo-player-001',
    message: 'I am Lyra, a half-elf fighter with a magic sword!',
    messageType: 'chat',
    metadata: {}
  },
  {
    id: 'chat-demo-003',
    roomId: 'room-demo-adventure',
    userId: 'user-demo-player-002',
    message: 'Gandolf the Wise, wizard extraordinaire at your service.',
    messageType: 'chat', 
    metadata: {}
  }
];

const sampleDiceRolls = [
  {
    id: 'dice-demo-001',
    roomId: 'room-demo-adventure',
    userId: 'user-demo-player-001',
    diceType: 'd20',
    diceCount: 1,
    results: [15],
    total: 15,
    modifier: 0,
    rollType: 'attack'
  },
  {
    id: 'dice-demo-002',
    roomId: 'room-demo-adventure', 
    userId: 'user-demo-player-002',
    diceType: 'd8',
    diceCount: 2,
    results: [6, 4],
    total: 10,
    modifier: 0,
    rollType: 'damage'
  }
];

async function seedDatabase() {
  try {
    console.log('🌱 Starting database seeding...');
    
    // Clear existing demo data
    console.log('🧹 Cleaning existing demo data...');
    await db.delete(chatMessages).where(sql`id LIKE 'chat-demo-%'`);
    await db.delete(diceRolls).where(sql`id LIKE 'dice-demo-%'`);
    await db.delete(boardAssets).where(sql`room_id LIKE 'room-demo-%'`);
    await db.delete(cardPiles).where(sql`room_id LIKE 'room-demo-%'`);
    await db.delete(cardDecks).where(sql`room_id LIKE 'room-demo-%'`);
    await db.delete(gameAssets).where(sql`id LIKE 'asset-demo-%'`);
    await db.delete(gameTemplates).where(sql`id LIKE 'template-demo-%'`);
    await db.delete(gameRooms).where(sql`id LIKE 'room-demo-%'`);
    await db.delete(gameSystems).where(sql`id LIKE 'system-demo-%'`);
    await db.delete(users).where(sql`id LIKE 'user-demo-%'`);
    
    // Insert sample data
    console.log('👥 Seeding users...');
    for (const user of sampleUsers) {
      await db.insert(users).values(user);
    }
    
    console.log('🎮 Seeding game systems...');  
    for (const system of sampleGameSystems) {
      await db.insert(gameSystems).values(system);
    }
    
    console.log('🏠 Seeding rooms...');
    for (const room of sampleRooms) {
      await db.insert(gameRooms).values(room);
    }
    
    console.log('🎨 Seeding assets...');
    for (const asset of sampleAssets) {
      await db.insert(gameAssets).values(asset);
    }
    
    console.log('📄 Seeding templates...');
    for (const template of sampleTemplates) {
      await db.insert(gameTemplates).values(template);
    }
    
    console.log('💬 Seeding chat messages...');
    for (const message of sampleChatMessages) {
      await db.insert(chatMessages).values(message);
    }
    
    console.log('🎲 Seeding dice rolls...');
    for (const roll of sampleDiceRolls) {
      await db.insert(diceRolls).values(roll);
    }
    
    // Add some board assets to the active adventure room
    console.log('🗺️ Placing tokens on board...');
    const sampleBoardAssets = [
      {
        id: 'board-demo-001',
        assetId: 'asset-demo-fighter-token',
        roomId: 'room-demo-adventure',
        assetType: 'token',
        positionX: 200,
        positionY: 150,
        rotation: 0,
        scale: 1.0,
        zIndex: 1,
        isFlipped: false,
        isLocked: false,
        ownerId: 'user-demo-player-001'
      },
      {
        id: 'board-demo-002',
        assetId: 'asset-demo-wizard-token',
        roomId: 'room-demo-adventure',
        assetType: 'token', 
        positionX: 250,
        positionY: 150,
        rotation: 0,
        scale: 1.0,
        zIndex: 1,
        isFlipped: false,
        isLocked: false,
        ownerId: 'user-demo-player-002'
      },
      {
        id: 'board-demo-003',
        assetId: 'asset-demo-dragon-token',
        roomId: 'room-demo-adventure',
        assetType: 'token',
        positionX: 400,
        positionY: 300,
        rotation: 45,
        scale: 2.0,
        zIndex: 2,
        isFlipped: false,
        isLocked: false,
        ownerId: null
      }
    ];
    
    for (const boardAsset of sampleBoardAssets) {
      await db.insert(boardAssets).values(boardAsset);
    }
    
    console.log('✅ Database seeding completed successfully!');
    console.log('');
    console.log('📊 Seeded data summary:');
    console.log(`   👥 Users: ${sampleUsers.length}`);
    console.log(`   🎮 Game Systems: ${sampleGameSystems.length}`);
    console.log(`   🏠 Rooms: ${sampleRooms.length}`);
    console.log(`   🎨 Assets: ${sampleAssets.length}`);
    console.log(`   📄 Templates: ${sampleTemplates.length}`);
    console.log(`   💬 Chat Messages: ${sampleChatMessages.length}`);
    console.log(`   🎲 Dice Rolls: ${sampleDiceRolls.length}`);
    console.log(`   🗺️ Board Assets: ${sampleBoardAssets.length}`);
    console.log('');
    console.log('🎯 Demo accounts created:');
    console.log('   📧 gamemaster@demo.local (Game Master)');
    console.log('   📧 player1@demo.local (Alice Player)');
    console.log('   📧 player2@demo.local (Bob Adventurer)'); 
    console.log('   📧 player3@demo.local (Carol Mage)');
    console.log('');
    console.log('🏠 Demo rooms created:');
    console.log('   🐉 The Dragon\'s Lair (Active D&D adventure)');
    console.log('   🃏 Friday Night Poker (Private poker game)');
    console.log('   ✅ Completed Campaign (Finished game for reference)');
    console.log('');
    console.log('🎮 Start the server and visit:');
    console.log('   🌐 http://localhost:5000 (main app)');
    console.log('   📚 http://localhost:5000/docs (API documentation)');
    
  } catch (error) {
    console.error('❌ Database seeding failed:', error);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

// Import sql function
const { sql } = require('drizzle-orm');

seedDatabase();
EOF

print_status "Running database seed script..."

# Run the seeding script
if node /tmp/seed-script.js; then
    print_success "Database seeded successfully!"
else
    print_error "Database seeding failed. Check the error messages above."
    rm -f /tmp/seed-script.js
    exit 1
fi

# Cleanup
rm -f /tmp/seed-script.js

echo ""
print_success "🎉 Database seeding complete!"
echo ""
echo "🎯 What's been created:"
echo "======================"
echo ""
echo "📧 Demo User Accounts:"
echo "   - gamemaster@demo.local (Game Master)"
echo "   - player1@demo.local (Alice Player)"  
echo "   - player2@demo.local (Bob Adventurer)"
echo "   - player3@demo.local (Carol Mage)"
echo ""
echo "🏠 Demo Game Rooms:"
echo "   - The Dragon's Lair (Active D&D adventure with tokens)"
echo "   - Friday Night Poker (Private poker game)" 
echo "   - Completed Campaign (Finished game for reference)"
echo ""
echo "🎮 Game Systems:"
echo "   - D&D 5e Demo System (with character tokens and maps)"
echo "   - Poker Demo System (with playing cards)"
echo ""
echo "📄 Templates:"
echo "   - D&D Starter Template (quick setup for new campaigns)"
echo ""
echo "💬 Sample Data:"
echo "   - Chat messages in active rooms"
echo "   - Dice roll history"
echo "   - Board assets and token positions"
echo ""
echo "🚀 Next Steps:"
echo "=============="
echo ""
echo "1. Start the development server:"
echo "   npm run dev"
echo ""
echo "2. Visit the application:"
echo "   - Main app: http://localhost:5000"
echo "   - API docs: http://localhost:5000/docs"
echo ""
echo "3. Try the demo rooms:"
echo "   - Browse public rooms to see 'The Dragon's Lair'"
echo "   - Join as different demo users to test multiplayer"
echo ""
echo "4. Test different features:"
echo "   - Real-time chat and dice rolling" 
echo "   - Token movement on the game board"
echo "   - Card and deck management"
echo "   - Template and game system creation"
echo ""

print_success "Happy gaming! 🎲"