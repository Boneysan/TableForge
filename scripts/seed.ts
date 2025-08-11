#!/usr/bin/env tsx
/**
 * Database Seeding Script for Vorpal Board
 * 
 * Creates demo game systems with cards, tokens, and assets for instant smoke-testing.
 * Run with: npx tsx scripts/seed.ts
 */

import { Pool, neonConfig } from '@neondatabase/serverless';
import { drizzle } from 'drizzle-orm/neon-serverless';
import ws from 'ws';
import { randomUUID } from 'crypto';
import * as schema from '../shared/schema.js';
import { 
  users, 
  gameRooms, 
  gameAssets, 
  gameSystems, 
  cardDecks, 
  cardPiles, 
  boardAssets, 
  chatMessages 
} from '../shared/schema.js';

// Configure WebSocket for Neon
neonConfig.webSocketConstructor = ws;

// Database connection
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const db = drizzle({ client: pool, schema });

// Demo data constants
const DEMO_PREFIX = 'demo-';
const DEMO_USER_ID = `${DEMO_PREFIX}user-gm`;
const DEMO_PLAYER_IDS = [
  `${DEMO_PREFIX}player-alice`,
  `${DEMO_PREFIX}player-bob`,
  `${DEMO_PREFIX}player-carol`,
];

/**
 * Sample users for testing
 */
const createDemoUsers = () => [
  {
    id: DEMO_USER_ID,
    email: 'demo-gm@vorpalboard.local',
    firstName: 'Demo',
    lastName: 'GameMaster',
    profileImageUrl: 'https://api.dicebear.com/7.x/avataaars/svg?seed=GameMaster',
  },
  ...DEMO_PLAYER_IDS.map((id, index) => {
    const names = ['Alice', 'Bob', 'Carol'];
    const surnames = ['Adventurer', 'Warrior', 'Mage'];
    return {
      id,
      email: `demo-${names[index].toLowerCase()}@vorpalboard.local`,
      firstName: names[index],
      lastName: surnames[index],
      profileImageUrl: `https://api.dicebear.com/7.x/avataaars/svg?seed=${names[index]}`,
    };
  })
];

/**
 * Demo game systems with complete asset sets
 */
const createDemoSystems = () => {
  const dndSystemId = `${DEMO_PREFIX}system-dnd5e`;
  const pokerSystemId = `${DEMO_PREFIX}system-poker`;

  return [
    {
      id: dndSystemId,
      name: 'D&D 5e Demo System',
      description: 'Complete D&D 5th Edition game system with character tokens, dice, and battle maps for immediate gameplay testing.',
      version: '1.0.0',
      isPublic: true,
      uploadedBy: DEMO_USER_ID,
      createdBy: DEMO_USER_ID,
    },
    {
      id: pokerSystemId,
      name: 'Poker Demo System',
      description: 'Standard 52-card poker deck with chips and table for card game testing.',
      version: '1.0.0', 
      isPublic: true,
      uploadedBy: DEMO_USER_ID,
      createdBy: DEMO_USER_ID,
    }
  ];
};

/**
 * Comprehensive asset library for testing
 */
const createDemoAssets = () => {
  const dndSystemId = `${DEMO_PREFIX}system-dnd5e`;
  const pokerSystemId = `${DEMO_PREFIX}system-poker`;

  return [
    // D&D Character Tokens
    {
      id: `${DEMO_PREFIX}asset-fighter`,
      name: 'Human Fighter',
      filePath: '/demo-assets/tokens/fighter.svg',
      type: 'token' as const,
      systemId: dndSystemId,
      isSystemAsset: true,
      tags: ['character', 'fighter', 'human', 'player'],
      metadata: { 
        size: 'medium', 
        category: 'player-character',
        hitPoints: 12,
        armorClass: 16
      },
      uploadedBy: DEMO_USER_ID,
      createdBy: DEMO_USER_ID,
    },
    {
      id: `${DEMO_PREFIX}asset-wizard`,
      name: 'Elf Wizard',
      filePath: '/demo-assets/tokens/wizard.svg',
      type: 'token' as const,
      systemId: dndSystemId,
      isSystemAsset: true,
      tags: ['character', 'wizard', 'elf', 'spellcaster'],
      metadata: { 
        size: 'medium', 
        category: 'player-character',
        hitPoints: 8,
        armorClass: 12,
        spellSlots: { level1: 3, level2: 1 }
      },
      uploadedBy: DEMO_USER_ID,
      createdBy: DEMO_USER_ID,
    },
    {
      id: `${DEMO_PREFIX}asset-rogue`,
      name: 'Halfling Rogue',
      filePath: '/demo-assets/tokens/rogue.svg',
      type: 'token' as const,
      systemId: dndSystemId,
      isSystemAsset: true,
      tags: ['character', 'rogue', 'halfling', 'stealth'],
      metadata: { 
        size: 'small', 
        category: 'player-character',
        hitPoints: 10,
        armorClass: 14,
        sneakAttack: '1d6'
      },
      uploadedBy: DEMO_USER_ID,
      createdBy: DEMO_USER_ID,
    },

    // D&D Monster Tokens  
    {
      id: `${DEMO_PREFIX}asset-goblin`,
      name: 'Goblin',
      filePath: '/demo-assets/tokens/goblin.svg',
      type: 'token' as const,
      systemId: dndSystemId,
      isSystemAsset: true,
      tags: ['monster', 'goblin', 'small', 'enemy'],
      metadata: { 
        size: 'small', 
        category: 'monster',
        challengeRating: '1/4',
        hitPoints: 7,
        armorClass: 15
      },
      uploadedBy: DEMO_USER_ID,
      createdBy: DEMO_USER_ID,
    },
    {
      id: `${DEMO_PREFIX}asset-orc`,
      name: 'Orc Warrior',
      filePath: '/demo-assets/tokens/orc.svg',
      type: 'token' as const,
      systemId: dndSystemId,
      isSystemAsset: true,
      tags: ['monster', 'orc', 'medium', 'warrior'],
      metadata: { 
        size: 'medium', 
        category: 'monster',
        challengeRating: '1',
        hitPoints: 15,
        armorClass: 13
      },
      uploadedBy: DEMO_USER_ID,
      createdBy: DEMO_USER_ID,
    },
    {
      id: `${DEMO_PREFIX}asset-dragon`,
      name: 'Young Red Dragon',
      filePath: '/demo-assets/tokens/red-dragon.svg',
      type: 'token' as const,
      systemId: dndSystemId,
      isSystemAsset: true,
      tags: ['monster', 'dragon', 'large', 'boss'],
      metadata: { 
        size: 'large', 
        category: 'boss-monster',
        challengeRating: '10',
        hitPoints: 178,
        armorClass: 18,
        breathWeapon: 'fire'
      },
      uploadedBy: DEMO_USER_ID,
      createdBy: DEMO_USER_ID,
    },

    // D&D Maps
    {
      id: `${DEMO_PREFIX}asset-tavern-map`,
      name: 'The Prancing Pony Tavern',
      filePath: '/demo-assets/maps/tavern-interior.jpg',
      type: 'board' as const,
      systemId: dndSystemId,
      isSystemAsset: true,
      tags: ['map', 'tavern', 'interior', 'social'],
      metadata: { 
        gridSize: 5, 
        width: 30, 
        height: 20, 
        category: 'battlemap',
        environment: 'indoor'
      },
      uploadedBy: DEMO_USER_ID,
      createdBy: DEMO_USER_ID,
    },
    {
      id: `${DEMO_PREFIX}asset-dungeon-map`,
      name: 'Ancient Crypt',
      filePath: '/demo-assets/maps/dungeon-crypt.jpg',
      type: 'board' as const,
      systemId: dndSystemId,
      isSystemAsset: true,
      tags: ['map', 'dungeon', 'crypt', 'undead'],
      metadata: { 
        gridSize: 5, 
        width: 40, 
        height: 25, 
        category: 'battlemap',
        environment: 'underground',
        traps: ['pit', 'poison-dart']
      },
      uploadedBy: DEMO_USER_ID,
      createdBy: DEMO_USER_ID,
    },

    // Poker Cards (sample)
    {
      id: `${DEMO_PREFIX}asset-card-back`,
      name: 'Poker Card Back',
      filePath: '/demo-assets/cards/card-back-red.svg',
      type: 'card' as const,
      systemId: pokerSystemId,
      isSystemAsset: true,
      tags: ['card-back', 'poker', 'standard'],
      metadata: { category: 'card-back', color: 'red' },
      uploadedBy: DEMO_USER_ID,
      createdBy: DEMO_USER_ID,
    },
    {
      id: `${DEMO_PREFIX}asset-ace-spades`,
      name: 'Ace of Spades',
      filePath: '/demo-assets/cards/ace-spades.svg',
      type: 'card' as const,
      systemId: pokerSystemId,
      isSystemAsset: true,
      tags: ['card', 'ace', 'spades', 'high'],
      metadata: { suit: 'spades', rank: 'ace', value: 14 },
      uploadedBy: DEMO_USER_ID,
      createdBy: DEMO_USER_ID,
    },
    {
      id: `${DEMO_PREFIX}asset-king-hearts`,
      name: 'King of Hearts',
      filePath: '/demo-assets/cards/king-hearts.svg',
      type: 'card' as const,
      systemId: pokerSystemId,
      isSystemAsset: true,
      tags: ['card', 'king', 'hearts', 'face'],
      metadata: { suit: 'hearts', rank: 'king', value: 13 },
      uploadedBy: DEMO_USER_ID,
      createdBy: DEMO_USER_ID,
    },

    // Poker Chips
    {
      id: `${DEMO_PREFIX}asset-chip-white`,
      name: 'White Poker Chip',
      filePath: '/demo-assets/chips/chip-white.svg',
      type: 'token' as const,
      systemId: pokerSystemId,
      isSystemAsset: true,
      tags: ['chip', 'white', 'currency'],
      metadata: { value: 1, color: 'white', category: 'chip' },
      uploadedBy: DEMO_USER_ID,
      createdBy: DEMO_USER_ID,
    },
    {
      id: `${DEMO_PREFIX}asset-chip-red`,
      name: 'Red Poker Chip',
      filePath: '/demo-assets/chips/chip-red.svg', 
      type: 'token' as const,
      systemId: pokerSystemId,
      isSystemAsset: true,
      tags: ['chip', 'red', 'currency'],
      metadata: { value: 5, color: 'red', category: 'chip' },
      uploadedBy: DEMO_USER_ID,
      createdBy: DEMO_USER_ID,
    }
  ];
};

/**
 * Demo game rooms for testing different scenarios
 */
const createDemoRooms = () => {
  const dndSystemId = `${DEMO_PREFIX}system-dnd5e`;
  const pokerSystemId = `${DEMO_PREFIX}system-poker`;

  return [
    {
      id: `${DEMO_PREFIX}room-tavern-brawl`,
      name: 'The Tavern Brawl',
      description: 'A classic D&D encounter in the local tavern. Perfect for testing combat mechanics and character interactions.',
      uploadedBy: DEMO_USER_ID,
      createdBy: DEMO_USER_ID,
      isPublic: true,
      maxPlayers: 4,
      currentPlayers: 3,
      status: 'active' as const,
      gameSystemId: dndSystemId,
      createdBy: DEMO_USER_ID,
      createdBy: DEMO_USER_ID,
      boardConfig: {
        width: 1200,
        height: 800,
        gridSize: 25,
        backgroundColor: '#8B4513',
        showGrid: true,
        snapToGrid: true
      }
    },
    {
      id: `${DEMO_PREFIX}room-dragon-lair`,
      name: 'Dragon\'s Lair Showdown',
      description: 'Epic boss battle against a young red dragon. Test high-level combat and special abilities.',
      uploadedBy: DEMO_USER_ID,
      createdBy: DEMO_USER_ID,
      isPublic: true,
      maxPlayers: 6,
      currentPlayers: 1,
      status: 'active' as const,
      gameSystemId: dndSystemId,
      createdBy: DEMO_USER_ID,
      boardConfig: {
        width: 1600,
        height: 1200,
        gridSize: 25,
        backgroundColor: '#4A0404',
        showGrid: true,
        snapToGrid: true
      }
    },
    {
      id: `${DEMO_PREFIX}room-poker-night`,
      name: 'Friday Night Poker',
      description: 'Casual poker game for testing card mechanics and player interactions.',
      uploadedBy: DEMO_USER_ID,
      createdBy: DEMO_USER_ID,
      isPublic: false,
      maxPlayers: 6,
      currentPlayers: 4,
      status: 'active' as const,
      gameSystemId: pokerSystemId,
      createdBy: DEMO_USER_ID,
      boardConfig: {
        width: 1000,
        height: 700,
        gridSize: 0,
        backgroundColor: '#0F5132',
        showGrid: false,
        snapToGrid: false
      }
    }
  ];
};

/**
 * Demo card decks for testing card game mechanics
 */
const createDemoDecks = () => {
  const dndSystemId = `${DEMO_PREFIX}system-dnd5e`;
  const pokerSystemId = `${DEMO_PREFIX}system-poker`;

  return [
    {
      id: `${DEMO_PREFIX}deck-spell-cards`,
      name: 'Spell Cards',
      description: 'Common wizard and cleric spells for quick reference',
      roomId: `${DEMO_PREFIX}room-dragon-lair`,
      systemId: dndSystemId,
      cardBackId: null,
      cards: [], // Will be populated with spell card assets
      isShuffled: false,
      uploadedBy: DEMO_USER_ID,
      createdBy: DEMO_USER_ID,
    },
    {
      id: `${DEMO_PREFIX}deck-poker-standard`,
      name: 'Standard Poker Deck',
      description: '52-card standard poker deck',
      roomId: `${DEMO_PREFIX}room-poker-night`,
      systemId: pokerSystemId,
      cardBackId: `${DEMO_PREFIX}asset-card-back`,
      cards: [], // Will be populated with all poker cards
      isShuffled: true,
      uploadedBy: DEMO_USER_ID,
      createdBy: DEMO_USER_ID,
    }
  ];
};

/**
 * Sample board positions for immediate visual feedback
 */
const createDemoBoardAssets = () => [
  // Tavern scene setup
  {
    id: `${DEMO_PREFIX}board-fighter-tavern`,
    assetId: `${DEMO_PREFIX}asset-fighter`,
    roomId: `${DEMO_PREFIX}room-tavern-brawl`,
    type: 'token' as const,
    positionX: 200,
    positionY: 150,
    rotation: 0,
    scale: 100,
    zIndex: 10,
    isFlipped: false,
    isLocked: false,
    ownerId: DEMO_PLAYER_IDS[0],
  },
  {
    id: `${DEMO_PREFIX}board-wizard-tavern`,
    assetId: `${DEMO_PREFIX}asset-wizard`,
    roomId: `${DEMO_PREFIX}room-tavern-brawl`,
    type: 'token' as const,
    positionX: 275,
    positionY: 175,
    rotation: 45,
    scale: 100,
    zIndex: 10,
    isFlipped: false,
    isLocked: false,
    ownerId: DEMO_PLAYER_IDS[1],
  },
  {
    id: `${DEMO_PREFIX}board-rogue-tavern`,
    assetId: `${DEMO_PREFIX}asset-rogue`,
    roomId: `${DEMO_PREFIX}room-tavern-brawl`,
    type: 'token' as const,
    positionX: 150,
    positionY: 200,
    rotation: 270,
    scale: 100,
    zIndex: 10,
    isFlipped: false,
    isLocked: false,
    ownerId: DEMO_PLAYER_IDS[2],
  },
  {
    id: `${DEMO_PREFIX}board-goblins-tavern`,
    assetId: `${DEMO_PREFIX}asset-goblin`,
    roomId: `${DEMO_PREFIX}room-tavern-brawl`,
    type: 'token' as const,
    positionX: 450,
    positionY: 300,
    rotation: 180,
    scale: 80,
    zIndex: 5,
    isFlipped: false,
    isLocked: false,
    ownerId: null,
  },

  // Dragon lair setup  
  {
    id: `${DEMO_PREFIX}board-dragon-lair`,
    assetId: `${DEMO_PREFIX}asset-dragon`,
    roomId: `${DEMO_PREFIX}room-dragon-lair`,
    type: 'token' as const,
    positionX: 800,
    positionY: 600,
    rotation: 315,
    scale: 250,
    zIndex: 20,
    isFlipped: false,
    isLocked: false,
    ownerId: null,
  }
];

/**
 * Sample chat messages for atmosphere
 */
const createDemoChatMessages = () => [
  {
    id: randomUUID(),
    roomId: `${DEMO_PREFIX}room-tavern-brawl`,
    userId: DEMO_USER_ID,
    message: 'Welcome to The Prancing Pony! The atmosphere is tense as rival adventuring parties eye each other suspiciously.',
    messageType: 'system' as const,
    metadata: { isNarration: true }
  },
  {
    id: randomUUID(),
    roomId: `${DEMO_PREFIX}room-tavern-brawl`,
    userId: DEMO_PLAYER_IDS[0],
    message: 'I slam my fist on the table and glare at the ruffians in the corner.',
    messageType: 'chat' as const,
    metadata: { characterName: 'Gareth the Fighter' }
  },
  {
    id: randomUUID(),
    roomId: `${DEMO_PREFIX}room-dragon-lair`,
    userId: DEMO_USER_ID,
    message: 'The ancient red dragon stirs, its massive form filling the cavern. Roll for initiative!',
    messageType: 'system' as const,
    metadata: { isNarration: true, requiresRoll: true }
  },
  {
    id: randomUUID(),
    roomId: `${DEMO_PREFIX}room-poker-night`,
    userId: DEMO_PLAYER_IDS[1],
    message: 'I\'ll raise you 50 chips.',
    messageType: 'chat' as const,
    metadata: { gameAction: 'bet', amount: 50 }
  }
];

/**
 * Clear all demo data from database
 */
async function clearDemoData() {
  console.log('🧹 Clearing existing demo data...');
  
  const { sql, like } = await import('drizzle-orm');
  
  // Delete in dependency order using proper parameterized queries
  await db.delete(chatMessages).where(like(chatMessages.roomId, `${DEMO_PREFIX}%`));
  await db.delete(boardAssets).where(like(boardAssets.roomId, `${DEMO_PREFIX}%`));
  await db.delete(cardPiles).where(like(cardPiles.roomId, `${DEMO_PREFIX}%`));
  await db.delete(cardDecks).where(like(cardDecks.id, `${DEMO_PREFIX}%`));
  await db.delete(gameAssets).where(like(gameAssets.id, `${DEMO_PREFIX}%`));
  await db.delete(gameRooms).where(like(gameRooms.id, `${DEMO_PREFIX}%`));
  await db.delete(gameSystems).where(like(gameSystems.id, `${DEMO_PREFIX}%`));
  await db.delete(users).where(like(users.id, `${DEMO_PREFIX}%`));
  
  console.log('✅ Demo data cleared successfully');
}

/**
 * Seed the database with comprehensive demo data
 */
async function seedDatabase() {
  try {
    console.log('🌱 Starting Vorpal Board database seeding...');
    console.log('📊 Creating comprehensive demo data for smoke testing\n');

    // Clear existing demo data
    await clearDemoData();

    console.log('👥 Creating demo users...');
    const demoUsers = createDemoUsers();
    for (const user of demoUsers) {
      await db.insert(users).values(user);
    }
    console.log(`✅ Created ${demoUsers.length} demo users`);

    console.log('🎮 Creating game systems...');
    const demoSystems = createDemoSystems();
    for (const system of demoSystems) {
      await db.insert(gameSystems).values(system);
    }
    console.log(`✅ Created ${demoSystems.length} game systems`);

    console.log('🎨 Creating game assets...');
    const demoAssets = createDemoAssets();
    for (const asset of demoAssets) {
      await db.insert(gameAssets).values(asset);
    }
    console.log(`✅ Created ${demoAssets.length} game assets`);

    console.log('🏠 Creating demo rooms...');
    const demoRooms = createDemoRooms();
    for (const room of demoRooms) {
      await db.insert(gameRooms).values(room);
    }
    console.log(`✅ Created ${demoRooms.length} demo rooms`);

    console.log('🃏 Creating card decks...');
    const demoDecks = createDemoDecks();
    for (const deck of demoDecks) {
      await db.insert(cardDecks).values(deck);
    }
    console.log(`✅ Created ${demoDecks.length} card decks`);

    console.log('🗺️ Placing tokens on boards...');
    const demoBoardAssets = createDemoBoardAssets();
    for (const boardAsset of demoBoardAssets) {
      await db.insert(boardAssets).values(boardAsset);
    }
    console.log(`✅ Placed ${demoBoardAssets.length} tokens on game boards`);

    console.log('💬 Adding sample chat messages...');
    const demoMessages = createDemoChatMessages();
    for (const message of demoMessages) {
      await db.insert(chatMessages).values(message);
    }
    console.log(`✅ Added ${demoMessages.length} chat messages`);

    console.log('\n🎉 Database seeding completed successfully!\n');
    
    console.log('📊 Demo Data Summary:');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(`👥 Users: ${demoUsers.length} (1 GM + ${DEMO_PLAYER_IDS.length} players)`);
    console.log(`🎮 Game Systems: ${demoSystems.length} (D&D 5e + Poker)`);
    console.log(`🎨 Assets: ${demoAssets.length} (tokens, maps, cards, chips)`);
    console.log(`🏠 Rooms: ${demoRooms.length} (2 active D&D + 1 poker game)`);
    console.log(`🃏 Decks: ${demoDecks.length} (spell cards + poker deck)`);
    console.log(`🗺️ Board Positions: ${demoBoardAssets.length} tokens placed`);
    console.log(`💬 Chat Messages: ${demoMessages.length} sample conversations`);
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    console.log('🎯 Demo Accounts:');
    demoUsers.forEach(user => {
      const role = user.id === DEMO_USER_ID ? 'Game Master' : 'Player';
      console.log(`   📧 ${user.email} (${user.firstName} ${user.lastName} - ${role})`);
    });

    console.log('\n🏠 Demo Rooms:');
    demoRooms.forEach(room => {
      const icon = room.gameSystemId?.includes('dnd') ? '🐉' : '🃏';
      const status = room.status === 'active' ? '🟢' : '🟡';
      console.log(`   ${icon} ${room.name} ${status} (${room.currentPlayers}/${room.maxPlayers} players)`);
    });

    console.log('\n🚀 Quick Start:');
    console.log('   1. Start the server: npm run dev');
    console.log('   2. Open http://localhost:5000');
    console.log('   3. Browse public rooms to join "The Tavern Brawl"');
    console.log('   4. Test token movement, chat, and dice rolling');
    console.log('   5. Try the Dragon\'s Lair for boss battle mechanics');
    console.log('   6. Check out poker room for card game testing\n');

  } catch (error) {
    console.error('❌ Database seeding failed:', error);
    throw error;
  } finally {
    await pool.end();
  }
}

// Main execution
if (import.meta.url === `file://${process.argv[1]}`) {
  // Check environment
  if (!process.env.DATABASE_URL) {
    console.error('❌ DATABASE_URL environment variable is required');
    console.error('💡 Make sure your .env file is configured properly');
    process.exit(1);
  }

  console.log('🎲 Vorpal Board Demo Data Seeder');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('Creating realistic game data for instant smoke testing...\n');
  
  seedDatabase()
    .then(() => {
      console.log('✨ Seeding completed successfully!');
      console.log('   Ready for testing and development 🎉');
      process.exit(0);
    })
    .catch((error) => {
      console.error('💥 Seeding failed:', error.message);
      process.exit(1);
    });
}

export { seedDatabase, clearDemoData };