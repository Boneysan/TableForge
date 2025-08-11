#!/usr/bin/env node

import { Pool, neonConfig } from '@neondatabase/serverless';
import { drizzle } from 'drizzle-orm/neon-serverless';
import ws from "ws";

/**
 * Database Seeding Script
 * 
 * Seeds the database with initial data including indexes verification
 * and sample data for development/testing purposes.
 */

// Setup WebSocket for Neon
neonConfig.webSocketConstructor = ws;

if (!process.env.DATABASE_URL) {
  console.error('❌ DATABASE_URL environment variable is not set');
  process.exit(1);
}

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const db = drizzle({ client: pool });

/**
 * Verify all indexes are created properly
 */
async function verifyIndexes() {
  console.log('🔍 Verifying database indexes...');
  
  try {
    const indexQuery = `
      SELECT 
        schemaname,
        tablename,
        indexname,
        indexdef
      FROM pg_indexes 
      WHERE schemaname = 'public'
      ORDER BY tablename, indexname;
    `;
    
    const result = await pool.query(indexQuery);
    const indexes = result.rows;
    
    console.log(`✅ Found ${indexes.length} indexes in the database`);
    
    // Group indexes by table
    const indexesByTable = indexes.reduce((acc, index) => {
      if (!acc[index.tablename]) {
        acc[index.tablename] = [];
      }
      acc[index.tablename].push(index.indexname);
      return acc;
    }, {});
    
    // Expected indexes based on our schema
    const expectedIndexes = {
      'game_rooms': [
        'idx_game_rooms_created_by',
        'idx_game_rooms_is_active', 
        'idx_game_rooms_created_at'
      ],
      'game_assets': [
        'idx_game_assets_room_id',
        'idx_game_assets_system_id',
        'idx_game_assets_uploaded_by',
        'idx_game_assets_type',
        'idx_game_assets_is_system_asset',
        'idx_game_assets_created_at',
        'idx_game_assets_room_type',
        'idx_game_assets_system_type'
      ],
      'room_players': [
        'idx_room_players_room_id',
        'idx_room_players_player_id',
        'idx_room_players_role',
        'idx_room_players_is_online',
        'idx_room_players_joined_at'
      ],
      'board_assets': [
        'idx_board_assets_room_id',
        'idx_board_assets_asset_id',
        'idx_board_assets_owned_by',
        'idx_board_assets_placed_by',
        'idx_board_assets_asset_type',
        'idx_board_assets_visibility',
        'idx_board_assets_z_index',
        'idx_board_assets_placed_at',
        'idx_board_assets_room_position',
        'idx_board_assets_room_z_order',
        'idx_board_assets_stack_order'
      ],
      'card_decks': [
        'idx_card_decks_room_id',
        'idx_card_decks_created_by',
        'idx_card_decks_card_back_asset_id',
        'idx_card_decks_created_at'
      ],
      'card_piles': [
        'idx_card_piles_room_id',
        'idx_card_piles_owner_id',
        'idx_card_piles_pile_type',
        'idx_card_piles_visibility',
        'idx_card_piles_created_at',
        'idx_card_piles_room_position',
        'idx_card_piles_room_type'
      ],
      'dice_rolls': [
        'idx_dice_rolls_room_id',
        'idx_dice_rolls_player_id',
        'idx_dice_rolls_rolled_at',
        'idx_dice_rolls_room_rolled_at'
      ],
      'chat_messages': [
        'idx_chat_messages_room_id',
        'idx_chat_messages_player_id',
        'idx_chat_messages_target_player_id',
        'idx_chat_messages_message_type',
        'idx_chat_messages_sent_at',
        'idx_chat_messages_room_sent_at'
      ],
      'game_templates': [
        'idx_game_templates_created_by',
        'idx_game_templates_is_public',
        'idx_game_templates_category',
        'idx_game_templates_created_at',
        'idx_game_templates_updated_at',
        'idx_game_templates_public_category',
        'idx_game_templates_public_created'
      ],
      'game_systems': [
        'idx_game_systems_created_by',
        'idx_game_systems_is_public',
        'idx_game_systems_is_official',
        'idx_game_systems_category',
        'idx_game_systems_complexity',
        'idx_game_systems_download_count',
        'idx_game_systems_rating',
        'idx_game_systems_created_at',
        'idx_game_systems_updated_at',
        'idx_game_systems_public_category',
        'idx_game_systems_public_official',
        'idx_game_systems_public_rating'
      ]
    };
    
    console.log('\n📊 Index Coverage by Table:');
    console.log('============================');
    
    let allIndexesPresent = true;
    
    for (const [tableName, expectedIndexList] of Object.entries(expectedIndexes)) {
      const actualIndexes = indexesByTable[tableName] || [];
      const missingIndexes = expectedIndexList.filter(idx => !actualIndexes.includes(idx));
      
      console.log(`\n📋 ${tableName}:`);
      console.log(`   Expected: ${expectedIndexList.length} indexes`);
      console.log(`   Found: ${actualIndexes.length} indexes`);
      
      if (missingIndexes.length > 0) {
        console.log(`   ❌ Missing: ${missingIndexes.join(', ')}`);
        allIndexesPresent = false;
      } else {
        console.log(`   ✅ All indexes present`);
      }
    }
    
    if (allIndexesPresent) {
      console.log('\n🎉 All expected indexes are present and optimized for queries!');
    } else {
      console.log('\n⚠️  Some indexes are missing. Run migrations to create them.');
    }
    
    return allIndexesPresent;
    
  } catch (error) {
    console.error('❌ Error verifying indexes:', error.message);
    return false;
  }
}

/**
 * Create sample data for development
 */
async function seedDevelopmentData() {
  console.log('\n🌱 Seeding development data...');
  
  try {
    // This would normally insert sample users, rooms, etc.
    // For now, we'll just verify the tables exist
    const tableQuery = `
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
      ORDER BY table_name;
    `;
    
    const result = await pool.query(tableQuery);
    const tables = result.rows.map(row => row.table_name);
    
    console.log(`✅ Found ${tables.length} tables:`, tables.join(', '));
    
    // Verify foreign key relationships
    const fkQuery = `
      SELECT 
        tc.table_name, 
        tc.constraint_name, 
        kcu.column_name, 
        ccu.table_name AS foreign_table_name,
        ccu.column_name AS foreign_column_name 
      FROM 
        information_schema.table_constraints AS tc 
        JOIN information_schema.key_column_usage AS kcu
          ON tc.constraint_name = kcu.constraint_name
        JOIN information_schema.constraint_column_usage AS ccu
          ON ccu.constraint_name = tc.constraint_name
      WHERE tc.constraint_type = 'FOREIGN KEY'
      ORDER BY tc.table_name;
    `;
    
    const fkResult = await pool.query(fkQuery);
    console.log(`✅ Found ${fkResult.rows.length} foreign key relationships`);
    
    console.log('✅ Development data verification complete');
    
  } catch (error) {
    console.error('❌ Error seeding development data:', error.message);
    throw error;
  }
}

async function main() {
  try {
    console.log('🚀 Database Seeding and Verification');
    console.log('====================================');
    
    // Verify indexes
    const indexesOk = await verifyIndexes();
    
    // Seed development data
    await seedDevelopmentData();
    
    if (indexesOk) {
      console.log('\n🎉 Database is fully optimized with all indexes!');
      console.log('   All relations (room_id, system_id, created_at, etc.) are properly indexed');
    } else {
      console.log('\n⚠️  Database needs index optimization. Run: node scripts/db-migrate.js migrate');
    }
    
  } catch (error) {
    console.error('❌ Seeding failed:', error.message);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

main();