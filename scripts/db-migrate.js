#!/usr/bin/env node

import { execSync } from 'child_process';
import { existsSync, mkdirSync } from 'fs';
import path from 'path';

/**
 * Database Migration Script
 * 
 * Provides comprehensive database migration management using Drizzle Kit.
 * Supports generating, applying, and checking database migrations with full
 * indexing support and error handling.
 */

const MIGRATIONS_DIR = './migrations';

// Ensure migrations directory exists
if (!existsSync(MIGRATIONS_DIR)) {
  mkdirSync(MIGRATIONS_DIR, { recursive: true });
  console.log(`✅ Created migrations directory: ${MIGRATIONS_DIR}`);
}

function runCommand(command, description) {
  console.log(`🔄 ${description}...`);
  try {
    const result = execSync(command, { 
      stdio: 'inherit',
      env: { ...process.env, NODE_ENV: process.env.NODE_ENV || 'development' }
    });
    console.log(`✅ ${description} completed successfully`);
    return result;
  } catch (error) {
    console.error(`❌ ${description} failed:`, error.message);
    process.exit(1);
  }
}

function checkDatabaseConnection() {
  if (!process.env.DATABASE_URL) {
    console.error('❌ DATABASE_URL environment variable is not set');
    console.error('   Make sure the database is provisioned in your Replit project');
    process.exit(1);
  }
  console.log('✅ Database URL configured');
}

const action = process.argv[2];

console.log('🚀 Drizzle Database Migration Tool');
console.log('=====================================');

checkDatabaseConnection();

switch (action) {
  case 'generate':
    runCommand('drizzle-kit generate', 'Generating migration files');
    console.log('📝 Migration files generated in ./migrations/');
    console.log('   Review the generated SQL before applying migrations');
    break;

  case 'migrate':
    runCommand('drizzle-kit migrate', 'Applying migrations to database');
    console.log('🎉 Database schema updated successfully');
    break;

  case 'push':
    runCommand('drizzle-kit push', 'Pushing schema changes directly to database');
    console.log('⚡ Schema synchronized with database');
    break;

  case 'introspect':
    runCommand('drizzle-kit introspect', 'Introspecting existing database schema');
    console.log('🔍 Database schema introspected');
    break;

  case 'studio':
    console.log('🎨 Starting Drizzle Studio...');
    console.log('   Access the database browser at the URL shown below');
    runCommand('drizzle-kit studio', 'Starting Drizzle Studio');
    break;

  case 'check':
    runCommand('drizzle-kit check', 'Checking migration consistency');
    break;

  case 'drop':
    console.log('⚠️  WARNING: This will drop migration files');
    console.log('   This action is irreversible!');
    runCommand('drizzle-kit drop', 'Dropping migration files');
    break;

  case 'status':
    console.log('📊 Database Migration Status');
    console.log('============================');
    
    try {
      // Check if migrations directory has files
      const fs = await import('fs');
      const files = fs.readdirSync(MIGRATIONS_DIR);
      const migrationFiles = files.filter(f => f.endsWith('.sql'));
      
      console.log(`📁 Migration files: ${migrationFiles.length}`);
      if (migrationFiles.length > 0) {
        console.log('   Files:', migrationFiles.join(', '));
      }
      
      console.log(`🗃️  Migrations directory: ${path.resolve(MIGRATIONS_DIR)}`);
      console.log(`🔗 Database: ${process.env.DATABASE_URL ? 'Connected' : 'Not configured'}`);
      
    } catch (error) {
      console.error('❌ Error checking migration status:', error.message);
    }
    break;

  case 'fresh':
    console.log('🔄 Fresh Migration: Drop + Generate + Migrate');
    console.log('⚠️  WARNING: This will reset your migration history');
    
    // Drop existing migrations
    try {
      runCommand('drizzle-kit drop', 'Dropping existing migrations');
    } catch (error) {
      console.log('ℹ️  No existing migrations to drop');
    }
    
    // Generate new migrations
    runCommand('drizzle-kit generate', 'Generating fresh migration files');
    
    // Apply migrations
    runCommand('drizzle-kit migrate', 'Applying fresh migrations');
    
    console.log('✨ Fresh migration completed successfully');
    break;

  default:
    console.log('Usage: node scripts/db-migrate.js <action>');
    console.log('');
    console.log('Available actions:');
    console.log('  generate    - Generate migration files from schema changes');
    console.log('  migrate     - Apply pending migrations to database');
    console.log('  push        - Push schema changes directly (skip migration files)');
    console.log('  introspect  - Generate schema from existing database');
    console.log('  studio      - Open Drizzle Studio database browser');
    console.log('  check       - Check migration consistency');
    console.log('  drop        - Drop migration files (dangerous!)');
    console.log('  status      - Show migration status and info');
    console.log('  fresh       - Reset and regenerate all migrations');
    console.log('');
    console.log('Examples:');
    console.log('  node scripts/db-migrate.js generate');
    console.log('  node scripts/db-migrate.js migrate');
    console.log('  node scripts/db-migrate.js push');
    console.log('  node scripts/db-migrate.js studio');
    break;
}

console.log('');
console.log('🔗 For more information, see: https://orm.drizzle.team/kit-docs/commands');