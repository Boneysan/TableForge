// server/database/migration-helper.ts
// Database Migration Helper for Phase 3 Connection Pool

import { getConnectionPool } from './enhanced-db';
import { createUserLogger } from '../utils/logger';
import { readdir, readFile } from 'fs/promises';
import { join } from 'path';

const logger = createUserLogger('db-migration');

export class MigrationHelper {
  private connectionPool = getConnectionPool();

  async runMigrations(migrationsPath: string = 'migrations'): Promise<MigrationResult> {
    const result: MigrationResult = {
      executed: [],
      skipped: [],
      failed: [],
      totalTime: 0
    };

    const startTime = Date.now();

    try {
      // Create migrations table if it doesn't exist
      await this.createMigrationsTable();

      // Get list of executed migrations
      const executedMigrations = await this.getExecutedMigrations();

      // Read migration files
      const migrationFiles = await this.getMigrationFiles(migrationsPath);

      logger.info('Starting database migrations', {
        totalFiles: migrationFiles.length,
        alreadyExecuted: executedMigrations.length
      });

      // Execute pending migrations
      for (const file of migrationFiles) {
        if (executedMigrations.includes(file.name)) {
          result.skipped.push(file.name);
          continue;
        }

        try {
          await this.executeMigration(file);
          result.executed.push(file.name);
          logger.info('Migration executed successfully', { migration: file.name });
        } catch (error: any) {
          logger.error('Migration failed', { migration: file.name, error: error.message });
          result.failed.push({ name: file.name, error: error.message });
          
          // Stop on first failure to maintain consistency
          break;
        }
      }

      result.totalTime = Date.now() - startTime;

      logger.info('Migration process completed', {
        executed: result.executed.length,
        skipped: result.skipped.length,
        failed: result.failed.length,
        totalTime: result.totalTime
      });

      return result;
    } catch (error: any) {
      logger.error('Migration process failed', { error: error.message });
      throw error;
    }
  }

  private async createMigrationsTable(): Promise<void> {
    const query = `
      CREATE TABLE IF NOT EXISTS _migrations (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL UNIQUE,
        executed_at TIMESTAMP DEFAULT NOW(),
        execution_time INTEGER,
        checksum VARCHAR(64)
      )
    `;

    await this.connectionPool.query(query);
  }

  private async getExecutedMigrations(): Promise<string[]> {
    const query = 'SELECT name FROM _migrations ORDER BY executed_at';
    const result = await this.connectionPool.query<Array<{ name: string }>>(query);
    return result.map(row => row.name);
  }

  private async getMigrationFiles(migrationsPath: string): Promise<MigrationFile[]> {
    try {
      const files = await readdir(migrationsPath);
      const migrationFiles: MigrationFile[] = [];

      for (const file of files) {
        if (file.endsWith('.sql')) {
          const filePath = join(migrationsPath, file);
          const content = await readFile(filePath, 'utf-8');
          
          migrationFiles.push({
            name: file,
            path: filePath,
            content,
            checksum: this.calculateChecksum(content)
          });
        }
      }

      // Sort by filename (assuming timestamp prefix)
      return migrationFiles.sort((a, b) => a.name.localeCompare(b.name));
    } catch (error: any) {
      if (error.code === 'ENOENT') {
        logger.warn('Migrations directory not found', { path: migrationsPath });
        return [];
      }
      throw error;
    }
  }

  private async executeMigration(migration: MigrationFile): Promise<void> {
    const startTime = Date.now();

    await this.connectionPool.transaction(async (client) => {
      // Execute the migration
      await client.query(migration.content);

      // Record the migration
      const executionTime = Date.now() - startTime;
      await client.query(
        'INSERT INTO _migrations (name, execution_time, checksum) VALUES ($1, $2, $3)',
        [migration.name, executionTime, migration.checksum]
      );
    });
  }

  private calculateChecksum(content: string): string {
    // Simple checksum implementation - in production, use a proper hashing library
    let hash = 0;
    for (let i = 0; i < content.length; i++) {
      const char = content.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return hash.toString(16);
  }

  async rollbackMigration(migrationName: string): Promise<void> {
    logger.info('Rolling back migration', { migration: migrationName });

    await this.connectionPool.transaction(async (client) => {
      // Remove from migrations table
      await client.query('DELETE FROM _migrations WHERE name = $1', [migrationName]);
      
      logger.warn('Migration rolled back from tracking table', { 
        migration: migrationName,
        note: 'Schema changes were NOT automatically reverted'
      });
    });
  }

  async getMigrationStatus(): Promise<MigrationStatus> {
    try {
      const executed = await this.getExecutedMigrations();
      const available = await this.getMigrationFiles('migrations');
      
      const pending = available
        .filter(file => !executed.includes(file.name))
        .map(file => file.name);

      return {
        executed: executed.length,
        pending: pending.length,
        total: available.length,
        executedMigrations: executed,
        pendingMigrations: pending
      };
    } catch (error: any) {
      logger.error('Failed to get migration status', { error: error.message });
      throw error;
    }
  }

  async validateMigrations(): Promise<ValidationResult> {
    const result: ValidationResult = {
      valid: true,
      issues: []
    };

    try {
      const migrations = await this.getMigrationFiles('migrations');
      const executed = await this.getExecutedMigrations();

      // Check for naming conventions
      for (const migration of migrations) {
        if (!/^\d{4}_\d{2}_\d{2}_\d{6}_/.test(migration.name)) {
          result.issues.push({
            type: 'naming',
            migration: migration.name,
            message: 'Migration does not follow naming convention: YYYY_MM_DD_HHMMSS_description.sql'
          });
        }
      }

      // Check for gaps in executed migrations
      const availableNames = migrations.map(m => m.name).sort();
      for (let i = 0; i < executed.length; i++) {
        const expectedName = availableNames[i];
        const actualName = executed[i];
        if (actualName && actualName !== expectedName) {
          result.issues.push({
            type: 'sequence',
            migration: actualName,
            message: `Migration sequence mismatch. Expected: ${expectedName}, Found: ${actualName}`
          });
        }
      }

      result.valid = result.issues.length === 0;
      return result;
    } catch (error: any) {
      logger.error('Migration validation failed', { error: error.message });
      throw error;
    }
  }
}

export interface MigrationFile {
  name: string;
  path: string;
  content: string;
  checksum: string;
}

export interface MigrationResult {
  executed: string[];
  skipped: string[];
  failed: Array<{ name: string; error: string }>;
  totalTime: number;
}

export interface MigrationStatus {
  executed: number;
  pending: number;
  total: number;
  executedMigrations: string[];
  pendingMigrations: string[];
}

export interface ValidationResult {
  valid: boolean;
  issues: Array<{
    type: 'naming' | 'sequence' | 'checksum';
    migration: string;
    message: string;
  }>;
}

// Singleton instance
let globalMigrationHelper: MigrationHelper | null = null;

export function getMigrationHelper(): MigrationHelper {
  if (!globalMigrationHelper) {
    globalMigrationHelper = new MigrationHelper();
  }
  return globalMigrationHelper;
}
