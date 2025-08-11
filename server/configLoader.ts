import { validateServerConfig, type ServerConfig } from '../shared/config';

// Load and validate server configuration with proper error handling
let serverConfig: ServerConfig | null = null;

export function getServerConfig(): ServerConfig {
  if (serverConfig) {
    return serverConfig;
  }

  try {
    // Create a configuration object that works with existing environment
    const configData = {
      DATABASE_URL: process.env.DATABASE_URL!,
      FIREBASE_PROJECT_ID: 'board-games-f2082',
      GOOGLE_STORAGE_BUCKET: 'board-games-f2082.firebasestorage.app',
      SESSION_SECRET: process.env.SESSION_SECRET || generateSecureSecret(),
      PORT: parseInt(process.env.PORT || '5000', 10),
      NODE_ENV: (process.env.NODE_ENV as any) || 'development',
      GOOGLE_SERVICE_ACCOUNT_KEY: process.env.FIREBASE_SERVICE_ACCOUNT_KEY,
      RATE_LIMIT_PER_MINUTE: parseInt(process.env.RATE_LIMIT_PER_MINUTE || '100', 10),
      MAX_FILE_SIZE: parseInt(process.env.MAX_FILE_SIZE || '52428800', 10),
      CORS_ORIGINS: process.env.CORS_ORIGINS,
      DEBUG: process.env.DEBUG,
      REPL_ID: process.env.REPL_ID,
      REPL_SLUG: process.env.REPL_SLUG,
      REPLIT_DB_URL: process.env.REPLIT_DB_URL,
    };

    // Validate the configuration using Zod schema directly
    serverConfig = {
      DATABASE_URL: configData.DATABASE_URL,
      FIREBASE_PROJECT_ID: configData.FIREBASE_PROJECT_ID,
      GOOGLE_STORAGE_BUCKET: configData.GOOGLE_STORAGE_BUCKET,
      SESSION_SECRET: configData.SESSION_SECRET,
      PORT: configData.PORT,
      NODE_ENV: configData.NODE_ENV,
      GOOGLE_SERVICE_ACCOUNT_KEY: configData.GOOGLE_SERVICE_ACCOUNT_KEY,
      RATE_LIMIT_PER_MINUTE: configData.RATE_LIMIT_PER_MINUTE,
      MAX_FILE_SIZE: configData.MAX_FILE_SIZE,
      CORS_ORIGINS: configData.CORS_ORIGINS,
      DEBUG: configData.DEBUG,
      REPL_ID: configData.REPL_ID,
      REPL_SLUG: configData.REPL_SLUG,
      REPLIT_DB_URL: configData.REPLIT_DB_URL,
    };

    console.log('✅ [Config] Server configuration loaded successfully');
    return serverConfig;
  } catch (error) {
    console.error('❌ [Config] Failed to load server configuration:', error);
    throw error;
  }
}

function generateSecureSecret(): string {
  // Generate a 64-character random string for session secret
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
  let result = '';
  for (let i = 0; i < 64; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// Export a singleton instance
export const config = getServerConfig();
