import { z } from 'zod';

// Environment-specific configuration schemas
export const ServerConfigSchema = z.object({
  // Database
  DATABASE_URL: z.string().url('Invalid DATABASE_URL format'),
  
  // Firebase
  FIREBASE_PROJECT_ID: z.string().min(1, 'FIREBASE_PROJECT_ID is required').default('board-games-f2082'),
  
  // Google Cloud Storage
  GOOGLE_APPLICATION_CREDENTIALS: z.string().optional(),
  GOOGLE_SERVICE_ACCOUNT_KEY: z.string().optional(),
  GOOGLE_STORAGE_BUCKET: z.string().min(1, 'GOOGLE_STORAGE_BUCKET is required').default('board-games-f2082.firebasestorage.app'),
  
  // Server
  PORT: z.coerce.number().int().min(1).max(65535).default(5000),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  
  // Security
  SESSION_SECRET: z.string().min(32, 'SESSION_SECRET must be at least 32 characters'),
  
  // Optional configurations
  CORS_ORIGINS: z.string().optional(),
  DEBUG: z.string().optional(),
  MAX_FILE_SIZE: z.coerce.number().int().positive().default(52428800), // 50MB
  RATE_LIMIT_PER_MINUTE: z.coerce.number().int().positive().default(100),
  
  // Replit-specific (auto-populated)
  REPL_ID: z.string().optional(),
  REPL_SLUG: z.string().optional(),
  REPLIT_DB_URL: z.string().optional(),
}).refine(
  (data) => data.GOOGLE_APPLICATION_CREDENTIALS || data.GOOGLE_SERVICE_ACCOUNT_KEY,
  {
    message: 'Either GOOGLE_APPLICATION_CREDENTIALS or GOOGLE_SERVICE_ACCOUNT_KEY must be provided',
    path: ['GOOGLE_APPLICATION_CREDENTIALS'],
  }
);

export const ClientConfigSchema = z.object({
  // Only include environment variables that should be exposed to the client
  // All client env vars must be prefixed with VITE_ to be available in Vite
  VITE_FIREBASE_PROJECT_ID: z.string().min(1, 'VITE_FIREBASE_PROJECT_ID is required').default('board-games-f2082'),
  VITE_GOOGLE_STORAGE_BUCKET: z.string().min(1, 'VITE_GOOGLE_STORAGE_BUCKET is required').default('board-games-f2082.firebasestorage.app'),
  VITE_NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
});

// Inferred types
export type ServerConfig = z.infer<typeof ServerConfigSchema>;
export type ClientConfig = z.infer<typeof ClientConfigSchema>;

// Configuration validation functions
export function validateServerConfig(): ServerConfig {
  try {
    const config = ServerConfigSchema.parse(process.env);
    
    // Additional validation logging in development
    if (config.NODE_ENV === 'development') {
      console.log('✅ [Config] Server configuration validated successfully');
      console.log(`📊 [Config] Environment: ${config.NODE_ENV}`);
      console.log(`🚀 [Config] Port: ${config.PORT}`);
      console.log(`🗄️  [Config] Database: ${config.DATABASE_URL.split('@')[1] || 'configured'}`);
      console.log(`🔥 [Config] Firebase Project: ${config.FIREBASE_PROJECT_ID}`);
      console.log(`☁️  [Config] Storage Bucket: ${config.GOOGLE_STORAGE_BUCKET}`);
    }
    
    return config;
  } catch (error) {
    console.error('❌ [Config] Server configuration validation failed:');
    if (error instanceof z.ZodError) {
      error.errors.forEach((err) => {
        console.error(`  • ${err.path.join('.')}: ${err.message}`);
      });
      console.error('\n💡 [Config] Check your .env file against .env.example');
      console.error('💡 [Config] Ensure all required environment variables are set');
    } else {
      console.error('  •', error);
    }
    
    console.error('\n🚨 [Config] Application cannot start with invalid configuration');
    process.exit(1);
  }
}

export function validateClientConfig(): ClientConfig {
  try {
    // In the client environment, use import.meta.env instead of process.env
    const env = typeof window !== 'undefined' ? import.meta.env : process.env;
    
    const config = ClientConfigSchema.parse(env);
    
    if (config.VITE_NODE_ENV === 'development') {
      console.log('✅ [Config] Client configuration validated successfully');
    }
    
    return config;
  } catch (error) {
    console.error('❌ [Config] Client configuration validation failed:');
    if (error instanceof z.ZodError) {
      error.errors.forEach((err) => {
        console.error(`  • ${err.path.join('.')}: ${err.message}`);
      });
      console.error('\n💡 [Config] Ensure client environment variables are prefixed with VITE_');
    } else {
      console.error('  •', error);
    }
    
    throw new Error('Invalid client configuration');
  }
}

// Environment-specific helpers
export const isDevelopment = () => process.env.NODE_ENV === 'development';
export const isProduction = () => process.env.NODE_ENV === 'production';
export const isTest = () => process.env.NODE_ENV === 'test';

// Safe config getters with defaults
export const getPort = () => parseInt(process.env.PORT || '5000', 10);
export const getMaxFileSize = () => parseInt(process.env.MAX_FILE_SIZE || '52428800', 10);
export const getRateLimit = () => parseInt(process.env.RATE_LIMIT_PER_MINUTE || '100', 10);

// CORS origins parser
export const getCorsOrigins = (): string[] => {
  const origins = process.env.CORS_ORIGINS;
  if (!origins) return [];
  return origins.split(',').map(origin => origin.trim());
};