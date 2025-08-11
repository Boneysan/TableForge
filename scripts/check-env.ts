#!/usr/bin/env tsx
/**
 * Environment validation script
 * Run with: npm run check-env
 */

import { validateServerConfig, validateClientConfig } from '../shared/config';

console.log('🔍 [Env Check] Validating environment configuration...\n');

try {
  // Check server configuration
  console.log('📋 [Env Check] Validating server environment...');
  const serverConfig = validateServerConfig();
  console.log('✅ [Env Check] Server configuration is valid\n');

  // Check client configuration
  console.log('📋 [Env Check] Validating client environment...');
  const clientConfig = validateClientConfig();
  console.log('✅ [Env Check] Client configuration is valid\n');

  // Show configuration summary
  console.log('📊 [Env Check] Configuration Summary:');
  console.log('  • Environment:', serverConfig.NODE_ENV);
  console.log('  • Port:', serverConfig.PORT);
  console.log('  • Database:', serverConfig.DATABASE_URL.split('@')[1]?.split('/')[0] || 'configured');
  console.log('  • Firebase Project:', serverConfig.FIREBASE_PROJECT_ID);
  console.log('  • Storage Bucket:', serverConfig.GOOGLE_STORAGE_BUCKET);
  console.log('  • Session Secret:', serverConfig.SESSION_SECRET ? '✅ Set' : '❌ Missing');
  console.log('  • Rate Limit:', `${serverConfig.RATE_LIMIT_PER_MINUTE}/min`);
  console.log('  • Max File Size:', `${Math.round(serverConfig.MAX_FILE_SIZE / 1024 / 1024)}MB`);
  
  if (serverConfig.CORS_ORIGINS) {
    console.log('  • CORS Origins:', serverConfig.CORS_ORIGINS.split(',').length, 'configured');
  }

  console.log('\n🎉 [Env Check] All environment variables are properly configured!');
  
} catch (error) {
  console.error('❌ [Env Check] Environment validation failed:');
  console.error(error);
  process.exit(1);
}