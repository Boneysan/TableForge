import { validateClientConfig } from '../../../shared/config';

// Validate and export client configuration
export const clientConfig = validateClientConfig();

// Convenience exports for commonly used config values
export const FIREBASE_PROJECT_ID = clientConfig.VITE_FIREBASE_PROJECT_ID;
export const GOOGLE_STORAGE_BUCKET = clientConfig.VITE_GOOGLE_STORAGE_BUCKET;
export const NODE_ENV = clientConfig.VITE_NODE_ENV;

// Environment helpers for client-side code
export const isDevelopment = NODE_ENV === 'development';
export const isProduction = NODE_ENV === 'production';
export const isTest = NODE_ENV === 'test';

// API base URL helper
export const getApiBaseUrl = () => {
  if (typeof window === 'undefined') return '';
  return window.location.origin;
};