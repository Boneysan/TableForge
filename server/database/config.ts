// server/database/config.ts
// Phase 3 Database Configuration

export interface DatabaseConfig {
  // Connection settings
  host: string;
  port: number;
  database: string;
  user: string;
  password?: string;
  connectionString?: string;
  
  // Pool settings
  poolMin: number;
  poolMax: number;
  idleTimeoutMs: number;
  connectionTimeoutMs: number;
  
  // Performance settings
  statementTimeoutMs: number;
  queryTimeoutMs: number;
  
  // SSL settings
  ssl: boolean | {
    rejectUnauthorized: boolean;
    ca?: string;
    cert?: string;
    key?: string;
  };
  
  // Monitoring settings
  enableMonitoring: boolean;
  monitoringIntervalMs: number;
  
  // Optimization settings
  enableOptimization: boolean;
  optimizationIntervalMs: number;
}

export function getDatabaseConfig(): DatabaseConfig {
  return {
    // Connection settings
    host: process.env.DATABASE_HOST || 'localhost',
    port: parseInt(process.env.DATABASE_PORT || '5432'),
    database: process.env.DATABASE_NAME || 'tableforge',
    user: process.env.DATABASE_USER || 'postgres',
    password: process.env.DATABASE_PASSWORD,
    connectionString: process.env.DATABASE_URL,
    
    // Pool settings
    poolMin: parseInt(process.env.DB_POOL_MIN || '5'),
    poolMax: parseInt(process.env.DB_POOL_MAX || '20'),
    idleTimeoutMs: parseInt(process.env.DB_IDLE_TIMEOUT || '30000'),
    connectionTimeoutMs: parseInt(process.env.DB_CONNECTION_TIMEOUT || '10000'),
    
    // Performance settings
    statementTimeoutMs: parseInt(process.env.DB_STATEMENT_TIMEOUT || '30000'),
    queryTimeoutMs: parseInt(process.env.DB_QUERY_TIMEOUT || '30000'),
    
    // SSL settings
    ssl: process.env.NODE_ENV === 'production' 
      ? { rejectUnauthorized: false }
      : false,
    
    // Monitoring settings
    enableMonitoring: process.env.DB_ENABLE_MONITORING !== 'false',
    monitoringIntervalMs: parseInt(process.env.DB_MONITORING_INTERVAL || '10000'),
    
    // Optimization settings
    enableOptimization: process.env.DB_ENABLE_OPTIMIZATION !== 'false',
    optimizationIntervalMs: parseInt(process.env.DB_OPTIMIZATION_INTERVAL || '300000') // 5 minutes
  };
}

export function getProductionDatabaseConfig(): DatabaseConfig {
  const config = getDatabaseConfig();
  
  return {
    ...config,
    // Production-specific overrides
    poolMin: Math.max(config.poolMin, 10),
    poolMax: Math.max(config.poolMax, 50),
    ssl: {
      rejectUnauthorized: false
    },
    enableMonitoring: true,
    enableOptimization: true
  };
}

export function getDevelopmentDatabaseConfig(): DatabaseConfig {
  const config = getDatabaseConfig();
  
  return {
    ...config,
    // Development-specific overrides
    poolMin: Math.min(config.poolMin, 2),
    poolMax: Math.min(config.poolMax, 10),
    ssl: false,
    enableMonitoring: true,
    enableOptimization: false,
    monitoringIntervalMs: 30000 // Less frequent in development
  };
}

export function validateDatabaseConfig(config: DatabaseConfig): string[] {
  const errors: string[] = [];
  
  if (!config.connectionString && (!config.host || !config.database || !config.user)) {
    errors.push('Either DATABASE_URL or individual connection parameters (host, database, user) must be provided');
  }
  
  if (config.poolMin < 1) {
    errors.push('DB_POOL_MIN must be at least 1');
  }
  
  if (config.poolMax < config.poolMin) {
    errors.push('DB_POOL_MAX must be greater than or equal to DB_POOL_MIN');
  }
  
  if (config.poolMax > 100) {
    errors.push('DB_POOL_MAX should not exceed 100 for performance reasons');
  }
  
  if (config.connectionTimeoutMs < 1000) {
    errors.push('DB_CONNECTION_TIMEOUT should be at least 1000ms');
  }
  
  if (config.queryTimeoutMs < 1000) {
    errors.push('DB_QUERY_TIMEOUT should be at least 1000ms');
  }
  
  return errors;
}

// Environment-specific configuration loader
export function loadDatabaseConfig(): DatabaseConfig {
  const nodeEnv = process.env.NODE_ENV || 'development';
  
  let config: DatabaseConfig;
  
  switch (nodeEnv) {
    case 'production':
      config = getProductionDatabaseConfig();
      break;
    case 'development':
      config = getDevelopmentDatabaseConfig();
      break;
    case 'test':
      config = {
        ...getDevelopmentDatabaseConfig(),
        database: process.env.TEST_DATABASE_NAME || 'tableforge_test',
        poolMin: 1,
        poolMax: 5
      };
      break;
    default:
      config = getDatabaseConfig();
  }
  
  // Validate configuration
  const errors = validateDatabaseConfig(config);
  if (errors.length > 0) {
    throw new Error(`Database configuration errors:\n${errors.join('\n')}`);
  }
  
  return config;
}
