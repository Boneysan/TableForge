// server/cache/simple-example.ts
import { createMultiLevelCache } from './index';

// Initialize the cache system
const cache = createMultiLevelCache();

// Simple cache usage examples
export class CacheExamples {
  
  // Example 1: Basic String Caching
  async cacheString(key: string, value: string, ttl = 3600): Promise<void> {
    await cache.set(key, value, 'simple-data', ttl);
    console.log(`Cached string: ${key} = ${value}`);
  }
  
  async getString(key: string): Promise<string | null> {
    const result = await cache.get<string>(key, 'simple-data');
    if (result.success && result.data) {
      console.log(`Cache hit for ${key}: ${result.data} (from ${result.cacheLevel})`);
      return result.data;
    } else {
      console.log(`Cache miss for ${key}`);
      return null;
    }
  }
  
  // Example 2: Object Caching with Data Loader
  async getUserData(userId: string): Promise<any> {
    const result = await cache.getOrSet(
      userId,
      'user-data',
      async () => {
        console.log(`Loading user data from database: ${userId}`);
        // Simulate database call
        return {
          id: userId,
          name: `User ${userId}`,
          email: `${userId}@example.com`,
          lastLogin: Date.now()
        };
      },
      1800 // 30 minutes
    );
    
    if (result.success) {
      console.log(`User data for ${userId}:`, result.data);
      return result.data;
    } else {
      console.log(`Failed to get user data for ${userId}:`, result.error);
      return null;
    }
  }
  
  // Example 3: Cache Performance Demo
  async demonstratePerformance(): Promise<void> {
    console.log('\n=== Cache Performance Demonstration ===');
    
    // First call (cache miss)
    console.log('\n1. First call (expecting cache miss):');
    const start1 = Date.now();
    await this.getUserData('user123');
    const time1 = Date.now() - start1;
    console.log(`Duration: ${time1}ms`);
    
    // Second call (cache hit)
    console.log('\n2. Second call (expecting cache hit):');
    const start2 = Date.now();
    await this.getUserData('user123');
    const time2 = Date.now() - start2;
    console.log(`Duration: ${time2}ms (${((time1 - time2) / time1 * 100).toFixed(1)}% faster)`);
    
    // Show statistics
    console.log('\n3. Cache Statistics:');
    const stats = await cache.getComprehensiveStats();
    console.log(`Hit Rate: ${(stats.hitRate * 100).toFixed(2)}%`);
    console.log(`Total Operations: ${stats.performance.totalOperations}`);
  }
  
  // Example 4: Cache Invalidation
  async demonstrateInvalidation(): Promise<void> {
    console.log('\n=== Cache Invalidation Demonstration ===');
    
    // Set some test data
    await this.cacheString('test1', 'value1');
    await this.cacheString('test2', 'value2');
    await this.cacheString('other', 'other-value');
    
    console.log('\n1. Before invalidation:');
    await this.getString('test1');
    await this.getString('test2');
    await this.getString('other');
    
    // Invalidate test* pattern
    console.log('\n2. Invalidating test* pattern...');
    const invalidated = await cache.invalidate('test*');
    console.log(`Invalidated entries:`, invalidated);
    
    console.log('\n3. After invalidation:');
    await this.getString('test1'); // Should be cache miss
    await this.getString('test2'); // Should be cache miss
    await this.getString('other'); // Should still be cached
  }
  
  // Example 5: Health Check
  async checkSystemHealth(): Promise<void> {
    console.log('\n=== Cache System Health Check ===');
    
    const health = await cache.healthCheck();
    console.log(`Overall Status: ${health.overall}`);
    
    health.levels.forEach(level => {
      console.log(`${level.level}: ${level.status}`);
      if (level.info) {
        console.log(`  Info: ${JSON.stringify(level.info, null, 2)}`);
      }
    });
  }
  
  // Example 6: Multiple Data Types
  async demonstrateDataTypes(): Promise<void> {
    console.log('\n=== Different Data Types Demonstration ===');
    
    // Number
    await cache.set('number-key', 42, 'numbers', 3600);
    const numberResult = await cache.get<number>('number-key', 'numbers');
    console.log(`Number: ${numberResult.data} (${typeof numberResult.data})`);
    
    // Array
    await cache.set('array-key', [1, 2, 3, 'hello'], 'arrays', 3600);
    const arrayResult = await cache.get<any[]>('array-key', 'arrays');
    console.log(`Array: ${JSON.stringify(arrayResult.data)}`);
    
    // Complex Object
    const complexObject = {
      id: 'obj123',
      nested: {
        values: [1, 2, 3],
        timestamp: Date.now()
      },
      metadata: {
        version: '1.0',
        tags: ['test', 'demo']
      }
    };
    
    await cache.set('object-key', complexObject, 'objects', 3600);
    const objectResult = await cache.get<typeof complexObject>('object-key', 'objects');
    console.log(`Object: ${JSON.stringify(objectResult.data, null, 2)}`);
  }
  
  // Example 7: TTL Testing
  async demonstrateTTL(): Promise<void> {
    console.log('\n=== TTL (Time To Live) Demonstration ===');
    
    // Set data with short TTL for demo
    console.log('Setting data with 3 second TTL...');
    await cache.set('short-ttl', 'expires-soon', 'ttl-test', 3);
    
    // Immediate read
    const immediate = await cache.get<string>('short-ttl', 'ttl-test');
    console.log(`Immediate read: ${immediate.data} (success: ${immediate.success})`);
    
    // Wait and read again
    console.log('Waiting 4 seconds...');
    await new Promise(resolve => setTimeout(resolve, 4000));
    
    const delayed = await cache.get<string>('short-ttl', 'ttl-test');
    console.log(`After expiry: ${delayed.data} (success: ${delayed.success})`);
    console.log(`Error: ${delayed.error}`);
  }
  
  // Example 8: Batch Operations Simulation
  async demonstrateBatchPattern(): Promise<void> {
    console.log('\n=== Batch Operations Pattern ===');
    
    const userIds = ['user1', 'user2', 'user3', 'user4', 'user5'];
    
    console.log('Loading multiple users (parallel):');
    const startTime = Date.now();
    
    const users = await Promise.all(
      userIds.map(id => this.getUserData(id))
    );
    
    const totalTime = Date.now() - startTime;
    console.log(`Loaded ${users.length} users in ${totalTime}ms`);
    
    // Second batch call should be much faster due to caching
    console.log('\nSecond batch call (should be faster):');
    const startTime2 = Date.now();
    
    const users2 = await Promise.all(
      userIds.map(id => this.getUserData(id))
    );
    
    const totalTime2 = Date.now() - startTime2;
    console.log(`Loaded ${users2.length} users in ${totalTime2}ms (${((totalTime - totalTime2) / totalTime * 100).toFixed(1)}% faster)`);
  }
  
  // Run all demonstrations
  async runAllDemonstrations(): Promise<void> {
    try {
      await this.demonstratePerformance();
      await this.demonstrateDataTypes();
      await this.demonstrateInvalidation();
      await this.demonstrateTTL();
      await this.demonstrateBatchPattern();
      await this.checkSystemHealth();
      
      console.log('\n=== All Demonstrations Complete ===');
    } catch (error) {
      console.error('Demonstration failed:', error);
    }
  }
}

// Export for use
export const cacheExamples = new CacheExamples();

// Run demonstrations if this file is executed directly
if (require.main === module) {
  cacheExamples.runAllDemonstrations().catch(console.error);
}
