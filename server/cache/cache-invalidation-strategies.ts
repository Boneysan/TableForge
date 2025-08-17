// server/cache/cache-invalidation-strategies.ts
// Phase 3 Cache invalidation strategies for TableForge

import { createUserLogger } from '../utils/logger';
import { metrics } from '../observability/metrics';
import { ApplicationCachePhase3 } from './application-cache-phase3';
import RedisCacheService from './redis-cache-phase3';

const logger = createUserLogger('cache-invalidation');

export interface InvalidationEvent {
  type: 'user' | 'room' | 'asset' | 'system' | 'pattern' | 'manual';
  target: string;
  pattern?: string;
  reason: string;
  source: string;
  timestamp: number;
  metadata?: Record<string, any>;
}

export interface InvalidationStrategy {
  name: string;
  description: string;
  execute(event: InvalidationEvent): Promise<number>;
  priority: number;
}

export class CacheInvalidationManager {
  private strategies = new Map<string, InvalidationStrategy>();
  private eventQueue: InvalidationEvent[] = [];
  private processing = false;

  constructor(
    private appCache: ApplicationCachePhase3,
    private redisCache: RedisCacheService
  ) {
    this.registerDefaultStrategies();
    this.startEventProcessor();
  }

  // Register invalidation strategies
  registerStrategy(strategy: InvalidationStrategy): void {
    this.strategies.set(strategy.name, strategy);
    logger.info('Invalidation strategy registered', { 
      name: strategy.name,
      priority: strategy.priority 
    });
  }

  // Queue invalidation event
  async invalidate(event: InvalidationEvent): Promise<void> {
    event.timestamp = Date.now();
    this.eventQueue.push(event);
    
    logger.debug('Invalidation event queued', {
      type: event.type,
      target: event.target,
      reason: event.reason,
      source: event.source
    });

    // Process immediately if not already processing
    if (!this.processing) {
      await this.processQueue();
    }
  }

  // Convenience methods for common invalidation scenarios
  async invalidateUser(userId: string, reason: string, source: string): Promise<void> {
    await this.invalidate({
      type: 'user',
      target: userId,
      reason,
      source,
      timestamp: Date.now()
    });
  }

  async invalidateRoom(roomId: string, reason: string, source: string): Promise<void> {
    await this.invalidate({
      type: 'room',
      target: roomId,
      reason,
      source,
      timestamp: Date.now()
    });
  }

  async invalidateAsset(assetId: string, reason: string, source: string): Promise<void> {
    await this.invalidate({
      type: 'asset',
      target: assetId,
      reason,
      source,
      timestamp: Date.now()
    });
  }

  async invalidatePattern(pattern: string, reason: string, source: string): Promise<void> {
    await this.invalidate({
      type: 'pattern',
      target: pattern,
      pattern,
      reason,
      source,
      timestamp: Date.now()
    });
  }

  // Batch invalidation for multiple related items
  async invalidateBatch(events: Omit<InvalidationEvent, 'timestamp'>[]): Promise<void> {
    const timestamp = Date.now();
    const batchEvents = events.map(event => ({ ...event, timestamp }));
    
    this.eventQueue.push(...batchEvents);
    
    logger.info('Batch invalidation queued', { 
      eventCount: batchEvents.length,
      types: [...new Set(batchEvents.map(e => e.type))]
    });

    if (!this.processing) {
      await this.processQueue();
    }
  }

  // Event queue processing
  private async processQueue(): Promise<void> {
    if (this.processing || this.eventQueue.length === 0) {
      return;
    }

    this.processing = true;
    const startTime = Date.now();
    let processedCount = 0;
    let totalInvalidated = 0;

    try {
      // Sort events by priority and timestamp
      this.eventQueue.sort((a, b) => {
        const priorityA = this.getEventPriority(a);
        const priorityB = this.getEventPriority(b);
        if (priorityA !== priorityB) {
          return priorityB - priorityA; // Higher priority first
        }
        return a.timestamp - b.timestamp; // Older events first
      });

      // Process events in batches
      while (this.eventQueue.length > 0) {
        const event = this.eventQueue.shift()!;
        
        try {
          const invalidatedCount = await this.processEvent(event);
          totalInvalidated += invalidatedCount;
          processedCount++;
          
          // Track metrics
          metrics.cacheInvalidations?.inc(
            { pattern: event.pattern || event.target },
            invalidatedCount
          );
          
        } catch (error) {
          logger.error('Failed to process invalidation event', {
            event,
            error: error instanceof Error ? error.message : String(error)
          });
        }
      }

      const duration = Date.now() - startTime;
      logger.debug('Invalidation queue processed', {
        processedCount,
        totalInvalidated,
        duration
      });

    } finally {
      this.processing = false;
    }
  }

  private async processEvent(event: InvalidationEvent): Promise<number> {
    const strategy = this.getStrategyForEvent(event);
    if (!strategy) {
      logger.warn('No strategy found for invalidation event', { event });
      return 0;
    }

    const startTime = Date.now();
    const invalidatedCount = await strategy.execute(event);
    const duration = Date.now() - startTime;

    logger.debug('Invalidation strategy executed', {
      strategy: strategy.name,
      event: event.type,
      target: event.target,
      invalidatedCount,
      duration
    });

    return invalidatedCount;
  }

  private getStrategyForEvent(event: InvalidationEvent): InvalidationStrategy | undefined {
    // Find the most appropriate strategy for the event
    const availableStrategies = Array.from(this.strategies.values())
      .filter(strategy => this.isStrategyApplicable(strategy, event))
      .sort((a, b) => b.priority - a.priority);

    return availableStrategies[0];
  }

  private isStrategyApplicable(strategy: InvalidationStrategy, event: InvalidationEvent): boolean {
    // Strategy naming convention: {type}_{operation}
    const strategyType = strategy.name.split('_')[0];
    return strategyType === event.type || strategyType === 'universal';
  }

  private getEventPriority(event: InvalidationEvent): number {
    // Higher priority for more impactful events
    switch (event.type) {
      case 'system': return 100;
      case 'user': return 80;
      case 'room': return 60;
      case 'asset': return 40;
      case 'pattern': return 30;
      case 'manual': return 20;
      default: return 10;
    }
  }

  // Default invalidation strategies
  private registerDefaultStrategies(): void {
    // User invalidation strategy
    this.registerStrategy({
      name: 'user_invalidation',
      description: 'Invalidates all user-related cache entries',
      priority: 80,
      execute: async (event: InvalidationEvent): Promise<number> => {
        const userId = event.target;
        let totalInvalidated = 0;

        // Application cache patterns
        const appPatterns = [
          `user:session:${userId}`,
          `user:profile:${userId}`,
          `user:rooms:${userId}`,
          `notification:${userId}`,
          `rate:${userId}:*`,
          `query:user:${userId}:*`
        ];

        for (const pattern of appPatterns) {
          totalInvalidated += this.appCache.invalidate(pattern);
        }

        // Redis cache invalidation
        try {
          await this.redisCache.invalidateUserData(userId);
          totalInvalidated += 5; // Estimate for Redis invalidations
        } catch (error) {
          logger.error('Redis user invalidation failed', { userId, error });
        }

        return totalInvalidated;
      }
    });

    // Room invalidation strategy
    this.registerStrategy({
      name: 'room_invalidation',
      description: 'Invalidates all room-related cache entries',
      priority: 60,
      execute: async (event: InvalidationEvent): Promise<number> => {
        const roomId = event.target;
        let totalInvalidated = 0;

        // Application cache patterns
        const appPatterns = [
          `room:state:${roomId}`,
          `room:players:${roomId}`,
          `room:chat:${roomId}:*`,
          `query:room:${roomId}:*`
        ];

        for (const pattern of appPatterns) {
          totalInvalidated += this.appCache.invalidate(pattern);
        }

        // Redis cache invalidation
        try {
          await this.redisCache.invalidateRoomData(roomId);
          totalInvalidated += 3; // Estimate for Redis invalidations
        } catch (error) {
          logger.error('Redis room invalidation failed', { roomId, error });
        }

        return totalInvalidated;
      }
    });

    // Asset invalidation strategy
    this.registerStrategy({
      name: 'asset_invalidation',
      description: 'Invalidates all asset-related cache entries',
      priority: 40,
      execute: async (event: InvalidationEvent): Promise<number> => {
        const assetId = event.target;
        let totalInvalidated = 0;

        // Application cache patterns
        const appPatterns = [
          `asset:meta:${assetId}`,
          `batch:assets:*${assetId}*`,
          `query:asset:${assetId}:*`
        ];

        for (const pattern of appPatterns) {
          totalInvalidated += this.appCache.invalidate(pattern);
        }

        // Redis cache invalidation
        try {
          totalInvalidated += await this.redisCache.invalidatePattern(`asset:meta:${assetId}`);
          totalInvalidated += await this.redisCache.invalidatePattern(`batch:assets:*${assetId}*`);
        } catch (error) {
          logger.error('Redis asset invalidation failed', { assetId, error });
        }

        return totalInvalidated;
      }
    });

    // Pattern-based invalidation strategy
    this.registerStrategy({
      name: 'pattern_invalidation',
      description: 'Invalidates cache entries matching a pattern',
      priority: 30,
      execute: async (event: InvalidationEvent): Promise<number> => {
        const pattern = event.pattern || event.target;
        let totalInvalidated = 0;

        // Application cache invalidation
        totalInvalidated += this.appCache.invalidate(pattern);

        // Redis cache invalidation
        try {
          totalInvalidated += await this.redisCache.invalidatePattern(pattern);
        } catch (error) {
          logger.error('Redis pattern invalidation failed', { pattern, error });
        }

        return totalInvalidated;
      }
    });

    // System-wide invalidation strategy
    this.registerStrategy({
      name: 'system_invalidation',
      description: 'Invalidates system configuration and global cache entries',
      priority: 100,
      execute: async (event: InvalidationEvent): Promise<number> => {
        let totalInvalidated = 0;

        // Application cache patterns
        const appPatterns = [
          'system:config:*',
          'system:template:*',
          'leaderboard:*',
          'search:*'
        ];

        for (const pattern of appPatterns) {
          totalInvalidated += this.appCache.invalidate(pattern);
        }

        // Redis cache invalidation
        try {
          for (const pattern of appPatterns) {
            totalInvalidated += await this.redisCache.invalidatePattern(pattern);
          }
        } catch (error) {
          logger.error('Redis system invalidation failed', { error });
        }

        return totalInvalidated;
      }
    });

    logger.info('Default invalidation strategies registered', {
      strategyCount: this.strategies.size
    });
  }

  // Event processor startup
  private startEventProcessor(): void {
    // Process queue every 100ms if there are pending events
    setInterval(async () => {
      if (this.eventQueue.length > 0 && !this.processing) {
        await this.processQueue();
      }
    }, 100);

    logger.info('Cache invalidation event processor started');
  }

  // Statistics and monitoring
  getStats(): any {
    return {
      registeredStrategies: Array.from(this.strategies.values()).map(s => ({
        name: s.name,
        description: s.description,
        priority: s.priority
      })),
      queueLength: this.eventQueue.length,
      processing: this.processing
    };
  }
}

export default CacheInvalidationManager;
