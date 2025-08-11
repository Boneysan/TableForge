import { logger } from '../utils/logger';
import { RoomCleanupJob } from './roomCleanupJob';
import { AssetCleanupJob } from './assetCleanupJob';
import { SocketCleanupJob } from './socketCleanupJob';
import type { WebSocketServer } from 'ws';

/**
 * Job Scheduler - Manages TTL cleanup jobs with retry logic and monitoring
 *
 * Features:
 * - Scheduled execution of cleanup jobs
 * - Retry logic for failed operations
 * - Job monitoring and health checks
 * - Configurable intervals and timeouts
 * - Comprehensive logging and metrics
 */

export interface JobResult {
  success: boolean;
  duration: number;
  timestamp: string;
  results?: any;
  errors?: string[];
}

export interface JobConfig {
  enabled: boolean;
  interval: number; // in milliseconds
  retryAttempts: number;
  retryDelay: number; // in milliseconds
  timeout: number; // in milliseconds
}

export interface JobSchedulerConfig {
  roomCleanup: JobConfig;
  assetCleanup: JobConfig;
  socketCleanup: JobConfig;
  healthCheck: JobConfig;
}

export class JobScheduler {
  private roomCleanupJob: RoomCleanupJob;
  private assetCleanupJob: AssetCleanupJob;
  private socketCleanupJob: SocketCleanupJob;

  private config: JobSchedulerConfig;
  private intervals: Map<string, NodeJS.Timeout> = new Map();
  private jobHistory: Map<string, JobResult[]> = new Map();
  private isShutdown = false;

  // Default configuration
  private static readonly DEFAULT_CONFIG: JobSchedulerConfig = {
    roomCleanup: {
      enabled: true,
      interval: 60 * 60 * 1000, // 1 hour
      retryAttempts: 3,
      retryDelay: 5 * 60 * 1000, // 5 minutes
      timeout: 30 * 60 * 1000, // 30 minutes
    },
    assetCleanup: {
      enabled: true,
      interval: 2 * 60 * 60 * 1000, // 2 hours
      retryAttempts: 3,
      retryDelay: 10 * 60 * 1000, // 10 minutes
      timeout: 45 * 60 * 1000, // 45 minutes
    },
    socketCleanup: {
      enabled: true,
      interval: 5 * 60 * 1000, // 5 minutes
      retryAttempts: 2,
      retryDelay: 1 * 60 * 1000, // 1 minute
      timeout: 2 * 60 * 1000, // 2 minutes
    },
    healthCheck: {
      enabled: true,
      interval: 15 * 60 * 1000, // 15 minutes
      retryAttempts: 1,
      retryDelay: 30 * 1000, // 30 seconds
      timeout: 1 * 60 * 1000, // 1 minute
    },
  };

  constructor(wss: WebSocketServer, config: Partial<JobSchedulerConfig> = {}) {
    this.config = { ...JobScheduler.DEFAULT_CONFIG, ...config };

    this.roomCleanupJob = new RoomCleanupJob();
    this.assetCleanupJob = new AssetCleanupJob();
    this.socketCleanupJob = new SocketCleanupJob(wss);

    this.initializeJobHistory();
  }

  /**
   * Start the job scheduler
   */
  start(): void {
    if (this.isShutdown) {
      throw new Error('Cannot start a shutdown job scheduler');
    }

    logger.info('📅 [Job Scheduler] Starting job scheduler', {
      config: this.config,
    } as any);

    // Schedule room cleanup job
    if (this.config.roomCleanup.enabled) {
      this.scheduleJob('roomCleanup', () => this.executeRoomCleanup());
    }

    // Schedule asset cleanup job
    if (this.config.assetCleanup.enabled) {
      this.scheduleJob('assetCleanup', () => this.executeAssetCleanup());
    }

    // Schedule socket cleanup job
    if (this.config.socketCleanup.enabled) {
      this.scheduleJob('socketCleanup', () => this.executeSocketCleanup());
    }

    // Schedule health check
    if (this.config.healthCheck.enabled) {
      this.scheduleJob('healthCheck', () => this.executeHealthCheck());
    }

    logger.info('✅ [Job Scheduler] Job scheduler started successfully', {
      activeJobs: this.intervals.size,
    } as any);
  }

  /**
   * Stop the job scheduler
   */
  async stop(): Promise<void> {
    logger.info('⏹️ [Job Scheduler] Stopping job scheduler');

    this.isShutdown = true;

    // Clear all intervals
    for (const [jobName, intervalId] of this.intervals.entries()) {
      clearInterval(intervalId);
      logger.info('⏹️ [Job Scheduler] Stopped job', { jobName } as any);
    }

    this.intervals.clear();

    // Close all socket connections
    await this.socketCleanupJob.closeAllConnections('Scheduler shutdown');

    logger.info('✅ [Job Scheduler] Job scheduler stopped successfully');
  }

  /**
   * Schedule a specific job
   */
  private scheduleJob(jobName: string, jobFunction: () => Promise<void>): void {
    const config = this.getJobConfig(jobName);

    const intervalId = setInterval(async () => {
      if (this.isShutdown) return;

      logger.info(`⏰ [Job Scheduler] Executing scheduled job: ${jobName}`);

      try {
        await this.executeWithRetry(jobName, jobFunction);
      } catch (error) {
        logger.error(`❌ [Job Scheduler] Failed to execute job: ${jobName}`, {
          error: (error as Error).message,
        } as any);
      }
    }, config.interval);

    this.intervals.set(jobName, intervalId);

    logger.info(`📅 [Job Scheduler] Scheduled job: ${jobName}`, {
      interval: config.interval,
      retryAttempts: config.retryAttempts,
    } as any);
  }

  /**
   * Execute a job with retry logic
   */
  private async executeWithRetry(jobName: string, jobFunction: () => Promise<void>): Promise<void> {
    const config = this.getJobConfig(jobName);
    let lastError: Error | null = null;

    for (let attempt = 1; attempt <= config.retryAttempts; attempt++) {
      try {
        await this.executeWithTimeout(jobFunction, config.timeout);
        return; // Success
      } catch (error) {
        lastError = error as Error;

        logger.warn(`⚠️ [Job Scheduler] Job attempt failed: ${jobName}`, {
          attempt,
          maxAttempts: config.retryAttempts,
          error: lastError.message,
        } as any);

        if (attempt < config.retryAttempts) {
          await this.delay(config.retryDelay);
        }
      }
    }

    throw lastError;
  }

  /**
   * Execute a function with timeout
   */
  private async executeWithTimeout<T>(
    func: () => Promise<T>,
    timeoutMs: number,
  ): Promise<T> {
    return Promise.race([
      func(),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error(`Job timed out after ${timeoutMs}ms`)), timeoutMs),
      ),
    ]);
  }

  /**
   * Execute room cleanup job
   */
  private async executeRoomCleanup(): Promise<void> {
    const startTime = Date.now();

    try {
      const results = await this.roomCleanupJob.execute();

      const jobResult: JobResult = {
        success: results.errors.length === 0,
        duration: Date.now() - startTime,
        timestamp: new Date().toISOString(),
        results,
        errors: results.errors,
      };

      this.recordJobResult('roomCleanup', jobResult);

      logger.info('✅ [Job Scheduler] Room cleanup completed', {
        results,
        duration: jobResult.duration,
      } as any);

    } catch (error) {
      const jobResult: JobResult = {
        success: false,
        duration: Date.now() - startTime,
        timestamp: new Date().toISOString(),
        errors: [(error as Error).message],
      };

      this.recordJobResult('roomCleanup', jobResult);
      throw error;
    }
  }

  /**
   * Execute asset cleanup job
   */
  private async executeAssetCleanup(): Promise<void> {
    const startTime = Date.now();

    try {
      const results = await this.assetCleanupJob.execute();

      const jobResult: JobResult = {
        success: results.errors.length === 0,
        duration: Date.now() - startTime,
        timestamp: new Date().toISOString(),
        results,
        errors: results.errors,
      };

      this.recordJobResult('assetCleanup', jobResult);

      logger.info('✅ [Job Scheduler] Asset cleanup completed', {
        results,
        duration: jobResult.duration,
      } as any);

    } catch (error) {
      const jobResult: JobResult = {
        success: false,
        duration: Date.now() - startTime,
        timestamp: new Date().toISOString(),
        errors: [(error as Error).message],
      };

      this.recordJobResult('assetCleanup', jobResult);
      throw error;
    }
  }

  /**
   * Execute socket cleanup job
   */
  private async executeSocketCleanup(): Promise<void> {
    const startTime = Date.now();

    try {
      const results = await this.socketCleanupJob.execute();

      const jobResult: JobResult = {
        success: results.errors.length === 0,
        duration: Date.now() - startTime,
        timestamp: new Date().toISOString(),
        results,
        errors: results.errors,
      };

      this.recordJobResult('socketCleanup', jobResult);

      logger.info('✅ [Job Scheduler] Socket cleanup completed', {
        results,
        duration: jobResult.duration,
      } as any);

    } catch (error) {
      const jobResult: JobResult = {
        success: false,
        duration: Date.now() - startTime,
        timestamp: new Date().toISOString(),
        errors: [(error as Error).message],
      };

      this.recordJobResult('socketCleanup', jobResult);
      throw error;
    }
  }

  /**
   * Execute health check
   */
  private async executeHealthCheck(): Promise<void> {
    const startTime = Date.now();

    try {
      const roomStats = await this.roomCleanupJob.getCleanupStats();
      const assetStats = await this.assetCleanupJob.getAssetCleanupStats();
      const socketStats = this.socketCleanupJob.getSocketStats();

      const healthData = {
        roomStats,
        assetStats,
        socketStats,
        scheduler: {
          activeJobs: this.intervals.size,
          jobHistory: this.getJobHistorySummary(),
        },
      };

      const jobResult: JobResult = {
        success: true,
        duration: Date.now() - startTime,
        timestamp: new Date().toISOString(),
        results: healthData,
      };

      this.recordJobResult('healthCheck', jobResult);

      logger.info('📊 [Job Scheduler] Health check completed', {
        healthData,
      } as any);

    } catch (error) {
      const jobResult: JobResult = {
        success: false,
        duration: Date.now() - startTime,
        timestamp: new Date().toISOString(),
        errors: [(error as Error).message],
      };

      this.recordJobResult('healthCheck', jobResult);
      throw error;
    }
  }

  /**
   * Get job configuration by name
   */
  private getJobConfig(jobName: string): JobConfig {
    return (this.config as any)[jobName] || JobScheduler.DEFAULT_CONFIG.roomCleanup;
  }

  /**
   * Record job execution result
   */
  private recordJobResult(jobName: string, result: JobResult): void {
    if (!this.jobHistory.has(jobName)) {
      this.jobHistory.set(jobName, []);
    }

    const history = this.jobHistory.get(jobName)!;
    history.push(result);

    // Keep only last 50 results per job
    if (history.length > 50) {
      history.splice(0, history.length - 50);
    }
  }

  /**
   * Initialize job history tracking
   */
  private initializeJobHistory(): void {
    this.jobHistory.set('roomCleanup', []);
    this.jobHistory.set('assetCleanup', []);
    this.jobHistory.set('socketCleanup', []);
    this.jobHistory.set('healthCheck', []);
  }

  /**
   * Get job history summary
   */
  private getJobHistorySummary(): Record<string, any> {
    const summary: Record<string, any> = {};

    for (const [jobName, history] of this.jobHistory.entries()) {
      const recentResults = history.slice(-10); // Last 10 results
      const successCount = recentResults.filter(r => r.success).length;
      const avgDuration = recentResults.length > 0
        ? recentResults.reduce((sum, r) => sum + r.duration, 0) / recentResults.length
        : 0;

      summary[jobName] = {
        totalExecutions: history.length,
        recentSuccessRate: recentResults.length > 0 ? successCount / recentResults.length : 0,
        averageDuration: avgDuration,
        lastExecution: history.length > 0 ? history[history.length - 1].timestamp : null,
      };
    }

    return summary;
  }

  /**
   * Get full job statistics
   */
  getJobStats(): {
    activeJobs: string[];
    jobHistory: Map<string, JobResult[]>;
    config: JobSchedulerConfig;
    isRunning: boolean;
  } {
    return {
      activeJobs: Array.from(this.intervals.keys()),
      jobHistory: this.jobHistory,
      config: this.config,
      isRunning: !this.isShutdown,
    };
  }

  /**
   * Manually trigger a specific job
   */
  async triggerJob(jobName: string): Promise<JobResult> {
    if (this.isShutdown) {
      throw new Error('Cannot trigger job on shutdown scheduler');
    }

    logger.info(`🚀 [Job Scheduler] Manually triggering job: ${jobName}`);

    switch (jobName) {
      case 'roomCleanup':
        await this.executeRoomCleanup();
        break;
      case 'assetCleanup':
        await this.executeAssetCleanup();
        break;
      case 'socketCleanup':
        await this.executeSocketCleanup();
        break;
      case 'healthCheck':
        await this.executeHealthCheck();
        break;
      default:
        throw new Error(`Unknown job: ${jobName}`);
    }

    const history = this.jobHistory.get(jobName);
    return history ? history[history.length - 1] : {
      success: false,
      duration: 0,
      timestamp: new Date().toISOString(),
      errors: ['No execution history found'],
    };
  }

  /**
   * Utility method for delays
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
