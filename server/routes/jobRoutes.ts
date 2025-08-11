import { Router } from 'express';
import { z } from 'zod';
import { validateRequest } from '../middleware/validation';
import { requireAuth } from '../auth/middleware';
import { requireRole } from '../auth/roleAuth';
import { logger } from '../utils/logger';
import type { JobScheduler } from '../jobs/jobScheduler';

/**
 * Job Management Routes - API endpoints for monitoring and controlling cleanup jobs
 * 
 * Features:
 * - Job status and statistics monitoring
 * - Manual job triggering (admin only)
 * - Job history and health checks
 * - Real-time job metrics
 */

// Validation schemas
const triggerJobSchema = z.object({
  jobName: z.enum(['roomCleanup', 'assetCleanup', 'socketCleanup', 'healthCheck'])
});

export function createJobRoutes(jobScheduler: JobScheduler): Router {
  const router = Router();

  /**
   * GET /api/jobs/stats - Get job statistics and status
   */
  router.get('/stats', requireAuth, requireRole(['admin', 'moderator']), async (req, res) => {
    const correlationId = req.headers['x-correlation-id'] as string || `job_stats_${Date.now()}`;
    
    try {
      logger.info('📊 [Job Routes] Getting job statistics', {
        correlationId,
        userId: (req as any).user?.uid
      } as any);

      const jobStats = jobScheduler.getJobStats();
      
      res.json({
        success: true,
        data: jobStats
      });

    } catch (error) {
      logger.error('❌ [Job Routes] Error getting job statistics', {
        correlationId,
        error: (error as Error).message
      } as any);

      res.status(500).json({
        success: false,
        error: 'Failed to retrieve job statistics'
      });
    }
  });

  /**
   * GET /api/jobs/health - Get system health overview
   */
  router.get('/health', requireAuth, requireRole(['admin', 'moderator']), async (req, res) => {
    const correlationId = req.headers['x-correlation-id'] as string || `job_health_${Date.now()}`;
    
    try {
      logger.info('🏥 [Job Routes] Getting system health', {
        correlationId,
        userId: (req as any).user?.uid
      } as any);

      // Trigger a health check to get fresh data
      const healthResult = await jobScheduler.triggerJob('healthCheck');
      const jobStats = jobScheduler.getJobStats();

      const healthOverview = {
        system: {
          status: healthResult.success ? 'healthy' : 'degraded',
          timestamp: healthResult.timestamp,
          uptime: process.uptime()
        },
        jobs: {
          active: jobStats.activeJobs.length,
          running: jobStats.isRunning,
          lastHealthCheck: healthResult
        },
        metrics: healthResult.results
      };
      
      res.json({
        success: true,
        data: healthOverview
      });

    } catch (error) {
      logger.error('❌ [Job Routes] Error getting system health', {
        correlationId,
        error: (error as Error).message
      } as any);

      res.status(500).json({
        success: false,
        error: 'Failed to retrieve system health',
        data: {
          system: {
            status: 'error',
            timestamp: new Date().toISOString()
          }
        }
      });
    }
  });

  /**
   * POST /api/jobs/trigger - Manually trigger a specific job
   */
  router.post(
    '/trigger',
    requireAuth,
    requireRole(['admin']), // Only admins can trigger jobs manually
    validateRequest({
      body: triggerJobSchema
    }),
    async (req, res) => {
      const correlationId = req.headers['x-correlation-id'] as string || `job_trigger_${Date.now()}`;
      const { jobName } = req.body;
      
      try {
        logger.info('🚀 [Job Routes] Manual job trigger requested', {
          correlationId,
          jobName,
          userId: (req as any).user?.uid
        } as any);

        const result = await jobScheduler.triggerJob(jobName);
        
        if (result.success) {
          logger.info('✅ [Job Routes] Job triggered successfully', {
            correlationId,
            jobName,
            duration: result.duration
          } as any);

          res.json({
            success: true,
            message: `Job ${jobName} executed successfully`,
            data: result
          });
        } else {
          logger.warn('⚠️ [Job Routes] Job execution completed with errors', {
            correlationId,
            jobName,
            errors: result.errors
          } as any);

          res.status(422).json({
            success: false,
            message: `Job ${jobName} completed with errors`,
            data: result
          });
        }

      } catch (error) {
        logger.error('❌ [Job Routes] Error triggering job', {
          correlationId,
          jobName,
          error: (error as Error).message
        } as any);

        res.status(500).json({
          success: false,
          error: `Failed to trigger job ${jobName}`,
          message: (error as Error).message
        });
      }
    }
  );

  /**
   * GET /api/jobs/history/:jobName - Get execution history for a specific job
   */
  router.get(
    '/history/:jobName',
    requireAuth,
    requireRole(['admin', 'moderator']),
    async (req, res) => {
      const correlationId = req.headers['x-correlation-id'] as string || `job_history_${Date.now()}`;
      const { jobName } = req.params;
      const limit = parseInt(req.query.limit as string) || 20;
      
      try {
        logger.info('📜 [Job Routes] Getting job history', {
          correlationId,
          jobName,
          limit,
          userId: (req as any).user?.uid
        } as any);

        const jobStats = jobScheduler.getJobStats();
        const history = jobStats.jobHistory.get(jobName) || [];
        
        // Return the most recent entries, limited by the limit parameter
        const recentHistory = history.slice(-limit).reverse(); // Most recent first

        res.json({
          success: true,
          data: {
            jobName,
            history: recentHistory,
            totalExecutions: history.length,
            summary: {
              successRate: history.length > 0 
                ? history.filter(r => r.success).length / history.length 
                : 0,
              averageDuration: history.length > 0 
                ? history.reduce((sum, r) => sum + r.duration, 0) / history.length 
                : 0,
              lastExecution: history.length > 0 ? history[history.length - 1] : null
            }
          }
        });

      } catch (error) {
        logger.error('❌ [Job Routes] Error getting job history', {
          correlationId,
          jobName,
          error: (error as Error).message
        } as any);

        res.status(500).json({
          success: false,
          error: `Failed to retrieve history for job ${jobName}`
        });
      }
    }
  );

  /**
   * GET /api/jobs/metrics - Get real-time system metrics
   */
  router.get('/metrics', requireAuth, requireRole(['admin', 'moderator']), async (req, res) => {
    const correlationId = req.headers['x-correlation-id'] as string || `job_metrics_${Date.now()}`;
    
    try {
      logger.info('📈 [Job Routes] Getting system metrics', {
        correlationId,
        userId: (req as any).user?.uid
      } as any);

      const jobStats = jobScheduler.getJobStats();
      const healthHistory = jobStats.jobHistory.get('healthCheck') || [];
      const latestHealth = healthHistory.length > 0 ? healthHistory[healthHistory.length - 1] : null;

      const metrics = {
        timestamp: new Date().toISOString(),
        system: {
          uptime: process.uptime(),
          memoryUsage: process.memoryUsage(),
          cpuUsage: process.cpuUsage(),
          platform: process.platform,
          nodeVersion: process.version
        },
        jobs: {
          scheduler: {
            isRunning: jobStats.isRunning,
            activeJobs: jobStats.activeJobs,
            config: jobStats.config
          },
          metrics: latestHealth?.results || {}
        }
      };
      
      res.json({
        success: true,
        data: metrics
      });

    } catch (error) {
      logger.error('❌ [Job Routes] Error getting system metrics', {
        correlationId,
        error: (error as Error).message
      } as any);

      res.status(500).json({
        success: false,
        error: 'Failed to retrieve system metrics'
      });
    }
  });

  return router;
}