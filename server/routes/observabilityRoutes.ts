import type { Request, Response, Router } from 'express';
import { Router as createRouter } from 'express';
import { getMetrics, getMetricsHealth } from '@server/observability/metrics';
import { getCurrentTraceContext } from '@server/observability/telemetry';
import { register } from 'prom-client';
import { logger } from '@server/utils/logger';

const router: Router = createRouter();

// Metrics endpoint for Prometheus scraping
router.get('/metrics', (req: Request, res: Response) => {
  try {
    const metrics = getMetrics();
    res.set('Content-Type', register.contentType);
    res.send(metrics);
  } catch (error) {
    logger.error('Error serving metrics', { error: (error as Error).message });
    res.status(500).json({ error: 'Failed to generate metrics' });
  }
});

// Health check endpoint with metrics validation
router.get('/health/metrics', (req: Request, res: Response) => {
  try {
    const health = getMetricsHealth();
    const statusCode = health.status === 'healthy' ? 200 : 503;
    
    res.status(statusCode).json({
      service: 'vorpal-board',
      component: 'metrics',
      ...health,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    logger.error('Error in metrics health check', { error: (error as Error).message });
    res.status(503).json({
      service: 'vorpal-board',
      component: 'metrics',
      status: 'unhealthy',
      error: (error as Error).message,
      timestamp: new Date().toISOString(),
    });
  }
});

// Tracing information endpoint
router.get('/trace/current', (req: Request, res: Response) => {
  try {
    const traceContext = getCurrentTraceContext();
    
    if (!traceContext) {
      res.status(204).json({
        message: 'No active trace context',
        timestamp: new Date().toISOString(),
      });
      return;
    }

    res.json({
      service: 'vorpal-board',
      component: 'tracing',
      traceContext: {
        traceId: traceContext.traceId,
        spanId: traceContext.spanId,
        userId: traceContext.userId,
        roomId: traceContext.roomId,
        sessionId: traceContext.sessionId,
      },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    logger.error('Error getting trace context', { error: (error as Error).message });
    res.status(500).json({
      error: 'Failed to get trace context',
      timestamp: new Date().toISOString(),
    });
  }
});

// Observability status endpoint
router.get('/status', (req: Request, res: Response) => {
  try {
    const metricsHealth = getMetricsHealth();
    const traceContext = getCurrentTraceContext();
    
    res.json({
      service: 'vorpal-board',
      observability: {
        metrics: {
          status: metricsHealth.status,
          totalMetrics: register.getMetricsAsJSON().length,
        },
        tracing: {
          active: !!traceContext,
          contextAvailable: !!traceContext,
          traceId: traceContext?.traceId || null,
        },
        logging: {
          level: process.env.LOG_LEVEL || 'info',
          structured: true,
        },
      },
      environment: process.env.NODE_ENV || 'development',
      version: '1.0.0',
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    logger.error('Error in observability status', { error: (error as Error).message });
    res.status(500).json({
      error: 'Failed to get observability status',
      timestamp: new Date().toISOString(),
    });
  }
});

// Manual metrics collection endpoint (for debugging)
router.post('/collect', (req: Request, res: Response) => {
  try {
    // Force collection of resource metrics
    const usage = process.memoryUsage();
    const uptime = process.uptime();
    
    logger.info('Manual metrics collection triggered', {
      memoryUsage: usage,
      uptime,
      metricsCount: register.getMetricsAsJSON().length,
    });

    res.json({
      message: 'Metrics collection triggered',
      collected: {
        memoryUsage: usage,
        uptime,
        metricsCount: register.getMetricsAsJSON().length,
      },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    logger.error('Error in manual metrics collection', { error: (error as Error).message });
    res.status(500).json({
      error: 'Failed to collect metrics',
      timestamp: new Date().toISOString(),
    });
  }
});

// Export specific metric values (for debugging)
router.get('/metrics/:metricName', (req: Request, res: Response) => {
  try {
    const { metricName } = req.params;
    const metric = register.getSingleMetric(metricName);
    
    if (!metric) {
      res.status(404).json({
        error: `Metric '${metricName}' not found`,
        availableMetrics: register.getMetricsAsJSON().map(m => m.name),
        timestamp: new Date().toISOString(),
      });
      return;
    }

    res.json({
      metric: {
        name: metric.name,
        help: metric.help,
        type: metric.type,
        values: metric.get(),
      },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    logger.error('Error getting specific metric', { 
      error: (error as Error).message,
      metricName: req.params.metricName,
    });
    res.status(500).json({
      error: 'Failed to get metric',
      timestamp: new Date().toISOString(),
    });
  }
});

export default router;