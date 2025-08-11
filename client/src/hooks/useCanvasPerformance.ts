/**
 * Performance monitoring and optimization hook for canvas operations
 * Provides comprehensive performance metrics and adaptive optimization strategies
 */

import { useRef, useState, useCallback, useEffect } from 'react';

interface PerformanceMetrics {
  fps: number;
  renderTime: number;
  workerLatency: number;
  memoryUsage: number;
  droppedFrames: number;
  adaptiveSettings: {
    throttleMs: number;
    batchSize: number;
    enableVirtualization: boolean;
    enableWorkers: boolean;
  };
}

interface UseCanvasPerformanceOptions {
  targetFps?: number;
  maxMemoryMB?: number;
  adaptiveOptimization?: boolean;
  performanceThreshold?: number;
}

export function useCanvasPerformance(options: UseCanvasPerformanceOptions = {}) {
  const {
    targetFps = 60,
    maxMemoryMB = 200,
    adaptiveOptimization = true,
    performanceThreshold = 0.8, // 80% of target performance
  } = options;

  const [metrics, setMetrics] = useState<PerformanceMetrics>({
    fps: 0,
    renderTime: 0,
    workerLatency: 0,
    memoryUsage: 0,
    droppedFrames: 0,
    adaptiveSettings: {
      throttleMs: 16, // ~60fps
      batchSize: 50,
      enableVirtualization: true,
      enableWorkers: true,
    },
  });

  const metricsRef = useRef({
    frameCount: 0,
    lastTime: performance.now(),
    renderTimes: [] as number[],
    droppedFrames: 0,
    workerLatencies: [] as number[],
    lastAdaptiveCheck: performance.now(),
  });

  // Record frame render time
  const recordFrameTime = useCallback((renderTime: number) => {
    metricsRef.current.renderTimes.push(renderTime);
    metricsRef.current.frameCount++;

    // Keep only last 60 samples for rolling average
    if (metricsRef.current.renderTimes.length > 60) {
      metricsRef.current.renderTimes.shift();
    }
  }, []);

  // Record worker operation latency
  const recordWorkerLatency = useCallback((latency: number) => {
    metricsRef.current.workerLatencies.push(latency);

    if (metricsRef.current.workerLatencies.length > 20) {
      metricsRef.current.workerLatencies.shift();
    }
  }, []);

  // Adaptive optimization based on performance
  const adaptSettings = useCallback(() => {
    const now = performance.now();
    const metrics_ref = metricsRef.current;

    // Only adapt every 2 seconds to avoid thrashing
    if (now - metrics_ref.lastAdaptiveCheck < 2000) return;
    metrics_ref.lastAdaptiveCheck = now;

    setMetrics(prev => {
      const currentFps = prev.fps;
      const targetRatio = currentFps / targetFps;
      
      let newSettings = { ...prev.adaptiveSettings };

      // Performance is below threshold, optimize for speed
      if (targetRatio < performanceThreshold) {
        // Increase throttling (reduce frequency)
        newSettings.throttleMs = Math.min(32, newSettings.throttleMs + 2);
        
        // Reduce batch size for lighter processing
        newSettings.batchSize = Math.max(10, newSettings.batchSize - 10);
        
        // Keep virtualization and workers enabled for heavy scenes
        newSettings.enableVirtualization = true;
        newSettings.enableWorkers = true;
        
      } else if (targetRatio > 0.95) {
        // Performance is good, can increase quality
        newSettings.throttleMs = Math.max(8, newSettings.throttleMs - 1);
        newSettings.batchSize = Math.min(100, newSettings.batchSize + 5);
      }

      // Memory pressure adaptation
      if (prev.memoryUsage > maxMemoryMB * 0.8) {
        newSettings.batchSize = Math.max(5, newSettings.batchSize - 20);
        newSettings.enableVirtualization = true; // Force virtualization
      }

      return {
        ...prev,
        adaptiveSettings: newSettings,
      };
    });
  }, [targetFps, performanceThreshold, maxMemoryMB]);

  // Update performance metrics periodically
  const updateMetrics = useCallback(() => {
    const now = performance.now();
    const metrics_ref = metricsRef.current;

    if (now - metrics_ref.lastTime >= 1000) {
      const fps = metrics_ref.frameCount / ((now - metrics_ref.lastTime) / 1000);
      
      const avgRenderTime = metrics_ref.renderTimes.length > 0
        ? metrics_ref.renderTimes.reduce((a, b) => a + b, 0) / metrics_ref.renderTimes.length
        : 0;

      const avgWorkerLatency = metrics_ref.workerLatencies.length > 0
        ? metrics_ref.workerLatencies.reduce((a, b) => a + b, 0) / metrics_ref.workerLatencies.length
        : 0;

      const memoryUsage = (performance as any).memory?.usedJSHeapSize
        ? Math.round((performance as any).memory.usedJSHeapSize / 1024 / 1024)
        : 0;

      setMetrics(prev => ({
        ...prev,
        fps: Math.round(fps),
        renderTime: Math.round(avgRenderTime * 100) / 100,
        workerLatency: Math.round(avgWorkerLatency * 100) / 100,
        memoryUsage,
        droppedFrames: metrics_ref.droppedFrames,
      }));

      // Reset counters
      metrics_ref.frameCount = 0;
      metrics_ref.lastTime = now;
      metrics_ref.droppedFrames = 0;

      // Run adaptive optimization
      if (adaptiveOptimization) {
        adaptSettings();
      }
    }
  }, [adaptiveOptimization, adaptSettings]);

  // Performance monitoring loop
  useEffect(() => {
    let rafId: number;

    const monitorLoop = () => {
      updateMetrics();
      rafId = requestAnimationFrame(monitorLoop);
    };

    rafId = requestAnimationFrame(monitorLoop);

    return () => {
      if (rafId) cancelAnimationFrame(rafId);
    };
  }, [updateMetrics]);

  // Helper to check if performance is acceptable
  const isPerformanceGood = useCallback(() => {
    return metrics.fps >= targetFps * performanceThreshold;
  }, [metrics.fps, targetFps, performanceThreshold]);

  // Helper to get performance status
  const getPerformanceStatus = useCallback(() => {
    if (metrics.fps === 0) return 'initializing';
    if (metrics.fps < targetFps * 0.5) return 'poor';
    if (metrics.fps < targetFps * performanceThreshold) return 'fair';
    return 'good';
  }, [metrics.fps, targetFps, performanceThreshold]);

  // Manual performance boost (emergency optimization)
  const performanceBoost = useCallback(() => {
    setMetrics(prev => ({
      ...prev,
      adaptiveSettings: {
        ...prev.adaptiveSettings,
        throttleMs: 32, // Reduce to 30fps
        batchSize: 10, // Small batches
        enableVirtualization: true,
        enableWorkers: true,
      },
    }));
  }, []);

  // Reset to default settings
  const resetSettings = useCallback(() => {
    setMetrics(prev => ({
      ...prev,
      adaptiveSettings: {
        throttleMs: 16,
        batchSize: 50,
        enableVirtualization: true,
        enableWorkers: true,
      },
    }));
  }, []);

  return {
    metrics,
    recordFrameTime,
    recordWorkerLatency,
    isPerformanceGood,
    getPerformanceStatus,
    performanceBoost,
    resetSettings,
    // Optimized settings for current performance
    optimizedSettings: metrics.adaptiveSettings,
  };
}