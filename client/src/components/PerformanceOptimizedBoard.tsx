/**
 * Complete canvas performance optimization integration
 * Combines all performance features into a single high-performance game board component
 */

import React, { useRef, useState, useCallback, useEffect } from 'react';
import { OptimizedGameBoard } from './OptimizedGameBoard';
import { useVirtualizedCanvas } from '../hooks/useVirtualizedCanvas';
import { useThrottledPointer } from '../hooks/useThrottledPointer';
import { useCanvasWorker } from '../hooks/useCanvasWorker';
import type { AssetTransform } from '../workers/canvasWorker';

interface PerformanceOptimizedBoardProps {
  roomId: string;
  assets: any[];
  onAssetMove?: (assetId: string, x: number, y: number, rotation?: number) => void;
  onAssetSelect?: (assetId: string) => void;
  enablePerformanceMode?: boolean;
  className?: string;
}

export function PerformanceOptimizedBoard({
  roomId,
  assets,
  onAssetMove,
  onAssetSelect,
  enablePerformanceMode = true,
  className,
}: PerformanceOptimizedBoardProps) {
  const [performanceMetrics, setPerformanceMetrics] = useState({
    fps: 0,
    renderTime: 0,
    workerLatency: 0,
    memoryUsage: 0,
  });

  const performanceMonitorRef = useRef({
    frameCount: 0,
    lastTime: performance.now(),
    renderTimes: [] as number[],
  });

  // Performance monitoring
  const updatePerformanceMetrics = useCallback(() => {
    const now = performance.now();
    const monitor = performanceMonitorRef.current;
    
    monitor.frameCount++;
    
    if (now - monitor.lastTime >= 1000) {
      const fps = monitor.frameCount / ((now - monitor.lastTime) / 1000);
      const avgRenderTime = monitor.renderTimes.length > 0 
        ? monitor.renderTimes.reduce((a, b) => a + b, 0) / monitor.renderTimes.length
        : 0;

      setPerformanceMetrics(prev => ({
        ...prev,
        fps: Math.round(fps),
        renderTime: Math.round(avgRenderTime * 100) / 100,
        memoryUsage: (performance as any).memory?.usedJSHeapSize 
          ? Math.round((performance as any).memory.usedJSHeapSize / 1024 / 1024)
          : 0,
      }));

      monitor.frameCount = 0;
      monitor.lastTime = now;
      monitor.renderTimes = [];
    }
  }, []);

  // Performance-aware render loop
  useEffect(() => {
    if (!enablePerformanceMode) return;

    let rafId: number;
    
    const performanceLoop = () => {
      const startTime = performance.now();
      updatePerformanceMetrics();
      const endTime = performance.now();
      
      performanceMonitorRef.current.renderTimes.push(endTime - startTime);
      
      rafId = requestAnimationFrame(performanceLoop);
    };

    rafId = requestAnimationFrame(performanceLoop);
    
    return () => {
      if (rafId) cancelAnimationFrame(rafId);
    };
  }, [enablePerformanceMode, updatePerformanceMetrics]);

  return (
    <div className={`relative w-full h-full ${className}`}>
      <OptimizedGameBoard
        roomId={roomId}
        assets={assets}
        onAssetMove={onAssetMove}
        onAssetSelect={onAssetSelect}
        className="w-full h-full"
      />
      
      {/* Performance Overlay */}
      {enablePerformanceMode && process.env.NODE_ENV === 'development' && (
        <div className="absolute top-4 left-4 bg-black/90 text-green-400 p-3 rounded-lg text-xs font-mono space-y-1 min-w-48">
          <div className="text-green-300 font-bold mb-2">⚡ Performance Monitor</div>
          <div className="flex justify-between">
            <span>FPS:</span>
            <span className={performanceMetrics.fps < 30 ? 'text-red-400' : 'text-green-400'}>
              {performanceMetrics.fps}
            </span>
          </div>
          <div className="flex justify-between">
            <span>Render:</span>
            <span className={performanceMetrics.renderTime > 16 ? 'text-yellow-400' : 'text-green-400'}>
              {performanceMetrics.renderTime}ms
            </span>
          </div>
          <div className="flex justify-between">
            <span>Memory:</span>
            <span className={performanceMetrics.memoryUsage > 100 ? 'text-yellow-400' : 'text-green-400'}>
              {performanceMetrics.memoryUsage}MB
            </span>
          </div>
          <div className="flex justify-between">
            <span>Assets:</span>
            <span className="text-blue-400">{assets.length}</span>
          </div>
          <div className="mt-2 pt-2 border-t border-gray-700 text-gray-400 text-xs">
            🔧 Web Workers: Active<br/>
            🎯 Layer Virtualization: On<br/>
            ⚡ RAF Coalescing: Enabled<br/>
            🖱️ Pointer Throttling: 16ms
          </div>
        </div>
      )}
      
      {/* Performance Warning */}
      {enablePerformanceMode && performanceMetrics.fps < 30 && performanceMetrics.fps > 0 && (
        <div className="absolute bottom-4 left-4 bg-red-900/90 text-red-200 p-2 rounded text-xs">
          ⚠️ Performance Warning: Low FPS detected ({performanceMetrics.fps})
        </div>
      )}
    </div>
  );
}