/**
 * Virtualized canvas rendering system
 * Manages layer virtualization, batched DOM updates, and performance optimization
 */

import { useRef, useCallback, useEffect, useState, useMemo } from 'react';
import { useCanvasWorker } from './useCanvasWorker';
import type { AssetTransform, ViewportBounds } from '../workers/canvasWorker';

export interface CanvasLayer {
  id: string;
  name: string;
  zIndex: number;
  visible: boolean;
  opacity: number;
  assets: AssetTransform[];
}

export interface RenderBatch {
  layerId: string;
  assets: AssetTransform[];
  transforms: any[];
  timestamp: number;
}

interface UseVirtualizedCanvasOptions {
  maxVisibleLayers?: number;
  batchSize?: number;
  renderThrottleMs?: number;
  enableVirtualization?: boolean;
  enableBatching?: boolean;
}

interface UseVirtualizedCanvasReturn {
  layers: CanvasLayer[];
  visibleAssets: string[];
  viewport: ViewportBounds;
  updateLayer: (layerId: string, updates: Partial<CanvasLayer>) => void;
  addAssetsToLayer: (layerId: string, assets: AssetTransform[]) => void;
  removeAssetsFromLayer: (layerId: string, assetIds: string[]) => void;
  updateViewport: (viewport: ViewportBounds) => void;
  getRenderQueue: () => RenderBatch[];
  clearRenderQueue: () => void;
  performanceStats: {
    visibleAssetsCount: number;
    totalAssetsCount: number;
    renderBatchCount: number;
    lastRenderTime: number;
  };
}

export function useVirtualizedCanvas(options: UseVirtualizedCanvasOptions = {}): UseVirtualizedCanvasReturn {
  const {
    maxVisibleLayers = 10,
    batchSize = 50,
    renderThrottleMs = 16,
    enableVirtualization = true,
    enableBatching = true,
  } = options;

  const [layers, setLayers] = useState<CanvasLayer[]>([]);
  const [viewport, setViewport] = useState<ViewportBounds>({
    x: 0,
    y: 0,
    width: 1920,
    height: 1080,
    scale: 1,
  });

  const { cullVisible, batchTransform, sortLayers, isWorkerReady } = useCanvasWorker();

  const renderQueueRef = useRef<RenderBatch[]>([]);
  const lastRenderTimeRef = useRef<number>(0);
  const pendingUpdatesRef = useRef<Set<string>>(new Set());
  const rafIdRef = useRef<number | null>(null);

  // Performance stats
  const [performanceStats, setPerformanceStats] = useState({
    visibleAssetsCount: 0,
    totalAssetsCount: 0,
    renderBatchCount: 0,
    lastRenderTime: 0,
  });

  // Calculate visible assets using worker
  const visibleAssets = useMemo(() => {
    if (!enableVirtualization) {
      return layers.flatMap(layer => layer.assets.map(asset => asset.id));
    }

    // This will be updated asynchronously by the worker
    return [];
  }, [layers, viewport, enableVirtualization]);

  // Update visible assets asynchronously
  const updateVisibleAssets = useCallback(async () => {
    if (!enableVirtualization) return;

    try {
      const allAssets = layers.flatMap(layer =>
        layer.visible ? layer.assets : [],
      );

      const visibleIds = await cullVisible(allAssets, viewport);

      setPerformanceStats(prev => ({
        ...prev,
        visibleAssetsCount: visibleIds.length,
        totalAssetsCount: allAssets.length,
      }));

    } catch (error) {
      console.warn('Failed to update visible assets:', error);
    }
  }, [layers, viewport, cullVisible, enableVirtualization]);

  // Batch DOM updates using RAF
  const batchRenderUpdates = useCallback(() => {
    if (pendingUpdatesRef.current.size === 0) return;

    const now = performance.now();
    if (now - lastRenderTimeRef.current < renderThrottleMs) {
      // Reschedule for next frame
      rafIdRef.current = requestAnimationFrame(batchRenderUpdates);
      return;
    }

    const layersToUpdate = Array.from(pendingUpdatesRef.current);
    pendingUpdatesRef.current.clear();

    // Process each layer that needs updates
    layersToUpdate.forEach(async (layerId) => {
      const layer = layers.find(l => l.id === layerId);
      if (!layer?.visible) return;

      try {
        // Get transforms for layer assets
        const transforms = await batchTransform(layer.assets);

        // Create render batch
        const batch: RenderBatch = {
          layerId,
          assets: layer.assets,
          transforms,
          timestamp: now,
        };

        renderQueueRef.current.push(batch);

        // Limit render queue size
        if (renderQueueRef.current.length > maxVisibleLayers) {
          renderQueueRef.current = renderQueueRef.current.slice(-maxVisibleLayers);
        }

      } catch (error) {
        console.warn(`Failed to process layer ${layerId}:`, error);
      }
    });

    lastRenderTimeRef.current = now;
    setPerformanceStats(prev => ({
      ...prev,
      renderBatchCount: renderQueueRef.current.length,
      lastRenderTime: now,
    }));

    rafIdRef.current = null;
  }, [layers, batchTransform, renderThrottleMs, maxVisibleLayers]);

  // Schedule layer update
  const scheduleLayerUpdate = useCallback((layerId: string) => {
    pendingUpdatesRef.current.add(layerId);

    if (rafIdRef.current === null) {
      rafIdRef.current = requestAnimationFrame(batchRenderUpdates);
    }
  }, [batchRenderUpdates]);

  // Update layer
  const updateLayer = useCallback((layerId: string, updates: Partial<CanvasLayer>) => {
    setLayers(prev => prev.map(layer =>
      layer.id === layerId
        ? { ...layer, ...updates }
        : layer,
    ));

    if (enableBatching) {
      scheduleLayerUpdate(layerId);
    }
  }, [enableBatching, scheduleLayerUpdate]);

  // Add assets to layer
  const addAssetsToLayer = useCallback((layerId: string, assets: AssetTransform[]) => {
    setLayers(prev => prev.map(layer =>
      layer.id === layerId
        ? { ...layer, assets: [...layer.assets, ...assets] }
        : layer,
    ));

    if (enableBatching) {
      scheduleLayerUpdate(layerId);
    }
  }, [enableBatching, scheduleLayerUpdate]);

  // Remove assets from layer
  const removeAssetsFromLayer = useCallback((layerId: string, assetIds: string[]) => {
    const assetIdSet = new Set(assetIds);

    setLayers(prev => prev.map(layer =>
      layer.id === layerId
        ? { ...layer, assets: layer.assets.filter(asset => !assetIdSet.has(asset.id)) }
        : layer,
    ));

    if (enableBatching) {
      scheduleLayerUpdate(layerId);
    }
  }, [enableBatching, scheduleLayerUpdate]);

  // Update viewport
  const updateViewport = useCallback((newViewport: ViewportBounds) => {
    setViewport(newViewport);

    // Trigger visibility recalculation
    updateVisibleAssets();
  }, [updateVisibleAssets]);

  // Get render queue
  const getRenderQueue = useCallback((): RenderBatch[] => {
    return [...renderQueueRef.current];
  }, []);

  // Clear render queue
  const clearRenderQueue = useCallback(() => {
    renderQueueRef.current = [];
  }, []);

  // Auto-update visible assets when viewport or layers change
  useEffect(() => {
    updateVisibleAssets();
  }, [updateVisibleAssets]);

  // Sort layers by z-index
  useEffect(() => {
    if (isWorkerReady) {
      const allAssets = layers.flatMap(layer => layer.assets);
      sortLayers(allAssets).then((sortedAssets) => {
        // Update layer order based on sorted assets
        const layerOrder = new Map<string, number>();
        sortedAssets.forEach((asset, index) => {
          const layer = layers.find(l => l.assets.some(a => a.id === asset.id));
          if (layer && !layerOrder.has(layer.id)) {
            layerOrder.set(layer.id, index);
          }
        });

        setLayers(prev => [...prev].sort((a, b) =>
          (layerOrder.get(a.id) || 0) - (layerOrder.get(b.id) || 0),
        ));
      });
    }
  }, [layers, sortLayers, isWorkerReady]);

  // Cleanup
  useEffect(() => {
    return () => {
      if (rafIdRef.current !== null) {
        cancelAnimationFrame(rafIdRef.current);
      }
    };
  }, []);

  return {
    layers,
    visibleAssets,
    viewport,
    updateLayer,
    addAssetsToLayer,
    removeAssetsFromLayer,
    updateViewport,
    getRenderQueue,
    clearRenderQueue,
    performanceStats,
  };
}
