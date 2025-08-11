/**
 * Optimized GameBoard component with canvas performance improvements
 * Features: virtualized layers, batched DOM updates, Web Worker integration,
 * throttled pointer events, and RAF-coalesced drag operations
 */

import { useRef, useCallback, useEffect, useState } from 'react';
import { useVirtualizedCanvas } from '../hooks/useVirtualizedCanvas';
import { useThrottledPointer } from '../hooks/useThrottledPointer';
import { useCanvasWorker } from '../hooks/useCanvasWorker';
import type { AssetTransform, ViewportBounds } from '../workers/canvasWorker';
import type { PointerEventData, DragState } from '../hooks/useThrottledPointer';

interface OptimizedGameBoardProps {
  roomId: string;
  assets: any[];
  onAssetMove?: (assetId: string, x: number, y: number, rotation?: number) => void;
  onAssetSelect?: (assetId: string) => void;
  className?: string;
}

export function OptimizedGameBoard({
  roomId,
  assets,
  onAssetMove,
  onAssetSelect,
  className = '',
}: OptimizedGameBoardProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const contextRef = useRef<CanvasRenderingContext2D | null>(null);

  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);
  const [draggedAsset, setDraggedAsset] = useState<AssetTransform | null>(null);

  const { detectCollisions } = useCanvasWorker();

  // Initialize virtualized canvas system
  const {
    layers,
    viewport,
    updateLayer,
    addAssetsToLayer,
    updateViewport,
    getRenderQueue,
    clearRenderQueue,
    performanceStats,
  } = useVirtualizedCanvas({
    maxVisibleLayers: 5,
    batchSize: 100,
    renderThrottleMs: 16,
    enableVirtualization: true,
    enableBatching: true,
  });

  // Convert assets to transforms
  const assetTransforms: AssetTransform[] = assets.map(asset => ({
    id: asset.id,
    x: asset.positionX || 0,
    y: asset.positionY || 0,
    rotation: asset.rotation || 0,
    scale: asset.scale || 1,
    width: asset.width || 100,
    height: asset.height || 100,
    zIndex: asset.zIndex || 0,
  }));

  // Handle asset dragging with collision detection
  const handleDragMove = useCallback(async (event: PointerEventData, dragState: DragState) => {
    if (!draggedAsset || !dragState.isDragging) return;

    const newAsset: AssetTransform = {
      ...draggedAsset,
      x: draggedAsset.x + dragState.deltaX,
      y: draggedAsset.y + dragState.deltaY,
    };

    // Detect collisions in worker
    try {
      const collisions = await detectCollisions(newAsset, assetTransforms);

      // Highlight colliding assets or handle collision response
      if (collisions.length > 0) {
        console.log('Collisions detected with:', collisions);
      }

      setDraggedAsset(newAsset);

      // Update layer with optimistic transform
      updateLayer('board', {
        assets: assetTransforms.map(asset =>
          asset.id === draggedAsset.id ? newAsset : asset,
        ),
      });

    } catch (error) {
      console.warn('Collision detection failed:', error);
      setDraggedAsset(newAsset);
    }
  }, [draggedAsset, assetTransforms, detectCollisions, updateLayer]);

  // Handle drag end
  const handleDragEnd = useCallback((event: PointerEventData, dragState: DragState) => {
    if (!draggedAsset) return;

    const finalAsset: AssetTransform = {
      ...draggedAsset,
      x: draggedAsset.x + dragState.deltaX,
      y: draggedAsset.y + dragState.deltaY,
    };

    // Call parent handler
    onAssetMove?.(finalAsset.id, finalAsset.x, finalAsset.y, finalAsset.rotation);

    setDraggedAsset(null);
  }, [draggedAsset, onAssetMove]);

  // Handle asset selection
  const handlePointerDown = useCallback((event: PointerEventData) => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const x = (event.clientX - rect.left) / viewport.scale + viewport.x;
    const y = (event.clientY - rect.top) / viewport.scale + viewport.y;

    // Find clicked asset (reverse order for top-most)
    const clickedAsset = [...assetTransforms]
      .reverse()
      .find(asset => {
        const bounds = {
          left: asset.x - (asset.width * asset.scale) / 2,
          top: asset.y - (asset.height * asset.scale) / 2,
          right: asset.x + (asset.width * asset.scale) / 2,
          bottom: asset.y + (asset.height * asset.scale) / 2,
        };

        return x >= bounds.left && x <= bounds.right &&
               y >= bounds.top && y <= bounds.bottom;
      });

    if (clickedAsset) {
      setSelectedAssetId(clickedAsset.id);
      setDraggedAsset(clickedAsset);
      onAssetSelect?.(clickedAsset.id);
    } else {
      setSelectedAssetId(null);
      setDraggedAsset(null);
    }
  }, [assetTransforms, viewport, onAssetSelect]);

  // Set up optimized pointer events
  const { dragState, bindPointerEvents } = useThrottledPointer({
    onPointerDown: handlePointerDown,
    onDragMove: handleDragMove,
    onDragEnd: handleDragEnd,
    throttleMs: 16,
    dragThreshold: 5,
    enableRafCoalescing: true,
  });

  // Canvas rendering using batched updates
  const renderCanvas = useCallback(() => {
    const canvas = canvasRef.current;
    const ctx = contextRef.current;
    if (!canvas || !ctx) return;

    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Apply viewport transform
    ctx.save();
    ctx.scale(viewport.scale, viewport.scale);
    ctx.translate(-viewport.x, -viewport.y);

    // Process render queue
    const renderQueue = getRenderQueue();

    renderQueue.forEach((batch) => {
      batch.assets.forEach((asset, index) => {
        const transform = batch.transforms[index];
        if (!transform) return;

        ctx.save();

        // Apply transform matrix
        ctx.setTransform(
          transform.matrix.a,
          transform.matrix.b,
          transform.matrix.c,
          transform.matrix.d,
          transform.matrix.e,
          transform.matrix.f,
        );

        // Render asset (simplified - would normally load and draw images)
        ctx.fillStyle = asset.id === selectedAssetId ? '#3B82F6' : '#6B7280';
        ctx.fillRect(
          -asset.width / 2,
          -asset.height / 2,
          asset.width,
          asset.height,
        );

        // Add selection outline
        if (asset.id === selectedAssetId) {
          ctx.strokeStyle = '#1D4ED8';
          ctx.lineWidth = 2;
          ctx.strokeRect(
            -asset.width / 2 - 2,
            -asset.height / 2 - 2,
            asset.width + 4,
            asset.height + 4,
          );
        }

        ctx.restore();
      });
    });

    ctx.restore();

    // Clear render queue after processing
    clearRenderQueue();
  }, [viewport, getRenderQueue, clearRenderQueue, selectedAssetId]);

  // Initialize canvas context
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    contextRef.current = canvas.getContext('2d');

    // Set up canvas size
    const resizeCanvas = () => {
      const container = containerRef.current;
      if (!container) return;

      const rect = container.getBoundingClientRect();
      canvas.width = rect.width * devicePixelRatio;
      canvas.height = rect.height * devicePixelRatio;
      canvas.style.width = `${rect.width}px`;
      canvas.style.height = `${rect.height}px`;

      if (contextRef.current) {
        contextRef.current.scale(devicePixelRatio, devicePixelRatio);
      }

      updateViewport({
        ...viewport,
        width: rect.width,
        height: rect.height,
      });
    };

    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    return () => {
      window.removeEventListener('resize', resizeCanvas);
    };
  }, [viewport, updateViewport]);

  // Set up main board layer
  useEffect(() => {
    updateLayer('board', {
      id: 'board',
      name: 'Game Board',
      zIndex: 0,
      visible: true,
      opacity: 1,
      assets: assetTransforms,
    });
  }, [assetTransforms, updateLayer]);

  // Render loop
  useEffect(() => {
    const animate = () => {
      renderCanvas();
      requestAnimationFrame(animate);
    };

    const rafId = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(rafId);
  }, [renderCanvas]);

  return (
    <div
      ref={containerRef}
      className={`relative w-full h-full overflow-hidden ${className}`}
      data-testid="optimized-game-board"
    >
      <canvas
        ref={canvasRef}
        className="absolute inset-0 touch-none"
        {...bindPointerEvents()}
        data-testid="game-canvas"
      />

      {/* Performance Stats (dev mode) */}
      {process.env.NODE_ENV === 'development' && (
        <div className="absolute top-2 right-2 bg-black/80 text-white p-2 rounded text-xs font-mono">
          <div>Visible: {performanceStats.visibleAssetsCount}/{performanceStats.totalAssetsCount}</div>
          <div>Batches: {performanceStats.renderBatchCount}</div>
          <div>Render: {performanceStats.lastRenderTime.toFixed(1)}ms</div>
          <div>Dragging: {dragState.isDragging ? 'Yes' : 'No'}</div>
        </div>
      )}

      {/* Layer Controls (dev mode) */}
      {process.env.NODE_ENV === 'development' && (
        <div className="absolute bottom-2 left-2 bg-black/80 text-white p-2 rounded text-xs">
          <div>Layers: {layers.length}</div>
          <div>Viewport: {viewport.scale.toFixed(2)}x</div>
          <div>Position: ({viewport.x.toFixed(0)}, {viewport.y.toFixed(0)})</div>
        </div>
      )}
    </div>
  );
}
