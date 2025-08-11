/**
 * Hook for managing Canvas Web Worker operations
 * Provides high-level interface for offloading canvas calculations
 */

import { useRef, useCallback, useEffect } from 'react';
import type { AssetTransform, ViewportBounds, WorkerMessage, WorkerResponse } from '../workers/canvasWorker';

interface UseCanvasWorkerReturn {
  batchTransform: (assets: AssetTransform[]) => Promise<any>;
  cullVisible: (assets: AssetTransform[], viewport: ViewportBounds) => Promise<string[]>;
  detectCollisions: (draggedAsset: AssetTransform, otherAssets: AssetTransform[]) => Promise<string[]>;
  sortLayers: (assets: AssetTransform[]) => Promise<AssetTransform[]>;
  isWorkerReady: boolean;
}

export function useCanvasWorker(): UseCanvasWorkerReturn {
  const workerRef = useRef<Worker | null>(null);
  const pendingRequests = useRef<Map<string, { resolve: (value: any) => void; reject: (error: any) => void }>>(new Map());
  const isWorkerReadyRef = useRef(false);

  // Initialize worker
  useEffect(() => {
    try {
      workerRef.current = new Worker(
        new URL('../workers/canvasWorker.ts', import.meta.url),
        { type: 'module' },
      );

      workerRef.current.onmessage = (event: MessageEvent<WorkerResponse>) => {
        const { type, payload, id } = event.data;
        const request = pendingRequests.current.get(id);

        if (request) {
          pendingRequests.current.delete(id);

          if (type === 'ERROR') {
            request.reject(new Error(payload.error));
          } else {
            request.resolve(payload);
          }
        }
      };

      workerRef.current.onerror = (error) => {
        console.error('Canvas Worker Error:', error);
        isWorkerReadyRef.current = false;
      };

      isWorkerReadyRef.current = true;

    } catch (error) {
      console.warn('Canvas Worker not supported, falling back to main thread');
      isWorkerReadyRef.current = false;
    }

    return () => {
      if (workerRef.current) {
        workerRef.current.terminate();
        workerRef.current = null;
      }
      pendingRequests.current.clear();
      isWorkerReadyRef.current = false;
    };
  }, []);

  // Generic worker message sender
  const sendWorkerMessage = useCallback(<T>(type: string, payload: any): Promise<T> => {
    return new Promise((resolve, reject) => {
      if (!workerRef.current || !isWorkerReadyRef.current) {
        reject(new Error('Worker not available'));
        return;
      }

      const id = `${type}-${Date.now()}-${Math.random()}`;

      pendingRequests.current.set(id, { resolve, reject });

      const message: WorkerMessage = {
        type: type as any,
        payload,
        id,
      };

      workerRef.current.postMessage(message);
    });
  }, []);

  // Batch transform assets
  const batchTransform = useCallback(async (assets: AssetTransform[]) => {
    if (!isWorkerReadyRef.current) {
      // Fallback to main thread
      return assets.map(asset => ({
        id: asset.id,
        matrix: {
          a: Math.cos(asset.rotation) * asset.scale,
          b: Math.sin(asset.rotation) * asset.scale,
          c: -Math.sin(asset.rotation) * asset.scale,
          d: Math.cos(asset.rotation) * asset.scale,
          e: asset.x,
          f: asset.y,
        },
        bounds: {
          left: asset.x - (asset.width * asset.scale) / 2,
          top: asset.y - (asset.height * asset.scale) / 2,
          right: asset.x + (asset.width * asset.scale) / 2,
          bottom: asset.y + (asset.height * asset.scale) / 2,
        },
      }));
    }

    return sendWorkerMessage('BATCH_TRANSFORM', { assets });
  }, [sendWorkerMessage]);

  // Cull visible assets
  const cullVisible = useCallback(async (assets: AssetTransform[], viewport: ViewportBounds): Promise<string[]> => {
    if (!isWorkerReadyRef.current) {
      // Simple fallback culling
      return assets.filter(asset => {
        const buffer = 100;
        const assetBounds = {
          left: asset.x - (asset.width * asset.scale) / 2,
          top: asset.y - (asset.height * asset.scale) / 2,
          right: asset.x + (asset.width * asset.scale) / 2,
          bottom: asset.y + (asset.height * asset.scale) / 2,
        };

        const viewportBounds = {
          left: viewport.x - buffer,
          top: viewport.y - buffer,
          right: viewport.x + viewport.width / viewport.scale + buffer,
          bottom: viewport.y + viewport.height / viewport.scale + buffer,
        };

        return (
          assetBounds.right >= viewportBounds.left &&
          assetBounds.left <= viewportBounds.right &&
          assetBounds.bottom >= viewportBounds.top &&
          assetBounds.top <= viewportBounds.bottom
        );
      }).map(asset => asset.id);
    }

    return sendWorkerMessage('VISIBILITY_CULL', { assets, viewport });
  }, [sendWorkerMessage]);

  // Detect collisions
  const detectCollisions = useCallback(async (
    draggedAsset: AssetTransform,
    otherAssets: AssetTransform[],
  ): Promise<string[]> => {
    if (!isWorkerReadyRef.current) {
      // Simple fallback collision detection
      const draggedBounds = {
        left: draggedAsset.x - (draggedAsset.width * draggedAsset.scale) / 2,
        top: draggedAsset.y - (draggedAsset.height * draggedAsset.scale) / 2,
        right: draggedAsset.x + (draggedAsset.width * draggedAsset.scale) / 2,
        bottom: draggedAsset.y + (draggedAsset.height * draggedAsset.scale) / 2,
      };

      return otherAssets.filter(asset => {
        if (asset.id === draggedAsset.id) return false;

        const assetBounds = {
          left: asset.x - (asset.width * asset.scale) / 2,
          top: asset.y - (asset.height * asset.scale) / 2,
          right: asset.x + (asset.width * asset.scale) / 2,
          bottom: asset.y + (asset.height * asset.scale) / 2,
        };

        return (
          draggedBounds.right >= assetBounds.left &&
          draggedBounds.left <= assetBounds.right &&
          draggedBounds.bottom >= assetBounds.top &&
          draggedBounds.top <= assetBounds.bottom
        );
      }).map(asset => asset.id);
    }

    return sendWorkerMessage('COLLISION_DETECT', { draggedAsset, otherAssets });
  }, [sendWorkerMessage]);

  // Sort layers
  const sortLayers = useCallback(async (assets: AssetTransform[]): Promise<AssetTransform[]> => {
    if (!isWorkerReadyRef.current) {
      return [...assets].sort((a, b) => a.zIndex - b.zIndex);
    }

    return sendWorkerMessage('SORT_LAYERS', { assets });
  }, [sendWorkerMessage]);

  return {
    batchTransform,
    cullVisible,
    detectCollisions,
    sortLayers,
    isWorkerReady: isWorkerReadyRef.current,
  };
}
