/**
 * Canvas Web Worker for offloading heavy rendering calculations
 * Handles batch processing of asset transformations, collision detection,
 * and complex mathematical operations away from the main thread
 */

export interface AssetTransform {
  id: string;
  x: number;
  y: number;
  rotation: number;
  scale: number;
  width: number;
  height: number;
  zIndex: number;
}

export interface ViewportBounds {
  x: number;
  y: number;
  width: number;
  height: number;
  scale: number;
}

export interface CollisionBounds {
  left: number;
  top: number;
  right: number;
  bottom: number;
}

export interface WorkerMessage {
  type: 'BATCH_TRANSFORM' | 'VISIBILITY_CULL' | 'COLLISION_DETECT' | 'SORT_LAYERS';
  payload: any;
  id: string;
}

export interface WorkerResponse {
  type: string;
  payload: any;
  id: string;
}

// Transform matrix calculations
function calculateTransformMatrix(transform: AssetTransform) {
  const cos = Math.cos(transform.rotation);
  const sin = Math.sin(transform.rotation);

  return {
    a: cos * transform.scale,
    b: sin * transform.scale,
    c: -sin * transform.scale,
    d: cos * transform.scale,
    e: transform.x,
    f: transform.y,
  };
}

// Viewport culling - only render visible assets
function cullVisibleAssets(assets: AssetTransform[], viewport: ViewportBounds): string[] {
  const visibleIds: string[] = [];
  const buffer = 100; // Extra buffer for partially visible assets

  for (const asset of assets) {
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

    // Check if asset bounds intersect with viewport
    if (
      assetBounds.right >= viewportBounds.left &&
      assetBounds.left <= viewportBounds.right &&
      assetBounds.bottom >= viewportBounds.top &&
      assetBounds.top <= viewportBounds.bottom
    ) {
      visibleIds.push(asset.id);
    }
  }

  return visibleIds;
}

// Collision detection for drag operations
function detectCollisions(
  draggedAsset: AssetTransform,
  otherAssets: AssetTransform[],
): string[] {
  const collisions: string[] = [];

  const draggedBounds = {
    left: draggedAsset.x - (draggedAsset.width * draggedAsset.scale) / 2,
    top: draggedAsset.y - (draggedAsset.height * draggedAsset.scale) / 2,
    right: draggedAsset.x + (draggedAsset.width * draggedAsset.scale) / 2,
    bottom: draggedAsset.y + (draggedAsset.height * draggedAsset.scale) / 2,
  };

  for (const asset of otherAssets) {
    if (asset.id === draggedAsset.id) continue;

    const assetBounds = {
      left: asset.x - (asset.width * asset.scale) / 2,
      top: asset.y - (asset.height * asset.scale) / 2,
      right: asset.x + (asset.width * asset.scale) / 2,
      bottom: asset.y + (asset.height * asset.scale) / 2,
    };

    if (
      draggedBounds.right >= assetBounds.left &&
      draggedBounds.left <= assetBounds.right &&
      draggedBounds.bottom >= assetBounds.top &&
      draggedBounds.top <= assetBounds.bottom
    ) {
      collisions.push(asset.id);
    }
  }

  return collisions;
}

// Z-index sorting for layer management
function sortAssetsByZIndex(assets: AssetTransform[]): AssetTransform[] {
  return [...assets].sort((a, b) => a.zIndex - b.zIndex);
}

// Batch process multiple transforms
function batchProcessTransforms(assets: AssetTransform[]) {
  return assets.map(asset => ({
    id: asset.id,
    matrix: calculateTransformMatrix(asset),
    bounds: {
      left: asset.x - (asset.width * asset.scale) / 2,
      top: asset.y - (asset.height * asset.scale) / 2,
      right: asset.x + (asset.width * asset.scale) / 2,
      bottom: asset.y + (asset.height * asset.scale) / 2,
    },
  }));
}

// Main worker message handler
self.addEventListener('message', (event: MessageEvent<WorkerMessage>) => {
  const { type, payload, id } = event.data;

  let result: any;

  try {
    switch (type) {
      case 'BATCH_TRANSFORM':
        result = batchProcessTransforms(payload.assets);
        break;

      case 'VISIBILITY_CULL':
        result = cullVisibleAssets(payload.assets, payload.viewport);
        break;

      case 'COLLISION_DETECT':
        result = detectCollisions(payload.draggedAsset, payload.otherAssets);
        break;

      case 'SORT_LAYERS':
        result = sortAssetsByZIndex(payload.assets);
        break;

      default:
        throw new Error(`Unknown worker message type: ${type}`);
    }

    const response: WorkerResponse = {
      type,
      payload: result,
      id,
    };

    self.postMessage(response);
  } catch (error) {
    const errorResponse: WorkerResponse = {
      type: 'ERROR',
      payload: { error: error.message },
      id,
    };

    self.postMessage(errorResponse);
  }
});

export default null; // This is a worker file
