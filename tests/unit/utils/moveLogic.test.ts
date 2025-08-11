/**
 * Unit tests for asset movement and collision logic
 */

import { describe, it, expect } from 'vitest';

// Mock move logic functions (these would be in a real utils file)
interface Position {
  x: number;
  y: number;
}

interface Asset {
  id: string;
  positionX: number;
  positionY: number;
  width: number;
  height: number;
  rotation?: number;
}

interface Bounds {
  left: number;
  top: number;
  right: number;
  bottom: number;
}

// Asset movement utilities
export function calculateNewPosition(
  currentPos: Position,
  delta: Position,
  bounds?: Bounds
): Position {
  let newX = currentPos.x + delta.x;
  let newY = currentPos.y + delta.y;

  if (bounds) {
    newX = Math.max(bounds.left, Math.min(bounds.right, newX));
    newY = Math.max(bounds.top, Math.min(bounds.bottom, newY));
  }

  return { x: newX, y: newY };
}

export function checkCollision(asset1: Asset, asset2: Asset): boolean {
  const a1Left = asset1.positionX;
  const a1Right = asset1.positionX + asset1.width;
  const a1Top = asset1.positionY;
  const a1Bottom = asset1.positionY + asset1.height;

  const a2Left = asset2.positionX;
  const a2Right = asset2.positionX + asset2.width;
  const a2Top = asset2.positionY;
  const a2Bottom = asset2.positionY + asset2.height;

  return !(
    a1Right <= a2Left ||
    a1Left >= a2Right ||
    a1Bottom <= a2Top ||
    a1Top >= a2Bottom
  );
}

export function snapToGrid(position: Position, gridSize: number): Position {
  return {
    x: Math.round(position.x / gridSize) * gridSize,
    y: Math.round(position.y / gridSize) * gridSize,
  };
}

export function rotatePoint(
  point: Position,
  center: Position,
  angleDegrees: number
): Position {
  const angleRadians = (angleDegrees * Math.PI) / 180;
  const cos = Math.cos(angleRadians);
  const sin = Math.sin(angleRadians);

  const dx = point.x - center.x;
  const dy = point.y - center.y;

  return {
    x: center.x + dx * cos - dy * sin,
    y: center.y + dx * sin + dy * cos,
  };
}

export function calculateDistance(pos1: Position, pos2: Position): number {
  const dx = pos2.x - pos1.x;
  const dy = pos2.y - pos1.y;
  return Math.sqrt(dx * dx + dy * dy);
}

export function findNearestAsset(
  targetPos: Position,
  assets: Asset[],
  maxDistance: number = Infinity
): Asset | null {
  let nearest: Asset | null = null;
  let minDistance = maxDistance;

  for (const asset of assets) {
    const assetCenter = {
      x: asset.positionX + asset.width / 2,
      y: asset.positionY + asset.height / 2,
    };
    
    const distance = calculateDistance(targetPos, assetCenter);
    
    if (distance < minDistance) {
      minDistance = distance;
      nearest = asset;
    }
  }

  return nearest;
}

export function isWithinBounds(asset: Asset, bounds: Bounds): boolean {
  return (
    asset.positionX >= bounds.left &&
    asset.positionY >= bounds.top &&
    asset.positionX + asset.width <= bounds.right &&
    asset.positionY + asset.height <= bounds.bottom
  );
}

describe('Move Logic', () => {
  describe('Position Calculation', () => {
    it('should calculate new position with delta', () => {
      const currentPos = { x: 100, y: 200 };
      const delta = { x: 50, y: -30 };

      const newPos = calculateNewPosition(currentPos, delta);

      expect(newPos).toEqual({ x: 150, y: 170 });
    });

    it('should respect bounds when moving', () => {
      const currentPos = { x: 90, y: 90 };
      const delta = { x: 50, y: 50 };
      const bounds = { left: 0, top: 0, right: 100, bottom: 100 };

      const newPos = calculateNewPosition(currentPos, delta, bounds);

      expect(newPos).toEqual({ x: 100, y: 100 });
    });

    it('should handle negative bounds', () => {
      const currentPos = { x: 0, y: 0 };
      const delta = { x: -50, y: -50 };
      const bounds = { left: -100, top: -100, right: 100, bottom: 100 };

      const newPos = calculateNewPosition(currentPos, delta, bounds);

      expect(newPos).toEqual({ x: -50, y: -50 });
    });
  });

  describe('Collision Detection', () => {
    const asset1: Asset = {
      id: '1',
      positionX: 0,
      positionY: 0,
      width: 50,
      height: 50,
    };

    it('should detect collision when assets overlap', () => {
      const asset2: Asset = {
        id: '2',
        positionX: 25,
        positionY: 25,
        width: 50,
        height: 50,
      };

      expect(checkCollision(asset1, asset2)).toBe(true);
    });

    it('should not detect collision when assets are separate', () => {
      const asset2: Asset = {
        id: '2',
        positionX: 100,
        positionY: 100,
        width: 50,
        height: 50,
      };

      expect(checkCollision(asset1, asset2)).toBe(false);
    });

    it('should detect collision when assets are touching', () => {
      const asset2: Asset = {
        id: '2',
        positionX: 50,
        positionY: 0,
        width: 50,
        height: 50,
      };

      expect(checkCollision(asset1, asset2)).toBe(false); // Touching but not overlapping
    });

    it('should handle zero-size assets', () => {
      const zeroAsset: Asset = {
        id: 'zero',
        positionX: 25,
        positionY: 25,
        width: 0,
        height: 0,
      };

      expect(checkCollision(asset1, zeroAsset)).toBe(false);
    });
  });

  describe('Grid Snapping', () => {
    it('should snap to grid correctly', () => {
      const position = { x: 123, y: 87 };
      const gridSize = 50;

      const snapped = snapToGrid(position, gridSize);

      expect(snapped).toEqual({ x: 100, y: 100 });
    });

    it('should handle exact grid positions', () => {
      const position = { x: 100, y: 150 };
      const gridSize = 50;

      const snapped = snapToGrid(position, gridSize);

      expect(snapped).toEqual({ x: 100, y: 150 });
    });

    it('should handle negative positions', () => {
      const position = { x: -23, y: -67 };
      const gridSize = 25;

      const snapped = snapToGrid(position, gridSize);

      expect(snapped).toEqual({ x: -25, y: -75 });
    });

    it('should handle small grid sizes', () => {
      const position = { x: 12.7, y: 8.3 };
      const gridSize = 5;

      const snapped = snapToGrid(position, gridSize);

      expect(snapped).toEqual({ x: 15, y: 10 });
    });
  });

  describe('Point Rotation', () => {
    it('should rotate point 90 degrees', () => {
      const point = { x: 10, y: 0 };
      const center = { x: 0, y: 0 };

      const rotated = rotatePoint(point, center, 90);

      expect(rotated.x).toBeCloseTo(0, 5);
      expect(rotated.y).toBeCloseTo(10, 5);
    });

    it('should rotate point 180 degrees', () => {
      const point = { x: 5, y: 5 };
      const center = { x: 0, y: 0 };

      const rotated = rotatePoint(point, center, 180);

      expect(rotated.x).toBeCloseTo(-5, 5);
      expect(rotated.y).toBeCloseTo(-5, 5);
    });

    it('should handle rotation around non-origin center', () => {
      const point = { x: 10, y: 10 };
      const center = { x: 5, y: 5 };

      const rotated = rotatePoint(point, center, 90);

      expect(rotated.x).toBeCloseTo(0, 5);
      expect(rotated.y).toBeCloseTo(10, 5);
    });

    it('should handle negative angles', () => {
      const point = { x: 10, y: 0 };
      const center = { x: 0, y: 0 };

      const rotated = rotatePoint(point, center, -90);

      expect(rotated.x).toBeCloseTo(0, 5);
      expect(rotated.y).toBeCloseTo(-10, 5);
    });
  });

  describe('Distance Calculation', () => {
    it('should calculate distance correctly', () => {
      const pos1 = { x: 0, y: 0 };
      const pos2 = { x: 3, y: 4 };

      const distance = calculateDistance(pos1, pos2);

      expect(distance).toBe(5); // 3-4-5 triangle
    });

    it('should handle same position', () => {
      const pos = { x: 10, y: 20 };

      const distance = calculateDistance(pos, pos);

      expect(distance).toBe(0);
    });

    it('should handle negative coordinates', () => {
      const pos1 = { x: -3, y: -4 };
      const pos2 = { x: 3, y: 4 };

      const distance = calculateDistance(pos1, pos2);

      expect(distance).toBe(10);
    });
  });

  describe('Nearest Asset Finding', () => {
    const assets: Asset[] = [
      { id: '1', positionX: 0, positionY: 0, width: 10, height: 10 },
      { id: '2', positionX: 50, positionY: 0, width: 10, height: 10 },
      { id: '3', positionX: 0, positionY: 50, width: 10, height: 10 },
    ];

    it('should find nearest asset', () => {
      const targetPos = { x: 10, y: 10 };

      const nearest = findNearestAsset(targetPos, assets);

      expect(nearest?.id).toBe('1');
    });

    it('should respect max distance', () => {
      const targetPos = { x: 100, y: 100 };
      const maxDistance = 50;

      const nearest = findNearestAsset(targetPos, assets, maxDistance);

      expect(nearest).toBeNull();
    });

    it('should handle empty asset list', () => {
      const targetPos = { x: 0, y: 0 };

      const nearest = findNearestAsset(targetPos, []);

      expect(nearest).toBeNull();
    });
  });

  describe('Bounds Checking', () => {
    const bounds = { left: 0, top: 0, right: 100, bottom: 100 };

    it('should detect asset within bounds', () => {
      const asset: Asset = {
        id: '1',
        positionX: 25,
        positionY: 25,
        width: 50,
        height: 50,
      };

      expect(isWithinBounds(asset, bounds)).toBe(true);
    });

    it('should detect asset outside bounds', () => {
      const asset: Asset = {
        id: '1',
        positionX: 150,
        positionY: 25,
        width: 50,
        height: 50,
      };

      expect(isWithinBounds(asset, bounds)).toBe(false);
    });

    it('should detect asset partially outside bounds', () => {
      const asset: Asset = {
        id: '1',
        positionX: 90,
        positionY: 25,
        width: 50, // Extends beyond right bound
        height: 50,
      };

      expect(isWithinBounds(asset, bounds)).toBe(false);
    });

    it('should handle asset exactly at bounds', () => {
      const asset: Asset = {
        id: '1',
        positionX: 0,
        positionY: 0,
        width: 100,
        height: 100,
      };

      expect(isWithinBounds(asset, bounds)).toBe(true);
    });
  });
});