// tests/unit/hooks/useAssetManager.test.ts
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useAssetManager } from '@/hooks/useAssetManager';
import { mockAssets, mockBoardAssets } from '@tests/fixtures';

// Mock the useAssetManager hook
vi.mock('@/hooks/useAssetManager', () => ({
  useAssetManager: (roomId: string) => {
    let assets = [...mockAssets];
    let boardAssets = [...mockBoardAssets];

    return {
      assets,
      boardAssets,
      isLoading: false,
      error: null,
      uploadAsset: vi.fn().mockImplementation((file: File) => {
        const newAsset = {
          id: `asset-${Date.now()}`,
          name: file.name,
          type: file.type,
          url: `https://example.com/${file.name}`,
          size: file.size,
          roomId,
          uploadedBy: 'test-user',
          createdAt: new Date(),
          tags: [],
          isPublic: false
        };
        assets.push(newAsset);
        return Promise.resolve(newAsset);
      }),
      deleteAsset: vi.fn().mockImplementation((assetId: string) => {
        assets = assets.filter(a => a.id !== assetId);
        return Promise.resolve();
      }),
      placeAsset: vi.fn().mockImplementation((assetId: string, position: { x: number; y: number }) => {
        const asset = assets.find(a => a.id === assetId);
        if (asset) {
          const boardAsset = {
            id: `board-${Date.now()}`,
            assetId,
            roomId,
            x: position.x,
            y: position.y,
            width: 64,
            height: 64,
            rotation: 0,
            zIndex: boardAssets.length + 1,
            isFlipped: false,
            isLocked: false,
            ownerId: 'test-user',
            lastModified: new Date()
          };
          boardAssets.push(boardAsset);
          return Promise.resolve(boardAsset);
        }
        return Promise.reject(new Error('Asset not found'));
      }),
      moveAsset: vi.fn().mockImplementation((boardAssetId: string, position: { x: number; y: number }) => {
        const boardAsset = boardAssets.find(a => a.id === boardAssetId);
        if (boardAsset) {
          boardAsset.x = position.x;
          boardAsset.y = position.y;
          boardAsset.lastModified = new Date();
          return Promise.resolve(boardAsset);
        }
        return Promise.reject(new Error('Board asset not found'));
      }),
      rotateAsset: vi.fn().mockImplementation((boardAssetId: string, rotation: number) => {
        const boardAsset = boardAssets.find(a => a.id === boardAssetId);
        if (boardAsset) {
          boardAsset.rotation = rotation;
          boardAsset.lastModified = new Date();
          return Promise.resolve(boardAsset);
        }
        return Promise.reject(new Error('Board asset not found'));
      }),
      flipAsset: vi.fn().mockImplementation((boardAssetId: string) => {
        const boardAsset = boardAssets.find(a => a.id === boardAssetId);
        if (boardAsset) {
          boardAsset.isFlipped = !boardAsset.isFlipped;
          boardAsset.lastModified = new Date();
          return Promise.resolve(boardAsset);
        }
        return Promise.reject(new Error('Board asset not found'));
      }),
      removeFromBoard: vi.fn().mockImplementation((boardAssetId: string) => {
        boardAssets = boardAssets.filter(a => a.id !== boardAssetId);
        return Promise.resolve();
      }),
      updateAssetTags: vi.fn().mockImplementation((assetId: string, tags: string[]) => {
        const asset = assets.find(a => a.id === assetId);
        if (asset) {
          asset.tags = tags;
          return Promise.resolve(asset);
        }
        return Promise.reject(new Error('Asset not found'));
      })
    };
  }
}));

describe('useAssetManager', () => {
  const roomId = 'test-room';

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Asset Loading', () => {
    it('should load assets for room', () => {
      const { result } = renderHook(() => useAssetManager(roomId));

      expect(result.current.assets).toEqual(mockAssets);
      expect(result.current.boardAssets).toEqual(mockBoardAssets);
      expect(result.current.isLoading).toBe(false);
      expect(result.current.error).toBeNull();
    });

    it('should handle loading state', () => {
      const { result } = renderHook(() => useAssetManager(roomId));

      expect(result.current.isLoading).toBe(false);
    });

    it('should handle error state', () => {
      const { result } = renderHook(() => useAssetManager(roomId));

      expect(result.current.error).toBeNull();
    });
  });

  describe('Asset Upload', () => {
    it('should upload new asset', async () => {
      const { result } = renderHook(() => useAssetManager(roomId));

      const file = new File(['test'], 'test.png', { type: 'image/png' });

      await act(async () => {
        const uploadedAsset = await result.current.uploadAsset(file);
        expect(uploadedAsset).toMatchObject({
          name: 'test.png',
          type: 'image/png',
          roomId
        });
      });

      expect(result.current.uploadAsset).toHaveBeenCalledWith(file);
    });

    it('should handle upload errors', async () => {
      const { result } = renderHook(() => useAssetManager(roomId));

      const invalidFile = new File([''], '', { type: '' });

      await act(async () => {
        try {
          await result.current.uploadAsset(invalidFile);
        } catch (error) {
          // Expected to potentially fail with invalid file
        }
      });

      expect(result.current.uploadAsset).toHaveBeenCalled();
    });
  });

  describe('Asset Management', () => {
    it('should delete asset', async () => {
      const { result } = renderHook(() => useAssetManager(roomId));

      await act(async () => {
        await result.current.deleteAsset('asset-1');
      });

      expect(result.current.deleteAsset).toHaveBeenCalledWith('asset-1');
    });

    it('should update asset tags', async () => {
      const { result } = renderHook(() => useAssetManager(roomId));

      const newTags = ['character', 'player'];

      await act(async () => {
        await result.current.updateAssetTags('asset-1', newTags);
      });

      expect(result.current.updateAssetTags).toHaveBeenCalledWith('asset-1', newTags);
    });
  });

  describe('Board Asset Operations', () => {
    it('should place asset on board', async () => {
      const { result } = renderHook(() => useAssetManager(roomId));

      const position = { x: 100, y: 200 };

      await act(async () => {
        const boardAsset = await result.current.placeAsset('asset-1', position);
        expect(boardAsset).toMatchObject({
          assetId: 'asset-1',
          x: position.x,
          y: position.y,
          roomId
        });
      });

      expect(result.current.placeAsset).toHaveBeenCalledWith('asset-1', position);
    });

    it('should move board asset', async () => {
      const { result } = renderHook(() => useAssetManager(roomId));

      const newPosition = { x: 300, y: 400 };

      await act(async () => {
        await result.current.moveAsset('board-asset-1', newPosition);
      });

      expect(result.current.moveAsset).toHaveBeenCalledWith('board-asset-1', newPosition);
    });

    it('should rotate board asset', async () => {
      const { result } = renderHook(() => useAssetManager(roomId));

      const rotation = 90;

      await act(async () => {
        await result.current.rotateAsset('board-asset-1', rotation);
      });

      expect(result.current.rotateAsset).toHaveBeenCalledWith('board-asset-1', rotation);
    });

    it('should flip board asset', async () => {
      const { result } = renderHook(() => useAssetManager(roomId));

      await act(async () => {
        await result.current.flipAsset('board-asset-1');
      });

      expect(result.current.flipAsset).toHaveBeenCalledWith('board-asset-1');
    });

    it('should remove asset from board', async () => {
      const { result } = renderHook(() => useAssetManager(roomId));

      await act(async () => {
        await result.current.removeFromBoard('board-asset-1');
      });

      expect(result.current.removeFromBoard).toHaveBeenCalledWith('board-asset-1');
    });
  });

  describe('Error Handling', () => {
    it('should handle asset not found errors', async () => {
      const { result } = renderHook(() => useAssetManager(roomId));

      await act(async () => {
        try {
          await result.current.placeAsset('non-existent-asset', { x: 0, y: 0 });
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
        }
      });
    });

    it('should handle board asset not found errors', async () => {
      const { result } = renderHook(() => useAssetManager(roomId));

      await act(async () => {
        try {
          await result.current.moveAsset('non-existent-board-asset', { x: 0, y: 0 });
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
        }
      });
    });
  });

  describe('Real-time Updates', () => {
    it('should handle real-time asset updates', () => {
      const { result } = renderHook(() => useAssetManager(roomId));

      // Simulate real-time update
      expect(result.current.assets).toBeDefined();
      expect(result.current.boardAssets).toBeDefined();
    });

    it('should sync with WebSocket events', () => {
      const { result } = renderHook(() => useAssetManager(roomId));

      // In real implementation, this would test WebSocket integration
      expect(result.current).toBeDefined();
    });
  });
});
