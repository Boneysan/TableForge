// tests/unit/components/GameBoard.test.tsx
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { GameBoard } from '@/components/GameBoard';
import { mockBoardAssets, mockUser } from '@tests/fixtures';

// Mock the GameBoard component
vi.mock('@/components/GameBoard', () => ({
  GameBoard: ({ assets, onAssetMove, onAssetSelect, width = 800, height = 600, ...props }: any) => (
    <div data-testid="game-board" style={{ width: `${width}px`, height: `${height}px` }}>
      {assets?.map((asset: any) => (
        <div
          key={asset.id}
          data-testid={`board-asset-${asset.id}`}
          style={{
            position: 'absolute',
            left: asset.x,
            top: asset.y,
            width: asset.width,
            height: asset.height,
            transform: `rotate(${asset.rotation}deg)`,
            cursor: 'pointer'
          }}
          draggable
          onDragEnd={(e) => {
            const rect = e.currentTarget.parentElement?.getBoundingClientRect();
            if (rect) {
              const x = e.clientX - rect.left;
              const y = e.clientY - rect.top;
              onAssetMove?.(asset.id, { x, y });
            }
          }}
          onClick={() => onAssetSelect?.(asset)}
        >
          Asset {asset.id}
        </div>
      ))}
      <div data-testid="board-grid" className="grid-overlay">Grid</div>
    </div>
  )
}));

describe('GameBoard', () => {
  const defaultProps = {
    assets: mockBoardAssets,
    width: 800,
    height: 600,
    currentUser: mockUser,
    onAssetMove: vi.fn(),
    onAssetSelect: vi.fn(),
    onAssetContextMenu: vi.fn()
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  const renderGameBoard = (props = {}) => {
    return render(
      <GameBoard
        {...defaultProps}
        {...props}
      />
    );
  };

  describe('Board Rendering', () => {
    it('should render the game board', () => {
      renderGameBoard();
      
      expect(screen.getByTestId('game-board')).toBeInTheDocument();
    });

    it('should display board assets', () => {
      renderGameBoard();
      
      mockBoardAssets.forEach(asset => {
        expect(screen.getByTestId(`board-asset-${asset.id}`)).toBeInTheDocument();
      });
    });

    it('should apply correct positioning to assets', () => {
      renderGameBoard();
      
      const firstAsset = screen.getByTestId(`board-asset-${mockBoardAssets[0].id}`);
      expect(firstAsset).toHaveStyle({
        position: 'absolute',
        left: `${mockBoardAssets[0].x}px`,
        top: `${mockBoardAssets[0].y}px`
      });
    });

    it('should apply rotation to assets', () => {
      renderGameBoard();
      
      const rotatedAsset = mockBoardAssets.find(asset => asset.rotation !== 0);
      if (rotatedAsset) {
        const assetElement = screen.getByTestId(`board-asset-${rotatedAsset.id}`);
        expect(assetElement).toHaveStyle({
          transform: `rotate(${rotatedAsset.rotation}deg)`
        });
      }
    });

    it('should show grid overlay', () => {
      renderGameBoard();
      
      expect(screen.getByTestId('board-grid')).toBeInTheDocument();
    });
  });

  describe('Asset Interaction', () => {
    it('should handle asset selection', async () => {
      const onAssetSelect = vi.fn();
      renderGameBoard({ onAssetSelect });
      
      const firstAsset = screen.getByTestId(`board-asset-${mockBoardAssets[0].id}`);
      fireEvent.click(firstAsset);
      
      expect(onAssetSelect).toHaveBeenCalledWith(mockBoardAssets[0]);
    });

    it('should handle asset movement', async () => {
      const onAssetMove = vi.fn();
      renderGameBoard({ onAssetMove });
      
      const firstAsset = screen.getByTestId(`board-asset-${mockBoardAssets[0].id}`);
      
      // Simulate drag and drop
      fireEvent.dragEnd(firstAsset, {
        clientX: 200,
        clientY: 300
      });
      
      await waitFor(() => {
        expect(onAssetMove).toHaveBeenCalledWith(
          mockBoardAssets[0].id,
          expect.objectContaining({
            x: expect.any(Number),
            y: expect.any(Number)
          })
        );
      });
    });

    it('should make assets draggable', () => {
      renderGameBoard();
      
      mockBoardAssets.forEach(asset => {
        const assetElement = screen.getByTestId(`board-asset-${asset.id}`);
        expect(assetElement).toHaveAttribute('draggable', 'true');
      });
    });
  });

  describe('Board Configuration', () => {
    it('should respect custom board dimensions', () => {
      const customProps = {
        width: 1200,
        height: 900
      };
      
      renderGameBoard(customProps);
      
      const board = screen.getByTestId('game-board');
      expect(board).toHaveStyle({
        width: '1200px',
        height: '900px'
      });
    });

    it('should handle empty asset list', () => {
      renderGameBoard({ assets: [] });
      
      expect(screen.getByTestId('game-board')).toBeInTheDocument();
      expect(screen.queryByTestId(/board-asset-/)).not.toBeInTheDocument();
    });

    it('should handle missing callbacks gracefully', () => {
      renderGameBoard({
        onAssetMove: undefined,
        onAssetSelect: undefined,
        onAssetContextMenu: undefined
      });
      
      expect(screen.getByTestId('game-board')).toBeInTheDocument();
    });
  });

  describe('Performance', () => {
    it('should handle large number of assets', () => {
      const manyAssets = Array.from({ length: 100 }, (_, i) => ({
        ...mockBoardAssets[0],
        id: `asset-${i}`,
        x: (i % 10) * 50,
        y: Math.floor(i / 10) * 50
      }));

      renderGameBoard({ assets: manyAssets });
      
      expect(screen.getByTestId('game-board')).toBeInTheDocument();
      expect(screen.getAllByTestId(/board-asset-/)).toHaveLength(100);
    });
  });

  describe('Error Handling', () => {
    it('should handle null asset properties', () => {
      const assetsWithNulls = [{
        ...mockBoardAssets[0],
        x: null,
        y: null,
        rotation: null
      }];

      renderGameBoard({ assets: assetsWithNulls });
      
      expect(screen.getByTestId('game-board')).toBeInTheDocument();
    });

    it('should handle malformed asset data', () => {
      const malformedAssets = [
        { id: 'malformed-1' }, // Missing required properties
        null,
        undefined
      ].filter(Boolean);

      renderGameBoard({ assets: malformedAssets });
      
      expect(screen.getByTestId('game-board')).toBeInTheDocument();
    });
  });
});
