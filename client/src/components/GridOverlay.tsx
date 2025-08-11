import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Input } from '@/components/ui/input';
import { Grid3X3, Settings } from 'lucide-react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';

interface GridOverlayProps {
  isVisible: boolean;
  gridSize: number;
  onToggle: (visible: boolean) => void;
  onGridSizeChange: (size: number) => void;
  boardWidth: number;
  boardHeight: number;
}

export function GridOverlay({
  isVisible,
  gridSize,
  onToggle,
  onGridSizeChange,
  boardWidth,
  boardHeight,
}: GridOverlayProps) {
  const [showSettings, setShowSettings] = useState(false);
  const [tempGridSize, setTempGridSize] = useState(gridSize);

  const handleSaveSettings = () => {
    onGridSizeChange(tempGridSize);
    setShowSettings(false);
  };

  if (!isVisible) return null;

  const gridLines = [];

  // Vertical lines
  for (let x = 0; x <= boardWidth; x += gridSize) {
    gridLines.push(
      <line
        key={`v-${x}`}
        x1={x}
        y1={0}
        x2={x}
        y2={boardHeight}
        stroke="rgba(0, 0, 0, 0.2)"
        strokeWidth="1"
        strokeDasharray="2,2"
      />,
    );
  }

  // Horizontal lines
  for (let y = 0; y <= boardHeight; y += gridSize) {
    gridLines.push(
      <line
        key={`h-${y}`}
        x1={0}
        y1={y}
        x2={boardWidth}
        y2={y}
        stroke="rgba(0, 0, 0, 0.2)"
        strokeWidth="1"
        strokeDasharray="2,2"
      />,
    );
  }

  return (
    <>
      <svg
        className="absolute inset-0 pointer-events-none z-10"
        width={boardWidth}
        height={boardHeight}
        data-testid="grid-overlay"
      >
        {gridLines}
      </svg>

      {/* Grid Controls */}
      <div className="absolute top-4 right-4 z-20">
        <Card className="w-48">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Grid3X3 className="w-4 h-4" />
              Grid System
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-center justify-between">
              <Label htmlFor="grid-toggle" className="text-sm">
                Show Grid
              </Label>
              <Switch
                id="grid-toggle"
                checked={isVisible}
                onCheckedChange={onToggle}
                data-testid="switch-grid-toggle"
              />
            </div>

            <Dialog open={showSettings} onOpenChange={setShowSettings}>
              <DialogTrigger asChild>
                <Button
                  variant="outline"
                  size="sm"
                  className="w-full justify-start"
                  data-testid="button-grid-settings"
                >
                  <Settings className="w-3 h-3 mr-2" />
                  Grid Settings
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Grid Configuration</DialogTitle>
                </DialogHeader>
                <div className="space-y-4">
                  <div>
                    <Label htmlFor="grid-size">Grid Size (pixels)</Label>
                    <Input
                      id="grid-size"
                      type="number"
                      min="10"
                      max="100"
                      value={tempGridSize}
                      onChange={(e) => setTempGridSize(parseInt(e.target.value) || 20)}
                      data-testid="input-grid-size"
                    />
                  </div>
                  <div className="flex justify-end space-x-2">
                    <Button variant="outline" onClick={() => setShowSettings(false)}>
                      Cancel
                    </Button>
                    <Button onClick={handleSaveSettings} data-testid="button-save-grid">
                      Save
                    </Button>
                  </div>
                </div>
              </DialogContent>
            </Dialog>
          </CardContent>
        </Card>
      </div>
    </>
  );
}

// Utility function for snapping coordinates to grid
export function snapToGrid(x: number, y: number, gridSize: number): { x: number; y: number } {
  return {
    x: Math.round(x / gridSize) * gridSize,
    y: Math.round(y / gridSize) * gridSize,
  };
}
