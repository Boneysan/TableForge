import { useState, useRef, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Ruler, X } from "lucide-react";

interface Point {
  x: number;
  y: number;
}

interface MeasurementToolProps {
  isActive: boolean;
  onToggle: (active: boolean) => void;
  boardWidth: number;
  boardHeight: number;
  gridSize?: number;
}

export function MeasurementTool({ 
  isActive, 
  onToggle, 
  boardWidth, 
  boardHeight,
  gridSize = 20 
}: MeasurementToolProps) {
  const [measurements, setMeasurements] = useState<Array<{ id: string; start: Point; end: Point; distance: number }>>([]);
  const [currentMeasurement, setCurrentMeasurement] = useState<{ start: Point; end: Point } | null>(null);
  const [isDrawing, setIsDrawing] = useState(false);
  const svgRef = useRef<SVGSVGElement>(null);

  const calculateDistance = (start: Point, end: Point): number => {
    const dx = end.x - start.x;
    const dy = end.y - start.y;
    const pixelDistance = Math.sqrt(dx * dx + dy * dy);
    return Math.round((pixelDistance / gridSize) * 100) / 100; // Convert to grid units
  };

  const handleMouseDown = (e: React.MouseEvent<SVGSVGElement>) => {
    if (!isActive) return;
    
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect) return;

    const point = {
      x: e.clientX - rect.left,
      y: e.clientY - rect.top
    };

    setCurrentMeasurement({ start: point, end: point });
    setIsDrawing(true);
  };

  const handleMouseMove = (e: React.MouseEvent<SVGSVGElement>) => {
    if (!isActive || !isDrawing || !currentMeasurement) return;

    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect) return;

    const point = {
      x: e.clientX - rect.left,
      y: e.clientY - rect.top
    };

    setCurrentMeasurement({
      ...currentMeasurement,
      end: point
    });
  };

  const handleMouseUp = () => {
    if (!isActive || !isDrawing || !currentMeasurement) return;

    const distance = calculateDistance(currentMeasurement.start, currentMeasurement.end);
    
    if (distance > 0.1) { // Only save if measurement is meaningful
      const newMeasurement = {
        id: Date.now().toString(),
        start: currentMeasurement.start,
        end: currentMeasurement.end,
        distance
      };
      
      setMeasurements(prev => [...prev, newMeasurement]);
    }

    setCurrentMeasurement(null);
    setIsDrawing(false);
  };

  const clearMeasurements = () => {
    setMeasurements([]);
    setCurrentMeasurement(null);
    setIsDrawing(false);
  };

  const removeMeasurement = (id: string) => {
    setMeasurements(prev => prev.filter(m => m.id !== id));
  };

  useEffect(() => {
    if (!isActive) {
      setCurrentMeasurement(null);
      setIsDrawing(false);
    }
  }, [isActive]);

  const renderMeasurementLine = (start: Point, end: Point, distance: number, id?: string, isTemporary = false) => {
    const midX = (start.x + end.x) / 2;
    const midY = (start.y + end.y) / 2;
    
    return (
      <g key={id || 'temp'}>
        {/* Measurement line */}
        <line
          x1={start.x}
          y1={start.y}
          x2={end.x}
          y2={end.y}
          stroke={isTemporary ? "#3b82f6" : "#ef4444"}
          strokeWidth="2"
          strokeDasharray={isTemporary ? "5,5" : "none"}
        />
        
        {/* Start point */}
        <circle
          cx={start.x}
          cy={start.y}
          r="4"
          fill={isTemporary ? "#3b82f6" : "#ef4444"}
        />
        
        {/* End point */}
        <circle
          cx={end.x}
          cy={end.y}
          r="4"
          fill={isTemporary ? "#3b82f6" : "#ef4444"}
        />
        
        {/* Distance label */}
        <text
          x={midX}
          y={midY - 10}
          textAnchor="middle"
          fill={isTemporary ? "#3b82f6" : "#ef4444"}
          fontSize="12"
          fontWeight="bold"
          className="pointer-events-none select-none"
        >
          {distance} units
        </text>
        
        {/* Delete button for saved measurements */}
        {!isTemporary && id && (
          <circle
            cx={midX + 30}
            cy={midY}
            r="8"
            fill="white"
            stroke="#ef4444"
            strokeWidth="1"
            className="cursor-pointer"
            onClick={() => removeMeasurement(id)}
          />
        )}
        {!isTemporary && id && (
          <text
            x={midX + 30}
            y={midY + 3}
            textAnchor="middle"
            fill="#ef4444"
            fontSize="10"
            className="cursor-pointer pointer-events-none"
          >
            ×
          </text>
        )}
      </g>
    );
  };

  return (
    <>
      <svg
        ref={svgRef}
        className={`absolute inset-0 z-30 ${isActive ? 'cursor-crosshair' : 'pointer-events-none'}`}
        width={boardWidth}
        height={boardHeight}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        data-testid="measurement-overlay"
      >
        {/* Render saved measurements */}
        {measurements.map(measurement => 
          renderMeasurementLine(
            measurement.start, 
            measurement.end, 
            measurement.distance, 
            measurement.id,
            false
          )
        )}
        
        {/* Render current measurement being drawn */}
        {currentMeasurement && renderMeasurementLine(
          currentMeasurement.start,
          currentMeasurement.end,
          calculateDistance(currentMeasurement.start, currentMeasurement.end),
          undefined,
          true
        )}
      </svg>

      {/* Measurement Tool Controls */}
      <div className="absolute top-4 left-4 z-20">
        <Card className="w-56">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Ruler className="w-4 h-4" />
              Measurement Tool
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <Button
              variant={isActive ? "default" : "outline"}
              size="sm"
              onClick={() => onToggle(!isActive)}
              className="w-full"
              data-testid="button-toggle-measurement"
            >
              {isActive ? "Active" : "Activate"} Ruler
            </Button>
            
            {measurements.length > 0 && (
              <Button
                variant="outline"
                size="sm"
                onClick={clearMeasurements}
                className="w-full"
                data-testid="button-clear-measurements"
              >
                <X className="w-3 h-3 mr-2" />
                Clear All
              </Button>
            )}
            
            <div className="text-xs text-gray-500">
              <p>Click and drag to measure distances</p>
              <p>Units based on grid size ({gridSize}px = 1 unit)</p>
              {measurements.length > 0 && (
                <p className="mt-2 font-medium">
                  {measurements.length} measurement{measurements.length !== 1 ? 's' : ''} active
                </p>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </>
  );
}