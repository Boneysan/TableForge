import { useState, useRef } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { PenTool, StickyNote, Type, Palette, Trash2, Undo } from "lucide-react";

interface Point {
  x: number;
  y: number;
}

interface DrawingPath {
  id: string;
  points: Point[];
  color: string;
  thickness: number;
}

interface StickyNote {
  id: string;
  x: number;
  y: number;
  text: string;
  color: string;
}

interface TextAnnotation {
  id: string;
  x: number;
  y: number;
  text: string;
  fontSize: number;
  color: string;
}

interface AnnotationSystemProps {
  isActive: boolean;
  onToggle: (active: boolean) => void;
  boardWidth: number;
  boardHeight: number;
}

export function AnnotationSystem({ isActive, onToggle, boardWidth, boardHeight }: AnnotationSystemProps) {
  const [mode, setMode] = useState<'draw' | 'note' | 'text'>('draw');
  const [drawings, setDrawings] = useState<DrawingPath[]>([]);
  const [notes, setNotes] = useState<StickyNote[]>([]);
  const [textAnnotations, setTextAnnotations] = useState<TextAnnotation[]>([]);
  
  const [currentPath, setCurrentPath] = useState<Point[]>([]);
  const [isDrawing, setIsDrawing] = useState(false);
  
  const [drawColor, setDrawColor] = useState('#ef4444');
  const [drawThickness, setDrawThickness] = useState(3);
  const [noteColor, setNoteColor] = useState('#fbbf24');
  const [textSize, setTextSize] = useState(16);
  
  const [showNoteDialog, setShowNoteDialog] = useState(false);
  const [showTextDialog, setShowTextDialog] = useState(false);
  const [pendingNote, setPendingNote] = useState<{ x: number; y: number } | null>(null);
  const [pendingText, setPendingText] = useState<{ x: number; y: number } | null>(null);
  const [noteText, setNoteText] = useState('');
  const [textContent, setTextContent] = useState('');
  
  const svgRef = useRef<SVGSVGElement>(null);

  const getMousePosition = (e: React.MouseEvent): Point => {
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect) return { x: 0, y: 0 };
    return {
      x: e.clientX - rect.left,
      y: e.clientY - rect.top
    };
  };

  const handleMouseDown = (e: React.MouseEvent) => {
    if (!isActive) return;
    
    const point = getMousePosition(e);
    
    if (mode === 'draw') {
      setCurrentPath([point]);
      setIsDrawing(true);
    } else if (mode === 'note') {
      setPendingNote(point);
      setShowNoteDialog(true);
    } else if (mode === 'text') {
      setPendingText(point);
      setShowTextDialog(true);
    }
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isActive || !isDrawing || mode !== 'draw') return;
    
    const point = getMousePosition(e);
    setCurrentPath(prev => [...prev, point]);
  };

  const handleMouseUp = () => {
    if (!isActive || !isDrawing || mode !== 'draw') return;
    
    if (currentPath.length > 1) {
      const newDrawing: DrawingPath = {
        id: Date.now().toString(),
        points: currentPath,
        color: drawColor,
        thickness: drawThickness
      };
      setDrawings(prev => [...prev, newDrawing]);
    }
    
    setCurrentPath([]);
    setIsDrawing(false);
  };

  const handleAddNote = () => {
    if (!pendingNote || !noteText.trim()) return;
    
    const newNote: StickyNote = {
      id: Date.now().toString(),
      x: pendingNote.x,
      y: pendingNote.y,
      text: noteText,
      color: noteColor
    };
    
    setNotes(prev => [...prev, newNote]);
    setNoteText('');
    setPendingNote(null);
    setShowNoteDialog(false);
  };

  const handleAddText = () => {
    if (!pendingText || !textContent.trim()) return;
    
    const newText: TextAnnotation = {
      id: Date.now().toString(),
      x: pendingText.x,
      y: pendingText.y,
      text: textContent,
      fontSize: textSize,
      color: drawColor
    };
    
    setTextAnnotations(prev => [...prev, newText]);
    setTextContent('');
    setPendingText(null);
    setShowTextDialog(false);
  };

  const clearAll = () => {
    setDrawings([]);
    setNotes([]);
    setTextAnnotations([]);
    setCurrentPath([]);
    setIsDrawing(false);
  };

  const undoLastDrawing = () => {
    if (drawings.length > 0) {
      setDrawings(prev => prev.slice(0, -1));
    }
  };

  const renderPath = (points: Point[]) => {
    if (points.length < 2) return '';
    
    let path = `M ${points[0].x} ${points[0].y}`;
    for (let i = 1; i < points.length; i++) {
      path += ` L ${points[i].x} ${points[i].y}`;
    }
    return path;
  };

  return (
    <>
      <svg
        ref={svgRef}
        className={`absolute inset-0 z-20 ${isActive ? 'pointer-events-auto' : 'pointer-events-none'}`}
        width={boardWidth}
        height={boardHeight}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        data-testid="annotation-overlay"
      >
        {/* Render saved drawings */}
        {drawings.map(drawing => (
          <path
            key={drawing.id}
            d={renderPath(drawing.points)}
            stroke={drawing.color}
            strokeWidth={drawing.thickness}
            fill="none"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        ))}
        
        {/* Render current drawing */}
        {currentPath.length > 1 && (
          <path
            d={renderPath(currentPath)}
            stroke={drawColor}
            strokeWidth={drawThickness}
            fill="none"
            strokeLinecap="round"
            strokeLinejoin="round"
            opacity="0.7"
          />
        )}
        
        {/* Render sticky notes */}
        {notes.map(note => (
          <g key={note.id}>
            <rect
              x={note.x}
              y={note.y}
              width="120"
              height="80"
              fill={note.color}
              stroke="#000"
              strokeWidth="1"
              rx="4"
            />
            <foreignObject
              x={note.x + 5}
              y={note.y + 5}
              width="110"
              height="70"
            >
              <div className="text-xs text-black p-1 overflow-hidden">
                {note.text}
              </div>
            </foreignObject>
            <circle
              cx={note.x + 115}
              cy={note.y + 5}
              r="8"
              fill="red"
              className="cursor-pointer"
              onClick={() => setNotes(prev => prev.filter(n => n.id !== note.id))}
            />
            <text
              x={note.x + 115}
              y={note.y + 9}
              textAnchor="middle"
              fill="white"
              fontSize="10"
              className="pointer-events-none"
            >
              ×
            </text>
          </g>
        ))}
        
        {/* Render text annotations */}
        {textAnnotations.map(text => (
          <g key={text.id}>
            <text
              x={text.x}
              y={text.y}
              fill={text.color}
              fontSize={text.fontSize}
              fontWeight="bold"
            >
              {text.text}
            </text>
            <circle
              cx={text.x + text.text.length * (text.fontSize * 0.6) + 10}
              cy={text.y - text.fontSize + 5}
              r="6"
              fill="red"
              className="cursor-pointer"
              onClick={() => setTextAnnotations(prev => prev.filter(t => t.id !== text.id))}
            />
            <text
              x={text.x + text.text.length * (text.fontSize * 0.6) + 10}
              y={text.y - text.fontSize + 8}
              textAnchor="middle"
              fill="white"
              fontSize="8"
              className="pointer-events-none"
            >
              ×
            </text>
          </g>
        ))}
      </svg>

      {/* Annotation Controls */}
      <div className="absolute bottom-4 left-4 z-30">
        <Card className="w-72">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <PenTool className="w-4 h-4" />
              Annotation Tools
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex gap-2">
              <Button
                variant={isActive ? "default" : "outline"}
                size="sm"
                onClick={() => onToggle(!isActive)}
                data-testid="button-toggle-annotations"
              >
                {isActive ? "Active" : "Activate"}
              </Button>
              
              {drawings.length > 0 && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={undoLastDrawing}
                  data-testid="button-undo-drawing"
                  title="Undo last drawing"
                >
                  <Undo className="w-3 h-3" />
                </Button>
              )}
              
              {(drawings.length > 0 || notes.length > 0 || textAnnotations.length > 0) && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={clearAll}
                  data-testid="button-clear-annotations"
                >
                  <Trash2 className="w-3 h-3" />
                </Button>
              )}
            </div>
            
            {isActive && (
              <>
                <div>
                  <Label className="text-xs">Mode</Label>
                  <Select value={mode} onValueChange={(value: 'draw' | 'note' | 'text') => setMode(value)}>
                    <SelectTrigger className="h-8">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="draw">
                        <span className="flex items-center gap-2">
                          <PenTool className="w-3 h-3" />
                          Draw
                        </span>
                      </SelectItem>
                      <SelectItem value="note">
                        <span className="flex items-center gap-2">
                          <StickyNote className="w-3 h-3" />
                          Sticky Note
                        </span>
                      </SelectItem>
                      <SelectItem value="text">
                        <span className="flex items-center gap-2">
                          <Type className="w-3 h-3" />
                          Text
                        </span>
                      </SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <Label className="text-xs">Color</Label>
                    <input
                      type="color"
                      value={mode === 'note' ? noteColor : drawColor}
                      onChange={(e) => {
                        if (mode === 'note') {
                          setNoteColor(e.target.value);
                        } else {
                          setDrawColor(e.target.value);
                        }
                      }}
                      className="w-full h-8 rounded border"
                      data-testid="input-annotation-color"
                    />
                  </div>
                  
                  {mode === 'draw' && (
                    <div>
                      <Label className="text-xs">Thickness</Label>
                      <Input
                        type="number"
                        min="1"
                        max="10"
                        value={drawThickness}
                        onChange={(e) => setDrawThickness(parseInt(e.target.value) || 3)}
                        className="h-8"
                        data-testid="input-draw-thickness"
                      />
                    </div>
                  )}
                  
                  {mode === 'text' && (
                    <div>
                      <Label className="text-xs">Size</Label>
                      <Input
                        type="number"
                        min="10"
                        max="48"
                        value={textSize}
                        onChange={(e) => setTextSize(parseInt(e.target.value) || 16)}
                        className="h-8"
                        data-testid="input-text-size"
                      />
                    </div>
                  )}
                </div>
              </>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Note Dialog */}
      <Dialog open={showNoteDialog} onOpenChange={setShowNoteDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add Sticky Note</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="note-text">Note Text</Label>
              <Input
                id="note-text"
                value={noteText}
                onChange={(e) => setNoteText(e.target.value)}
                placeholder="Enter your note..."
                data-testid="input-note-text"
              />
            </div>
            <div className="flex justify-end space-x-2">
              <Button variant="outline" onClick={() => setShowNoteDialog(false)}>
                Cancel
              </Button>
              <Button onClick={handleAddNote} data-testid="button-add-note">
                Add Note
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Text Dialog */}
      <Dialog open={showTextDialog} onOpenChange={setShowTextDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add Text</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="text-content">Text Content</Label>
              <Input
                id="text-content"
                value={textContent}
                onChange={(e) => setTextContent(e.target.value)}
                placeholder="Enter text..."
                data-testid="input-text-content"
              />
            </div>
            <div className="flex justify-end space-x-2">
              <Button variant="outline" onClick={() => setShowTextDialog(false)}>
                Cancel
              </Button>
              <Button onClick={handleAddText} data-testid="button-add-text">
                Add Text
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}