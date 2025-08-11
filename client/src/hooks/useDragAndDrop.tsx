import { useRef } from 'react';

interface DragData {
  type: string;
  data: any;
}

export function useDragAndDrop() {
  const dragDataRef = useRef<DragData | null>(null);

  const dragStart = (event: React.DragEvent, dragData: DragData) => {
    dragDataRef.current = dragData;

    // Set drag effect
    event.dataTransfer.effectAllowed = 'copy';

    // Set a minimal drag image to reduce visual clutter
    const dragImage = new Image();
    dragImage.src = 'data:image/gif;base64,R0lGODlhAQABAIAAAAUEBAAAACwAAAAAAQABAAACAkQBADs=';
    event.dataTransfer.setDragImage(dragImage, 0, 0);
  };

  const dragOver = (event: React.DragEvent) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = 'copy';
  };

  const drop = (event: React.DragEvent): DragData | null => {
    event.preventDefault();
    const data = dragDataRef.current;
    dragDataRef.current = null;
    return data;
  };

  return {
    dragStart,
    dragOver,
    drop,
  };
}
