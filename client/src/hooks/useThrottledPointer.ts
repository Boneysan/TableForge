/**
 * Optimized pointer event handling with throttling and RAF coalescing
 * Provides high-performance drag operations for canvas elements
 */

import { useRef, useCallback, useEffect } from 'react';

export interface PointerEventData {
  clientX: number;
  clientY: number;
  pointerId: number;
  pressure?: number;
  tiltX?: number;
  tiltY?: number;
  timestamp: number;
}

export interface DragState {
  isDragging: boolean;
  dragStartPos: { x: number; y: number } | null;
  currentPos: { x: number; y: number } | null;
  deltaX: number;
  deltaY: number;
  velocity: { x: number; y: number };
}

interface UseThrottledPointerOptions {
  onPointerDown?: (event: PointerEventData) => void;
  onPointerMove?: (event: PointerEventData, dragState: DragState) => void;
  onPointerUp?: (event: PointerEventData, dragState: DragState) => void;
  onDragStart?: (event: PointerEventData) => void;
  onDragMove?: (event: PointerEventData, dragState: DragState) => void;
  onDragEnd?: (event: PointerEventData, dragState: DragState) => void;
  throttleMs?: number;
  dragThreshold?: number;
  enableRafCoalescing?: boolean;
}

interface UseThrottledPointerReturn {
  dragState: DragState;
  bindPointerEvents: () => {
    onPointerDown: (e: React.PointerEvent) => void;
    onPointerMove: (e: React.PointerEvent) => void;
    onPointerUp: (e: React.PointerEvent) => void;
    onPointerCancel: (e: React.PointerEvent) => void;
  };
  resetDrag: () => void;
}

export function useThrottledPointer(options: UseThrottledPointerOptions): UseThrottledPointerReturn {
  const {
    onPointerDown,
    onPointerMove,
    onPointerUp,
    onDragStart,
    onDragMove,
    onDragEnd,
    throttleMs = 16, // ~60fps
    dragThreshold = 5,
    enableRafCoalescing = true,
  } = options;

  // Current drag state
  const dragStateRef = useRef<DragState>({
    isDragging: false,
    dragStartPos: null,
    currentPos: null,
    deltaX: 0,
    deltaY: 0,
    velocity: { x: 0, y: 0 },
  });

  // Event throttling state
  const lastEventTime = useRef<number>(0);
  const lastPosition = useRef<{ x: number; y: number } | null>(null);
  const pendingRafId = useRef<number | null>(null);
  const pendingEvents = useRef<PointerEventData[]>([]);

  // Velocity calculation
  const calculateVelocity = useCallback((
    currentPos: { x: number; y: number },
    lastPos: { x: number; y: number } | null,
    deltaTime: number,
  ): { x: number; y: number } => {
    if (!lastPos || deltaTime === 0) {
      return { x: 0, y: 0 };
    }

    return {
      x: (currentPos.x - lastPos.x) / deltaTime,
      y: (currentPos.y - lastPos.y) / deltaTime,
    };
  }, []);

  // Process coalesced events using RAF
  const processCoalescedEvents = useCallback(() => {
    if (pendingEvents.current.length === 0) return;

    // Get the most recent event (coalesce all others)
    const latestEvent = pendingEvents.current[pendingEvents.current.length - 1];
    pendingEvents.current = [];

    const currentState = dragStateRef.current;
    const currentPos = { x: latestEvent.clientX, y: latestEvent.clientY };

    // Calculate velocity
    const deltaTime = lastEventTime.current > 0 ? latestEvent.timestamp - lastEventTime.current : 0;
    const velocity = calculateVelocity(currentPos, lastPosition.current, deltaTime);

    // Update drag state
    if (currentState.isDragging && currentState.dragStartPos) {
      const newState: DragState = {
        ...currentState,
        currentPos,
        deltaX: currentPos.x - currentState.dragStartPos.x,
        deltaY: currentPos.y - currentState.dragStartPos.y,
        velocity,
      };

      dragStateRef.current = newState;
      onDragMove?.(latestEvent, newState);
    }

    onPointerMove?.(latestEvent, dragStateRef.current);

    lastPosition.current = currentPos;
    lastEventTime.current = latestEvent.timestamp;
    pendingRafId.current = null;
  }, [onPointerMove, onDragMove, calculateVelocity]);

  // Handle pointer down
  const handlePointerDown = useCallback((e: React.PointerEvent) => {
    const eventData: PointerEventData = {
      clientX: e.clientX,
      clientY: e.clientY,
      pointerId: e.pointerId,
      pressure: e.pressure,
      tiltX: e.tiltX,
      tiltY: e.tiltY,
      timestamp: performance.now(),
    };

    // Capture pointer for consistent events
    (e.target as Element).setPointerCapture?.(e.pointerId);

    const startPos = { x: e.clientX, y: e.clientY };
    dragStateRef.current = {
      isDragging: false,
      dragStartPos: startPos,
      currentPos: startPos,
      deltaX: 0,
      deltaY: 0,
      velocity: { x: 0, y: 0 },
    };

    lastPosition.current = startPos;
    lastEventTime.current = eventData.timestamp;

    onPointerDown?.(eventData);
  }, [onPointerDown]);

  // Handle pointer move with throttling
  const handlePointerMove = useCallback((e: React.PointerEvent) => {
    const now = performance.now();
    const eventData: PointerEventData = {
      clientX: e.clientX,
      clientY: e.clientY,
      pointerId: e.pointerId,
      pressure: e.pressure,
      tiltX: e.tiltX,
      tiltY: e.tiltY,
      timestamp: now,
    };

    const currentState = dragStateRef.current;

    // Check if we should start dragging
    if (!currentState.isDragging && currentState.dragStartPos) {
      const distance = Math.sqrt(
        Math.pow(e.clientX - currentState.dragStartPos.x, 2) +
        Math.pow(e.clientY - currentState.dragStartPos.y, 2),
      );

      if (distance >= dragThreshold) {
        dragStateRef.current = {
          ...currentState,
          isDragging: true,
        };
        onDragStart?.(eventData);
      }
    }

    // Throttle events
    if (now - lastEventTime.current < throttleMs) {
      if (enableRafCoalescing) {
        // Add to pending events for coalescing
        pendingEvents.current.push(eventData);

        // Schedule RAF if not already scheduled
        if (pendingRafId.current === null) {
          pendingRafId.current = requestAnimationFrame(processCoalescedEvents);
        }
      }
      return;
    }

    // Process immediately for non-coalesced mode
    if (!enableRafCoalescing) {
      const currentPos = { x: eventData.clientX, y: eventData.clientY };
      const deltaTime = now - lastEventTime.current;
      const velocity = calculateVelocity(currentPos, lastPosition.current, deltaTime);

      if (currentState.isDragging && currentState.dragStartPos) {
        const newState: DragState = {
          ...currentState,
          currentPos,
          deltaX: currentPos.x - currentState.dragStartPos.x,
          deltaY: currentPos.y - currentState.dragStartPos.y,
          velocity,
        };

        dragStateRef.current = newState;
        onDragMove?.(eventData, newState);
      }

      onPointerMove?.(eventData, dragStateRef.current);

      lastPosition.current = currentPos;
      lastEventTime.current = now;
    } else {
      // Add to coalesced events
      pendingEvents.current = [eventData]; // Replace with latest
      if (pendingRafId.current === null) {
        pendingRafId.current = requestAnimationFrame(processCoalescedEvents);
      }
    }
  }, [
    throttleMs,
    dragThreshold,
    enableRafCoalescing,
    onPointerMove,
    onDragStart,
    onDragMove,
    processCoalescedEvents,
    calculateVelocity,
  ]);

  // Handle pointer up
  const handlePointerUp = useCallback((e: React.PointerEvent) => {
    const eventData: PointerEventData = {
      clientX: e.clientX,
      clientY: e.clientY,
      pointerId: e.pointerId,
      pressure: e.pressure,
      tiltX: e.tiltX,
      tiltY: e.tiltY,
      timestamp: performance.now(),
    };

    const currentState = dragStateRef.current;

    // Cancel any pending RAF
    if (pendingRafId.current !== null) {
      cancelAnimationFrame(pendingRafId.current);
      pendingRafId.current = null;
    }

    // Process final coalesced events
    if (pendingEvents.current.length > 0) {
      processCoalescedEvents();
    }

    // Release pointer capture
    (e.target as Element).releasePointerCapture?.(e.pointerId);

    if (currentState.isDragging) {
      onDragEnd?.(eventData, currentState);
    }

    onPointerUp?.(eventData, currentState);

    // Reset drag state
    dragStateRef.current = {
      isDragging: false,
      dragStartPos: null,
      currentPos: null,
      deltaX: 0,
      deltaY: 0,
      velocity: { x: 0, y: 0 },
    };

    lastPosition.current = null;
    lastEventTime.current = 0;
    pendingEvents.current = [];
  }, [onPointerUp, onDragEnd, processCoalescedEvents]);

  // Handle pointer cancel
  const handlePointerCancel = useCallback((e: React.PointerEvent) => {
    handlePointerUp(e); // Same as pointer up for cleanup
  }, [handlePointerUp]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (pendingRafId.current !== null) {
        cancelAnimationFrame(pendingRafId.current);
      }
    };
  }, []);

  // Reset drag state manually
  const resetDrag = useCallback(() => {
    if (pendingRafId.current !== null) {
      cancelAnimationFrame(pendingRafId.current);
      pendingRafId.current = null;
    }

    dragStateRef.current = {
      isDragging: false,
      dragStartPos: null,
      currentPos: null,
      deltaX: 0,
      deltaY: 0,
      velocity: { x: 0, y: 0 },
    };

    lastPosition.current = null;
    lastEventTime.current = 0;
    pendingEvents.current = [];
  }, []);

  return {
    dragState: dragStateRef.current,
    bindPointerEvents: () => ({
      onPointerDown: handlePointerDown,
      onPointerMove: handlePointerMove,
      onPointerUp: handlePointerUp,
      onPointerCancel: handlePointerCancel,
    }),
    resetDrag,
  };
}
