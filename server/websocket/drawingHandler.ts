/**
 * Drawing and Annotation WebSocket Handler
 * 
 * Handles real-time drawing, annotations, and sketching with security measures:
 * - Stroke rate limiting to prevent pathological payloads
 * - Text sanitization for annotations
 * - Coordinate validation and bounds checking
 */

import { WebSocket } from 'ws';
import { sanitizeStrokeData, sanitizeText } from '../../shared/sanitization.js';

// Drawing event types
export interface DrawingStroke {
  id: string;
  roomId: string;
  userId: string;
  points: Array<{ x: number; y: number; pressure?: number }>;
  color: string;
  width: number;
  tool: string;
  timestamp: number;
}

export interface DrawingAnnotation {
  id: string;
  roomId: string;
  userId: string;
  text: string;
  positionX: number;
  positionY: number;
  fontSize: number;
  color: string;
  timestamp: number;
}

export interface DrawingClear {
  roomId: string;
  userId: string;
  timestamp: number;
  layerId?: string; // Optional layer-specific clear
}

/**
 * Handle drawing stroke events with rate limiting and validation
 */
export async function handleDrawingStroke(
  ws: WebSocket,
  data: any,
  userId: string,
  roomId: string
): Promise<void> {
  const correlationId = `draw-stroke-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  
  console.log('🎨 [Drawing] Processing stroke event', {
    correlationId,
    userId,
    roomId,
    pointCount: data.points?.length || 0,
    tool: data.tool,
  });

  try {
    // Validate required fields
    if (!data.points || !Array.isArray(data.points)) {
      throw new Error('Invalid points data');
    }

    if (!data.roomId || data.roomId !== roomId) {
      throw new Error('Room ID mismatch');
    }

    // Sanitize and validate stroke data
    const sanitizationResult = sanitizeStrokeData({
      points: data.points,
      color: data.color,
      width: data.width,
      tool: data.tool,
      userId,
      timestamp: Date.now(),
    });

    if (!sanitizationResult.valid) {
      console.warn('🚫 [Drawing] Stroke validation failed', {
        correlationId,
        userId,
        roomId,
        errors: sanitizationResult.errors,
      });
      
      ws.send(JSON.stringify({
        type: 'error',
        message: 'Invalid drawing data: ' + sanitizationResult.errors.join(', '),
        correlationId,
      }));
      return;
    }

    // Create validated stroke object
    const stroke: DrawingStroke = {
      id: data.id || `stroke-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      roomId,
      userId,
      points: sanitizationResult.sanitized.points,
      color: sanitizationResult.sanitized.color,
      width: sanitizationResult.sanitized.width,
      tool: sanitizationResult.sanitized.tool,
      timestamp: sanitizationResult.sanitized.timestamp,
    };

    // Broadcast to other users in the room
    const broadcastData = {
      type: 'drawing_stroke',
      data: stroke,
      timestamp: new Date().toISOString(),
    };

    // Here you would typically:
    // 1. Save to database if persistence is needed
    // 2. Broadcast to other room members
    // 3. Update any drawing state caches

    console.log('✅ [Drawing] Stroke processed successfully', {
      correlationId,
      userId,
      roomId,
      strokeId: stroke.id,
      pointCount: stroke.points.length,
    });

    // Example broadcast (you would implement room-based broadcasting)
    ws.send(JSON.stringify({
      type: 'drawing_stroke_ack',
      strokeId: stroke.id,
      correlationId,
    }));

  } catch (error) {
    console.error('❌ [Drawing] Stroke processing failed', {
      correlationId,
      userId,
      roomId,
      error: error instanceof Error ? error.message : 'Unknown error',
    });

    ws.send(JSON.stringify({
      type: 'error',
      message: 'Failed to process drawing stroke',
      correlationId,
    }));
  }
}

/**
 * Handle drawing annotation events with text sanitization
 */
export async function handleDrawingAnnotation(
  ws: WebSocket,
  data: any,
  userId: string,
  roomId: string
): Promise<void> {
  const correlationId = `draw-annotation-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

  console.log('📝 [Drawing] Processing annotation event', {
    correlationId,
    userId,
    roomId,
    textLength: data.text?.length || 0,
  });

  try {
    // Validate required fields
    if (!data.text || typeof data.text !== 'string') {
      throw new Error('Invalid annotation text');
    }

    if (!data.roomId || data.roomId !== roomId) {
      throw new Error('Room ID mismatch');
    }

    // Validate position coordinates
    if (
      typeof data.positionX !== 'number' ||
      typeof data.positionY !== 'number' ||
      !isFinite(data.positionX) ||
      !isFinite(data.positionY) ||
      Math.abs(data.positionX) > 50000 ||
      Math.abs(data.positionY) > 50000
    ) {
      throw new Error('Invalid position coordinates');
    }

    // Sanitize the annotation text
    const sanitizedText = sanitizeText(data.text, 'annotation');
    
    if (!sanitizedText || sanitizedText.length === 0) {
      throw new Error('Annotation text is empty after sanitization');
    }

    // Validate font size
    let fontSize = 14; // Default
    if (data.fontSize) {
      if (
        typeof data.fontSize === 'number' &&
        isFinite(data.fontSize) &&
        data.fontSize >= 8 &&
        data.fontSize <= 72
      ) {
        fontSize = data.fontSize;
      } else {
        console.warn('🚫 [Drawing] Invalid font size, using default', {
          correlationId,
          providedSize: data.fontSize,
        });
      }
    }

    // Validate color
    let color = '#000000'; // Default black
    if (data.color) {
      const colorMatch = data.color.match(/^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/);
      if (colorMatch) {
        color = data.color;
      } else {
        console.warn('🚫 [Drawing] Invalid color format, using default', {
          correlationId,
          providedColor: data.color,
        });
      }
    }

    // Create validated annotation object
    const annotation: DrawingAnnotation = {
      id: data.id || `annotation-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      roomId,
      userId,
      text: sanitizedText,
      positionX: data.positionX,
      positionY: data.positionY,
      fontSize,
      color,
      timestamp: Date.now(),
    };

    console.log('✅ [Drawing] Annotation processed successfully', {
      correlationId,
      userId,
      roomId,
      annotationId: annotation.id,
      textLength: annotation.text.length,
    });

    // Send acknowledgment
    ws.send(JSON.stringify({
      type: 'drawing_annotation_ack',
      annotationId: annotation.id,
      correlationId,
    }));

  } catch (error) {
    console.error('❌ [Drawing] Annotation processing failed', {
      correlationId,
      userId,
      roomId,
      error: error instanceof Error ? error.message : 'Unknown error',
    });

    ws.send(JSON.stringify({
      type: 'error',
      message: 'Failed to process drawing annotation',
      correlationId,
    }));
  }
}

/**
 * Handle drawing clear events
 */
export async function handleDrawingClear(
  ws: WebSocket,
  data: any,
  userId: string,
  roomId: string
): Promise<void> {
  const correlationId = `draw-clear-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

  console.log('🧹 [Drawing] Processing clear event', {
    correlationId,
    userId,
    roomId,
    layerId: data.layerId,
  });

  try {
    if (!data.roomId || data.roomId !== roomId) {
      throw new Error('Room ID mismatch');
    }

    // Create clear event
    const clearEvent: DrawingClear = {
      roomId,
      userId,
      timestamp: Date.now(),
      layerId: data.layerId,
    };

    console.log('✅ [Drawing] Clear event processed successfully', {
      correlationId,
      userId,
      roomId,
      layerId: clearEvent.layerId,
    });

    // Send acknowledgment
    ws.send(JSON.stringify({
      type: 'drawing_clear_ack',
      correlationId,
    }));

  } catch (error) {
    console.error('❌ [Drawing] Clear processing failed', {
      correlationId,
      userId,
      roomId,
      error: error instanceof Error ? error.message : 'Unknown error',
    });

    ws.send(JSON.stringify({
      type: 'error',
      message: 'Failed to process drawing clear',
      correlationId,
    }));
  }
}

/**
 * Main drawing event router
 */
export function handleDrawingEvent(
  ws: WebSocket,
  eventType: string,
  data: any,
  userId: string,
  roomId: string
): Promise<void> {
  switch (eventType) {
    case 'drawing_stroke':
      return handleDrawingStroke(ws, data, userId, roomId);
    
    case 'drawing_annotation':
      return handleDrawingAnnotation(ws, data, userId, roomId);
    
    case 'drawing_clear':
      return handleDrawingClear(ws, data, userId, roomId);
    
    default:
      console.warn('🚫 [Drawing] Unknown drawing event type', {
        eventType,
        userId,
        roomId,
      });
      
      ws.send(JSON.stringify({
        type: 'error',
        message: `Unknown drawing event type: ${eventType}`,
      }));
      
      return Promise.resolve();
  }
}