/**
 * Text Sanitization and Input Validation
 * 
 * Provides secure text sanitization for user input, especially for drawing
 * annotations and chat messages to prevent XSS and other injection attacks.
 */

import DOMPurify from 'dompurify';

// Configuration for different content types
const SANITIZATION_CONFIG = {
  // For chat messages and annotations
  chat: {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'u', 'br'],
    ALLOWED_ATTR: [],
    KEEP_CONTENT: true,
    RETURN_DOM: false,
    RETURN_DOM_FRAGMENT: false,
    SANITIZE_DOM: true,
  },
  
  // For drawing annotations (most restrictive)
  annotation: {
    ALLOWED_TAGS: [],
    ALLOWED_ATTR: [],
    KEEP_CONTENT: true,
    RETURN_DOM: false,
    RETURN_DOM_FRAGMENT: false,
    SANITIZE_DOM: true,
  },

  // For general text content
  general: {
    ALLOWED_TAGS: ['p', 'br', 'b', 'i', 'em', 'strong', 'u', 'span'],
    ALLOWED_ATTR: ['class'],
    KEEP_CONTENT: true,
    RETURN_DOM: false,
    RETURN_DOM_FRAGMENT: false,
    SANITIZE_DOM: true,
  }
} as const;

// Rate limiting for stroke points per second
const STROKE_RATE_LIMITS = {
  MAX_POINTS_PER_SECOND: 120, // Reasonable for fast drawing
  MAX_POINTS_PER_MINUTE: 3600, // Prevent abuse
  BURST_ALLOWANCE: 50, // Allow short bursts
  COOLDOWN_PERIOD: 1000, // 1 second cooldown
} as const;

// Track stroke points per user
interface StrokeRateTracker {
  points: number;
  lastReset: number;
  burstUsed: number;
  lastBurst: number;
}

const strokeTrackers = new Map<string, StrokeRateTracker>();

/**
 * Sanitize text content based on context
 */
export function sanitizeText(
  text: string, 
  context: keyof typeof SANITIZATION_CONFIG = 'general'
): string {
  if (!text || typeof text !== 'string') {
    return '';
  }

  // Basic length check
  if (text.length > 10000) {
    throw new Error('Text too long (maximum 10,000 characters)');
  }

  const config = SANITIZATION_CONFIG[context];
  
  // Use DOMPurify for sanitization
  const sanitized = DOMPurify.sanitize(text, config);
  
  // Additional validation for specific contexts
  if (context === 'annotation') {
    return sanitizeAnnotationText(sanitized);
  }
  
  return sanitized;
}

/**
 * Extra sanitization for drawing annotations
 */
function sanitizeAnnotationText(text: string): string {
  // Remove any remaining HTML-like patterns
  let cleaned = text.replace(/<[^>]*>/g, '');
  
  // Remove script-like patterns
  cleaned = cleaned.replace(/javascript:/gi, '');
  cleaned = cleaned.replace(/data:/gi, '');
  cleaned = cleaned.replace(/vbscript:/gi, '');
  
  // Remove excessive whitespace
  cleaned = cleaned.replace(/\s+/g, ' ').trim();
  
  // Limit length for annotations
  if (cleaned.length > 500) {
    cleaned = cleaned.substring(0, 500) + '...';
  }
  
  return cleaned;
}

/**
 * Validate and rate limit stroke points for drawing
 */
export function validateStrokePoints(
  userId: string,
  points: Array<{ x: number; y: number; pressure?: number }>,
  timestamp: number = Date.now()
): { allowed: boolean; reason?: string } {
  if (!Array.isArray(points)) {
    return { allowed: false, reason: 'Invalid points format' };
  }

  // Validate individual points
  for (const point of points) {
    if (
      typeof point.x !== 'number' || 
      typeof point.y !== 'number' ||
      !isFinite(point.x) || 
      !isFinite(point.y) ||
      Math.abs(point.x) > 50000 ||
      Math.abs(point.y) > 50000
    ) {
      return { allowed: false, reason: 'Invalid point coordinates' };
    }

    if (point.pressure !== undefined) {
      if (
        typeof point.pressure !== 'number' ||
        !isFinite(point.pressure) ||
        point.pressure < 0 ||
        point.pressure > 1
      ) {
        return { allowed: false, reason: 'Invalid pressure value' };
      }
    }
  }

  // Get or create tracker for user
  let tracker = strokeTrackers.get(userId);
  if (!tracker) {
    tracker = {
      points: 0,
      lastReset: timestamp,
      burstUsed: 0,
      lastBurst: timestamp,
    };
    strokeTrackers.set(userId, tracker);
  }

  // Reset counters if enough time has passed
  if (timestamp - tracker.lastReset >= 1000) {
    tracker.points = 0;
    tracker.lastReset = timestamp;
  }

  // Reset burst allowance if cooldown has passed
  if (timestamp - tracker.lastBurst >= STROKE_RATE_LIMITS.COOLDOWN_PERIOD) {
    tracker.burstUsed = 0;
    tracker.lastBurst = timestamp;
  }

  // Check rate limits
  const pointsToAdd = points.length;
  
  // Check per-second limit
  if (tracker.points + pointsToAdd > STROKE_RATE_LIMITS.MAX_POINTS_PER_SECOND) {
    // Allow burst if available
    const burstNeeded = (tracker.points + pointsToAdd) - STROKE_RATE_LIMITS.MAX_POINTS_PER_SECOND;
    
    if (tracker.burstUsed + burstNeeded <= STROKE_RATE_LIMITS.BURST_ALLOWANCE) {
      tracker.burstUsed += burstNeeded;
    } else {
      return { 
        allowed: false, 
        reason: `Drawing too fast (limit: ${STROKE_RATE_LIMITS.MAX_POINTS_PER_SECOND} points/second)` 
      };
    }
  }

  // Update tracker
  tracker.points += pointsToAdd;
  
  return { allowed: true };
}

/**
 * Sanitize drawing stroke data
 */
export function sanitizeStrokeData(strokeData: {
  points: Array<{ x: number; y: number; pressure?: number }>;
  color?: string;
  width?: number;
  tool?: string;
  userId: string;
  timestamp?: number;
}): {
  sanitized: typeof strokeData;
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];
  const timestamp = strokeData.timestamp || Date.now();

  // Validate stroke points
  const pointValidation = validateStrokePoints(
    strokeData.userId, 
    strokeData.points, 
    timestamp
  );

  if (!pointValidation.allowed) {
    errors.push(pointValidation.reason || 'Invalid stroke points');
  }

  // Sanitize color
  let color = '#000000'; // Default black
  if (strokeData.color) {
    const colorMatch = strokeData.color.match(/^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/);
    if (colorMatch) {
      color = strokeData.color;
    } else {
      errors.push('Invalid color format');
    }
  }

  // Validate width
  let width = 2; // Default width
  if (strokeData.width !== undefined) {
    if (
      typeof strokeData.width === 'number' &&
      isFinite(strokeData.width) &&
      strokeData.width >= 1 &&
      strokeData.width <= 50
    ) {
      width = strokeData.width;
    } else {
      errors.push('Invalid stroke width (must be 1-50)');
    }
  }

  // Validate tool
  const allowedTools = ['pen', 'brush', 'marker', 'pencil', 'highlighter'];
  let tool = 'pen'; // Default tool
  if (strokeData.tool) {
    if (allowedTools.includes(strokeData.tool)) {
      tool = strokeData.tool;
    } else {
      errors.push('Invalid drawing tool');
    }
  }

  const sanitized = {
    points: strokeData.points, // Already validated above
    color,
    width,
    tool,
    userId: strokeData.userId,
    timestamp,
  };

  return {
    sanitized,
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Clean up old stroke trackers to prevent memory leaks
 */
export function cleanupStrokeTrackers(): void {
  const now = Date.now();
  const maxAge = 5 * 60 * 1000; // 5 minutes
  
  for (const [userId, tracker] of strokeTrackers.entries()) {
    if (now - tracker.lastReset > maxAge) {
      strokeTrackers.delete(userId);
    }
  }
}

// Clean up trackers periodically
if (typeof setInterval !== 'undefined') {
  setInterval(cleanupStrokeTrackers, 60 * 1000); // Every minute
}

/**
 * Validate chat message content
 */
export function validateChatMessage(message: {
  content: string;
  userId: string;
  roomId: string;
  messageType?: 'chat' | 'system' | 'roll';
}): {
  valid: boolean;
  sanitized: string;
  errors: string[];
} {
  const errors: string[] = [];

  if (!message.content || typeof message.content !== 'string') {
    errors.push('Message content is required');
    return { valid: false, sanitized: '', errors };
  }

  if (message.content.length > 2000) {
    errors.push('Message too long (maximum 2000 characters)');
  }

  if (!message.userId || typeof message.userId !== 'string') {
    errors.push('User ID is required');
  }

  if (!message.roomId || typeof message.roomId !== 'string') {
    errors.push('Room ID is required');
  }

  // Sanitize the content
  const sanitized = sanitizeText(message.content, 'chat');

  // Check for spam patterns
  if (sanitized.length > 0) {
    const repeatedChars = /(.)\1{20,}/g;
    if (repeatedChars.test(sanitized)) {
      errors.push('Message contains excessive repeated characters');
    }
  }

  return {
    valid: errors.length === 0,
    sanitized,
    errors,
  };
}

/**
 * Export types for TypeScript
 */
export type SanitizationContext = keyof typeof SANITIZATION_CONFIG;
export type StrokePoint = { x: number; y: number; pressure?: number };
export type StrokeData = {
  points: StrokePoint[];
  color?: string;
  width?: number;
  tool?: string;
  userId: string;
  timestamp?: number;
};