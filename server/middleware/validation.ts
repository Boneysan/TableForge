import { z } from 'zod';
import { Request, Response, NextFunction } from 'express';

// Generic validation middleware factory
export function validateSchema<T extends z.ZodType>(schema: T, source: 'body' | 'query' | 'params' = 'body') {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      const data = req[source];
      const validatedData = schema.parse(data);
      
      // Replace the original data with validated data
      (req as any)[source] = validatedData;
      
      next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          error: 'Validation failed',
          details: error.errors.map(err => ({
            field: err.path.join('.'),
            message: err.message,
            code: err.code,
          })),
        });
      }
      
      return res.status(400).json({
        error: 'Invalid request data',
        message: error instanceof Error ? error.message : 'Unknown validation error',
      });
    }
  };
}

// Common validation schemas
export const commonSchemas = {
  objectId: z.string().min(1, 'ID is required'),
  pagination: z.object({
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(20),
  }),
  search: z.object({
    q: z.string().optional(),
    sort: z.enum(['name', 'createdAt', 'updatedAt']).optional(),
    order: z.enum(['asc', 'desc']).default('desc'),
  }),
};

// File upload validation
export const fileUploadSchema = z.object({
  filename: z.string().min(1, 'Filename is required'),
  mimetype: z.string().refine(
    (type) => [
      'image/jpeg',
      'image/png',
      'image/gif',
      'image/webp',
      'image/svg+xml',
      'application/pdf',
    ].includes(type),
    'Invalid file type'
  ),
  size: z.number().max(50 * 1024 * 1024, 'File size must be less than 50MB'),
});

// Room validation schemas
export const roomSchemas = {
  create: z.object({
    name: z.string().min(1, 'Room name is required').max(100, 'Room name too long'),
    description: z.string().optional(),
    isPublic: z.boolean().default(false),
    maxPlayers: z.number().int().min(1).max(20).default(8),
  }),
  update: z.object({
    name: z.string().min(1).max(100).optional(),
    description: z.string().optional(),
    isPublic: z.boolean().optional(),
    maxPlayers: z.number().int().min(1).max(20).optional(),
  }),
  join: z.object({
    password: z.string().optional(),
  }),
};

// Game system validation schemas
export const systemSchemas = {
  create: z.object({
    name: z.string().min(1, 'System name is required').max(100, 'System name too long'),
    description: z.string().optional(),
    version: z.string().default('1.0.0'),
    tags: z.array(z.string()).default([]),
  }),
  update: z.object({
    name: z.string().min(1).max(100).optional(),
    description: z.string().optional(),
    version: z.string().optional(),
    tags: z.array(z.string()).optional(),
  }),
};

// Asset validation schemas  
export const assetSchemas = {
  create: z.object({
    name: z.string().min(1, 'Asset name is required').max(100, 'Asset name too long'),
    type: z.enum(['card', 'token', 'map', 'rule']),
    category: z.string().optional(),
    tags: z.array(z.string()).default([]),
    metadata: z.record(z.any()).optional(),
  }),
  update: z.object({
    name: z.string().min(1).max(100).optional(),
    type: z.enum(['card', 'token', 'map', 'rule']).optional(),
    category: z.string().optional(),
    tags: z.array(z.string()).optional(),
    metadata: z.record(z.any()).optional(),
  }),
};