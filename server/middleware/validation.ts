import type { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import type { ValidationError } from '@shared/validators';
import { validateSchema, createValidationError } from '@shared/validators';

// Enhanced request interface with validated data
interface ValidatedRequest<T = any> extends Request {
  validatedData: T;
}

// Generic validation middleware factory for request bodies
export function validateBody<T>(schema: z.ZodSchema<T>) {
  return (req: Request, res: Response, next: NextFunction) => {
    console.log(`🔍 [Validation] Validating request body for ${req.method} ${req.path}`);
    console.log(`🔍 [Validation] Request body:`, req.body);

    const result = validateSchema(schema, req.body);

    if (!result.success) {
      console.log(`❌ [Validation] Body validation failed:`, result.error);
      return res.status(400).json(result.error);
    }

    console.log(`✅ [Validation] Body validation passed`);
    (req as ValidatedRequest<T>).validatedData = result.data;
    next();
  };
}

// Generic validation middleware factory for query parameters
export function validateQuery<T>(schema: z.ZodSchema<T>) {
  return (req: Request, res: Response, next: NextFunction) => {
    console.log(`🔍 [Validation] Validating query params for ${req.method} ${req.path}`);
    console.log(`🔍 [Validation] Query params:`, req.query);

    const result = validateSchema(schema, req.query);

    if (!result.success) {
      console.log(`❌ [Validation] Query validation failed:`, result.error);
      return res.status(400).json(result.error);
    }

    console.log(`✅ [Validation] Query validation passed`);
    (req as ValidatedRequest<T>).validatedData = result.data;
    next();
  };
}

// Generic validation middleware factory for route parameters
export function validateParams<T>(schema: z.ZodSchema<T>) {
  return (req: Request, res: Response, next: NextFunction) => {
    console.log(`🔍 [Validation] Validating route params for ${req.method} ${req.path}`);
    console.log(`🔍 [Validation] Route params:`, req.params);

    const result = validateSchema(schema, req.params);

    if (!result.success) {
      console.log(`❌ [Validation] Params validation failed:`, result.error);
      return res.status(400).json(result.error);
    }

    console.log(`✅ [Validation] Params validation passed`);
    (req as ValidatedRequest<T>).validatedData = result.data;
    next();
  };
}

// Combined validation middleware for body + params
export function validateBodyAndParams<TBody, TParams>(
  bodySchema: z.ZodSchema<TBody>,
  paramsSchema: z.ZodSchema<TParams>,
) {
  return (req: Request, res: Response, next: NextFunction) => {
    console.log(`🔍 [Validation] Validating body and params for ${req.method} ${req.path}`);

    // Validate body
    const bodyResult = validateSchema(bodySchema, req.body);
    if (!bodyResult.success) {
      console.log(`❌ [Validation] Body validation failed:`, bodyResult.error);
      return res.status(400).json(bodyResult.error);
    }

    // Validate params
    const paramsResult = validateSchema(paramsSchema, req.params);
    if (!paramsResult.success) {
      console.log(`❌ [Validation] Params validation failed:`, paramsResult.error);
      return res.status(400).json(paramsResult.error);
    }

    console.log(`✅ [Validation] Combined validation passed`);
    (req as ValidatedRequest<{ body: TBody; params: TParams }>).validatedData = {
      body: bodyResult.data,
      params: paramsResult.data,
    };
    next();
  };
}

// Specific validation middleware for common patterns
export const validateRoomId = validateParams(z.object({
  roomId: z.string().min(1, 'Room ID is required'),
}));

export const validateAssetId = validateParams(z.object({
  id: z.string().min(1, 'Asset ID is required'),
}));

export const validateUserId = validateParams(z.object({
  userId: z.string().min(1, 'User ID is required'),
}));

export const validatePagination = validateQuery(z.object({
  limit: z.coerce.number().min(1).max(100).default(10),
  offset: z.coerce.number().min(0).default(0),
}));

export const validateLimit = validateQuery(z.object({
  limit: z.coerce.number().min(1).max(100).default(10),
}));

// Error handling for validation failures
export function handleValidationError(error: ValidationError, res: Response): void {
  console.log(`❌ [Validation] Sending validation error response:`, error);
  res.status(400).json(error);
}

// Type guard for validated requests
export function isValidatedRequest<T>(req: Request): req is ValidatedRequest<T> {
  return 'validatedData' in req;
}

// Helper to get validated data from request
export function getValidatedData<T>(req: Request): T {
  if (isValidatedRequest<T>(req)) {
    return req.validatedData;
  }
  throw new Error('Request not validated. Ensure validation middleware is applied.');
}

// WebSocket validation helper
export function validateWebSocketMessage<T>(schema: z.ZodSchema<T>, message: unknown): { success: true; data: T } | { success: false; error: ValidationError } {
  console.log(`🔍 [WS Validation] Validating WebSocket message`);
  console.log(`🔍 [WS Validation] Message:`, message);

  const result = validateSchema(schema, message);

  if (!result.success) {
    console.log(`❌ [WS Validation] Message validation failed:`, result.error);
  } else {
    console.log(`✅ [WS Validation] Message validation passed`);
  }

  return result;
}

// Export types
export type { ValidatedRequest };
