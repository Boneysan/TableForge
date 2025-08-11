import type { Request, Response, NextFunction } from 'express';
import { validateFirebaseToken, extractTokenFromRequest, validateTokenFreshness, type ValidatedUser } from './tokenValidator';
import { roomAuthManager } from './roomAuth';

// Extend Request type to include validated user
declare global {
  namespace Express {
    interface Request {
      user?: ValidatedUser;
      roomClaims?: any;
    }
  }
}

/**
 * Middleware to authenticate and validate Firebase ID tokens
 */
export const authenticateToken = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    console.log('🔐 [Auth Middleware] Authenticating request:', {
      method: req.method,
      path: req.path,
      hasAuth: !!req.headers.authorization,
    });

    const token = extractTokenFromRequest(req);
    if (!token) {
      res.status(401).json({
        error: 'Authentication required',
        message: 'Valid authentication token must be provided',
      });
      return;
    }

    const user = await validateFirebaseToken(token);

    if (!validateTokenFreshness(user)) {
      res.status(401).json({
        error: 'Token expired',
        message: 'Authentication token has expired, please sign in again',
      });
      return;
    }

    // Attach validated user to request
    req.user = user;

    console.log('✅ [Auth Middleware] User authenticated:', {
      uid: user.uid,
      email: user.email,
      source: user.source,
    });

    next();
  } catch (error) {
    console.error('❌ [Auth Middleware] Authentication failed:', error);
    res.status(401).json({
      error: 'Authentication failed',
      message: error instanceof Error ? error.message : 'Invalid authentication token',
    });
  }
};

/**
 * Middleware to validate room membership and permissions
 */
export const authorizeRoom = (requiredPermission = 'read_room') => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.user) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const roomId = req.params.roomId || req.body.roomId;
      if (!roomId) {
        res.status(400).json({ error: 'Room ID is required' });
        return;
      }

      console.log('🏠 [Room Auth Middleware] Authorizing room access:', {
        userId: req.user.uid,
        roomId,
        requiredPermission,
        path: req.path,
      });

      const result = await roomAuthManager.validateRoomAction(
        req.user,
        roomId,
        req.path,
        requiredPermission,
      );

      if (!result.allowed) {
        console.log('❌ [Room Auth Middleware] Access denied:', result.reason);
        res.status(403).json({
          error: 'Access denied',
          message: result.reason || 'Insufficient permissions for this room',
        });
        return;
      }

      // Attach room claims to request
      req.roomClaims = result.claims;

      console.log('✅ [Room Auth Middleware] Room access authorized');
      next();
    } catch (error) {
      console.error('❌ [Room Auth Middleware] Authorization error:', error);
      res.status(500).json({
        error: 'Authorization error',
        message: 'Failed to validate room permissions',
      });
    }
  };
};

/**
 * Optional authentication middleware (doesn't fail if no token)
 */
export const optionalAuth = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const token = extractTokenFromRequest(req);
    if (token) {
      const user = await validateFirebaseToken(token);
      if (validateTokenFreshness(user)) {
        req.user = user;
        console.log('✅ [Optional Auth] User authenticated:', user.uid);
      }
    }
    next();
  } catch (error) {
    // Continue without authentication
    console.log('⚠️ [Optional Auth] Authentication failed, continuing without user');
    next();
  }
};

/**
 * Middleware to log authentication events for security monitoring
 */
export const logAuthEvents = (req: Request, res: Response, next: NextFunction): void => {
  const originalSend = res.send;

  res.send = function(body: any) {
    // Log authentication failures
    if (res.statusCode === 401 || res.statusCode === 403) {
      console.warn('🚨 [Auth Monitor] Authentication/Authorization failure:', {
        ip: req.ip,
        method: req.method,
        path: req.path,
        userAgent: req.get('User-Agent'),
        statusCode: res.statusCode,
        userId: req.user?.uid,
        timestamp: new Date().toISOString(),
      });
    }

    return originalSend.call(this, body);
  };

  next();
};
