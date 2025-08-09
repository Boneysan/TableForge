import { Request, Response, NextFunction } from "express";
import { firebaseAuthMiddleware, type FirebaseUser } from "./firebaseAuth";
import { isAuthenticated } from "./replitAuth";

export interface HybridUser {
  uid: string;
  email?: string;
  displayName?: string;
  photoURL?: string;
  source: 'firebase' | 'replit';
}

// Middleware that supports both Firebase and Replit authentication
export const hybridAuthMiddleware = async (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  
  // If there's a Bearer token, try Firebase auth first
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return firebaseAuthMiddleware(req, res, (err) => {
      if (err) {
        // Firebase auth failed, fall back to Replit auth
        return isAuthenticated(req, res, next);
      }
      // Firebase auth succeeded, convert to hybrid user format
      if (req.user) {
        const firebaseUser = req.user as FirebaseUser;
        req.user = {
          uid: firebaseUser.uid,
          email: firebaseUser.email,
          displayName: firebaseUser.displayName,
          photoURL: firebaseUser.photoURL,
          source: 'firebase'
        } as HybridUser;
      }
      next();
    });
  }
  
  // No Bearer token, try Replit auth
  return isAuthenticated(req, res, (err?: any) => {
    if (err) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    // Replit auth succeeded, convert to hybrid user format
    if (req.user && (req.user as any).claims) {
      const replitUser = req.user as any;
      req.user = {
        uid: replitUser.claims.sub,
        email: replitUser.claims.email,
        displayName: replitUser.claims.first_name || replitUser.claims.email?.split('@')[0],
        photoURL: replitUser.claims.profile_image_url,
        source: 'replit'
      } as HybridUser;
    }
    next();
  });
};