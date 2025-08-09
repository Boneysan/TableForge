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
  console.log(`🔄 [Hybrid Auth] ${req.method} ${req.path} - Processing hybrid authentication`);
  
  const authHeader = req.headers.authorization;
  console.log("🔄 [Hybrid Auth] Auth header present:", !!authHeader);
  console.log("🔄 [Hybrid Auth] Auth header type:", authHeader?.startsWith('Bearer ') ? 'Bearer Token' : 'Other/None');
  
  // If there's a Bearer token, try Firebase auth first
  if (authHeader && authHeader.startsWith('Bearer ')) {
    console.log("🔄 [Hybrid Auth] Attempting Firebase authentication...");
    return firebaseAuthMiddleware(req, res, (err) => {
      if (err) {
        console.log("⚠️ [Hybrid Auth] Firebase auth failed, falling back to Replit auth...");
        // Firebase auth failed, fall back to Replit auth
        return isAuthenticated(req, res, next);
      }
      console.log("✅ [Hybrid Auth] Firebase auth succeeded");
      // Firebase auth succeeded, convert to hybrid user format
      if (req.user) {
        const firebaseUser = req.user as FirebaseUser;
        const hybridUser = {
          uid: firebaseUser.uid,
          email: firebaseUser.email,
          displayName: firebaseUser.displayName,
          photoURL: firebaseUser.photoURL,
          source: 'firebase'
        } as HybridUser;
        req.user = hybridUser;
        console.log("✅ [Hybrid Auth] Converted to hybrid user:", {
          uid: hybridUser.uid,
          email: hybridUser.email,
          displayName: hybridUser.displayName,
          source: hybridUser.source
        });
      }
      next();
    });
  }
  
  console.log("🔄 [Hybrid Auth] No Bearer token, attempting Replit authentication...");
  // No Bearer token, try Replit auth
  return isAuthenticated(req, res, (err?: any) => {
    if (err) {
      console.log("❌ [Hybrid Auth] Both Firebase and Replit auth failed");
      return res.status(401).json({ message: "Unauthorized" });
    }
    console.log("✅ [Hybrid Auth] Replit auth succeeded");
    // Replit auth succeeded, convert to hybrid user format
    if (req.user && (req.user as any).claims) {
      const replitUser = req.user as any;
      const hybridUser = {
        uid: replitUser.claims.sub,
        email: replitUser.claims.email,
        displayName: replitUser.claims.first_name || replitUser.claims.email?.split('@')[0],
        photoURL: replitUser.claims.profile_image_url,
        source: 'replit'
      } as HybridUser;
      req.user = hybridUser;
      console.log("✅ [Hybrid Auth] Converted to hybrid user:", {
        uid: hybridUser.uid,
        email: hybridUser.email,
        displayName: hybridUser.displayName,
        source: hybridUser.source
      });
    }
    next();
  });
};