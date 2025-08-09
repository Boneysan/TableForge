import { Request, Response, NextFunction } from "express";
import * as admin from "firebase-admin";

// Initialize Firebase Admin SDK if not already initialized
let firebaseAdminInitialized = false;
try {
  console.log("🔥 [Firebase Admin] Attempting to initialize Firebase Admin SDK...");
  console.log("🔥 [Firebase Admin] Current apps count:", admin.apps ? admin.apps.length : 0);
  
  if (admin.apps && admin.apps.length === 0) {
    console.log("🔥 [Firebase Admin] No existing apps found, initializing new app...");
    // In development, Firebase Admin SDK will use the default credentials
    // In production, you might need to provide service account credentials
    admin.initializeApp({
      // You can add your Firebase config here if needed
      // credential: admin.credential.applicationDefault(),
    });
    firebaseAdminInitialized = true;
    console.log("✅ [Firebase Admin] Firebase Admin SDK initialized successfully");
  } else if (admin.apps && admin.apps.length > 0) {
    firebaseAdminInitialized = true;
    console.log("✅ [Firebase Admin] Firebase Admin SDK already initialized, using existing app");
  }
} catch (error) {
  console.error("❌ [Firebase Admin] Firebase Admin SDK initialization failed:", error);
  console.error("❌ [Firebase Admin] Error details:", {
    name: error.name,
    message: error.message,
    code: error.code,
    stack: error.stack
  });
}

export interface FirebaseUser {
  uid: string;
  email?: string;
  displayName?: string;
  photoURL?: string;
}

export async function verifyFirebaseToken(idToken: string): Promise<FirebaseUser | null> {
  try {
    console.log("🔐 [Firebase Auth] Attempting to verify Firebase ID token...");
    console.log("🔐 [Firebase Auth] Token length:", idToken?.length || 0);
    console.log("🔐 [Firebase Auth] Firebase Admin initialized:", firebaseAdminInitialized);
    
    if (!firebaseAdminInitialized) {
      console.warn("⚠️ [Firebase Auth] Firebase Admin not initialized, skipping token verification");
      return null;
    }
    
    console.log("🔐 [Firebase Auth] Calling admin.auth().verifyIdToken()...");
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    
    console.log("✅ [Firebase Auth] Token verified successfully");
    console.log("✅ [Firebase Auth] Decoded token details:", {
      uid: decodedToken.uid,
      email: decodedToken.email,
      name: decodedToken.name,
      picture: decodedToken.picture,
      iss: decodedToken.iss,
      aud: decodedToken.aud,
      exp: new Date(decodedToken.exp * 1000).toISOString(),
      iat: new Date(decodedToken.iat * 1000).toISOString()
    });
    
    return {
      uid: decodedToken.uid,
      email: decodedToken.email,
      displayName: decodedToken.name,
      photoURL: decodedToken.picture,
    };
  } catch (error) {
    console.error("❌ [Firebase Auth] Error verifying Firebase token:", error);
    console.error("❌ [Firebase Auth] Error details:", {
      name: error.name,
      message: error.message,
      code: error.code,
      stack: error.stack
    });
    return null;
  }
}

export const firebaseAuthMiddleware = async (req: Request, res: Response, next: NextFunction) => {
  console.log(`🔐 [Firebase Middleware] ${req.method} ${req.path} - Processing authentication`);
  
  const authHeader = req.headers.authorization;
  console.log("🔐 [Firebase Middleware] Auth header present:", !!authHeader);
  console.log("🔐 [Firebase Middleware] Auth header starts with 'Bearer ':", authHeader?.startsWith('Bearer '));
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.log("❌ [Firebase Middleware] No valid authorization header found");
    return res.status(401).json({ message: "Unauthorized" });
  }

  const idToken = authHeader.split('Bearer ')[1];
  console.log("🔐 [Firebase Middleware] Extracted token length:", idToken?.length || 0);
  
  try {
    const user = await verifyFirebaseToken(idToken);
    if (!user) {
      console.log("❌ [Firebase Middleware] Token verification failed");
      return res.status(401).json({ message: "Invalid token" });
    }
    
    console.log("✅ [Firebase Middleware] User authenticated successfully:", {
      uid: user.uid,
      email: user.email,
      displayName: user.displayName
    });
    
    // Attach user info to request
    req.user = user;
    next();
  } catch (error) {
    console.error("❌ [Firebase Middleware] Middleware error:", error);
    return res.status(401).json({ message: "Unauthorized" });
  }
};