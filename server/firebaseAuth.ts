import { Request, Response, NextFunction } from "express";
import admin from "firebase-admin";

// Initialize Firebase Admin SDK if not already initialized
let firebaseAdminInitialized = false;

// Add global error handlers to catch Firebase Admin errors
process.on('unhandledRejection', (reason, promise) => {
  console.error("❌ [Global] Unhandled rejection:", reason);
});

console.log("🔥 [Firebase Admin] Starting initialization process...");
console.log("🔥 [Firebase Admin] Service account key available:", !!process.env.FIREBASE_SERVICE_ACCOUNT_KEY);

// Initialize Firebase Admin with safer approach
try {
  console.log("🔥 [Firebase Admin] Attempting to access Firebase Admin apps...");
  // Use try-catch to handle undefined admin.apps gracefully
  let currentApps = [];
  try {
    currentApps = admin.apps || [];
    console.log("🔥 [Firebase Admin] admin.apps is available, current count:", currentApps.length);
  } catch (appsError) {
    console.log("⚠️ [Firebase Admin] Cannot access admin.apps, initializing directly");
    currentApps = [];
  }
  
  console.log("🔥 [Firebase Admin] Attempting to initialize Firebase Admin SDK...");
  console.log("🔥 [Firebase Admin] Current apps count:", currentApps.length);
  
  if (currentApps.length === 0) {
    console.log("🔥 [Firebase Admin] No existing apps found, initializing new app...");
    
    const serviceAccountKey = process.env.FIREBASE_SERVICE_ACCOUNT_KEY;
    if (serviceAccountKey) {
      console.log("🔥 [Firebase Admin] Service account key found, using credential authentication...");
      console.log("🔥 [Firebase Admin] Service account key length:", serviceAccountKey.length);
      try {
        const serviceAccount = JSON.parse(serviceAccountKey);
        console.log("🔥 [Firebase Admin] Service account parsed successfully");
        console.log("🔥 [Firebase Admin] Project ID from service account:", serviceAccount.project_id);
        console.log("🔥 [Firebase Admin] Creating credential with service account...");
        console.log("🔥 [Firebase Admin] Checking admin.credential availability:", !!admin.credential);
        
        if (!admin.credential) {
          console.error("❌ [Firebase Admin] admin.credential is undefined - Firebase Admin SDK not properly loaded");
          throw new Error("Firebase Admin credential module not available");
        }
        
        let credential;
        try {
          console.log("🔥 [Firebase Admin] Calling admin.credential.cert()...");
          credential = admin.credential.cert(serviceAccount);
          console.log("🔥 [Firebase Admin] Credential created successfully");
        } catch (credError) {
          console.error("❌ [Firebase Admin] Error creating credential:", credError);
          throw credError;
        }
        
        console.log("🔥 [Firebase Admin] Initializing Firebase app...");
        try {
          admin.initializeApp({
            credential: credential,
          });
          console.log("✅ [Firebase Admin] Firebase app initialized successfully");
        } catch (initError) {
          console.error("❌ [Firebase Admin] Error initializing app:", initError);
          throw initError;
        }
      } catch (parseError) {
        console.error("❌ [Firebase Admin] Failed to parse service account key:", parseError);
        throw parseError;
      }
    } else {
      console.log("🔥 [Firebase Admin] No service account key found, using default credentials...");
      admin.initializeApp({
        projectId: process.env.VITE_FIREBASE_PROJECT_ID || "board-games-f2082",
      });
    }
    firebaseAdminInitialized = true;
    console.log("✅ [Firebase Admin] Firebase Admin SDK initialized successfully");
  } else if (currentApps.length > 0) {
    firebaseAdminInitialized = true;
    console.log("✅ [Firebase Admin] Firebase Admin SDK already initialized, using existing app");
  }
} catch (error) {
    console.error("❌ [Firebase Admin] Firebase Admin SDK initialization failed:", error);
    if (error instanceof Error) {
      console.error("❌ [Firebase Admin] Error details:", {
        name: error.name,
        message: error.message,
        code: (error as any).code,
        stack: error.stack
      });
    }
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
    if (error instanceof Error) {
      console.error("❌ [Firebase Auth] Error details:", {
        name: error.name,
        message: error.message,
        code: (error as any).code,
        stack: error.stack
      });
    }
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