import { Request, Response, NextFunction } from "express";
import * as admin from "firebase-admin";

// Initialize Firebase Admin SDK if not already initialized
try {
  if (!admin.apps.length) {
    // In development, Firebase Admin SDK will use the default credentials
    // In production, you might need to provide service account credentials
    admin.initializeApp({
      // You can add your Firebase config here if needed
      // credential: admin.credential.applicationDefault(),
    });
  }
} catch (error) {
  console.warn("Firebase Admin SDK initialization skipped:", error);
}

export interface FirebaseUser {
  uid: string;
  email?: string;
  displayName?: string;
  photoURL?: string;
}

export async function verifyFirebaseToken(idToken: string): Promise<FirebaseUser | null> {
  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    return {
      uid: decodedToken.uid,
      email: decodedToken.email,
      displayName: decodedToken.name,
      photoURL: decodedToken.picture,
    };
  } catch (error) {
    console.error("Error verifying Firebase token:", error);
    return null;
  }
}

export const firebaseAuthMiddleware = async (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const idToken = authHeader.split('Bearer ')[1];
  
  try {
    const user = await verifyFirebaseToken(idToken);
    if (!user) {
      return res.status(401).json({ message: "Invalid token" });
    }
    
    // Attach user info to request
    req.user = user;
    next();
  } catch (error) {
    console.error("Firebase auth middleware error:", error);
    return res.status(401).json({ message: "Unauthorized" });
  }
};