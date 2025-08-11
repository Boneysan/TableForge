import { initializeApp } from "firebase/app";
import { getAuth, GoogleAuthProvider, signInWithRedirect, signInWithPopup, getRedirectResult, signOut, onAuthStateChanged } from "firebase/auth";
import type { User } from "firebase/auth";
import { FIREBASE_PROJECT_ID, GOOGLE_STORAGE_BUCKET, isDevelopment } from "./config";

// Check if Firebase configuration is available
if (isDevelopment) {
  console.log("🔥 [Firebase Client] Checking Firebase configuration...");
  console.log("🔥 [Firebase Client] VITE_FIREBASE_API_KEY present:", !!import.meta.env.VITE_FIREBASE_API_KEY);
  console.log("🔥 [Firebase Client] VITE_FIREBASE_PROJECT_ID:", FIREBASE_PROJECT_ID);
  console.log("🔥 [Firebase Client] VITE_FIREBASE_APP_ID present:", !!import.meta.env.VITE_FIREBASE_APP_ID);
}

const hasFirebaseConfig = !!(
  import.meta.env.VITE_FIREBASE_API_KEY &&
  FIREBASE_PROJECT_ID &&
  import.meta.env.VITE_FIREBASE_APP_ID
);

if (isDevelopment) {
  console.log("🔥 [Firebase Client] Has complete Firebase config:", hasFirebaseConfig);
}

const firebaseConfig = hasFirebaseConfig ? {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain: `${FIREBASE_PROJECT_ID}.firebaseapp.com`,
  projectId: FIREBASE_PROJECT_ID,
  storageBucket: `${FIREBASE_PROJECT_ID}.firebasestorage.app`,
  appId: import.meta.env.VITE_FIREBASE_APP_ID,
} : null;

console.log("🔥 [Firebase Client] Firebase config object:", firebaseConfig ? {
  ...firebaseConfig,
  apiKey: firebaseConfig.apiKey ? `${firebaseConfig.apiKey.substring(0, 8)}...` : "NOT_SET"
} : "NULL");

const app = firebaseConfig ? initializeApp(firebaseConfig) : null;
console.log("🔥 [Firebase Client] Firebase app initialized:", !!app);

export const auth = app ? getAuth(app) : null;
console.log("🔥 [Firebase Client] Firebase Auth instance created:", !!auth);

export const googleProvider = auth ? new GoogleAuthProvider() : null;
console.log("🔥 [Firebase Client] Google Auth Provider created:", !!googleProvider);

// Configure Google provider
if (googleProvider) {
  googleProvider.addScope('email');
  googleProvider.addScope('profile');
}

export const signInWithGoogle = () => {
  console.log("🔐 [Google Auth] Starting Google sign-in process...");
  
  if (!auth || !googleProvider) {
    console.error("❌ [Google Auth] Firebase not configured - auth:", !!auth, "provider:", !!googleProvider);
    throw new Error('Firebase not configured. Please add Firebase secrets.');
  }
  
  console.log("🔐 [Google Auth] Firebase components available:");
  console.log("🔐 [Google Auth] - Auth instance:", !!auth);
  console.log("🔐 [Google Auth] - Google provider:", !!googleProvider);
  console.log("🔐 [Google Auth] - Current URL:", window.location.origin);
  console.log("🔐 [Google Auth] - Auth domain:", `${import.meta.env.VITE_FIREBASE_PROJECT_ID}.firebaseapp.com`);
  
  // Always try popup first, let the error handler in the calling code deal with failures
  console.log("🔐 [Google Auth] Using popup authentication method");
  
  const authPromise = signInWithPopup(auth, googleProvider);
  
  authPromise.then((result) => {
    console.log("✅ [Google Auth] Sign-in successful!");
    console.log("✅ [Google Auth] User info:", {
      uid: result.user.uid,
      email: result.user.email,
      displayName: result.user.displayName,
      photoURL: result.user.photoURL
    });
    console.log("✅ [Google Auth] User authenticated successfully");
  }).catch((error) => {
    console.error("❌ [Google Auth] Sign-in failed:", error);
    console.error("❌ [Google Auth] Error details:", {
      code: error.code,
      message: error.message,
      email: error.email,
      credential: error.credential
    });
  });
  
  return authPromise;
};

export const handleRedirectResult = () => {
  if (!auth) {
    return Promise.resolve(null);
  }
  return getRedirectResult(auth);
};

export const signOutUser = () => {
  if (!auth) {
    return Promise.resolve();
  }
  return signOut(auth);
};

export const onAuthChange = (callback: (user: User | null) => void) => {
  console.log("🔐 [Auth State] Setting up auth state listener...");
  
  if (!auth) {
    console.log("⚠️ [Auth State] No auth instance, calling callback with null");
    callback(null);
    return () => {};
  }
  
  return onAuthStateChanged(auth, (user) => {
    if (user) {
      console.log("✅ [Auth State] User signed in:", {
        uid: user.uid,
        email: user.email,
        displayName: user.displayName,
        emailVerified: user.emailVerified,
        isAnonymous: user.isAnonymous
      });
    } else {
      console.log("ℹ️ [Auth State] User signed out");
    }
    callback(user);
  });
};

export const isFirebaseConfigured = () => hasFirebaseConfig;

export type { User };