import { initializeApp } from "firebase/app";
import { getAuth, GoogleAuthProvider, signInWithRedirect, signInWithPopup, getRedirectResult, signOut, onAuthStateChanged } from "firebase/auth";
import type { User } from "firebase/auth";

// Check if Firebase configuration is available
const hasFirebaseConfig = !!(
  import.meta.env.VITE_FIREBASE_API_KEY &&
  import.meta.env.VITE_FIREBASE_PROJECT_ID &&
  import.meta.env.VITE_FIREBASE_APP_ID
);

const firebaseConfig = hasFirebaseConfig ? {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain: `${import.meta.env.VITE_FIREBASE_PROJECT_ID}.firebaseapp.com`,
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID,
  storageBucket: `${import.meta.env.VITE_FIREBASE_PROJECT_ID}.firebasestorage.app`,
  appId: import.meta.env.VITE_FIREBASE_APP_ID,
} : null;

const app = firebaseConfig ? initializeApp(firebaseConfig) : null;
export const auth = app ? getAuth(app) : null;
export const googleProvider = auth ? new GoogleAuthProvider() : null;

// Configure Google provider
if (googleProvider) {
  googleProvider.addScope('email');
  googleProvider.addScope('profile');
}

export const signInWithGoogle = () => {
  if (!auth || !googleProvider) {
    throw new Error('Firebase not configured. Please add Firebase secrets.');
  }
  console.log('Initiating Google sign-in from:', window.location.origin);
  console.log('Auth domain:', `${import.meta.env.VITE_FIREBASE_PROJECT_ID}.firebaseapp.com`);
  
  // Check if we're in Replit development environment
  const isReplitDev = window.location.hostname.includes('.janeway.replit.dev') || 
                      window.location.hostname.includes('.replit.dev');
  
  if (isReplitDev) {
    console.log('Development environment detected - redirecting to Firebase auth page');
    // Create direct Firebase auth URL for development
    const authUrl = `https://${import.meta.env.VITE_FIREBASE_PROJECT_ID}.firebaseapp.com/__/auth/handler?` +
      `apiKey=${import.meta.env.VITE_FIREBASE_API_KEY}&` +
      `providerId=google.com&` +
      `scopes=email,profile&` +
      `customParameter=%7B%7D&` +
      `redirectUrl=${encodeURIComponent(window.location.origin)}`;
    
    window.location.href = authUrl;
    return Promise.resolve();
  } else {
    console.log('Using popup authentication for production environment');
    return signInWithPopup(auth, googleProvider);
  }
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
  if (!auth) {
    callback(null);
    return () => {};
  }
  return onAuthStateChanged(auth, callback);
};

export const isFirebaseConfigured = () => hasFirebaseConfig;

export type { User };