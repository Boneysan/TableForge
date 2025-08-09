import { initializeApp } from "firebase/app";
import { getAuth, GoogleAuthProvider, signInWithRedirect, getRedirectResult, signOut, onAuthStateChanged } from "firebase/auth";
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
  return signInWithRedirect(auth, googleProvider);
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