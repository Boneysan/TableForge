import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { authenticatedApiRequest } from "@/lib/authClient";
import { onAuthChange } from "@/lib/firebase";

export function useAuth() {
  const queryClient = useQueryClient();

  const { data: user, isLoading, error } = useQuery({
    queryKey: ["/api/auth/user"],
    queryFn: async () => {
      console.log("🔐 [useAuth] Fetching user data with Firebase auth...");
      try {
        const response = await authenticatedApiRequest("GET", "/api/auth/user");
        const userData = await response.json();
        console.log("✅ [useAuth] User data fetched successfully:", userData);
        return userData;
      } catch (error) {
        console.error("❌ [useAuth] Failed to fetch user data:", error);
        // Don't throw for 401 errors, just return null to indicate no user
        if (error instanceof Error && error.message.includes('401')) {
          console.log("ℹ️ [useAuth] User not authenticated, returning null");
          return null;
        }
        throw error;
      }
    },
    retry: false,
  });

  // Listen for Firebase auth state changes and refetch user data
  useEffect(() => {
    console.log("🔐 [useAuth] Setting up Firebase auth state listener...");
    
    const unsubscribe = onAuthChange((firebaseUser) => {
      console.log("🔐 [useAuth] Firebase auth state changed:", {
        hasFirebaseUser: !!firebaseUser,
        uid: firebaseUser?.uid,
        email: firebaseUser?.email
      });
      
      // If user signed in, add a small delay to ensure auth state is fully settled
      if (firebaseUser) {
        console.log("🔐 [useAuth] User signed in, waiting for auth state to settle...");
        setTimeout(() => {
          console.log("🔐 [useAuth] Refetching user data after Firebase auth state change");
          queryClient.invalidateQueries({ queryKey: ["/api/auth/user"] });
        }, 100); // Small delay to ensure Firebase auth is fully settled
      } else {
        // If user signed out, invalidate immediately
        console.log("🔐 [useAuth] User signed out, invalidating queries immediately");
        queryClient.invalidateQueries({ queryKey: ["/api/auth/user"] });
      }
    });

    return unsubscribe;
  }, [queryClient]);

  console.log("🔐 [useAuth] Hook state:", { 
    hasUser: !!user, 
    isLoading, 
    hasError: !!error,
    isAuthenticated: !!user 
  });

  return {
    user,
    isLoading,
    isAuthenticated: !!user,
  };
}