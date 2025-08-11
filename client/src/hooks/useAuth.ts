import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { authenticatedApiRequest } from "@/lib/authClient";
import { onAuthChange } from "@/lib/firebase";
import { queryKeys } from "@/lib/queryKeys";

export function useAuth() {
  const queryClient = useQueryClient();

  const { data: user, isLoading, error, refetch } = useQuery({
    queryKey: queryKeys.auth.user(),
    queryFn: async () => {
      console.log("🔐 [useAuth] Fetching user data with Firebase auth...");
      console.log("🔐 [useAuth] Query execution timestamp:", new Date().toISOString());
      try {
        const response = await authenticatedApiRequest("GET", "/api/auth/user");
        console.log("🔐 [useAuth] API response received, status:", response.status);
        
        if (!response.ok) {
          console.log("❌ [useAuth] API response not OK:", response.status, response.statusText);
          const errorText = await response.text();
          console.log("❌ [useAuth] Error response body:", errorText);
          throw new Error(`${response.status}: ${response.statusText} - ${errorText}`);
        }
        
        const userData = await response.json();
        console.log("✅ [useAuth] User data fetched successfully:", userData);
        console.log("✅ [useAuth] User data type:", typeof userData);
        console.log("✅ [useAuth] User data keys:", userData ? Object.keys(userData) : "null");
        return userData;
      } catch (error) {
        console.error("❌ [useAuth] Failed to fetch user data:", error);
        console.error("❌ [useAuth] Error type:", typeof error);
        console.error("❌ [useAuth] Error constructor:", error?.constructor?.name);
        console.error("❌ [useAuth] Error message:", error instanceof Error ? error.message : String(error));
        
        // Don't throw for 401 errors, just return null to indicate no user
        if (error instanceof Error && error.message.includes('401')) {
          console.log("ℹ️ [useAuth] User not authenticated, returning null");
          return null;
        }
        // Don't throw any errors to prevent unhandled rejections
        console.log("ℹ️ [useAuth] Returning null due to error");
        return null;
      }
    },
    retry: false,
    staleTime: 5 * 60 * 1000, // Cache for 5 minutes
    gcTime: 10 * 60 * 1000, // Keep in cache for 10 minutes
  });

  // Listen for Firebase auth state changes and refetch user data
  useEffect(() => {
    console.log("🔐 [useAuth] Setting up Firebase auth state listener...");
    let refetchTimeout: NodeJS.Timeout | null = null;
    
    const unsubscribe = onAuthChange((firebaseUser) => {
      console.log("🔐 [useAuth] ===== FIREBASE AUTH STATE CHANGE =====");
      console.log("🔐 [useAuth] Change timestamp:", new Date().toISOString());
      console.log("🔐 [useAuth] Firebase auth state changed:", {
        hasFirebaseUser: !!firebaseUser,
        uid: firebaseUser?.uid,
        email: firebaseUser?.email,
        displayName: firebaseUser?.displayName,
        emailVerified: firebaseUser?.emailVerified
      });
      
      // Clear any existing timeout
      if (refetchTimeout) {
        clearTimeout(refetchTimeout);
      }
      
      // Only refetch if there's a significant auth state change
      if (firebaseUser) {
        console.log("🔐 [useAuth] User signed in, scheduling refetch...");
        refetchTimeout = setTimeout(() => {
          console.log("🔐 [useAuth] ===== REFETCHING USER DATA =====");
          console.log("🔐 [useAuth] Refetch timestamp:", new Date().toISOString());
          
          // Simple invalidation without aggressive removal
          queryClient.invalidateQueries({ queryKey: queryKeys.auth.user() });
        }, 500);
      } else {
        // If user signed out, invalidate immediately
        console.log("🔐 [useAuth] User signed out, invalidating queries immediately");
        queryClient.invalidateQueries({ queryKey: queryKeys.auth.user() });
      }
    });

    return () => {
      if (refetchTimeout) {
        clearTimeout(refetchTimeout);
      }
      unsubscribe();
    };
  }, [queryClient, refetch]);

  console.log("🔐 [useAuth] ===== HOOK STATE =====");
  console.log("🔐 [useAuth] Hook execution timestamp:", new Date().toISOString());
  console.log("🔐 [useAuth] Hook state:", { 
    hasUser: !!user, 
    isLoading, 
    hasError: !!error,
    isAuthenticated: !!user,
    userData: user,
    errorDetails: error
  });
  console.log("🔐 [useAuth] ==============================");

  return {
    user,
    isLoading,
    isAuthenticated: !!user,
  };
}