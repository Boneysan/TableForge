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
        throw error;
      }
    },
    retry: false,
    staleTime: 0, // Always fetch fresh data
    gcTime: 0, // Don't cache
  });

  // Listen for Firebase auth state changes and refetch user data
  useEffect(() => {
    console.log("🔐 [useAuth] Setting up Firebase auth state listener...");
    
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
      
      // If user signed in, add a small delay to ensure auth state is fully settled
      if (firebaseUser) {
        console.log("🔐 [useAuth] User signed in, waiting for auth state to settle...");
        console.log("🔐 [useAuth] Starting 500ms delay before refetch...");
        setTimeout(() => {
          console.log("🔐 [useAuth] ===== REFETCHING USER DATA =====");
          console.log("🔐 [useAuth] Refetch timestamp:", new Date().toISOString());
          console.log("🔐 [useAuth] Invalidating and refetching user data after Firebase auth state change");
          
          queryClient.invalidateQueries({ queryKey: ["/api/auth/user"] });
          queryClient.refetchQueries({ queryKey: ["/api/auth/user"] }).then(() => {
            console.log("✅ [useAuth] Refetch completed successfully");
          }).catch((error) => {
            console.error("❌ [useAuth] Refetch failed:", error);
          });
        }, 500); // Increase delay to ensure Firebase auth is fully settled
      } else {
        // If user signed out, invalidate immediately
        console.log("🔐 [useAuth] User signed out, invalidating queries immediately");
        queryClient.invalidateQueries({ queryKey: ["/api/auth/user"] });
        queryClient.refetchQueries({ queryKey: ["/api/auth/user"] });
      }
    });

    return unsubscribe;
  }, [queryClient]);

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