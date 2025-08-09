import { useQuery } from "@tanstack/react-query";
import { authenticatedApiRequest } from "@/lib/authClient";

export function useAuth() {
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