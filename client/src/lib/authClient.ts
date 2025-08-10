import { auth } from "./firebase";

// Helper to get the current Firebase ID token for API requests
export async function getAuthToken(): Promise<string | null> {
  try {
    console.log("🔐 [Auth Token] Getting Firebase ID token...");
    console.log("🔐 [Auth Token] Auth instance available:", !!auth);
    
    if (!auth) {
      console.log("⚠️ [Auth Token] No auth instance available");
      return null;
    }
    
    const user = auth.currentUser;
    console.log("🔐 [Auth Token] Current user:", user ? {
      uid: user.uid,
      email: user.email,
      displayName: user.displayName
    } : "null");
    
    if (!user) {
      console.log("⚠️ [Auth Token] No current user");
      return null;
    }
    
    console.log("🔐 [Auth Token] Calling getIdToken()...");
    const token = await user.getIdToken();
    console.log("✅ [Auth Token] Token retrieved, length:", token?.length || 0);
    
    return token;
  } catch (error) {
    console.error("❌ [Auth Token] Error getting auth token:", error);
    return null;
  }
}

// Enhanced API request function that includes Firebase auth token
export async function authenticatedApiRequest(
  method: string,
  endpoint: string,
  data?: any
): Promise<Response> {
  console.log("🌐 [API Request] ===== STARTING API REQUEST =====");
  console.log("🌐 [API Request] Request timestamp:", new Date().toISOString());
  console.log(`🌐 [API Request] ${method} ${endpoint}`);
  
  const token = await getAuthToken();
  console.log("🌐 [API Request] Token available:", !!token);
  console.log("🌐 [API Request] Token length:", token?.length || 0);
  if (token) {
    console.log("🌐 [API Request] Token preview:", `${token.substring(0, 50)}...`);
  }
  
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
    console.log("🌐 [API Request] Authorization header added");
  } else {
    console.log("⚠️ [API Request] No token available - proceeding without auth header");
  }
  
  const config: RequestInit = {
    method,
    headers,
  };
  
  if (data && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
    config.body = JSON.stringify(data);
    console.log("🌐 [API Request] Request body length:", JSON.stringify(data).length);
  }
  
  console.log("🌐 [API Request] Final headers:", headers);
  console.log("🌐 [API Request] Making fetch request...");
  
  try {
    const response = await fetch(endpoint, config);
    
    console.log("🌐 [API Request] ===== RESPONSE RECEIVED =====");
    console.log("🌐 [API Request] Response timestamp:", new Date().toISOString());
    console.log("🌐 [API Request] Response status:", response.status);
    console.log("🌐 [API Request] Response statusText:", response.statusText);
    console.log("🌐 [API Request] Response headers:", Object.fromEntries(response.headers.entries()));
    console.log("🌐 [API Request] Response ok:", response.ok);
    
    if (!response.ok) {
      const errorText = await response.text();
      console.error("❌ [API Request] Request failed:", {
        status: response.status,
        statusText: response.statusText,
        errorText: errorText
      });
      throw new Error(`${response.status}: ${response.statusText} - ${errorText}`);
    }
    
    console.log("✅ [API Request] Request successful");
    return response;
  } catch (error) {
    console.error("❌ [API Request] Fetch failed:", error);
    throw error;
  }
}