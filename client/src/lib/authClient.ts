import { auth } from "./firebase";

// Helper to get the current Firebase ID token for API requests
export async function getAuthToken(): Promise<string | null> {
  try {
    if (!auth) return null;
    const user = auth.currentUser;
    if (!user) return null;
    
    const token = await user.getIdToken();
    return token;
  } catch (error) {
    console.error("Error getting auth token:", error);
    return null;
  }
}

// Enhanced API request function that includes Firebase auth token
export async function authenticatedApiRequest(
  method: string,
  endpoint: string,
  data?: any
): Promise<Response> {
  const token = await getAuthToken();
  
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  
  const config: RequestInit = {
    method,
    headers,
  };
  
  if (data && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
    config.body = JSON.stringify(data);
  }
  
  const response = await fetch(endpoint, config);
  
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`${response.status}: ${errorText}`);
  }
  
  return response;
}