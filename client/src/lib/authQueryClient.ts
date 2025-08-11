import type { DefaultOptions, QueryFunction } from '@tanstack/react-query';
import { QueryClient } from '@tanstack/react-query';
import { authenticatedApiRequest } from './authClient';

const queryConfig: DefaultOptions = {
  queries: {
    staleTime: 1000 * 60 * 5, // 5 minutes
    refetchOnWindowFocus: false,
    retry: (failureCount, error) => {
      // Don't retry on auth errors
      if (error instanceof Error && error.message.includes('401')) {
        return false;
      }
      return failureCount < 3;
    },
  },
};

export const authQueryClient = new QueryClient({ defaultOptions: queryConfig });

// Enhanced default query function that uses Firebase auth
const defaultQueryFn: QueryFunction = async ({ queryKey }) => {
  const url = queryKey[0] as string;

  try {
    const response = await authenticatedApiRequest('GET', url);
    return response.json();
  } catch (error) {
    console.error(`Query failed for ${url}:`, error);
    throw error;
  }
};

authQueryClient.setQueryDefaults([], { queryFn: defaultQueryFn });
