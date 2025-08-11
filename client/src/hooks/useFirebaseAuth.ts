import { useState, useEffect } from 'react';
import { onAuthChange, handleRedirectResult, isFirebaseConfigured, type User } from '@/lib/firebase';
import { useToast } from '@/hooks/use-toast';

export function useFirebaseAuth() {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const { toast } = useToast();

  useEffect(() => {
    if (!isFirebaseConfigured()) {
      setUser(null);
      setIsLoading(false);
      return;
    }

    // Handle redirect result on page load
    handleRedirectResult()
      .then((result) => {
        if (result?.user) {
          toast({
            title: 'Welcome!',
            description: 'Successfully signed in with Google',
          });
        }
      })
      .catch((error) => {
        console.error('Error handling redirect:', error);
        console.log('Current domain:', window.location.hostname);
        console.log('Current origin:', window.location.origin);
        console.log('Error details:', error.code, error.message);
        toast({
          title: 'Sign in failed',
          description: 'There was an error signing in with Google',
          variant: 'destructive',
        });
      });

    // Listen for auth state changes
    const unsubscribe = onAuthChange((user) => {
      setUser(user);
      setIsLoading(false);
    });

    return () => unsubscribe();
  }, [toast]);

  return {
    user,
    isLoading,
    isAuthenticated: !!user,
  };
}
