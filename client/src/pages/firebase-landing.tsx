import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { signInWithGoogle, isFirebaseConfigured } from "@/lib/firebase";
import { useToast } from "@/hooks/use-toast";
import { Dice1, Users, Upload, Shield } from "lucide-react";

export default function FirebaseLanding() {
  const { toast } = useToast();
  
  const handleGoogleSignIn = async () => {
    console.log("Sign in button clicked");
    console.log("Firebase configured:", isFirebaseConfigured());
    console.log("Environment vars:", {
      apiKey: !!import.meta.env.VITE_FIREBASE_API_KEY,
      projectId: !!import.meta.env.VITE_FIREBASE_PROJECT_ID,
      appId: !!import.meta.env.VITE_FIREBASE_APP_ID
    });
    
    if (!isFirebaseConfigured()) {
      toast({
        title: "Configuration Required",
        description: "Firebase secrets need to be configured for Google OAuth to work.",
        variant: "destructive",
      });
      return;
    }
    
    try {
      console.log("Attempting Google sign in...");
      await signInWithGoogle();
      console.log("Sign in initiated successfully");
    } catch (error) {
      console.error("Sign in error:", error);
      toast({
        title: "Sign In Error",
        description: `Failed to initiate Google sign-in: ${(error as Error).message}`,
        variant: "destructive",
      });
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      <div className="container mx-auto px-4 py-16">
        {/* Header */}
        <div className="text-center mb-16">
          <h1 className="text-5xl font-bold text-white mb-4">
            Virtual Tabletop
          </h1>
          <p className="text-xl text-gray-300 mb-8">
            Play board games online with friends. Upload your own cards, tokens, and maps.
          </p>
          
          {/* Google Sign In Button */}
          <Button
            onClick={handleGoogleSignIn}
            size="lg"
            className="bg-white text-gray-900 hover:bg-gray-100 px-8 py-4 text-lg font-semibold"
            data-testid="button-google-signin"
          >
            <svg className="w-5 h-5 mr-3" viewBox="0 0 24 24">
              <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
              <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
              <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
              <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
            </svg>
            Continue with Google
          </Button>
        </div>

        {/* Features Grid */}
        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 mb-16">
          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader>
              <Upload className="w-8 h-8 text-blue-400 mb-2" />
              <CardTitle className="text-white">Upload Assets</CardTitle>
              <CardDescription className="text-gray-400">
                Import your own cards, tokens, and game boards
              </CardDescription>
            </CardHeader>
          </Card>

          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader>
              <Users className="w-8 h-8 text-green-400 mb-2" />
              <CardTitle className="text-white">Multiplayer</CardTitle>
              <CardDescription className="text-gray-400">
                Play with friends in real-time game rooms
              </CardDescription>
            </CardHeader>
          </Card>

          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader>
              <Dice1 className="w-8 h-8 text-purple-400 mb-2" />
              <CardTitle className="text-white">Dice Rolling</CardTitle>
              <CardDescription className="text-gray-400">
                Built-in dice system with roll history
              </CardDescription>
            </CardHeader>
          </Card>

          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader>
              <Shield className="w-8 h-8 text-orange-400 mb-2" />
              <CardTitle className="text-white">Secure Rooms</CardTitle>
              <CardDescription className="text-gray-400">
                Private game rooms with access controls
              </CardDescription>
            </CardHeader>
          </Card>
        </div>

        {/* How it Works */}
        <div className="text-center">
          <h2 className="text-3xl font-bold text-white mb-8">How it Works</h2>
          <div className="grid md:grid-cols-3 gap-8 max-w-4xl mx-auto">
            <div className="text-center">
              <div className="bg-blue-600 text-white rounded-full w-12 h-12 flex items-center justify-center mx-auto mb-4 text-xl font-bold">
                1
              </div>
              <h3 className="text-xl font-semibold text-white mb-2">Sign In</h3>
              <p className="text-gray-400">
                Create an account using your Google account for quick access
              </p>
            </div>
            
            <div className="text-center">
              <div className="bg-green-600 text-white rounded-full w-12 h-12 flex items-center justify-center mx-auto mb-4 text-xl font-bold">
                2
              </div>
              <h3 className="text-xl font-semibold text-white mb-2">Create Room</h3>
              <p className="text-gray-400">
                Set up your game room and upload your game assets
              </p>
            </div>
            
            <div className="text-center">
              <div className="bg-purple-600 text-white rounded-full w-12 h-12 flex items-center justify-center mx-auto mb-4 text-xl font-bold">
                3
              </div>
              <h3 className="text-xl font-semibold text-white mb-2">Play</h3>
              <p className="text-gray-400">
                Invite friends and start playing your favorite board games
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}