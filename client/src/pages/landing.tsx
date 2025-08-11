import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Dice1, Users, Upload, Gamepad2 } from 'lucide-react';

export default function Landing() {
  return (
    <div className="min-h-screen bg-[#1F2937] text-gray-100">
      <div className="container mx-auto px-4 py-16">
        {/* Header */}
        <div className="text-center mb-16">
          <div className="flex items-center justify-center mb-6">
            <Dice1 className="w-12 h-12 text-[#2563EB] mr-4" />
            <h1 className="text-5xl font-bold text-white">TabletopHub</h1>
          </div>
          <p className="text-xl text-gray-300 max-w-2xl mx-auto">
            The ultimate virtual tabletop platform for board games. Upload your assets,
            create rooms, and play with friends in real-time.
          </p>
        </div>

        {/* Features */}
        <div className="grid md:grid-cols-3 gap-8 mb-16">
          <Card className="bg-[#374151] border-gray-600">
            <CardHeader>
              <CardTitle className="flex items-center text-gray-100">
                <Upload className="w-6 h-6 text-[#10B981] mr-3" />
                Asset Management
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-gray-300">
                Upload and organize your cards, tokens, maps, and game pieces.
                Automatic categorization makes it easy to find what you need.
              </p>
            </CardContent>
          </Card>

          <Card className="bg-[#374151] border-gray-600">
            <CardHeader>
              <CardTitle className="flex items-center text-gray-100">
                <Users className="w-6 h-6 text-[#F59E0B] mr-3" />
                Multiplayer Rooms
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-gray-300">
                Create private game rooms and invite friends. Real-time
                synchronization ensures everyone sees the same game state.
              </p>
            </CardContent>
          </Card>

          <Card className="bg-[#374151] border-gray-600">
            <CardHeader>
              <CardTitle className="flex items-center text-gray-100">
                <Gamepad2 className="w-6 h-6 text-[#7C3AED] mr-3" />
                Interactive Gameplay
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-gray-300">
                Drag and drop pieces, roll dice, flip cards, and interact
                with your game assets just like a physical tabletop.
              </p>
            </CardContent>
          </Card>
        </div>

        {/* Call to Action */}
        <div className="text-center">
          <Card className="bg-[#374151] border-gray-600 max-w-md mx-auto">
            <CardHeader>
              <CardTitle className="text-gray-100">Get Started</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-gray-300 mb-6">
                Sign in with your Replit account to start creating game rooms
                and uploading your tabletop assets.
              </p>
              <Button
                onClick={() => window.location.href = '/api/login'}
                className="w-full bg-[#2563EB] hover:bg-blue-700 text-white"
                data-testid="button-login"
              >
                Sign In to Play
              </Button>
            </CardContent>
          </Card>
        </div>

        {/* Footer */}
        <div className="mt-16 text-center text-gray-400">
          <p>Built for tabletop gaming enthusiasts</p>
        </div>
      </div>
    </div>
  );
}
