import { Settings, Gamepad2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface ViewSelectorProps {
  onSelectView: (view: 'admin' | 'gamemaster') => void;
  currentUser: { firstName?: string | null; lastName?: string | null };
}

export function ViewSelector({ onSelectView, currentUser }: ViewSelectorProps) {
  const userName = currentUser.firstName || currentUser.lastName 
    ? `${currentUser.firstName || ''} ${currentUser.lastName || ''}`.trim()
    : 'Game Master';

  return (
    <div className="min-h-screen bg-gray-100 dark:bg-gray-900 flex items-center justify-center p-4">
      <div className="max-w-2xl w-full space-y-6">
        <div className="text-center space-y-2">
          <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100">
            Welcome, {userName}
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Choose your game master interface
          </p>
        </div>

        <div className="grid md:grid-cols-2 gap-6">
          {/* Admin Interface Option */}
          <Card className="cursor-pointer hover:shadow-lg transition-shadow" data-testid="card-admin-view">
            <CardHeader className="text-center">
              <div className="mx-auto w-16 h-16 bg-blue-100 dark:bg-blue-900 rounded-full flex items-center justify-center mb-4">
                <Settings className="w-8 h-8 text-blue-600 dark:text-blue-400" />
              </div>
              <CardTitle className="text-xl">Admin Interface</CardTitle>
            </CardHeader>
            <CardContent className="text-center space-y-4">
              <p className="text-gray-600 dark:text-gray-400">
                Focus on game setup and management. Upload assets, organize content, and configure the game environment.
              </p>
              <ul className="text-sm text-gray-500 dark:text-gray-500 space-y-1">
                <li>• File upload and management</li>
                <li>• Asset organization</li>
                <li>• Room configuration</li>
                <li>• Player management</li>
              </ul>
              <Button 
                onClick={() => onSelectView('admin')}
                className="w-full"
                data-testid="button-select-admin"
              >
                Use Admin Interface
              </Button>
            </CardContent>
          </Card>

          {/* Game Master Interface Option */}
          <Card className="cursor-pointer hover:shadow-lg transition-shadow" data-testid="card-gamemaster-view">
            <CardHeader className="text-center">
              <div className="mx-auto w-16 h-16 bg-purple-100 dark:bg-purple-900 rounded-full flex items-center justify-center mb-4">
                <Gamepad2 className="w-8 h-8 text-purple-600 dark:text-purple-400" />
              </div>
              <CardTitle className="text-xl">Game Master Console</CardTitle>
            </CardHeader>
            <CardContent className="text-center space-y-4">
              <p className="text-gray-600 dark:text-gray-400">
                Actively participate in gameplay while maintaining control. Perfect for running and playing in sessions.
              </p>
              <ul className="text-sm text-gray-500 dark:text-gray-500 space-y-1">
                <li>• Interactive game board</li>
                <li>• Real-time dice rolling</li>
                <li>• Asset management tools</li>
                <li>• Live player monitoring</li>
              </ul>
              <Button 
                onClick={() => onSelectView('gamemaster')}
                className="w-full bg-purple-600 hover:bg-purple-700"
                data-testid="button-select-gamemaster"
              >
                Use Game Master Console
              </Button>
            </CardContent>
          </Card>
        </div>

        <div className="text-center">
          <p className="text-sm text-gray-500 dark:text-gray-400">
            You can switch between interfaces at any time during your session
          </p>
        </div>
      </div>
    </div>
  );
}