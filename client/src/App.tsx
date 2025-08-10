import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ThemeProvider } from "@/components/ThemeProvider";
import { useAuth } from "@/hooks/useAuth";
import NotFound from "@/pages/not-found";
import Home from "@/pages/home";
import FirebaseLanding from "@/pages/firebase-landing";
import GameRoom from "@/pages/game-room";
import AdminDashboard from "@/pages/admin-dashboard";
import CreateGameSystem from "@/pages/create-game-system";
import EditGameSystem from "@/pages/edit-game-system";

function Router() {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-muted-foreground">Loading...</div>
      </div>
    );
  }

  return (
    <Switch>
      <Route path="/" component={isAuthenticated ? Home : FirebaseLanding} />
      <Route path="/admin" component={AdminDashboard} />
      <Route path="/create-game-system" component={CreateGameSystem} />
      <Route path="/edit-game-system/:systemId">
        {(params) => <EditGameSystem systemId={params.systemId} />}
      </Route>
      <Route path="/room/:roomId" component={GameRoom} />
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <ThemeProvider defaultTheme="system" storageKey="vorpal-board-theme">
      <QueryClientProvider client={queryClient}>
        <TooltipProvider>
          <Toaster />
          <Router />
        </TooltipProvider>
      </QueryClientProvider>
    </ThemeProvider>
  );
}

export default App;
