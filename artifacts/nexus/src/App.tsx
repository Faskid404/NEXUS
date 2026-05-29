import React, { useState, useEffect } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import LockScreen from "@/components/LockScreen";
import MainLab from "@/components/MainLab";

const queryClient = new QueryClient();

function AppContent() {
  const [unlocked, setUnlocked] = useState(false);

  useEffect(() => {
    if (sessionStorage.getItem("nxauth") === "omowoli12345@") {
      setUnlocked(true);
    }
  }, []);

  const handleUnlock = () => {
    sessionStorage.setItem("nxauth", "omowoli12345@");
    setUnlocked(true);
  };

  return unlocked ? <MainLab /> : <LockScreen onUnlock={handleUnlock} />;
}

function App() {
  useEffect(() => {
    document.documentElement.classList.add("dark");
  }, []);

  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <AppContent />
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
