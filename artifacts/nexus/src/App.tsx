import React, { useState, useEffect } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import LockScreen from "@/components/LockScreen";
import MainLab from "@/components/MainLab";

const AUTH_KEY = "nxauth_v6";
const AUTH_VAL = "omowoli12345@*";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 0,
    },
  },
});

function AppContent() {
  const [unlocked, setUnlocked] = useState(false);

  useEffect(() => {
    if (sessionStorage.getItem(AUTH_KEY) === AUTH_VAL) {
      setUnlocked(true);
    }
  }, []);

  const handleUnlock = () => {
    sessionStorage.setItem(AUTH_KEY, AUTH_VAL);
    setUnlocked(true);
  };

  return unlocked ? <MainLab /> : <LockScreen onUnlock={handleUnlock} />;
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AppContent />
    </QueryClientProvider>
  );
}
