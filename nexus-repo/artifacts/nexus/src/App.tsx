import React, { useState, useEffect } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import LockScreen from "@/components/LockScreen";
import MainLab from "@/components/MainLab";

const AUTH_KEY = "nxauth_v7";
const API_URL = (import.meta.env as Record<string, string>)["VITE_API_URL"] ?? "";

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
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    const token = sessionStorage.getItem(AUTH_KEY);
    if (!token) {
      setChecking(false);
      return;
    }
    fetch(`${API_URL}/api/auth/verify`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((r) => {
        setUnlocked(r.ok);
        setChecking(false);
      })
      .catch(() => setChecking(false));
  }, []);

  const handleUnlock = (token: string) => {
    sessionStorage.setItem(AUTH_KEY, token);
    setUnlocked(true);
  };

  if (checking) return null;

  return unlocked ? <MainLab /> : <LockScreen onUnlock={handleUnlock} />;
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AppContent />
    </QueryClientProvider>
  );
}
