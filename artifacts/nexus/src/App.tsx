import React, { useState, useEffect } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { setAuthTokenGetter } from "@workspace/api-client-react";
import LockScreen from "@/components/LockScreen";
import MainLab from "@/components/MainLab";
import { AUTH_KEY, getToken } from "@/lib/auth";

const API_URL = (import.meta.env as Record<string, string>)["VITE_API_URL"] ?? "";

// Wire up the generated API hooks to always send the current session token
setAuthTokenGetter(getToken);

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
        if (!r.ok) sessionStorage.removeItem(AUTH_KEY);
        setUnlocked(r.ok);
        setChecking(false);
      })
      .catch(() => {
        // Network error — clear potentially stale token and show lock screen
        sessionStorage.removeItem(AUTH_KEY);
        setChecking(false);
      });
  }, []);

  const handleUnlock = (token: string) => {
    sessionStorage.setItem(AUTH_KEY, token);
    setUnlocked(true);
  };

  if (checking) {
    return (
      <div className="min-h-screen w-full bg-[#080808] flex items-center justify-center font-mono">
        <div className="flex flex-col items-center gap-4">
          <span
            className="text-red-500 font-black text-2xl tracking-[.18em] uppercase"
            style={{ textShadow: "0 0 32px rgba(220,38,38,.55)" }}
          >
            NEXUS
          </span>
          <div className="w-5 h-5 border-2 border-red-700 border-t-transparent rounded-full animate-spin" />
        </div>
      </div>
    );
  }

  return unlocked ? <MainLab /> : <LockScreen onUnlock={handleUnlock} />;
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AppContent />
    </QueryClientProvider>
  );
}
