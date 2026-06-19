import React, { useState, useEffect, Component } from "react";
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

// ─── Error Boundary ───────────────────────────────────────────────────────────
// Catches any render-time crash inside MainLab instead of showing a black screen.
interface EBState { error: Error | null }
class DashboardErrorBoundary extends Component<{ children: React.ReactNode }, EBState> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { error: null };
  }
  static getDerivedStateFromError(error: Error): EBState {
    return { error };
  }
  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error("[NEXUS] Dashboard crash:", error, info.componentStack);
  }
  render() {
    if (this.state.error) {
      return (
        <div className="min-h-screen w-full bg-[#080808] flex items-center justify-center font-mono">
          <div className="w-full max-w-md px-8 text-center">
            <h1
              className="text-red-500 font-black text-3xl tracking-[.18em] uppercase mb-6"
              style={{ textShadow: "0 0 32px rgba(220,38,38,.55)" }}
            >
              NEXUS
            </h1>
            <div
              className="bg-[#0e0e0e] border border-red-900/40 p-6 text-left"
              style={{ boxShadow: "0 0 0 1px rgba(255,255,255,.03)" }}
            >
              <p className="text-[10px] text-red-500 uppercase tracking-[.3em] mb-3">
                Runtime Error — Dashboard crashed
              </p>
              <pre className="text-[10px] text-zinc-500 font-mono break-all whitespace-pre-wrap leading-relaxed mb-5">
                {this.state.error.message}
              </pre>
              <button
                onClick={() => this.setState({ error: null })}
                className="w-full py-2.5 border border-red-700/50 text-red-400 text-[11px] uppercase tracking-[.25em] hover:bg-red-950/30 transition-colors"
              >
                Reload Dashboard
              </button>
            </div>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

// ─── App Content ──────────────────────────────────────────────────────────────
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
        sessionStorage.removeItem(AUTH_KEY);
        setChecking(false);
      });
  // eslint-disable-next-line react-hooks/exhaustive-deps
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

  return unlocked ? (
    <DashboardErrorBoundary>
      <MainLab />
    </DashboardErrorBoundary>
  ) : (
    <LockScreen onUnlock={handleUnlock} />
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AppContent />
    </QueryClientProvider>
  );
}
