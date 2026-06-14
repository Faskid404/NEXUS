import React, { useState, useEffect, useRef } from "react";

const API_URL = (import.meta.env as Record<string, string>)["VITE_API_URL"] ?? "";

export default function LockScreen({ onUnlock }: { onUnlock: (token: string) => void }) {
  const [value,   setValue]   = useState("");
  const [error,   setError]   = useState(false);
  const [loading, setLoading] = useState(false);
  const [shake,   setShake]   = useState(false);
  const [ready,   setReady]   = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const t = setTimeout(() => { setReady(true); inputRef.current?.focus(); }, 200);
    return () => clearTimeout(t);
  }, []);

  const attempt = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!value.trim()) return;
    setLoading(true);
    setError(false);
    try {
      const res = await fetch(`${API_URL}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: value }),
      });
      if (res.ok) {
        const { token } = await res.json() as { token: string };
        onUnlock(token);
        return;
      }
      setError(true);
      setShake(true);
      setValue("");
      setTimeout(() => { setShake(false); setError(false); }, 2200);
    } catch { /* network error — fall through */ }
    setLoading(false);
    setTimeout(() => inputRef.current?.focus(), 50);
  };

  return (
    <div className="min-h-screen w-full bg-[#080808] flex items-center justify-center font-mono overflow-hidden relative">

      {/* subtle radial glow behind card */}
      <div className="absolute inset-0 pointer-events-none"
        style={{ background: "radial-gradient(ellipse 70% 55% at 50% 52%, rgba(180,20,20,0.07) 0%, transparent 70%)" }} />

      <style>{`
        @keyframes nf-in    { from { opacity:0; transform:translateY(12px) } to { opacity:1; transform:translateY(0) } }
        @keyframes nf-shake { 0%,100%{transform:translateX(0)} 20%,60%{transform:translateX(-8px)} 40%,80%{transform:translateX(8px)} }
        @keyframes nf-glow  { 0%,100%{text-shadow:0 0 32px rgba(220,38,38,.45)} 50%{text-shadow:0 0 64px rgba(220,38,38,.75),0 0 120px rgba(220,38,38,.2)} }
        @keyframes nf-err   { 0%,100%{opacity:0;transform:translateY(-4px)} 15%,85%{opacity:1;transform:translateY(0)} }
        @keyframes nf-spin  { to { transform: rotate(360deg) } }
      `}</style>

      <div
        className="relative w-full max-w-sm mx-auto px-8"
        style={{ animation: ready ? "nf-in .5s cubic-bezier(.22,1,.36,1) forwards" : "none", opacity: ready ? 1 : 0 }}
      >
        {/* Logo / name */}
        <div className="text-center mb-12 select-none">
          <h1
            className="text-5xl font-black text-white tracking-[.18em] uppercase leading-none"
            style={{ animation: "nf-glow 4s ease-in-out infinite" }}
          >
            NEXUS
          </h1>
          <div className="text-[11px] font-bold text-red-700 tracking-[.55em] uppercase mt-1.5">
            FORGE
          </div>
        </div>

        {/* Card */}
        <div
          className="bg-[#0e0e0e] border border-white/[.06] px-8 py-8"
          style={{
            boxShadow: "0 32px 80px rgba(0,0,0,.7), 0 0 0 1px rgba(255,255,255,.03)",
            animation: shake ? "nf-shake .42s ease" : "none",
          }}
        >
          <p className="text-[10px] text-zinc-600 uppercase tracking-[.28em] text-center mb-7 select-none">
            Authorization Required
          </p>

          <form onSubmit={attempt} autoComplete="off" className="space-y-4">
            {/* Input */}
            <div className="relative">
              <input
                ref={inputRef}
                type="password"
                value={value}
                onChange={e => { setValue(e.target.value); setError(false); }}
                placeholder="Enter password"
                disabled={loading}
                autoComplete="new-password"
                spellCheck={false}
                className="w-full bg-black/60 border text-white text-sm px-4 py-3 placeholder-zinc-700 focus:outline-none transition-colors tracking-widest"
                style={{
                  borderColor: error ? "rgba(220,38,38,.7)" : "rgba(255,255,255,.08)",
                  boxShadow: error ? "0 0 0 1px rgba(220,38,38,.3), inset 0 0 24px rgba(220,38,38,.04)" : "none",
                }}
              />
            </div>

            {/* Error */}
            {error && (
              <p
                className="text-[10px] text-red-500 tracking-[.15em] uppercase text-center"
                style={{ animation: "nf-err 2.2s ease forwards" }}
              >
                Incorrect password
              </p>
            )}

            {/* Button */}
            <button
              type="submit"
              disabled={loading || !value.trim()}
              className="w-full py-3 text-[11px] font-bold uppercase tracking-[.3em] transition-all border disabled:opacity-30"
              style={{
                background: loading || !value.trim() ? "transparent" : "rgba(220,38,38,.12)",
                borderColor: loading || !value.trim() ? "rgba(255,255,255,.07)" : "rgba(220,38,38,.5)",
                color: loading || !value.trim() ? "#52525b" : "#f87171",
              }}
            >
              {loading
                ? <span className="inline-block w-3 h-3 border border-red-500 border-t-transparent rounded-full" style={{ animation: "nf-spin .7s linear infinite" }} />
                : "Unlock"}
            </button>
          </form>
        </div>

        {/* Footer */}
        <p className="text-center text-[8px] text-zinc-800 tracking-[.2em] uppercase mt-6 select-none">
          Restricted Access · Authorised Users Only
        </p>
      </div>
    </div>
  );
}
