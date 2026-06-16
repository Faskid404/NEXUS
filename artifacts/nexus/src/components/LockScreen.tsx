import React, { useState, useEffect, useRef } from "react";

const API_URL = (import.meta.env as Record<string, string>)["VITE_API_URL"] ?? "";
const REQUIRED_PREFIX = "omowoli12345@";

export default function LockScreen({ onUnlock }: { onUnlock: (token: string) => void }) {
  const [value,    setValue]    = useState("");
  const [error,    setError]    = useState(false);
  const [errorMsg, setErrorMsg] = useState("Incorrect password");
  const [loading,  setLoading]  = useState(false);
  const [shake,    setShake]    = useState(false);
  const [ready,    setReady]    = useState(false);
  const [hint,     setHint]     = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const t = setTimeout(() => { setReady(true); inputRef.current?.focus(); }, 200);
    return () => clearTimeout(t);
  }, []);

  const triggerError = (msg: string, clearInput = true) => {
    setError(true);
    setErrorMsg(msg);
    setShake(true);
    if (clearInput) setValue("");
    setTimeout(() => { setShake(false); setError(false); }, 2200);
  };

  const attempt = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!value.trim()) return;
    if (!value.startsWith(REQUIRED_PREFIX)) {
      triggerError("Invalid format — check password", true);
      setHint(true);
      setTimeout(() => setHint(false), 4000);
      return;
    }
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
      triggerError("Incorrect password", true);
    } catch {
      triggerError("Connection error — server unreachable", false);
    }
    setLoading(false);
    setTimeout(() => inputRef.current?.focus(), 50);
  };

  return (
    <div className="min-h-screen w-full bg-[#080808] flex items-center justify-center font-mono overflow-hidden relative">
      <div className="absolute inset-0 pointer-events-none"
        style={{ background:"radial-gradient(ellipse 70% 55% at 50% 52%, rgba(180,20,20,0.07) 0%, transparent 70%)" }} />
      <div className="absolute inset-0 pointer-events-none overflow-hidden opacity-[0.025]"
        style={{ backgroundImage:"repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(255,255,255,.05) 2px, rgba(255,255,255,.05) 4px)", backgroundSize:"100% 4px" }} />

      <style>{`
        @keyframes nf-in    { from { opacity:0; transform:translateY(12px) } to { opacity:1; transform:translateY(0) } }
        @keyframes nf-shake { 0%,100%{transform:translateX(0)} 20%,60%{transform:translateX(-8px)} 40%,80%{transform:translateX(8px)} }
        @keyframes nf-glow  { 0%,100%{text-shadow:0 0 32px rgba(220,38,38,.45)} 50%{text-shadow:0 0 64px rgba(220,38,38,.75),0 0 120px rgba(220,38,38,.2)} }
        @keyframes nf-err   { 0%,100%{opacity:0;transform:translateY(-4px)} 15%,85%{opacity:1;transform:translateY(0)} }
        @keyframes nf-spin  { to { transform: rotate(360deg) } }
        @keyframes nf-hint  { 0%,100%{opacity:0} 15%,85%{opacity:1} }
        @keyframes nf-scan  { 0%{transform:translateY(-100%)} 100%{transform:translateY(100vh)} }
      `}</style>

      <div className="absolute inset-x-0 h-px bg-red-900/30 pointer-events-none"
        style={{ animation:"nf-scan 8s linear infinite", top:0 }} />

      <div className="relative w-full max-w-sm mx-auto px-8"
        style={{ animation:ready?"nf-in .5s cubic-bezier(.22,1,.36,1) forwards":"none", opacity:ready?1:0 }}>
        <div className="text-center mb-12 select-none">
          <div className="text-[9px] text-red-900 tracking-[.8em] uppercase mb-2">░░░░░░░░░░░░░░░░░░░░░░</div>
          <h1 className="text-5xl font-black text-white tracking-[.18em] uppercase leading-none"
            style={{ animation:"nf-glow 4s ease-in-out infinite" }}>
            NEXUS
          </h1>
          <div className="text-[11px] font-bold text-red-700 tracking-[.55em] uppercase mt-1.5">FORGE</div>
          <div className="text-[9px] text-red-900 tracking-[.8em] uppercase mt-2">░░░░░░░░░░░░░░░░░░░░░░</div>
        </div>

        <div className="bg-[#0e0e0e] border border-white/[.06] px-8 py-8"
          style={{ boxShadow:"0 32px 80px rgba(0,0,0,.7), 0 0 0 1px rgba(255,255,255,.03)", animation:shake?"nf-shake .42s ease":"none" }}>
          <div className="flex items-center gap-2 mb-5">
            <div className="w-1.5 h-1.5 rounded-full bg-red-600 animate-pulse" />
            <p className="text-[9px] text-zinc-600 uppercase tracking-[.28em] select-none">Authorization Required</p>
          </div>

          <form onSubmit={attempt} autoComplete="off" className="space-y-4">
            <div className="relative">
              <input
                ref={inputRef}
                type="password"
                value={value}
                onChange={e => { setValue(e.target.value); setError(false); }}
                placeholder="Enter access credential"
                disabled={loading}
                autoComplete="new-password"
                spellCheck={false}
                className="w-full bg-black/60 border text-white text-sm px-4 py-3 placeholder-zinc-700 focus:outline-none transition-colors tracking-widest"
                style={{
                  borderColor: error ? "rgba(220,38,38,.7)" :
                    value.length > 0 && !value.startsWith(REQUIRED_PREFIX) ? "rgba(234,88,12,.5)" :
                    "rgba(255,255,255,.08)",
                  boxShadow: error ? "0 0 0 1px rgba(220,38,38,.3), inset 0 0 24px rgba(220,38,38,.04)" :
                    value.length > 0 && !value.startsWith(REQUIRED_PREFIX) ? "0 0 0 1px rgba(234,88,12,.2)" : "none",
                }}
              />
              {value.length > 0 && (
                <div className="absolute right-3 top-1/2 -translate-y-1/2">
                  {value.startsWith(REQUIRED_PREFIX)
                    ? <div className="w-1.5 h-1.5 rounded-full bg-green-500" />
                    : <div className="w-1.5 h-1.5 rounded-full bg-orange-600" />}
                </div>
              )}
            </div>

            {error && (
              <p className="text-[10px] text-red-500 tracking-[.15em] uppercase text-center"
                style={{ animation:"nf-err 2.2s ease forwards" }}>
                {errorMsg}
              </p>
            )}
            {hint && !error && (
              <p className="text-[9px] text-orange-700 tracking-[.1em] uppercase text-center"
                style={{ animation:"nf-hint 4s ease forwards" }}>
                Credential format mismatch
              </p>
            )}

            <button type="submit" disabled={loading || !value.trim()}
              className="w-full py-3 text-[11px] font-bold uppercase tracking-[.3em] transition-all border disabled:opacity-30"
              style={{
                background: loading||!value.trim() ? "transparent" : "rgba(220,38,38,.12)",
                borderColor: loading||!value.trim() ? "rgba(255,255,255,.07)" : "rgba(220,38,38,.5)",
                color: loading||!value.trim() ? "#52525b" : "#f87171",
              }}>
              {loading
                ? <span className="inline-block w-3 h-3 border border-red-500 border-t-transparent rounded-full" style={{ animation:"nf-spin .7s linear infinite" }} />
                : "Authenticate"}
            </button>
          </form>
        </div>

        <div className="flex items-center gap-3 mt-6">
          <div className="flex-1 h-px bg-white/[.04]" />
          <p className="text-[8px] text-zinc-800 tracking-[.2em] uppercase select-none">Restricted Access · Authorized Operators Only</p>
          <div className="flex-1 h-px bg-white/[.04]" />
        </div>
      </div>
    </div>
  );
}
