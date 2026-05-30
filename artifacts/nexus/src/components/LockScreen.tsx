import React, { useState, useRef, useEffect } from "react";

const PASS = "omowoli12345@*";

export default function LockScreen({ onUnlock }: { onUnlock: () => void }) {
  const [value, setValue]   = useState("");
  const [error, setError]   = useState(false);
  const [shake, setShake]   = useState(false);
  const inputRef            = useRef<HTMLInputElement>(null);

  useEffect(() => { inputRef.current?.focus(); }, []);

  const attempt = (e: React.FormEvent) => {
    e.preventDefault();
    if (value === PASS) {
      onUnlock();
    } else {
      setError(true);
      setShake(true);
      setValue("");
      setTimeout(() => setShake(false), 500);
      inputRef.current?.focus();
    }
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-black font-mono">
      <div
        className={`w-full max-w-sm border border-red-900 bg-zinc-950 p-8 ${shake ? "animate-[shake_0.4s_ease]" : ""}`}
        style={shake ? { animation: "shake 0.4s ease" } : {}}
      >
        <style>{`@keyframes shake{0%,100%{transform:translateX(0)}20%,60%{transform:translateX(-8px)}40%,80%{transform:translateX(8px)}}`}</style>
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold tracking-[0.3em] text-red-600">NEXUSFORGE</h1>
          <div className="mt-1 text-[10px] text-zinc-600 tracking-widest uppercase">Command Injection Platform</div>
        </div>
        <form onSubmit={attempt} className="space-y-4" autoComplete="off">
          <div>
            <label className="block text-[10px] text-zinc-600 uppercase tracking-wider mb-1.5">
              Authorization Key
            </label>
            <input
              ref={inputRef}
              type="password"
              value={value}
              onChange={e => { setValue(e.target.value); setError(false); }}
              className="w-full bg-black border border-red-900/60 px-3 py-2.5 text-red-400 text-sm focus:outline-none focus:border-red-500 transition-colors"
              autoComplete="new-password"
              spellCheck={false}
            />
          </div>
          {error && (
            <div className="text-red-500 text-xs font-bold tracking-wider uppercase">
              Access Denied
            </div>
          )}
          <button
            type="submit"
            className="w-full bg-red-950/50 border border-red-900 text-red-500 py-2.5 text-sm font-bold uppercase tracking-widest hover:bg-red-900/40 hover:text-red-400 transition-colors"
          >
            Unlock
          </button>
        </form>
      </div>
    </div>
  );
}
