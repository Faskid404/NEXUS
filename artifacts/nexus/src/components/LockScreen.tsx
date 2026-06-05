import React, { useState, useRef, useEffect } from "react";

const API_URL = (import.meta.env as Record<string, string>)["VITE_API_URL"] ?? "";

function MatrixRain() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const resize = () => {
      canvas.width  = window.innerWidth;
      canvas.height = window.innerHeight;
    };
    resize();
    window.addEventListener("resize", resize);

    const CHARS = "NEXUSFORGE01ABCDEF0123456789%@#!&|;><[]{}()+=-_/\\?~^";
    const FONT_SIZE = 13;
    const cols = Math.floor(window.innerWidth / FONT_SIZE);
    const drops: number[] = Array.from({ length: cols }, () => Math.random() * -50);
    const speeds: number[] = Array.from({ length: cols }, () => 0.3 + Math.random() * 0.7);
    const bright: number[] = Array.from({ length: cols }, () => Math.random());

    let raf: number;
    let last = 0;

    const draw = (ts: number) => {
      raf = requestAnimationFrame(draw);
      if (ts - last < 40) return;
      last = ts;

      ctx.fillStyle = "rgba(0,0,0,0.055)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      for (let i = 0; i < drops.length; i++) {
        const ch = CHARS[Math.floor(Math.random() * CHARS.length)]!;
        const x  = i * FONT_SIZE;
        const y  = drops[i]! * FONT_SIZE;

        ctx.font      = `bold ${FONT_SIZE}px monospace`;
        ctx.fillStyle = bright[i]! > 0.75 ? "#00ffcc" : "#00cc66";
        ctx.fillText(ch, x, y);

        if (Math.random() > 0.97) {
          ctx.fillStyle = "#dc2626";
          ctx.fillText(CHARS[Math.floor(Math.random() * CHARS.length)]!, x, y - FONT_SIZE * 2);
        }

        drops[i]! += speeds[i]!;
        if (drops[i]! * FONT_SIZE > canvas.height && Math.random() > 0.975) {
          drops[i] = 0;
          speeds[i] = 0.3 + Math.random() * 0.7;
          bright[i] = Math.random();
        }
      }
    };

    raf = requestAnimationFrame(draw);
    return () => { cancelAnimationFrame(raf); window.removeEventListener("resize", resize); };
  }, []);

  return <canvas ref={canvasRef} className="absolute inset-0 w-full h-full" style={{ opacity: 0.5 }} />;
}

export default function LockScreen({ onUnlock }: { onUnlock: (token: string) => void }) {
  const [value, setValue] = useState("");
  const [error, setError] = useState(false);
  const [shake, setShake] = useState(false);
  const [loading, setLoading] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => { inputRef.current?.focus(); }, []);

  const attempt = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!value.trim() || loading) return;
    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: value }),
      });
      if (res.ok) {
        const { token } = await res.json() as { token: string };
        onUnlock(token);
      } else {
        setError(true);
        setShake(true);
        setValue("");
        setTimeout(() => setShake(false), 500);
        inputRef.current?.focus();
      }
    } catch {
      setError(true);
      setShake(true);
      setValue("");
      setTimeout(() => setShake(false), 500);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-black font-mono relative overflow-hidden">
      <MatrixRain />
      <div
        className="absolute inset-0 pointer-events-none z-10"
        style={{ background: "repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.08) 2px,rgba(0,0,0,0.08) 4px)" }}
      />
      <div className="relative z-20 w-full max-w-sm" style={shake ? { animation: "shake 0.45s ease" } : {}}>
        <style>{`
          @keyframes shake{0%,100%{transform:translateX(0)}20%,60%{transform:translateX(-9px)}40%,80%{transform:translateX(9px)}}
          @keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
          @keyframes glitch{0%,100%{text-shadow:2px 0 #dc2626,-2px 0 #00ffcc}25%{text-shadow:-2px 0 #dc2626,2px 0 #00ffcc}50%{text-shadow:2px 0 #00ffcc,-2px 0 #dc2626}}
        `}</style>
        <div
          className="border border-red-900/70 bg-black/85 backdrop-blur-sm p-8"
          style={{ boxShadow: "0 0 40px rgba(220,38,38,0.15), inset 0 0 40px rgba(0,0,0,0.5)" }}
        >
          <div className="text-center mb-8">
            <h1
              className="text-4xl font-bold tracking-[0.35em] text-red-600 select-none"
              style={{ animation: "glitch 4s infinite", fontFamily: "monospace" }}
            >
              NEXUSFORGE
            </h1>
            <div className="mt-2 text-[9px] text-zinc-600 tracking-[0.4em] uppercase select-none">
              Command Injection Research Platform
            </div>
          </div>
          <div className="flex items-center gap-2 mb-6 border border-zinc-900 bg-zinc-950/60 px-3 py-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-red-500" style={{ animation: "blink 1.2s infinite" }} />
            <span className="text-[9px] text-zinc-600 flex-1">SYSTEM LOCKED — AUTHORIZATION REQUIRED</span>
            <span className="text-[9px] text-red-800">■</span>
          </div>
          <form onSubmit={attempt} className="space-y-4" autoComplete="off">
            <div>
              <label className="block text-[9px] text-zinc-600 uppercase tracking-[0.2em] mb-1.5">Authorization Key</label>
              <input
                ref={inputRef}
                type="password"
                value={value}
                onChange={e => { setValue(e.target.value); setError(false); }}
                className="w-full bg-black border border-red-900/60 px-3 py-2.5 text-red-400 text-sm focus:outline-none focus:border-red-500 transition-colors tracking-widest"
                autoComplete="new-password"
                spellCheck={false}
                disabled={loading}
              />
            </div>
            {error && (
              <div className="flex items-center gap-2 text-red-500 text-[10px] font-bold tracking-widest uppercase">
                <span>■</span><span>Access Denied — Invalid Credentials</span>
              </div>
            )}
            <button
              type="submit"
              disabled={loading}
              className="w-full bg-red-950/40 border border-red-800/60 text-red-400 py-2.5 text-[11px] font-bold uppercase tracking-[0.3em] hover:bg-red-900/40 hover:text-red-300 hover:border-red-600 transition-all disabled:opacity-50"
              style={{ boxShadow: "0 0 12px rgba(220,38,38,0.1)" }}
            >
              {loading ? "Verifying..." : "Authenticate"}
            </button>
          </form>
          <div className="mt-6 flex justify-between text-[8px] text-zinc-800 select-none">
            <span>v6.2.0</span>
            <span>RCE · BYPASS · CHAIN · SCAN</span>
            <span>©NXF</span>
          </div>
        </div>
      </div>
    </div>
  );
}
