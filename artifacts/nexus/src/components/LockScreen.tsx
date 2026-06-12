import React, { useState, useEffect, useRef } from "react";

const API_URL = (import.meta.env as Record<string,string>)["VITE_API_URL"] ?? "";

function MatrixRain() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const resize = () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight; };
    resize();
    window.addEventListener("resize", resize);
    const chars = "アイウエオカキクケコサシスセソタチツテトハヒフヘホ0123456789ABCDEF<>/\\|{}[]";
    const cols = () => Math.floor(canvas.width / 15);
    let drops: number[] = Array.from({ length: cols() }, () => Math.random() * -60);
    const draw = () => {
      ctx.fillStyle = "rgba(0,0,0,0.055)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.font = "12px monospace";
      drops.forEach((y, i) => {
        const char  = chars[Math.floor(Math.random() * chars.length)]!;
        const x     = i * 15;
        const rand  = Math.random();
        ctx.fillStyle = rand > 0.97 ? "#ef4444" : rand > 0.85 ? "#7f1d1d50" : "#ef444412";
        ctx.fillText(char, x, y * 15);
        if (y * 15 > canvas.height && Math.random() > 0.975) drops[i] = 0;
        drops[i] = (drops[i] ?? 0) + 1;
      });
    };
    const ro = new ResizeObserver(() => {
      resize();
      drops = Array.from({ length: cols() }, () => Math.random() * -60);
    });
    ro.observe(document.body);
    const id = setInterval(draw, 45);
    return () => { clearInterval(id); window.removeEventListener("resize", resize); ro.disconnect(); };
  }, []);
  return <canvas ref={canvasRef} className="absolute inset-0 w-full h-full opacity-[0.22]" />;
}

const BOOT_LINES = [
  { text: "NEXUSFORGE OS v9.0.0 — Restricted Access Terminal",            color: "#ef4444",   delay: 0 },
  { text: "[ OK ] Cryptographic subsystems initialized",                   color: "#3f3f46",   delay: 130 },
  { text: "[ OK ] Injection engine library — 13 engines loaded",           color: "#3f3f46",   delay: 270 },
  { text: "[ OK ] Payload database — 30 modes / 2400+ variants mounted",   color: "#3f3f46",   delay: 410 },
  { text: "[ OK ] OOB callback listener started — SSE active",             color: "#3f3f46",   delay: 545 },
  { text: "[ OK ] CVE exploit library — 2024–2025 synchronized",           color: "#3f3f46",   delay: 670 },
  { text: "[ OK ] WebSocket escalation engine ready",                       color: "#3f3f46",   delay: 800 },
  { text: "[ OK ] Mutation scanner subprocess spawned",                     color: "#3f3f46",   delay: 920 },
  { text: "[ OK ] Payload delivery engine armed",                           color: "#3f3f46",   delay: 1040 },
  { text: "[ OK ] Persistence mechanism generator online",                  color: "#3f3f46",   delay: 1160 },
  { text: "[ OK ] Network interfaces bound",                                color: "#14532d80", delay: 1280 },
  { text: "[ OK ] AI payload generator online",                             color: "#14532d80", delay: 1390 },
  { text: "[ OK ] Bypass engine armed — WAF evasion ready",                 color: "#14532d80", delay: 1490 },
  { text: "",                                                                color: "",          delay: 1580 },
  { text: "ALL MODULES OPERATIONAL — AUTHORIZATION REQUIRED",               color: "#ef4444",   delay: 1640 },
];

export default function LockScreen({ onUnlock }: { onUnlock: (token: string) => void }) {
  const [value,        setValue]        = useState("");
  const [error,        setError]        = useState(false);
  const [loading,      setLoading]      = useState(false);
  const [shake,        setShake]        = useState(false);
  const [visibleLines, setVisibleLines] = useState(-1);
  const [showForm,     setShowForm]     = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    BOOT_LINES.forEach((_, i) => {
      setTimeout(() => setVisibleLines(i), BOOT_LINES[i]!.delay + 80);
    });
    setTimeout(() => setShowForm(true),    1880);
    setTimeout(() => inputRef.current?.focus(), 2060);
  }, []);

  const attempt = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!value.trim()) return;
    setLoading(true);
    setError(false);
    try {
      const res = await fetch(`${API_URL}/api/auth/login`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ password: value }),
      });
      if (res.ok) {
        const { token } = await res.json() as { token: string };
        onUnlock(token);
        return;
      }
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

      {/* CRT scanlines */}
      <div className="absolute inset-0 pointer-events-none z-10"
        style={{ background: "repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.055) 2px, rgba(0,0,0,0.055) 4px)" }} />

      {/* Vignette */}
      <div className="absolute inset-0 pointer-events-none z-10"
        style={{ background: "radial-gradient(ellipse at center, transparent 32%, rgba(0,0,0,0.78) 100%)" }} />

      <div className="relative z-20 w-full max-w-lg px-6">
        <style>{`
          @keyframes nxf-glitch {
            0%,88%,100% { text-shadow:2px 0 #dc2626,-2px 0 #22d3ee,0 0 14px rgba(220,38,38,.3); letter-spacing:.35em; }
            89% { text-shadow:-5px 0 #dc2626,5px 0 #22d3ee,0 0 24px rgba(220,38,38,.7); letter-spacing:.44em; }
            90% { text-shadow:4px 2px #22d3ee,-4px -2px #dc2626; clip-path:inset(20% 0 30% 0); }
            91% { text-shadow:2px 0 #dc2626,-2px 0 #22d3ee; clip-path:none; letter-spacing:.32em; }
            92% { letter-spacing:.35em; text-shadow:2px 0 #dc2626,-2px 0 #22d3ee,0 0 14px rgba(220,38,38,.3); }
          }
          @keyframes nxf-shake  { 0%,100%{transform:translateX(0)} 20%,60%{transform:translateX(-10px)} 40%,80%{transform:translateX(10px)} }
          @keyframes nxf-slide  { from{opacity:0;transform:translateY(16px)} to{opacity:1;transform:translateY(0)} }
          @keyframes nxf-fade   { from{opacity:0} to{opacity:1} }
          @keyframes nxf-blink  { 0%,49%{opacity:1} 50%,100%{opacity:0} }
          @keyframes nxf-pulse  { 0%,100%{opacity:1} 50%{opacity:.35} }
        `}</style>

        {/* Boot log */}
        <div className="mb-7 text-[11px] space-y-[3px] min-h-[208px]">
          {BOOT_LINES.slice(0, visibleLines + 1).map((line, i) => (
            <div key={i} style={{ color: line.color || "transparent", animation: "nxf-fade 0.16s ease" }}>
              {line.text && <><span className="opacity-40 mr-2 select-none">›</span>{line.text}</>}
            </div>
          ))}
          {visibleLines >= 0 && visibleLines < BOOT_LINES.length - 1 && (
            <span style={{ color: "#ef4444", animation: "nxf-blink 0.9s step-end infinite" }}>█</span>
          )}
        </div>

        {/* Auth card */}
        {showForm && (
          <div className="relative border border-red-900/50 bg-black/94 px-8 py-7"
            style={{
              boxShadow: "0 0 70px rgba(220,38,38,.09),0 0 140px rgba(220,38,38,.04),inset 0 0 60px rgba(0,0,0,.5)",
              animation: shake ? "nxf-shake .45s ease" : "nxf-slide .42s ease forwards",
            }}>

            {/* Corner brackets */}
            {([["top-0 left-0","border-t-2 border-l-2","-translate-x-px -translate-y-px"],
               ["top-0 right-0","border-t-2 border-r-2","translate-x-px -translate-y-px"],
               ["bottom-0 left-0","border-b-2 border-l-2","-translate-x-px translate-y-px"],
               ["bottom-0 right-0","border-b-2 border-r-2","translate-x-px translate-y-px"],
            ] as [string,string,string][]).map(([pos, border, t], ki) => (
              <div key={ki} className={`absolute ${pos} w-5 h-5 ${border} border-red-700/50 transform ${t}`} />
            ))}

            {/* Title */}
            <div className="text-center mb-7">
              <h1 className="text-4xl font-black text-red-600 uppercase select-none"
                style={{ animation: "nxf-glitch 7s infinite", fontFamily: "monospace", letterSpacing: ".35em" }}>
                NEXUSFORGE
              </h1>
              <div className="mt-2 text-[9px] text-zinc-700 tracking-[.45em] uppercase select-none">
                Command Injection Research Platform
              </div>
              <div className="mt-0.5 text-[8px] text-zinc-800 tracking-[.28em] uppercase select-none">
                v9.0.0 · {new Date().getFullYear()} · RESTRICTED ACCESS
              </div>
            </div>

            {/* Status bar */}
            <div className="flex items-center gap-2 mb-6 border border-zinc-900 bg-zinc-950/70 px-3 py-2">
              <span className="w-1.5 h-1.5 rounded-full bg-red-500 shrink-0"
                style={{ animation: "nxf-pulse 1.3s infinite" }} />
              <span className="text-[9px] text-zinc-600 flex-1 uppercase tracking-[.2em]">
                System Locked — Authorization Required
              </span>
              <div className="flex gap-1">
                {[1,2,3].map(n => <span key={n} className="w-1 h-1 bg-red-900 rounded-full" />)}
              </div>
            </div>

            <form onSubmit={attempt} autoComplete="off" className="space-y-4">
              <div>
                <div className="flex justify-between items-center mb-1.5">
                  <label className="text-[9px] text-zinc-600 uppercase tracking-[.18em]">Authorization Key</label>
                  <span className="text-[8px] text-zinc-800 uppercase">HMAC-SHA256 · 24h TTL</span>
                </div>
                <input
                  ref={inputRef}
                  type="password"
                  value={value}
                  onChange={e => { setValue(e.target.value); setError(false); }}
                  className="w-full bg-black border border-red-900/45 px-3 py-2.5 text-red-400 text-sm focus:outline-none focus:border-red-500 transition-colors tracking-widest"
                  style={error ? { boxShadow: "0 0 18px rgba(220,38,38,.22)" } : {}}
                  autoComplete="new-password"
                  spellCheck={false}
                  disabled={loading}
                />
              </div>

              {error && (
                <div className="flex items-center gap-2 text-[10px] font-bold tracking-widest uppercase text-red-500 border border-red-900/35 bg-red-950/12 px-3 py-2">
                  <span>■</span>
                  <span>Access Denied — Invalid Authorization Key</span>
                </div>
              )}

              <button type="submit" disabled={loading || !value.trim()}
                className="w-full bg-red-950/28 border border-red-800/45 text-red-400 py-3 text-[11px] font-bold uppercase tracking-[.28em] hover:bg-red-900/38 hover:text-red-300 hover:border-red-600/70 transition-all disabled:opacity-40">
                {loading ? "Verifying…" : "Authenticate →"}
              </button>
            </form>

            {/* Footer stats */}
            <div className="mt-6 pt-4 border-t border-zinc-900/50 grid grid-cols-4 gap-2 text-center select-none">
              {([["ENGINES","13"],["MODES","30"],["VECTORS","2400+"],["MODULES","15"]] as [string,string][]).map(([label,val]) => (
                <div key={label}>
                  <div className="text-[8px] text-zinc-800 uppercase mb-0.5">{label}</div>
                  <div className="text-[11px] text-red-900 font-bold">{val}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
