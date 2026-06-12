import React, { useState, useEffect, useRef } from "react";

const API_URL = (import.meta.env as Record<string,string>)["VITE_API_URL"] ?? "";

/* ─── Matrix rain ───────────────────────────────────────────── */
function MatrixRain() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const resize = () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight; };
    resize();
    const chars = "アイウエオカキクケコサシスセソタチツテトハヒフヘホ0123456789ABCDEF<>/\\|{}[]";
    const cols = () => Math.floor(canvas.width / 14);
    let drops: number[] = Array.from({ length: cols() }, () => Math.random() * -80);
    const draw = () => {
      ctx.fillStyle = "rgba(0,0,0,0.05)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.font = "11px monospace";
      drops.forEach((y, i) => {
        const char = chars[Math.floor(Math.random() * chars.length)]!;
        const x    = i * 14;
        const r    = Math.random();
        ctx.fillStyle = r > 0.97 ? "#ef4444" : r > 0.92 ? "#ef444430" : r > 0.85 ? "#22d3ee18" : "#ef444408";
        ctx.fillText(char, x, y * 14);
        if (y * 14 > canvas.height && Math.random() > 0.975) drops[i] = 0;
        drops[i] = (drops[i] ?? 0) + 1;
      });
    };
    const ro = new ResizeObserver(() => { resize(); drops = Array.from({ length: cols() }, () => Math.random() * -80); });
    ro.observe(document.body);
    window.addEventListener("resize", resize);
    const id = setInterval(draw, 42);
    return () => { clearInterval(id); window.removeEventListener("resize", resize); ro.disconnect(); };
  }, []);
  return <canvas ref={canvasRef} className="absolute inset-0 w-full h-full opacity-20" />;
}

/* ─── Live clock ────────────────────────────────────────────── */
function LiveClock() {
  const [t, setT] = useState(() => new Date());
  useEffect(() => { const id = setInterval(() => setT(new Date()), 1000); return () => clearInterval(id); }, []);
  const pad = (n: number) => String(n).padStart(2, "0");
  return (
    <div className="text-right select-none">
      <div className="text-[13px] text-red-500 font-bold tabular-nums tracking-widest">
        {pad(t.getHours())}:{pad(t.getMinutes())}:{pad(t.getSeconds())}
      </div>
      <div className="text-[8px] text-zinc-700 tracking-[.15em] uppercase mt-0.5">
        {t.toLocaleDateString("en-US",{weekday:"short",month:"short",day:"2-digit",year:"numeric"})}
      </div>
    </div>
  );
}

/* ─── Telemetry ticker ──────────────────────────────────────── */
function useTicker(min: number, max: number, interval = 900) {
  const [val, setVal] = useState(min + Math.floor(Math.random() * (max - min)));
  useEffect(() => {
    const id = setInterval(() => setVal(v => {
      const delta = Math.floor(Math.random() * 7) - 3;
      return Math.min(max, Math.max(min, v + delta));
    }), interval);
    return () => clearInterval(id);
  }, [min, max, interval]);
  return val;
}

function Telemetry() {
  const cpu = useTicker(12, 38, 800);
  const mem = useTicker(44, 68, 1100);
  const pkt = useTicker(200, 900, 400);
  const bars = (pct: number, color: string) => {
    const filled = Math.round(pct / 10);
    return (
      <span style={{ color }}>
        {"█".repeat(filled)}<span className="opacity-20">{"░".repeat(10 - filled)}</span>
      </span>
    );
  };
  return (
    <div className="grid grid-cols-3 gap-3 text-[9px] font-mono border border-zinc-900 bg-black/60 px-3 py-2 select-none">
      <div>
        <div className="text-zinc-700 uppercase tracking-widest mb-1">CPU</div>
        <div className="text-red-500 tabular-nums font-bold">{cpu}%</div>
        <div className="mt-0.5">{bars(cpu, "#ef4444")}</div>
      </div>
      <div>
        <div className="text-zinc-700 uppercase tracking-widest mb-1">MEM</div>
        <div className="text-red-400 tabular-nums font-bold">{mem}%</div>
        <div className="mt-0.5">{bars(mem, "#f87171")}</div>
      </div>
      <div>
        <div className="text-zinc-700 uppercase tracking-widest mb-1">PKT/s</div>
        <div className="text-cyan-700 tabular-nums font-bold">{pkt}</div>
        <div className="mt-0.5">{bars(Math.round((pkt / 900) * 100), "#164e63")}</div>
      </div>
    </div>
  );
}

/* ─── Boot sequence ─────────────────────────────────────────── */
const BOOT_LINES: { text: string; color: string; delay: number; tag?: string }[] = [
  { text: "NEXUSFORGE OS v9.0.0 — Restricted Access Terminal",          color: "#ef4444",   delay: 0,    tag: "HEAD" },
  { text: "[ OK ] Cryptographic subsystems initialized",                 color: "#52525b",   delay: 120  },
  { text: "[ OK ] Injection engine library — 13 engines loaded",         color: "#52525b",   delay: 250  },
  { text: "[ OK ] Payload database — 30 modes / 2400+ variants mounted", color: "#52525b",   delay: 380  },
  { text: "[ OK ] OOB callback listener started — SSE active",           color: "#52525b",   delay: 510  },
  { text: "[ OK ] CVE exploit library — 2024–2025 synchronized",         color: "#52525b",   delay: 630  },
  { text: "[ OK ] WebSocket escalation engine ready",                     color: "#52525b",   delay: 750  },
  { text: "[ OK ] Mutation scanner subprocess spawned",                   color: "#52525b",   delay: 865  },
  { text: "[ OK ] Payload delivery engine armed",                         color: "#52525b",   delay: 975  },
  { text: "[ OK ] Persistence mechanism generator online",                color: "#52525b",   delay: 1080 },
  { text: "[ OK ] AI payload generator online",                           color: "#3d6b4f",   delay: 1180 },
  { text: "[ OK ] Bypass engine armed — WAF evasion ready",               color: "#3d6b4f",   delay: 1270 },
  { text: "[ OK ] Network interfaces bound",                              color: "#3d6b4f",   delay: 1350 },
  { text: "",                                                              color: "",          delay: 1430 },
  { text: "ALL MODULES OPERATIONAL — AUTHORIZATION REQUIRED",             color: "#ef4444",   delay: 1490, tag: "ALERT" },
];
const TOTAL_MODULES = BOOT_LINES.filter(l => l.text.startsWith("[ OK ]")).length;

/* ─── Scanning line ─────────────────────────────────────────── */
function ScanLine() {
  return (
    <div className="absolute inset-0 pointer-events-none overflow-hidden rounded-[inherit]">
      <div style={{
        position: "absolute", left: 0, right: 0, height: "2px",
        background: "linear-gradient(90deg,transparent,rgba(220,38,38,0.12),rgba(220,38,38,0.25),rgba(220,38,38,0.12),transparent)",
        animation: "nxf-scan 4s linear infinite",
      }} />
    </div>
  );
}

/* ─── Corner brackets ───────────────────────────────────────── */
function Corners({ animate }: { animate?: boolean }) {
  return (
    <>
      {([
        ["top-0 left-0",     "border-t-2 border-l-2", "-translate-x-px -translate-y-px"],
        ["top-0 right-0",    "border-t-2 border-r-2",  "translate-x-px -translate-y-px"],
        ["bottom-0 left-0",  "border-b-2 border-l-2", "-translate-x-px translate-y-px"],
        ["bottom-0 right-0", "border-b-2 border-r-2",  "translate-x-px translate-y-px"],
      ] as [string,string,string][]).map(([pos, border, t], i) => (
        <div key={i}
          className={`absolute ${pos} w-5 h-5 ${border} border-red-700/60 transform ${t}`}
          style={animate ? { animation: `nxf-corner-in 0.3s ${i * 60}ms both` } : {}}
        />
      ))}
    </>
  );
}

/* ─── Main component ────────────────────────────────────────── */
export default function LockScreen({ onUnlock }: { onUnlock: (token: string) => void }) {
  const [value,        setValue]        = useState("");
  const [error,        setError]        = useState(false);
  const [loading,      setLoading]      = useState(false);
  const [shake,        setShake]        = useState(false);
  const [visibleLines, setVisibleLines] = useState(-1);
  const [showForm,     setShowForm]     = useState(false);
  const [attempts,     setAttempts]     = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    BOOT_LINES.forEach((_, i) => setTimeout(() => setVisibleLines(i), BOOT_LINES[i]!.delay + 80));
    setTimeout(() => setShowForm(true),                  1720);
    setTimeout(() => inputRef.current?.focus(),          1900);
  }, []);

  const okCount    = visibleLines < 0 ? 0 : BOOT_LINES.slice(0, visibleLines + 1).filter(l => l.text.startsWith("[ OK ]")).length;
  const bootPct    = Math.round((okCount / TOTAL_MODULES) * 100);
  const bootDone   = visibleLines >= BOOT_LINES.length - 1;

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
      setAttempts(a => a + 1);
      setValue("");
      setTimeout(() => setShake(false), 520);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-black font-mono relative overflow-hidden">
      <MatrixRain />

      {/* CRT scanlines */}
      <div className="absolute inset-0 pointer-events-none z-10"
        style={{ background: "repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.045) 2px,rgba(0,0,0,0.045) 4px)" }} />

      {/* Vignette */}
      <div className="absolute inset-0 pointer-events-none z-10"
        style={{ background: "radial-gradient(ellipse at center, transparent 28%, rgba(0,0,0,0.82) 100%)" }} />

      <div className="relative z-20 w-full max-w-xl px-5">
        <style>{`
          @keyframes nxf-glitch {
            0%,86%,100% { text-shadow:2px 0 #dc2626,-2px 0 #22d3ee,0 0 18px rgba(220,38,38,.35); letter-spacing:.38em; }
            87%          { text-shadow:-6px 0 #dc2626,6px 0 #22d3ee,0 0 28px rgba(220,38,38,.8);  letter-spacing:.46em; }
            88%          { text-shadow:4px 2px #22d3ee,-4px -2px #dc2626; clip-path:inset(15% 0 35% 0); }
            89%          { text-shadow:2px 0 #dc2626,-2px 0 #22d3ee; clip-path:none; letter-spacing:.33em; }
            90%          { letter-spacing:.38em; text-shadow:2px 0 #dc2626,-2px 0 #22d3ee,0 0 18px rgba(220,38,38,.35); }
            93%          { text-shadow:-3px 1px #22d3ee88, 3px 0 #dc262650; clip-path:inset(55% 0 10% 0); letter-spacing:.42em; }
            94%          { clip-path:none; letter-spacing:.38em; text-shadow:2px 0 #dc2626,-2px 0 #22d3ee; }
          }
          @keyframes nxf-shake  { 0%,100%{transform:translateX(0)} 18%,54%{transform:translateX(-9px)} 36%,72%{transform:translateX(9px)} }
          @keyframes nxf-slide  { from{opacity:0;transform:translateY(18px)} to{opacity:1;transform:translateY(0)} }
          @keyframes nxf-fade   { from{opacity:0} to{opacity:1} }
          @keyframes nxf-blink  { 0%,49%{opacity:1} 50%,100%{opacity:0} }
          @keyframes nxf-pulse  { 0%,100%{opacity:1} 50%{opacity:.3} }
          @keyframes nxf-scan   { 0%{top:-2px} 100%{top:100%} }
          @keyframes nxf-corner-in { from{opacity:0;transform:scale(.6)} to{opacity:1;transform:scale(1)} }
          @keyframes nxf-progfill  { from{width:0%} to{width:var(--pct)} }
          @keyframes nxf-errpulse  { 0%,100%{box-shadow:0 0 10px rgba(220,38,38,.2)} 50%{box-shadow:0 0 28px rgba(220,38,38,.55)} }
        `}</style>

        {/* Top bar: system ID + clock */}
        <div className="flex justify-between items-start mb-4 px-1">
          <div className="select-none">
            <div className="text-[9px] text-zinc-700 uppercase tracking-[.25em]">System</div>
            <div className="text-[11px] text-zinc-600 tracking-widest font-bold">NEXUSFORGE-NODE-01</div>
          </div>
          <LiveClock />
        </div>

        {/* Boot log */}
        <div className="mb-5 text-[10px] leading-[1.65] min-h-[196px]">
          {BOOT_LINES.slice(0, visibleLines + 1).map((line, i) => (
            <div key={i} style={{ color: line.color || "transparent", animation: "nxf-fade 0.14s ease" }}>
              {line.text && (
                <span>
                  <span className="opacity-30 mr-2 select-none">›</span>
                  {line.tag === "ALERT" ? <span className="font-bold tracking-[.12em]">{line.text}</span> : line.text}
                </span>
              )}
            </div>
          ))}
          {visibleLines >= 0 && !bootDone && (
            <span style={{ color: "#ef4444", animation: "nxf-blink 0.85s step-end infinite" }}>█</span>
          )}
        </div>

        {/* Boot progress bar */}
        <div className="mb-5 select-none">
          <div className="flex justify-between text-[8px] text-zinc-700 uppercase tracking-widest mb-1">
            <span>Module Init</span>
            <span className="tabular-nums text-red-900">{bootPct}%</span>
          </div>
          <div className="h-[3px] bg-zinc-900 relative overflow-hidden">
            <div
              className="h-full bg-red-800 transition-all duration-300"
              style={{ width: `${bootPct}%` }}
            />
            {!bootDone && (
              <div className="absolute inset-0"
                style={{ background: "linear-gradient(90deg,transparent,rgba(220,38,38,0.35),transparent)", animation: "nxf-scan 1.2s linear infinite" }} />
            )}
          </div>
        </div>

        {/* Auth card */}
        {showForm && (
          <div className="relative border border-red-900/45 bg-black/96"
            style={{
              boxShadow: error
                ? "0 0 60px rgba(220,38,38,.18),0 0 120px rgba(220,38,38,.07),inset 0 0 50px rgba(0,0,0,.6)"
                : "0 0 60px rgba(220,38,38,.07),0 0 120px rgba(220,38,38,.03),inset 0 0 50px rgba(0,0,0,.6)",
              animation: shake ? "nxf-shake .48s ease" : "nxf-slide .38s ease forwards",
            }}>

            <ScanLine />
            <Corners animate />

            <div className="px-8 py-7">
              {/* Title */}
              <div className="text-center mb-6">
                <h1 className="text-[2.2rem] font-black text-red-600 uppercase select-none leading-none"
                  style={{ animation: "nxf-glitch 8s infinite", fontFamily: "monospace", letterSpacing: ".38em" }}>
                  NEXUS
                </h1>
                <div className="text-[8px] text-red-900/80 font-bold tracking-[.5em] uppercase mt-1 select-none">FORGE</div>
                <div className="mt-2 text-[9px] text-zinc-700 tracking-[.38em] uppercase select-none">
                  Command Injection Research Platform
                </div>
                <div className="mt-0.5 text-[7px] text-zinc-800 tracking-[.22em] uppercase select-none">
                  v9.0.0 · {new Date().getFullYear()} · RESTRICTED ACCESS
                </div>
              </div>

              {/* Telemetry */}
              <Telemetry />

              {/* Status bar */}
              <div className="flex items-center gap-2 mt-4 mb-5 border border-zinc-900 bg-zinc-950/80 px-3 py-2">
                <span className="w-1.5 h-1.5 rounded-full bg-red-500 shrink-0"
                  style={{ animation: "nxf-pulse 1.4s infinite" }} />
                <span className="text-[9px] text-zinc-600 flex-1 uppercase tracking-[.18em]">
                  {attempts > 0
                    ? `${attempts} Failed Attempt${attempts > 1 ? "s" : ""} — System Locked`
                    : "System Locked — Authorization Required"}
                </span>
                <div className="flex gap-1">
                  {[0,1,2].map(n => (
                    <span key={n} className="w-1.5 h-1.5 rounded-full"
                      style={{ background: n < attempts ? "#7f1d1d" : "#27272a" }} />
                  ))}
                </div>
              </div>

              <form onSubmit={attempt} autoComplete="off" className="space-y-3">
                <div>
                  <div className="flex justify-between items-center mb-1.5">
                    <label className="text-[9px] text-zinc-600 uppercase tracking-[.18em]">Authorization Key</label>
                    <span className="text-[7px] text-zinc-800 uppercase tracking-widest">HMAC-SHA256 · 24h TTL</span>
                  </div>
                  <div className="relative">
                    <input
                      ref={inputRef}
                      type="password"
                      value={value}
                      onChange={e => { setValue(e.target.value); setError(false); }}
                      className="w-full bg-black border border-red-900/40 px-3 py-2.5 text-red-400 text-sm focus:outline-none focus:border-red-600/70 transition-colors tracking-[.18em] pr-10"
                      style={error ? { boxShadow: "0 0 22px rgba(220,38,38,.28)", animation: "nxf-errpulse 1s ease infinite" } : {}}
                      autoComplete="new-password"
                      spellCheck={false}
                      disabled={loading}
                      placeholder="••••••••••••"
                    />
                    {/* terminal prompt */}
                    <span className="absolute right-3 top-1/2 -translate-y-1/2 text-red-900 text-xs select-none pointer-events-none">
                      {loading ? "…" : "_"}
                    </span>
                  </div>
                </div>

                {error && (
                  <div className="flex items-center gap-2 text-[10px] font-bold tracking-[.12em] uppercase text-red-500 border border-red-900/40 bg-red-950/10 px-3 py-2">
                    <span className="text-red-600">■</span>
                    <span>Access Denied — Invalid Authorization Key</span>
                  </div>
                )}

                <button type="submit" disabled={loading || !value.trim()}
                  className="w-full bg-red-950/25 border border-red-800/40 text-red-400 py-2.5 text-[11px] font-bold uppercase tracking-[.3em] hover:bg-red-900/35 hover:text-red-300 hover:border-red-600/65 transition-all disabled:opacity-35 active:scale-[.99]">
                  {loading ? "Verifying…" : "Authenticate →"}
                </button>
              </form>

              {/* Footer stats */}
              <div className="mt-5 pt-4 border-t border-zinc-900/60 grid grid-cols-5 gap-1.5 text-center select-none">
                {([["ENGINES","13"],["MODES","30"],["VECTORS","2.4k"],["MODULES","15"],["CVEs","47+"]] as [string,string][]).map(([label, val]) => (
                  <div key={label} className="border border-zinc-900/60 py-1.5">
                    <div className="text-[7px] text-zinc-800 uppercase tracking-widest mb-0.5">{label}</div>
                    <div className="text-[11px] text-red-900 font-bold tabular-nums">{val}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Bottom node ID */}
        <div className="mt-3 flex justify-between text-[7px] text-zinc-800 uppercase tracking-widest px-1 select-none">
          <span>NODE-01 · CLASSIFIED</span>
          <span>DO NOT DISTRIBUTE</span>
        </div>
      </div>
    </div>
  );
}
