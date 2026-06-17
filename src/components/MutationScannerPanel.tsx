import React, { useState, useRef, useCallback, useEffect } from "react";
import NexusTerminal, { type NexusTerminalHandle, ansiLine } from "./NexusTerminal";
import { useReconnectingWs } from "../hooks/use-reconnecting-ws";

const API_URL = (import.meta.env as Record<string, string>)["VITE_API_URL"] ?? "";

interface ConfirmedPayload { payload: string; score: number; evidence: string; generation: number; }
interface TopPayload       { payload: string; score: number; }

type MutStrategy = "genetic" | "random" | "beam";
type MutWafProfile = "auto" | "cloudflare" | "akamai" | "modsec" | "aws" | "imperva" | "none";

const MUT_STRATEGIES: Record<MutStrategy, { label: string; desc: string }> = {
  genetic: { label: "Genetic",     desc: "Crossover + fitness selection — broadest coverage" },
  random:  { label: "Random Walk", desc: "Stochastic mutation — maximum variance, unpredictable" },
  beam:    { label: "Beam Search", desc: "Keeps top-K survivors per gen — fastest convergence" },
};

const MUT_WAF_PROFILES: Record<MutWafProfile, { label: string; minDelay: number; maxDelay: number; color: string }> = {
  auto:       { label: "Auto",        minDelay: 600,  maxDelay: 1800, color: "text-zinc-400"   },
  cloudflare: { label: "Cloudflare",  minDelay: 2000, maxDelay: 5000, color: "text-orange-400" },
  akamai:     { label: "Akamai",      minDelay: 1200, maxDelay: 3000, color: "text-blue-400"   },
  modsec:     { label: "ModSecurity", minDelay: 500,  maxDelay: 1500, color: "text-yellow-400" },
  aws:        { label: "AWS WAF",     minDelay: 800,  maxDelay: 2500, color: "text-amber-400"  },
  imperva:    { label: "Imperva",     minDelay: 1500, maxDelay: 4000, color: "text-purple-400" },
  none:       { label: "No WAF",      minDelay: 80,   maxDelay: 250,  color: "text-green-400"  },
};

const MUT_OPS = [
  { id: "encoding",   label: "Encoding",   desc: "Base64, hex, octal, unicode escapes" },
  { id: "syntax",     label: "Syntax",     desc: "IFS, ${IFS}, ca''t, co$()mmand" },
  { id: "whitespace", label: "Whitespace", desc: "Tab/newline substitution, $IFS" },
  { id: "comment",    label: "Comment",    desc: "Inline comment injection: /**/,/**/" },
  { id: "unicode",    label: "Unicode",    desc: "Homoglyph & fullwidth char swaps" },
  { id: "case",       label: "Case",       desc: "Mixed case, leet-speak transforms" },
  { id: "chunked",    label: "Chunked",    desc: "Split payload across multiple params" },
  { id: "polyglot",   label: "Polyglot",   desc: "SSTI + SQL + shell hybrid payloads" },
] as const;

function msgToAnsi(msg: Record<string, unknown>): string | null {
  const type = msg["type"] as string;
  if (type === "banner" || type === "data" || type === "text") {
    const t = ((msg["text"] ?? msg["chunk"] ?? "") as string).trimEnd();
    if (!t) return null;
    return t.split("\n").map(l => ansiLine(l)).join("\r\n");
  }
  if (type === "phase") {
    return `\x1b[36m[PHASE] ${msg["phase"] as string}: ${msg["text"] as string}\x1b[0m`;
  }
  if (type === "baseline") {
    return `\x1b[90m${msg["text"] as string}\x1b[0m`;
  }
  if (type === "generation_start") {
    const t = msg["text"] as string;
    return t.split("\n").map(l =>
      /GENERATION/.test(l) ? `\x1b[1;35m${l}\x1b[0m` : `\x1b[90m${l}\x1b[0m`
    ).join("\r\n");
  }
  if (type === "probe") {
    return `\x1b[90m${msg["text"] as string}\x1b[0m`;
  }
  if (type === "result") {
    const t = msg["text"] as string;
    if (/RCE/.test(t))  return `\x1b[1;31m${t}\x1b[0m`;
    if (/HIT/.test(t))  return `\x1b[33m${t}\x1b[0m`;
    if (/DIFF/.test(t)) return `\x1b[32m${t}\x1b[0m`;
    return `\x1b[90m${t}\x1b[0m`;
  }
  if (type === "confirmed") {
    const t = msg["text"] as string;
    return t.split("\n").map(l => `\x1b[1;32m${l}\x1b[0m`).join("\r\n");
  }
  if (type === "generation_done") {
    const t = msg["text"] as string;
    return t.split("\n").map(l =>
      /TOP-5/.test(l) ? `\x1b[35m${l}\x1b[0m` : `\x1b[36m${l}\x1b[0m`
    ).join("\r\n");
  }
  if (type === "evolve") {
    return `\x1b[33m${msg["text"] as string}\x1b[0m`;
  }
  if (type === "propagation_start") {
    const t = msg["text"] as string;
    return t.split("\n").map(l =>
      /PROPAGATION/.test(l) ? `\x1b[1;36m${l}\x1b[0m` : `\x1b[90m${l}\x1b[0m`
    ).join("\r\n");
  }
  if (type === "propagation_probe") {
    return `\x1b[90m${msg["text"] as string}\x1b[0m`;
  }
  if (type === "propagation_result") {
    const t = msg["text"] as string;
    return msg["propagated"] ? `\x1b[1;31m${t}\x1b[0m` : `\x1b[90m${t}\x1b[0m`;
  }
  if (type === "end") {
    const t = msg["text"] as string;
    return t.split("\n").map(l =>
      /COMPLETE/.test(l) ? `\x1b[1;32m${l}\x1b[0m` : `\x1b[32m${l}\x1b[0m`
    ).join("\r\n");
  }
  if (type === "error") {
    return `\x1b[31m[ERROR] ${msg["message"] as string}\x1b[0m`;
  }
  return null;
}

export default function MutationScannerPanel() {
  const [targetUrl,    setTargetUrl]    = useState("");
  const [injectParam,  setInjectParam]  = useState("cmd");
  const [httpMethod,   setHttpMethod]   = useState("GET");
  const [generations,  setGenerations]  = useState("6");
  const [popSize,      setPopSize]      = useState("20");
  const [extraParams,  setExtraParams]  = useState("");
  const [customHdrs,   setCustomHdrs]   = useState("");
  const [strategy,     setStrategy]     = useState<MutStrategy>("genetic");
  const [wafProfile,   setWafProfile]   = useState<MutWafProfile>("auto");
  const [probeMinDelay,setProbeMinDelay]= useState("600");
  const [probeMaxDelay,setProbeMaxDelay]= useState("1800");
  const [enabledOps,   setEnabledOps]   = useState<Set<string>>(
    new Set(MUT_OPS.map(o => o.id))
  );
  const [eliteSize,    setEliteSize]    = useState("4");
  const [mutationRate, setMutationRate] = useState("0.35");

  const [running,      setRunning]      = useState(false);
  const [showConfig,   setShowConfig]   = useState(true);
  const [elapsed,      setElapsed]      = useState<number | null>(null);
  const [generation,   setGeneration]   = useState<number>(0);
  const [totalGens,    setTotalGens]    = useState<number>(0);
  const [confirmed,    setConfirmed]    = useState<ConfirmedPayload[]>([]);
  const [topPayloads,  setTopPayloads]  = useState<TopPayload[]>([]);
  const [copied,       setCopied]       = useState<string | null>(null);
  const [done,         setDone]         = useState(false);

  const termRef  = useRef<NexusTerminalHandle | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const startRef = useRef<number>(0);

  const handleWsMessage = useCallback((msg: unknown) => {
    const m    = msg as Record<string, unknown>;
    const type = m["type"] as string;

    const ansi = msgToAnsi(m);
    if (ansi) termRef.current?.writeAnsi(ansi + "\r\n");

    if (type === "generation_start") {
      setGeneration(m["generation"] as number);
      setTotalGens(m["total"] as number);
    } else if (type === "confirmed") {
      setConfirmed(prev => {
        if (prev.find(c => c.payload === (m["payload"] as string))) return prev;
        return [...prev, {
          payload:    m["payload"]    as string,
          score:      m["score"]      as number,
          evidence:   m["evidence"]   as string,
          generation: m["generation"] as number,
        }];
      });
    } else if (type === "end") {
      setRunning(false);
      setDone(true);
      setElapsed(Date.now() - startRef.current);
      if (timerRef.current) { clearInterval(timerRef.current); timerRef.current = null; }
      const top = m["topPayloads"] as TopPayload[] | undefined;
      if (top) setTopPayloads(top);
    } else if (type === "error") {
      setRunning(false);
      if (timerRef.current) { clearInterval(timerRef.current); timerRef.current = null; }
    }
  }, []);

  const handleWsClose = useCallback((wasClean: boolean) => {
    setRunning(false);
    if (timerRef.current) { clearInterval(timerRef.current); timerRef.current = null; }
    if (!wasClean) {
      termRef.current?.writeAnsi("\x1b[31m[WS]\x1b[0m connection lost\r\n");
    }
  }, []);

  const wsHook = useReconnectingWs({ onMessage: handleWsMessage, onClose: handleWsClose });

  useEffect(() => () => {
    if (timerRef.current) clearInterval(timerRef.current);
  }, []);

  const copy = useCallback((text: string, id: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(id); setTimeout(() => setCopied(c => c === id ? null : c), 1800);
    }).catch(() => {});
  }, []);

  const launch = useCallback(() => {
    if (!targetUrl.trim() || running) return;
    setRunning(true);
    setDone(false);
    setConfirmed([]);
    setTopPayloads([]);
    setGeneration(0);
    setElapsed(null);
    setShowConfig(false);
    startRef.current = Date.now();
    termRef.current?.clear();

    const waf = MUT_WAF_PROFILES[wafProfile];
    const effMin = parseInt(probeMinDelay) || waf.minDelay;
    const effMax = parseInt(probeMaxDelay) || waf.maxDelay;

    termRef.current?.writeAnsi(`\x1b[1;35m[MUTATION SCANNER]\x1b[0m Genetic Payload Evolution Engine\r\n`);
    termRef.current?.writeAnsi(`\x1b[35m[STRATEGY]\x1b[0m ${MUT_STRATEGIES[strategy].label} — ${MUT_STRATEGIES[strategy].desc}\r\n`);
    termRef.current?.writeAnsi(`\x1b[35m[WAF]\x1b[0m ${waf.label} · probe delay ${effMin}–${effMax}ms · ${enabledOps.size} mutation operators\r\n`);
    termRef.current?.writeAnsi(`\x1b[90m${"─".repeat(64)}\x1b[0m\r\n`);

    timerRef.current = setInterval(() => setElapsed(Date.now() - startRef.current), 250);

    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = API_URL
      ? `${API_URL.replace(/^http/, "ws")}/api/ws/mutation`
      : `${proto}//${window.location.host}/api/ws/mutation`;

    wsHook.connect(wsUrl, {
      targetUrl:     targetUrl.trim(),
      injectParam:   injectParam.trim() || "cmd",
      httpMethod,
      generations:   generations.trim() || "6",
      popSize:       popSize.trim() || "20",
      extraParams:   extraParams.trim(),
      customHeaders: customHdrs.trim(),
      strategy,
      wafProfile,
      probeMinDelay: effMin,
      probeMaxDelay: effMax,
      mutationOps:   Array.from(enabledOps).join(","),
      eliteSize:     parseInt(eliteSize) || 4,
      mutationRate:  parseFloat(mutationRate) || 0.35,
    });

    requestAnimationFrame(() => termRef.current?.fit());
  }, [targetUrl, injectParam, httpMethod, generations, popSize, extraParams, customHdrs,
      strategy, wafProfile, probeMinDelay, probeMaxDelay, enabledOps, eliteSize, mutationRate,
      running, wsHook]);

  const stop = useCallback(() => {
    wsHook.disconnect();
    setRunning(false);
    if (timerRef.current) { clearInterval(timerRef.current); timerRef.current = null; }
    termRef.current?.writeAnsi("\x1b[33m[STOPPED]\x1b[0m\r\n");
  }, [wsHook]);

  const reset = () => {
    setConfirmed([]); setTopPayloads([]); setGeneration(0);
    setElapsed(null); setDone(false);
    termRef.current?.clear();
  };

  const progressPct = totalGens > 0 ? Math.round((generation / totalGens) * 100) : 0;

  return (
    <div className="flex flex-col h-full bg-black text-zinc-300 font-mono text-xs overflow-hidden">

      <div className="flex items-center gap-2 px-3 py-1.5 bg-zinc-950 border-b border-zinc-900 shrink-0">
        <span className="text-fuchsia-500 font-bold uppercase tracking-widest text-[11px]">
          MUTATION SCANNER
        </span>
        <span className="text-zinc-700 text-[10px]">genetic payload evolution · propagation mapping</span>

        {running && (
          <span className="text-yellow-400 text-[10px] animate-pulse">
            ▶ gen {generation}/{totalGens} · {elapsed !== null ? `${(elapsed / 1000).toFixed(1)}s` : ""}
          </span>
        )}
        {done && elapsed !== null && (
          <span className="text-zinc-500 text-[10px]">
            done {(elapsed / 1000).toFixed(1)}s · {confirmed.length} confirmed
          </span>
        )}
        {confirmed.length > 0 && (
          <span className="text-lime-400 font-bold text-[10px] border border-lime-800 bg-lime-950/30 px-2 py-0.5">
            ✔ {confirmed.length} RCE{confirmed.length > 1 ? "s" : ""} found
          </span>
        )}

        <div className="ml-auto flex items-center gap-2">
          <button
            onClick={() => setShowConfig(v => !v)}
            className={`text-[10px] px-2 py-0.5 border uppercase tracking-wider transition-colors
              ${showConfig ? "border-fuchsia-800 text-fuchsia-400 bg-fuchsia-950/20" : "border-zinc-800 text-zinc-600 hover:border-zinc-600 hover:text-zinc-400"}`}>
            {showConfig ? "HIDE CONFIG" : "CONFIG"}
          </button>
        </div>
      </div>

      <div className="flex flex-1 min-h-0 overflow-hidden">

        {showConfig && (
          <div className="w-60 shrink-0 border-r border-zinc-900 flex flex-col overflow-y-auto">
            <div className="p-3 space-y-2">
              <div className="text-[10px] text-fuchsia-400 uppercase mb-1">Mutation Configuration</div>

              <div>
                <label className="text-[9px] text-zinc-600 uppercase block mb-0.5">Target URL *</label>
                <input value={targetUrl} onChange={e => setTargetUrl(e.target.value)}
                  placeholder="https://target.com/page"
                  className="w-full bg-zinc-900 border border-zinc-800 focus:border-fuchsia-800 text-zinc-200 px-2 py-1 text-[10px] outline-none placeholder:text-zinc-700"/>
              </div>

              <div className="flex gap-2">
                <div className="flex-1">
                  <label className="text-[9px] text-zinc-600 uppercase block mb-0.5">Param</label>
                  <input value={injectParam} onChange={e => setInjectParam(e.target.value)}
                    placeholder="cmd"
                    className="w-full bg-zinc-900 border border-zinc-800 focus:border-fuchsia-800 text-zinc-200 px-2 py-1 text-[10px] outline-none placeholder:text-zinc-700"/>
                </div>
                <div className="flex-1">
                  <label className="text-[9px] text-zinc-600 uppercase block mb-0.5">Method</label>
                  <select value={httpMethod} onChange={e => setHttpMethod(e.target.value)}
                    className="w-full bg-zinc-900 border border-zinc-800 text-zinc-200 px-2 py-1 text-[10px] outline-none">
                    {["GET","POST","PUT","PATCH"].map(m => <option key={m} value={m}>{m}</option>)}
                  </select>
                </div>
              </div>

              <div className="flex gap-2">
                <div className="flex-1">
                  <label className="text-[9px] text-zinc-600 uppercase block mb-0.5">Generations</label>
                  <input value={generations} onChange={e => setGenerations(e.target.value)}
                    type="number" min="2" max="12"
                    className="w-full bg-zinc-900 border border-zinc-800 focus:border-fuchsia-800 text-zinc-200 px-2 py-1 text-[10px] outline-none"/>
                </div>
                <div className="flex-1">
                  <label className="text-[9px] text-zinc-600 uppercase block mb-0.5">Pop Size</label>
                  <input value={popSize} onChange={e => setPopSize(e.target.value)}
                    type="number" min="8" max="40"
                    className="w-full bg-zinc-900 border border-zinc-800 focus:border-fuchsia-800 text-zinc-200 px-2 py-1 text-[10px] outline-none"/>
                </div>
              </div>

              <div>
                <label className="text-[9px] text-zinc-600 uppercase block mb-0.5">Extra Params to Map</label>
                <input value={extraParams} onChange={e => setExtraParams(e.target.value)}
                  placeholder="q, search, input"
                  className="w-full bg-zinc-900 border border-zinc-800 focus:border-fuchsia-800 text-zinc-200 px-2 py-1 text-[10px] outline-none placeholder:text-zinc-700"/>
                <div className="text-[8px] text-zinc-700 mt-0.5">comma-separated — propagation mapping</div>
              </div>

              <div>
                <label className="text-[9px] text-zinc-600 uppercase block mb-0.5">Custom Headers</label>
                <textarea value={customHdrs} onChange={e => setCustomHdrs(e.target.value)}
                  rows={2} placeholder={"Cookie: session=abc\nAuthorization: Bearer ..."}
                  className="w-full bg-zinc-900 border border-zinc-800 focus:border-fuchsia-800 text-zinc-300 px-2 py-1 text-[10px] outline-none placeholder:text-zinc-700 resize-none"/>
              </div>
            </div>

            {/* ── Strategy & Evasion ── */}
            <div className="p-3 space-y-2 border-t border-zinc-900">
              <div className="text-[10px] text-fuchsia-400 uppercase mb-1">Strategy &amp; Evasion</div>

              {/* Mutation Strategy */}
              <div>
                <label className="text-[9px] text-zinc-600 uppercase block mb-0.5">Mutation Strategy</label>
                <div className="space-y-0.5">
                  {(Object.keys(MUT_STRATEGIES) as MutStrategy[]).map(k => (
                    <button key={k} onClick={() => setStrategy(k)}
                      className={`w-full text-left px-2 py-1 border text-[9px] transition-all ${
                        strategy === k
                          ? "border-fuchsia-700 text-fuchsia-300 bg-fuchsia-950/30"
                          : "border-zinc-900 text-zinc-600 hover:border-zinc-700 hover:text-zinc-400"
                      }`}>
                      <span className="font-bold">{MUT_STRATEGIES[k].label}</span>
                      <span className="text-zinc-700 ml-1">— {MUT_STRATEGIES[k].desc}</span>
                    </button>
                  ))}
                </div>
              </div>

              {/* Evolution Params */}
              <div className="flex gap-2">
                <div className="flex-1">
                  <label className="text-[9px] text-zinc-600 uppercase block mb-0.5">Elite Size</label>
                  <input value={eliteSize} onChange={e => setEliteSize(e.target.value)} type="number" min="1" max="10"
                    className="w-full bg-zinc-900 border border-zinc-800 focus:border-fuchsia-800 text-zinc-200 px-2 py-1 text-[10px] outline-none"/>
                  <div className="text-[8px] text-zinc-700 mt-0.5">survivors/gen</div>
                </div>
                <div className="flex-1">
                  <label className="text-[9px] text-zinc-600 uppercase block mb-0.5">Mutation Rate</label>
                  <input value={mutationRate} onChange={e => setMutationRate(e.target.value)} type="number" min="0.05" max="1" step="0.05"
                    className="w-full bg-zinc-900 border border-zinc-800 focus:border-fuchsia-800 text-zinc-200 px-2 py-1 text-[10px] outline-none"/>
                  <div className="text-[8px] text-zinc-700 mt-0.5">0.0–1.0</div>
                </div>
              </div>

              {/* WAF Profile */}
              <div>
                <label className="text-[9px] text-zinc-600 uppercase block mb-0.5">WAF Profile</label>
                <div className="grid grid-cols-2 gap-0.5">
                  {(Object.keys(MUT_WAF_PROFILES) as MutWafProfile[]).map(k => {
                    const p = MUT_WAF_PROFILES[k];
                    return (
                      <button key={k} onClick={() => {
                        setWafProfile(k);
                        setProbeMinDelay(String(p.minDelay));
                        setProbeMaxDelay(String(p.maxDelay));
                      }}
                        className={`text-[8px] px-1.5 py-1 border uppercase tracking-wider text-left transition-all ${
                          wafProfile === k
                            ? `${p.color} border-current bg-zinc-950`
                            : "border-zinc-900 text-zinc-600 hover:border-zinc-700 hover:text-zinc-400"
                        }`}>
                        {p.label}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Probe Delay */}
              <div className="flex gap-2">
                <div className="flex-1">
                  <label className="text-[9px] text-zinc-600 uppercase block mb-0.5">Min Probe (ms)</label>
                  <input value={probeMinDelay} onChange={e => setProbeMinDelay(e.target.value)} type="number" min="50"
                    className="w-full bg-zinc-900 border border-zinc-800 focus:border-fuchsia-800 text-zinc-200 px-2 py-1 text-[10px] outline-none"/>
                </div>
                <div className="flex-1">
                  <label className="text-[9px] text-zinc-600 uppercase block mb-0.5">Max Probe (ms)</label>
                  <input value={probeMaxDelay} onChange={e => setProbeMaxDelay(e.target.value)} type="number" min="50"
                    className="w-full bg-zinc-900 border border-zinc-800 focus:border-fuchsia-800 text-zinc-200 px-2 py-1 text-[10px] outline-none"/>
                </div>
              </div>
              {(() => {
                const lo = parseInt(probeMinDelay) || 100, hi = parseInt(probeMaxDelay) || 2000;
                const pct = lo / (hi + 1) * 100;
                return (
                  <div className="relative h-1 bg-zinc-900 rounded overflow-hidden">
                    <div className="absolute inset-y-0 bg-fuchsia-800/60" style={{ left: `${pct}%`, right: 0 }}/>
                    <div className="absolute inset-y-0 left-0 bg-zinc-800" style={{ width: `${pct}%` }}/>
                  </div>
                );
              })()}

              {/* Mutation Operators */}
              <div>
                <div className="flex items-center justify-between mb-0.5">
                  <label className="text-[9px] text-zinc-600 uppercase">Mutation Operators</label>
                  <button onClick={() => setEnabledOps(
                    enabledOps.size === MUT_OPS.length
                      ? new Set()
                      : new Set(MUT_OPS.map(o => o.id))
                  )} className="text-[8px] text-zinc-700 hover:text-zinc-400">
                    {enabledOps.size === MUT_OPS.length ? "none" : "all"}
                  </button>
                </div>
                <div className="space-y-0.5">
                  {MUT_OPS.map(op => (
                    <label key={op.id} className="flex items-start gap-1.5 cursor-pointer select-none group">
                      <input type="checkbox" checked={enabledOps.has(op.id)}
                        onChange={e => {
                          const s = new Set(enabledOps);
                          if (e.target.checked) s.add(op.id); else s.delete(op.id);
                          setEnabledOps(s);
                        }}
                        className="mt-0.5 w-3 h-3 accent-fuchsia-600 shrink-0"/>
                      <span>
                        <span className="text-[9px] text-zinc-400 group-hover:text-zinc-300">{op.label}</span>
                        <span className="text-[8px] text-zinc-700 ml-1">{op.desc}</span>
                      </span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="flex gap-2 pt-1">
                <button
                  onClick={launch}
                  disabled={running || !targetUrl.trim()}
                  className="flex-1 py-2 bg-fuchsia-900/60 border border-fuchsia-700 text-fuchsia-300 text-[11px] uppercase tracking-widest hover:bg-fuchsia-800/60 disabled:opacity-40 disabled:cursor-not-allowed transition-colors font-bold">
                  {running ? "EVOLVING…" : "▶ LAUNCH"}
                </button>
                {running && (
                  <button onClick={stop}
                    className="px-3 bg-zinc-900 border border-zinc-700 text-zinc-400 text-[10px] uppercase hover:border-red-700 hover:text-red-400">
                    STOP
                  </button>
                )}
              </div>
              {done && (
                <button onClick={reset}
                  className="w-full py-1 text-[10px] text-zinc-600 hover:text-zinc-400 border border-zinc-900 hover:border-zinc-700">
                  CLEAR
                </button>
              )}

              {running && totalGens > 0 && (
                <div>
                  <div className="flex justify-between text-[9px] text-zinc-600 mb-1">
                    <span>GENERATION</span>
                    <span>{generation}/{totalGens} · {progressPct}%</span>
                  </div>
                  <div className="h-1 bg-zinc-900 rounded-full overflow-hidden">
                    <div className="h-full bg-fuchsia-700 transition-all duration-500 rounded-full"
                      style={{ width: `${progressPct}%` }}/>
                  </div>
                </div>
              )}
            </div>

            {confirmed.length > 0 && (
              <div className="border-t border-zinc-900 p-2 flex-1 overflow-y-auto">
                <div className="text-[9px] text-lime-400 uppercase mb-1.5">
                  Confirmed RCE Payloads ({confirmed.length})
                </div>
                <div className="space-y-1.5">
                  {confirmed.map((c, i) => (
                    <div key={i} className="border border-lime-900/60 bg-lime-950/20 p-1.5">
                      <div className="flex justify-between text-[8px] text-zinc-600 mb-0.5">
                        <span>gen {c.generation} · score {c.score}</span>
                        <button onClick={() => copy(c.payload, `cp${i}`)}
                          className="hover:text-green-400">{copied === `cp${i}` ? "✓" : "COPY"}</button>
                      </div>
                      <div className="text-[9px] text-lime-300 break-all mb-0.5">{c.payload}</div>
                      <div className="text-[8px] text-zinc-500">{c.evidence}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {topPayloads.length > 0 && !running && (
              <div className="border-t border-zinc-900 p-2 shrink-0">
                <div className="text-[9px] text-fuchsia-400 uppercase mb-1.5">Top Scored Payloads</div>
                <div className="space-y-0.5">
                  {topPayloads.slice(0, 8).map((p, i) => (
                    <div key={i} className="flex items-center gap-1 group hover:bg-zinc-900 px-1 py-0.5">
                      <span className="text-fuchsia-700 text-[8px] shrink-0 w-8">{p.score}</span>
                      <span className="text-zinc-400 text-[9px] flex-1 truncate font-mono">{p.payload}</span>
                      <button onClick={() => copy(p.payload, `tp${i}`)}
                        className="text-[8px] text-zinc-700 hover:text-green-400 shrink-0 opacity-0 group-hover:opacity-100">
                        {copied === `tp${i}` ? "✓" : "CPY"}
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
          <NexusTerminal
            ref={termRef}
            className="flex-1 min-h-0"
          />
          <div className="border-t border-zinc-900 px-3 py-1 bg-zinc-950 shrink-0 flex items-center gap-3">
            <span className="text-[9px] text-zinc-700">
              {running
                ? `gen ${generation}/${totalGens} evolving…`
                : done ? `scan complete · ${confirmed.length} RCE confirmed` : "ready"}
            </span>
            <div className="ml-auto flex items-center gap-2">
              {running && (
                <button onClick={stop}
                  className="text-[9px] px-2 py-0.5 border border-red-800 text-red-400 hover:bg-red-950/30 uppercase">
                  STOP
                </button>
              )}
              <button onClick={() => termRef.current?.clear()}
                className="text-[9px] px-2 py-0.5 border border-zinc-800 text-zinc-600 hover:text-zinc-400 uppercase">
                CLR
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
