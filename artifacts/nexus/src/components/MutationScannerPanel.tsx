import React, { useState, useRef, useCallback, useEffect } from "react";
import NexusTerminal, { type NexusTerminalHandle, ansiLine } from "./NexusTerminal";
import { useReconnectingWs } from "../hooks/use-reconnecting-ws";
import { withAuthToken } from "../lib/auth";

const API_URL = (import.meta.env as Record<string, string>)["VITE_API_URL"] ?? "";

interface ConfirmedPayload { payload: string; score: number; evidence: string; generation: number; }
interface TopPayload       { payload: string; score: number; }

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

    timerRef.current = setInterval(() => setElapsed(Date.now() - startRef.current), 250);

    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = API_URL
      ? `${API_URL.replace(/^http/, "ws")}/api/ws/mutation`
      : `${proto}//${window.location.host}/api/ws/mutation`;

    wsHook.connect(withAuthToken(wsUrl), {
      targetUrl:    targetUrl.trim(),
      injectParam:  injectParam.trim() || "cmd",
      httpMethod,
      generations:  generations.trim() || "6",
      popSize:      popSize.trim() || "20",
      extraParams:  extraParams.trim(),
      customHeaders:customHdrs.trim(),
    });

    requestAnimationFrame(() => termRef.current?.fit());
  }, [targetUrl, injectParam, httpMethod, generations, popSize, extraParams, customHdrs, running, wsHook]);

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
