import React, { useState, useCallback, useEffect, useRef } from "react";
import { getToken, withAuthToken } from "../lib/auth";

const API_URL = (import.meta.env as Record<string, string>)["VITE_API_URL"] ?? "";

function wsBase(): string {
  if (API_URL) {
    const u = new URL(API_URL);
    return `${u.protocol === "https:" ? "wss:" : "ws:"}//${u.host}/api/ws`;
  }
  return `${window.location.protocol === "https:" ? "wss:" : "ws:"}//${window.location.host}/api/ws`;
}

function apiBase(): string {
  return API_URL || "";
}

const WS_CHANNELS = [
  { path: "/api/ws/exec",         label: "Stream Exec",      group: "CORE" },
  { path: "/api/ws/scan",         label: "Target Scanner",   group: "CORE" },
  { path: "/api/ws/chain",        label: "Exploit Chain",    group: "CORE" },
  { path: "/api/ws/probe",        label: "Probe Target",     group: "CORE" },
  { path: "/api/ws/autoexploit",  label: "Auto-Exploit",     group: "AUTO" },
  { path: "/api/ws/postexploit",  label: "Post-Exploit",     group: "AUTO" },
  { path: "/api/ws/cve",          label: "CVE Exploit",      group: "AUTO" },
  { path: "/api/ws/mutation",     label: "Mutation Scanner", group: "SCAN" },
  { path: "/api/ws/chainreactor", label: "Chain Reactor",    group: "SCAN" },
  { path: "/api/ws/c2",           label: "C2 Operator",      group: "C2"   },
  { path: "/api/ws/c2-implant",   label: "C2 Implant",       group: "C2"   },
  { path: "/api/ws/c2-sniffer",   label: "C2 Sniffer",       group: "C2"   },
] as const;

type ChannelPath = typeof WS_CHANNELS[number]["path"];
type ProbeStatus = "idle" | "probing" | "ok" | "auth_fail" | "error" | "timeout";
type ApiStatus   = "unknown" | "online" | "error";

interface ChannelState {
  path:         ChannelPath;
  label:        string;
  group:        string;
  serverCount:  number;
  probeStatus:  ProbeStatus;
  latencyMs:    number | null;
  probeError:   string | undefined;
  lastProbed:   string | undefined;
}

interface ServerStats {
  uptimeMs:    number;
  totalEver:   number;
  activeTotal: number;
  channels:    Record<string, number>;
}

const PROBE_TIMEOUT_MS = 6_000;
const POLL_INTERVAL_MS = 5_000;

const GROUP_COLOR: Record<string, string> = {
  CORE: "text-cyan-500 border-cyan-900",
  AUTO: "text-fuchsia-500 border-fuchsia-900",
  SCAN: "text-yellow-500 border-yellow-900",
  C2:   "text-red-500 border-red-900",
};

const PROBE_DOT: Record<ProbeStatus, string> = {
  idle:      "bg-zinc-700",
  probing:   "bg-yellow-400 animate-pulse",
  ok:        "bg-green-500",
  auth_fail: "bg-orange-500",
  error:     "bg-red-600",
  timeout:   "bg-red-800",
};

const PROBE_LABEL: Record<ProbeStatus, string> = {
  idle:      "IDLE",
  probing:   "PROBING",
  ok:        "REACHABLE",
  auth_fail: "AUTH FAIL",
  error:     "UNREACHABLE",
  timeout:   "TIMEOUT",
};

const PROBE_TEXT: Record<ProbeStatus, string> = {
  idle:      "text-zinc-600",
  probing:   "text-yellow-400",
  ok:        "text-green-400",
  auth_fail: "text-orange-400",
  error:     "text-red-500",
  timeout:   "text-red-700",
};

function fmtUptime(ms: number): string {
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  const h = Math.floor(m / 60);
  const d = Math.floor(h / 24);
  if (d > 0) return `${d}d ${h % 24}h ${m % 60}m`;
  if (h > 0) return `${h}h ${m % 60}m ${s % 60}s`;
  if (m > 0) return `${m}m ${s % 60}s`;
  return `${s}s`;
}

function ts(): string {
  return new Date().toISOString().slice(11, 23);
}

function probeChannel(
  path: string,
  base: string,
  token: string,
  onDone: (status: ProbeStatus, latencyMs: number, error?: string) => void,
): () => void {
  let settled = false;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let ws: WebSocket | null = null;

  const done = (status: ProbeStatus, latencyMs: number, error?: string) => {
    if (settled) return;
    settled = true;
    if (timer) { clearTimeout(timer); timer = null; }
    onDone(status, latencyMs, error);
  };

  const suffix = path.slice("/api/ws".length);
  const url = `${base}${suffix}?token=${encodeURIComponent(token)}`;
  const t0 = Date.now();

  try {
    ws = new WebSocket(url);

    timer = setTimeout(() => {
      try { ws?.close(); } catch { /* ignore */ }
      done("timeout", Date.now() - t0, "no response in 6s");
    }, PROBE_TIMEOUT_MS);

    ws.onopen = () => {
      const lat = Date.now() - t0;
      try { ws?.close(1000, "probe-ok"); } catch { /* ignore */ }
      done("ok", lat);
    };

    ws.onerror = () => {
      const lat = Date.now() - t0;
      done("error", lat, "connection refused or network error");
    };

    ws.onclose = (ev) => {
      const lat = Date.now() - t0;
      if (settled) return;
      if (ev.code === 1000 || ev.code === 1001) {
        done("ok", lat);
      } else if (ev.code === 401 || (ev.reason && ev.reason.toLowerCase().includes("auth"))) {
        done("auth_fail", lat, `HTTP ${ev.code} — auth rejected`);
      } else {
        done("error", lat, `WS close code ${ev.code}: ${ev.reason || "no reason"}`);
      }
    };
  } catch (e) {
    done("error", Date.now() - t0, String(e));
  }

  return () => {
    settled = true;
    if (timer) { clearTimeout(timer); timer = null; }
    try { ws?.close(); } catch { /* ignore */ }
  };
}

const initChannels = (): ChannelState[] =>
  WS_CHANNELS.map(c => ({
    path:        c.path,
    label:       c.label,
    group:       c.group,
    serverCount: 0,
    probeStatus: "idle",
    latencyMs:   null,
    probeError:  undefined,
    lastProbed:  undefined,
  }));

export default function WsHealthPanel() {
  const [channels,    setChannels]    = useState<ChannelState[]>(initChannels);
  const [stats,       setStats]       = useState<ServerStats | null>(null);
  const [apiStatus,   setApiStatus]   = useState<ApiStatus>("unknown");
  const [log,         setLog]         = useState<string[]>([]);
  const [polling,     setPolling]     = useState(false);
  const [probing,     setProbing]     = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [lastFetch,   setLastFetch]   = useState<string>("—");

  const logRef    = useRef<HTMLDivElement>(null);
  const pollTimer = useRef<ReturnType<typeof setInterval> | null>(null);
  const abortRef  = useRef<AbortController | null>(null);
  const cleanups  = useRef<Array<() => void>>([]);

  const addLog = useCallback((line: string) =>
    setLog(p => [...p.slice(-300), line]), []);

  const fetchStats = useCallback(async () => {
    const token = getToken();
    if (!token) { setApiStatus("error"); addLog(`[${ts()}] [!] No auth token — log in first`); return; }
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    try {
      const r = await fetch(`${apiBase()}/api/hub/ws-stats`, {
        headers: { Authorization: `Bearer ${token}` },
        signal: ac.signal,
      });
      if (!r.ok) { setApiStatus("error"); addLog(`[${ts()}] [!] /hub/ws-stats returned ${r.status}`); return; }
      const data = await r.json() as ServerStats;
      setStats(data);
      setApiStatus("online");
      setLastFetch(ts());
      setChannels(prev => prev.map(ch => ({
        ...ch,
        serverCount: data.channels[ch.path] ?? 0,
      })));
      addLog(`[${ts()}] ↺ stats refresh — active: ${data.activeTotal} total-ever: ${data.totalEver} uptime: ${fmtUptime(data.uptimeMs)}`);
    } catch (e) {
      if ((e as Error).name === "AbortError") return;
      setApiStatus("error");
      addLog(`[${ts()}] [!] Fetch error: ${String(e)}`);
    }
  }, [addLog]);

  useEffect(() => {
    void fetchStats();
  }, [fetchStats]);

  useEffect(() => {
    if (pollTimer.current) clearInterval(pollTimer.current);
    if (autoRefresh) {
      setPolling(true);
      pollTimer.current = setInterval(() => { void fetchStats(); }, POLL_INTERVAL_MS);
    } else {
      setPolling(false);
    }
    return () => { if (pollTimer.current) clearInterval(pollTimer.current); };
  }, [autoRefresh, fetchStats]);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [log]);

  useEffect(() => () => {
    abortRef.current?.abort();
    if (pollTimer.current) clearInterval(pollTimer.current);
    cleanups.current.forEach(fn => fn());
  }, []);

  const probeAll = useCallback(() => {
    if (probing) return;
    cleanups.current.forEach(fn => fn());
    cleanups.current = [];
    setProbing(true);
    const token = getToken();
    if (!token) { addLog(`[${ts()}] [!] No auth token`); setProbing(false); return; }
    const base = wsBase();
    addLog(`[${ts()}] ▶ Probing all ${WS_CHANNELS.length} WS channels via ${base}`);

    setChannels(prev => prev.map(ch => ({ ...ch, probeStatus: "probing", latencyMs: null, probeError: undefined })));

    let remaining = WS_CHANNELS.length;
    for (const ch of WS_CHANNELS) {
      const cancel = probeChannel(ch.path, base, token, (status, latencyMs, error) => {
        const now = ts();
        setChannels(prev => prev.map(c =>
          c.path === ch.path ? { ...c, probeStatus: status, latencyMs, probeError: error, lastProbed: now } : c
        ));
        const lat = latencyMs < 1000 ? `${latencyMs}ms` : `${(latencyMs / 1000).toFixed(1)}s`;
        if (status === "ok") {
          addLog(`[${now}] ✓ ${ch.label} (${ch.path}) — REACHABLE ${lat}`);
        } else {
          addLog(`[${now}] ✗ ${ch.label} (${ch.path}) — ${PROBE_LABEL[status]} ${lat}${error ? `: ${error}` : ""}`);
        }
        remaining--;
        if (remaining === 0) {
          setProbing(false);
          addLog(`[${ts()}] ■ Probe sweep complete`);
          cleanups.current = [];
        }
      });
      cleanups.current.push(cancel);
    }
  }, [probing, addLog]);

  const probeSingle = useCallback((path: ChannelPath) => {
    const token = getToken();
    if (!token) { addLog(`[${ts()}] [!] No auth token`); return; }
    const base = wsBase();
    setChannels(prev => prev.map(c =>
      c.path === path ? { ...c, probeStatus: "probing", latencyMs: null, probeError: undefined } : c
    ));
    const ch = WS_CHANNELS.find(c => c.path === path)!;
    addLog(`[${ts()}] ▶ Probing ${ch.label}…`);
    const cancel = probeChannel(path, base, token, (status, latencyMs, error) => {
      const now = ts();
      setChannels(prev => prev.map(c =>
        c.path === path ? { ...c, probeStatus: status, latencyMs, probeError: error, lastProbed: now } : c
      ));
      const lat = latencyMs < 1000 ? `${latencyMs}ms` : `${(latencyMs / 1000).toFixed(1)}s`;
      addLog(`[${now}] ${status === "ok" ? "✓" : "✗"} ${ch.label} — ${PROBE_LABEL[status]} ${lat}${error ? `: ${error}` : ""}`);
    });
    cleanups.current.push(cancel);
  }, [addLog]);

  const groups = ["CORE", "AUTO", "SCAN", "C2"] as const;
  const okCount = channels.filter(c => c.probeStatus === "ok").length;
  const errCount = channels.filter(c => c.probeStatus === "error" || c.probeStatus === "timeout" || c.probeStatus === "auth_fail").length;
  const probedCount = channels.filter(c => c.probeStatus !== "idle").length;

  return (
    <div className="flex flex-1 min-h-0 overflow-hidden flex-col bg-black">

      <div className="border-b border-white/[.04] px-4 py-2.5 flex items-center gap-4 shrink-0 bg-black/40">
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full ${apiStatus === "online" ? "bg-green-500" : apiStatus === "error" ? "bg-red-600" : "bg-zinc-600"} ${apiStatus === "online" && polling ? "animate-pulse" : ""}`} />
          <span className={`text-[10px] font-bold uppercase tracking-widest ${apiStatus === "online" ? "text-green-400" : apiStatus === "error" ? "text-red-400" : "text-zinc-600"}`}>
            API {apiStatus}
          </span>
        </div>
        {stats && (
          <>
            <div className="text-[9px] text-zinc-600 border-l border-white/[.04] pl-4">
              <span className="text-zinc-500">uptime</span> <span className="text-white font-mono">{fmtUptime(stats.uptimeMs)}</span>
            </div>
            <div className="text-[9px] text-zinc-600">
              <span className="text-zinc-500">active WS</span> <span className="text-cyan-400 font-bold font-mono">{stats.activeTotal}</span>
            </div>
            <div className="text-[9px] text-zinc-600">
              <span className="text-zinc-500">total sessions</span> <span className="text-white font-mono">{stats.totalEver}</span>
            </div>
          </>
        )}
        {probedCount > 0 && (
          <div className="text-[9px] flex items-center gap-3">
            <span className="text-green-400 font-bold">{okCount} UP</span>
            {errCount > 0 && <span className="text-red-400 font-bold">{errCount} DOWN</span>}
          </div>
        )}
        <div className="ml-auto flex items-center gap-2">
          <span className="text-[8px] text-zinc-700">last poll {lastFetch}</span>
          <button onClick={() => setAutoRefresh(v => !v)}
            className={`text-[9px] px-2 py-1 border uppercase tracking-widest ${autoRefresh ? "border-cyan-800 text-cyan-600 bg-cyan-950/20" : "border-zinc-800 text-zinc-600"}`}>
            {autoRefresh ? "● AUTO" : "○ AUTO"}
          </button>
          <button onClick={() => { void fetchStats(); }}
            className="text-[9px] px-2 py-1 border border-zinc-800 text-zinc-500 hover:text-zinc-300 uppercase tracking-widest">
            ↺ Refresh
          </button>
          <button onClick={probeAll} disabled={probing}
            className="text-[9px] px-4 py-1.5 border font-bold uppercase tracking-widest transition-all disabled:opacity-40"
            style={{ background: probing ? "transparent" : "rgba(220,38,38,.12)", borderColor: probing ? "rgba(255,255,255,.07)" : "rgba(220,38,38,.4)", color: probing ? "#52525b" : "#f87171" }}>
            {probing
              ? <span className="flex items-center gap-2"><span className="w-3 h-3 border border-red-400 border-t-transparent rounded-full animate-spin" />Probing…</span>
              : "⚡ Probe All"}
          </button>
        </div>
      </div>

      <div className="flex flex-1 min-h-0 overflow-hidden">

        <div className="flex-1 overflow-y-auto p-4 min-h-0">
          <div className="space-y-5">
            {groups.map(group => {
              const chans = channels.filter(c => c.group === group);
              const [gcText, gcBorder] = (GROUP_COLOR[group] ?? "text-zinc-500 border-zinc-800").split(" ");
              return (
                <div key={group}>
                  <div className="flex items-center gap-2 mb-2">
                    <span className={`text-[9px] font-bold uppercase tracking-widest ${gcText}`}>{group}</span>
                    <div className={`flex-1 border-t ${gcBorder}`} />
                    <span className="text-[8px] text-zinc-700">{chans.filter(c => c.probeStatus === "ok").length}/{chans.length} up</span>
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    {chans.map(ch => {
                      const dotCls   = PROBE_DOT[ch.probeStatus];
                      const lblCls   = PROBE_TEXT[ch.probeStatus];
                      const isActive = ch.serverCount > 0;
                      return (
                        <div key={ch.path}
                          className={`border p-3 flex flex-col gap-1.5 transition-all cursor-pointer hover:border-zinc-600 ${ch.probeStatus === "ok" ? "border-green-900/50 bg-green-950/5" : ch.probeStatus === "error" || ch.probeStatus === "timeout" ? "border-red-900/40 bg-red-950/5" : "border-zinc-800 bg-black/20"}`}
                          onClick={() => probeSingle(ch.path as ChannelPath)}>
                          <div className="flex items-center gap-2">
                            <span className={`w-2 h-2 rounded-full flex-shrink-0 ${dotCls}`} />
                            <span className="text-[10px] text-white font-bold truncate">{ch.label}</span>
                            {isActive && (
                              <span className="ml-auto text-[8px] px-1.5 border border-cyan-900 text-cyan-400 bg-cyan-950/20 shrink-0">
                                {ch.serverCount} conn
                              </span>
                            )}
                          </div>
                          <div className="text-[8px] text-zinc-700 font-mono">{ch.path}</div>
                          <div className="flex items-center justify-between">
                            <span className={`text-[8px] font-bold uppercase ${lblCls}`}>{PROBE_LABEL[ch.probeStatus]}</span>
                            {ch.latencyMs !== null && (
                              <span className={`text-[8px] font-mono ${ch.latencyMs < 200 ? "text-green-500" : ch.latencyMs < 800 ? "text-yellow-500" : "text-red-500"}`}>
                                {ch.latencyMs < 1000 ? `${ch.latencyMs}ms` : `${(ch.latencyMs / 1000).toFixed(1)}s`}
                              </span>
                            )}
                          </div>
                          {ch.probeError && (
                            <div className="text-[8px] text-red-700 truncate">{ch.probeError}</div>
                          )}
                          {ch.lastProbed && (
                            <div className="text-[8px] text-zinc-800">probed {ch.lastProbed}</div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>

          {stats && (
            <div className="mt-5 border border-zinc-800 p-4 bg-black/20">
              <div className="text-[9px] text-zinc-600 uppercase tracking-widest mb-3">Server-side Active Connections</div>
              <div className="grid grid-cols-3 gap-2">
                {WS_CHANNELS.map(ch => {
                  const count = stats.channels[ch.path] ?? 0;
                  return (
                    <div key={ch.path} className={`flex items-center justify-between border px-3 py-2 ${count > 0 ? "border-cyan-900/60 bg-cyan-950/10" : "border-zinc-900"}`}>
                      <span className="text-[8px] text-zinc-500 truncate">{ch.label}</span>
                      <span className={`text-[10px] font-bold font-mono ml-2 ${count > 0 ? "text-cyan-400" : "text-zinc-700"}`}>{count}</span>
                    </div>
                  );
                })}
              </div>
              <div className="mt-3 flex gap-6 text-[9px]">
                <div><span className="text-zinc-600">Server uptime</span> <span className="text-white font-mono">{fmtUptime(stats.uptimeMs)}</span></div>
                <div><span className="text-zinc-600">Total sessions ever</span> <span className="text-white font-mono">{stats.totalEver}</span></div>
                <div><span className="text-zinc-600">Active now</span> <span className="text-cyan-400 font-mono font-bold">{stats.activeTotal}</span></div>
              </div>
            </div>
          )}
        </div>

        <div className="w-80 border-l border-white/[.04] flex flex-col shrink-0 bg-black/10">
          <div className="px-3 py-2 border-b border-white/[.04] flex items-center justify-between shrink-0">
            <span className="text-[9px] text-zinc-600 uppercase tracking-widest">Event Log</span>
            <button onClick={() => setLog([])} className="text-[8px] text-zinc-700 hover:text-zinc-400 uppercase">Clear</button>
          </div>
          <div ref={logRef} className="flex-1 overflow-y-auto p-3 font-mono min-h-0">
            {log.length === 0 && (
              <div className="flex flex-col items-center justify-center h-full text-zinc-800 gap-2">
                <span className="text-2xl opacity-20">📡</span>
                <p className="text-[9px] uppercase tracking-widest text-center">WS events will appear here</p>
              </div>
            )}
            {log.map((l, i) => (
              <div key={i} className={`text-[8px] leading-[1.7] ${
                l.includes("✓")          ? "text-green-400" :
                l.includes("✗") || l.includes("[!]") ? "text-red-400" :
                l.includes("■")          ? "text-orange-400" :
                l.includes("▶")          ? "text-cyan-400" :
                l.includes("↺")          ? "text-zinc-500" :
                "text-zinc-600"
              }`}>{l}</div>
            ))}
          </div>

          <div className="border-t border-white/[.04] p-3 space-y-2 shrink-0">
            <div className="text-[8px] text-zinc-700 uppercase tracking-widest mb-1">Legend</div>
            {(["idle","probing","ok","auth_fail","error","timeout"] as ProbeStatus[]).map(s => (
              <div key={s} className="flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full flex-shrink-0 ${PROBE_DOT[s]}`} />
                <span className={`text-[8px] ${PROBE_TEXT[s]}`}>{PROBE_LABEL[s]}</span>
              </div>
            ))}
            <div className="border-t border-white/[.04] pt-2 text-[8px] text-zinc-700">
              Click any channel card to probe it individually. Probe All runs all 12 simultaneously. Stats auto-refresh every 5s.
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
