import React, { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { authHeaders } from "../lib/auth";

interface OobHit {
  id: string; ts: number; type: "http"; method: string; path: string;
  sourceIp: string; userAgent: string; headers: Record<string, string>;
  body: string; query: Record<string, string>; data: string;
  token: string; size: number; receivedAt?: string; decodedData?: string;
}
interface DnsSession {
  key: string; token: string; prefix: string;
  chunks: Record<number, string>; total: number; received: number;
  complete: boolean; assembled: string | null; decoded: string | null; byteLen: number;
  receivedAt: number; lastChunkAt: number; completedAt: number | null;
}

function wsBase(): string {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}`;
}

function timeAgo(ts: number): string {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 2) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return new Date(ts).toLocaleTimeString();
}

function tryDecode(raw: string): { text: string; decoded: boolean } {
  if (!raw) return { text: "", decoded: false };
  try {
    const clean = raw.trim().replace(/[ ]/g, "+").replace(/-/g, "+").replace(/_/g, "/");
    const dec = atob(clean);
    if (/^[\x09\x0a\x0d\x20-\x7e]+$/.test(dec) && dec.length > 2) return { text: dec, decoded: true };
  } catch { /* */ }
  if (raw.length > 20 && /^[0-9a-f]+$/i.test(raw.trim())) {
    try {
      const hex = Buffer ? Buffer.from(raw.trim(), "hex").toString("utf8") : raw;
      if (/[\x20-\x7e]{4,}/.test(hex)) return { text: hex, decoded: true };
    } catch { /* */ }
  }
  try {
    const url = decodeURIComponent(raw);
    if (url !== raw) return { text: url, decoded: true };
  } catch { /* */ }
  return { text: raw, decoded: false };
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n}B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)}KB`;
  return `${(n / 1048576).toFixed(2)}MB`;
}

function statusColor(code: number): string {
  if (code < 300) return "text-emerald-400";
  if (code < 400) return "text-yellow-400";
  if (code < 500) return "text-orange-400";
  return "text-red-400";
}

function methodBadge(m: string): string {
  if (m === "GET")  return "bg-emerald-900/60 text-emerald-400 border border-emerald-800/50";
  if (m === "POST") return "bg-blue-900/60 text-blue-400 border border-blue-800/50";
  if (m === "PUT" || m === "PATCH") return "bg-amber-900/60 text-amber-400 border border-amber-800/50";
  if (m === "DELETE") return "bg-red-900/60 text-red-400 border border-red-800/50";
  return "bg-zinc-800 text-zinc-400 border border-zinc-700";
}

const PREFIX_LABELS: Record<string, string> = {
  p: "/etc/passwd", e: "ENV secrets", s: "/etc/shadow", aws: "AWS creds",
  ssh: "SSH keys", m: "mass-dump", k: "K8s token", py: "Python exec", w: "Win ENV",
};

export default function OobPanel() {
  const [tab,         setTab]         = useState<"live" | "dns" | "stats">("live");
  const [hits,        setHits]        = useState<OobHit[]>([]);
  const [dnsSessions, setDnsSessions] = useState<DnsSession[]>([]);
  const [expanded,    setExpanded]    = useState<string | null>(null);
  const [expandedDns, setExpandedDns] = useState<string | null>(null);
  const [filter,      setFilter]      = useState("");
  const [flash,       setFlash]       = useState<string | null>(null);
  const [wsStatus,    setWsStatus]    = useState<"connecting" | "connected" | "disconnected">("connecting");
  const [lastHitTime, setLastHitTime] = useState<number | null>(null);
  const [copied,      setCopied]      = useState<string | null>(null);
  const [autoScroll,  setAutoScroll]  = useState(true);
  const wsRef   = useRef<WebSocket | null>(null);
  const feedRef = useRef<HTMLDivElement | null>(null);
  const reconnectRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mountedRef   = useRef(true);

  const connect = useCallback(() => {
    if (!mountedRef.current) return;
    if (wsRef.current && wsRef.current.readyState <= 1) return;
    setWsStatus("connecting");

    const url = `${wsBase()}/api/ws/oob`;
    const ws  = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      if (!mountedRef.current) { ws.close(); return; }
      setWsStatus("connected");
      if (reconnectRef.current) { clearTimeout(reconnectRef.current); reconnectRef.current = null; }
    };

    ws.onmessage = (ev) => {
      if (!mountedRef.current) return;
      let msg: Record<string, unknown>;
      try { msg = JSON.parse(ev.data as string) as Record<string, unknown>; } catch { return; }

      if (msg.type === "snapshot") {
        setHits((msg.hits as OobHit[] | undefined) ?? []);
        setDnsSessions((msg.sessions as DnsSession[] | undefined) ?? []);
      } else if (msg.type === "hit") {
        const hit = msg.hit as OobHit;
        setHits(prev => [hit, ...prev].slice(0, 1000));
        setLastHitTime(Date.now());
        setFlash(hit.id);
        setTimeout(() => setFlash(f => f === hit.id ? null : f), 800);
        if (autoScroll && feedRef.current) feedRef.current.scrollTop = 0;
      } else if (msg.type === "dns_session") {
        const sess = msg.session as DnsSession;
        setDnsSessions(prev => {
          const idx = prev.findIndex(s => s.key === sess.key);
          if (idx >= 0) { const n = [...prev]; n[idx] = sess; return n; }
          return [sess, ...prev].slice(0, 500);
        });
      } else if (msg.type === "dns_chunk") {
        setDnsSessions(prev => prev.map(s =>
          s.key === (msg.key as string)
            ? { ...s, received: s.received + 1, lastChunkAt: Date.now() }
            : s
        ));
      } else if (msg.type === "dns_complete") {
        const sess = msg.session as DnsSession;
        setDnsSessions(prev => prev.map(s => s.key === sess.key ? sess : s));
      } else if (msg.type === "cleared") {
        setHits([]);
      } else if (msg.type === "dns_cleared") {
        setDnsSessions([]);
      }
    };

    ws.onerror  = () => setWsStatus("disconnected");
    ws.onclose  = () => {
      setWsStatus("disconnected");
      if (!mountedRef.current) return;
      reconnectRef.current = setTimeout(() => { if (mountedRef.current) connect(); }, 3000);
    };
  }, [autoScroll]);

  useEffect(() => {
    mountedRef.current = true;
    connect();
    return () => {
      mountedRef.current = false;
      wsRef.current?.close();
      if (reconnectRef.current) clearTimeout(reconnectRef.current);
    };
  }, [connect]);

  const clearHits = useCallback(() => {
    if (wsRef.current?.readyState === 1) {
      wsRef.current.send(JSON.stringify({ action: "clear_hits" }));
    }
    setHits([]);
  }, []);

  const clearDns = useCallback(() => {
    if (wsRef.current?.readyState === 1) {
      wsRef.current.send(JSON.stringify({ action: "clear_dns" }));
    }
    setDnsSessions([]);
  }, []);

  const copy = useCallback((text: string, key: string) => {
    navigator.clipboard.writeText(text).catch(() => {});
    setCopied(key);
    setTimeout(() => setCopied(k => k === key ? null : k), 1800);
  }, []);

  const filteredHits = useMemo(() => {
    if (!filter.trim()) return hits;
    const q = filter.toLowerCase();
    return hits.filter(h =>
      h.token.includes(q) || h.sourceIp.includes(q) ||
      h.method.toLowerCase().includes(q) || h.path.toLowerCase().includes(q) ||
      h.data.toLowerCase().includes(q) || (h.decodedData ?? "").toLowerCase().includes(q)
    );
  }, [hits, filter]);

  const stats = useMemo(() => {
    const uniqueTokens = new Set(hits.map(h => h.token)).size;
    const uniqueIps    = new Set(hits.map(h => h.sourceIp)).size;
    const totalBytes   = hits.reduce((a, h) => a + h.size, 0);
    const completeDns  = dnsSessions.filter(s => s.complete).length;
    return { total: hits.length, uniqueTokens, uniqueIps, totalBytes, completeDns, totalDns: dnsSessions.length };
  }, [hits, dnsSessions]);

  const wsIndicator = wsStatus === "connected"
    ? <span className="flex items-center gap-1 text-emerald-400"><span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse inline-block"/>{" "}LIVE</span>
    : wsStatus === "connecting"
    ? <span className="flex items-center gap-1 text-yellow-500"><span className="w-2 h-2 rounded-full bg-yellow-500 animate-pulse inline-block"/>{" "}CONNECTING…</span>
    : <span className="flex items-center gap-1 text-red-500"><span className="w-2 h-2 rounded-full bg-red-600 inline-block"/>DISCONNECTED</span>;

  return (
    <div className="flex flex-col h-full bg-black text-zinc-200 font-mono text-xs select-none">
      <div className="flex items-center justify-between px-3 py-2 border-b border-zinc-900 shrink-0">
        <div className="flex items-center gap-3">
          <span className="text-red-500 font-bold tracking-widest text-[10px]">OOB CALLBACK DASHBOARD</span>
          <span className="text-[9px]">{wsIndicator}</span>
          {lastHitTime && (
            <span className="text-zinc-500 text-[9px]">last hit: {timeAgo(lastHitTime)}</span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setAutoScroll(v => !v)}
            className={`px-2 py-0.5 text-[9px] border rounded transition-colors ${autoScroll ? "border-emerald-700 text-emerald-400 bg-emerald-950/40" : "border-zinc-700 text-zinc-500"}`}
          >
            {autoScroll ? "AUTO-SCROLL ON" : "AUTO-SCROLL OFF"}
          </button>
          <button
            onClick={() => wsRef.current?.readyState !== 1 && connect()}
            className="px-2 py-0.5 text-[9px] border border-zinc-700 text-zinc-400 hover:text-zinc-200 rounded"
          >RECONNECT</button>
        </div>
      </div>

      <div className="grid grid-cols-5 gap-px border-b border-zinc-900 shrink-0 bg-zinc-900">
        {[
          ["HITS",      String(stats.total),        "text-red-400"],
          ["TOKENS",    String(stats.uniqueTokens), "text-amber-400"],
          ["SOURCE IPs",String(stats.uniqueIps),    "text-cyan-400"],
          ["DATA",      fmtBytes(stats.totalBytes),  "text-purple-400"],
          ["DNS OOB",   `${stats.completeDns}/${stats.totalDns}`, "text-emerald-400"],
        ].map(([label, val, cls]) => (
          <div key={label} className="bg-black px-3 py-2 flex flex-col gap-0.5">
            <span className="text-zinc-600 text-[8px] tracking-widest uppercase">{label}</span>
            <span className={`${cls} text-sm font-bold leading-none`}>{val}</span>
          </div>
        ))}
      </div>

      <div className="flex items-center gap-0 border-b border-zinc-900 shrink-0">
        {(["live","dns","stats"] as const).map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`px-4 py-2 text-[10px] uppercase tracking-wider border-r border-zinc-900 transition-colors ${tab === t ? "bg-black text-red-400 border-b border-red-600" : "text-zinc-600 hover:text-zinc-400"}`}>
            {t === "live" ? `LIVE FEED (${filteredHits.length})` : t === "dns" ? `DNS OOB (${dnsSessions.length})` : "STATS"}
          </button>
        ))}
        <div className="flex-1 flex items-center gap-2 px-3">
          <input
            value={filter} onChange={e => setFilter(e.target.value)}
            placeholder="filter by token / IP / path / data…"
            className="flex-1 bg-transparent border-0 outline-none text-zinc-300 placeholder-zinc-700 text-xs"
          />
          {filter && <button onClick={() => setFilter("")} className="text-zinc-600 hover:text-zinc-400">✕</button>}
        </div>
        {tab === "live" && (
          <button onClick={clearHits}
            className="px-3 py-2 text-[9px] text-red-700 hover:text-red-400 border-l border-zinc-900 transition-colors">
            CLEAR HITS
          </button>
        )}
        {tab === "dns" && (
          <button onClick={clearDns}
            className="px-3 py-2 text-[9px] text-red-700 hover:text-red-400 border-l border-zinc-900 transition-colors">
            CLEAR DNS
          </button>
        )}
      </div>

      <div ref={feedRef} className="flex-1 overflow-y-auto">
        {tab === "live" && (
          filteredHits.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full gap-3 text-zinc-700">
              <div className="text-3xl">⚡</div>
              <div className="text-sm">No OOB callbacks yet</div>
              <div className="text-[10px]">Fire payloads from AutoChain to see real-time hits here</div>
            </div>
          ) : (
            <div className="divide-y divide-zinc-900">
              {filteredHits.map(hit => {
                const isExpanded = expanded === hit.id;
                const isNew      = flash === hit.id;
                const decoded    = tryDecode(hit.data || hit.decodedData || "");
                return (
                  <div key={hit.id}
                    className={`transition-all duration-200 ${isNew ? "bg-red-950/40 border-l-2 border-red-500" : "border-l-2 border-transparent hover:bg-zinc-900/30"}`}>
                    <div
                      className="flex items-center gap-2 px-3 py-2 cursor-pointer"
                      onClick={() => setExpanded(isExpanded ? null : hit.id)}
                    >
                      <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${methodBadge(hit.method)}`}>{hit.method}</span>
                      <span className="text-zinc-300 truncate flex-1 max-w-[180px]">{hit.path}</span>
                      <span className="text-zinc-600 shrink-0">{hit.sourceIp}</span>
                      <span className="text-amber-600 font-mono text-[9px] shrink-0 bg-amber-950/30 px-1 rounded">
                        {hit.token.slice(0, 8)}
                      </span>
                      {fmtBytes(hit.size) !== "0B" && (
                        <span className="text-zinc-600 text-[9px] shrink-0">{fmtBytes(hit.size)}</span>
                      )}
                      <span className="text-zinc-700 text-[9px] shrink-0">{timeAgo(hit.ts)}</span>
                      {decoded.decoded && (
                        <span className="text-emerald-500 text-[8px] font-bold border border-emerald-800 px-1 rounded shrink-0">DECODED</span>
                      )}
                      <span className={`text-zinc-600 text-[9px] ml-auto shrink-0 transition-transform ${isExpanded ? "rotate-90" : ""}`}>▶</span>
                    </div>

                    {isExpanded && (
                      <div className="px-3 pb-3 flex flex-col gap-2 border-t border-zinc-900/50">
                        {decoded.text && (
                          <div className="mt-2">
                            <div className="flex items-center justify-between mb-1">
                              <span className="text-[9px] text-zinc-600 uppercase tracking-wider">
                                {decoded.decoded ? "EXFILTRATED DATA (decoded)" : "RAW DATA"}
                              </span>
                              <button onClick={() => copy(decoded.text, hit.id + "_data")}
                                className="text-[8px] text-zinc-600 hover:text-zinc-300">
                                {copied === hit.id + "_data" ? "copied!" : "copy"}
                              </button>
                            </div>
                            <pre className="bg-zinc-950 border border-zinc-800 rounded p-2 text-[10px] text-emerald-300 overflow-x-auto max-h-40 whitespace-pre-wrap break-all">
                              {decoded.text}
                            </pre>
                          </div>
                        )}

                        <div className="grid grid-cols-2 gap-2 mt-1">
                          <div>
                            <div className="text-[9px] text-zinc-600 uppercase tracking-wider mb-1">QUERY PARAMS</div>
                            <div className="bg-zinc-950 border border-zinc-800/50 rounded p-2 text-[10px] text-zinc-400 space-y-0.5 max-h-24 overflow-y-auto">
                              {Object.keys(hit.query).length === 0
                                ? <span className="text-zinc-700">—</span>
                                : Object.entries(hit.query).map(([k, v]) => (
                                  <div key={k}><span className="text-cyan-600">{k}</span><span className="text-zinc-600">: </span>{v}</div>
                                ))}
                            </div>
                          </div>
                          <div>
                            <div className="text-[9px] text-zinc-600 uppercase tracking-wider mb-1">HEADERS</div>
                            <div className="bg-zinc-950 border border-zinc-800/50 rounded p-2 text-[10px] text-zinc-400 space-y-0.5 max-h-24 overflow-y-auto">
                              {Object.entries(hit.headers).slice(0, 12).map(([k, v]) => (
                                <div key={k} className="truncate"><span className="text-purple-600">{k}</span><span className="text-zinc-600">: </span>{v}</div>
                              ))}
                            </div>
                          </div>
                        </div>

                        {hit.body && (
                          <div>
                            <div className="flex items-center justify-between mb-1">
                              <span className="text-[9px] text-zinc-600 uppercase tracking-wider">REQUEST BODY</span>
                              <button onClick={() => copy(hit.body, hit.id + "_body")}
                                className="text-[8px] text-zinc-600 hover:text-zinc-300">
                                {copied === hit.id + "_body" ? "copied!" : "copy"}
                              </button>
                            </div>
                            <pre className="bg-zinc-950 border border-zinc-800 rounded p-2 text-[10px] text-zinc-300 overflow-x-auto max-h-32 whitespace-pre-wrap break-all">
                              {hit.body}
                            </pre>
                          </div>
                        )}

                        <div className="flex items-center gap-3 text-[9px] text-zinc-600 pt-1 border-t border-zinc-900">
                          <span>UA: {hit.userAgent.slice(0, 60) || "—"}</span>
                          <span className="ml-auto">{hit.receivedAt ?? new Date(hit.ts).toISOString()}</span>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )
        )}

        {tab === "dns" && (
          dnsSessions.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full gap-3 text-zinc-700">
              <div className="text-3xl">🔍</div>
              <div className="text-sm">No DNS OOB sessions yet</div>
              <div className="text-[10px]">DNS-based exfiltration callbacks will appear here</div>
            </div>
          ) : (
            <div className="divide-y divide-zinc-900">
              {dnsSessions.map(sess => {
                const isExpanded = expandedDns === sess.key;
                const pct = sess.total > 0 ? Math.round((sess.received / sess.total) * 100) : 0;
                return (
                  <div key={sess.key} className="border-l-2 border-transparent hover:bg-zinc-900/30">
                    <div className="flex items-center gap-2 px-3 py-2 cursor-pointer"
                      onClick={() => setExpandedDns(isExpanded ? null : sess.key)}>
                      <span className={`text-[9px] font-bold border rounded px-1.5 py-0.5 ${sess.complete ? "border-emerald-700 text-emerald-400 bg-emerald-950/30" : "border-yellow-700 text-yellow-400 bg-yellow-950/30"}`}>
                        {sess.complete ? "COMPLETE" : "IN PROGRESS"}
                      </span>
                      <span className="text-purple-400 font-mono text-[10px]">{PREFIX_LABELS[sess.prefix] ?? sess.prefix}</span>
                      <span className="text-amber-600 text-[9px] font-mono">{sess.token.slice(0, 8)}</span>
                      <div className="flex-1 h-1 bg-zinc-800 rounded overflow-hidden mx-2">
                        <div className={`h-full rounded transition-all ${sess.complete ? "bg-emerald-600" : "bg-yellow-600"}`}
                          style={{ width: `${pct}%` }} />
                      </div>
                      <span className="text-zinc-500 text-[9px]">{sess.received}/{sess.total || "?"}</span>
                      <span className="text-zinc-500 text-[9px]">{fmtBytes(sess.byteLen)}</span>
                      <span className="text-zinc-700 text-[9px]">{timeAgo(sess.receivedAt)}</span>
                      <span className={`text-zinc-600 text-[9px] ml-auto shrink-0 transition-transform ${isExpanded ? "rotate-90" : ""}`}>▶</span>
                    </div>
                    {isExpanded && sess.assembled && (
                      <div className="px-3 pb-3 border-t border-zinc-900/50">
                        {sess.decoded ? (
                          <>
                            <div className="flex items-center justify-between mb-1 mt-2">
                              <span className="text-[9px] text-zinc-600 uppercase tracking-wider">DECODED EXFIL DATA</span>
                              <button onClick={() => copy(sess.decoded!, sess.key + "_dec")}
                                className="text-[8px] text-zinc-600 hover:text-zinc-300">
                                {copied === sess.key + "_dec" ? "copied!" : "copy"}
                              </button>
                            </div>
                            <pre className="bg-zinc-950 border border-zinc-800 rounded p-2 text-[10px] text-emerald-300 overflow-x-auto max-h-48 whitespace-pre-wrap break-all">
                              {sess.decoded}
                            </pre>
                          </>
                        ) : (
                          <>
                            <div className="text-[9px] text-zinc-600 uppercase tracking-wider mb-1 mt-2">RAW ASSEMBLED</div>
                            <pre className="bg-zinc-950 border border-zinc-800 rounded p-2 text-[10px] text-zinc-300 overflow-x-auto max-h-48 whitespace-pre-wrap break-all">
                              {sess.assembled}
                            </pre>
                          </>
                        )}
                        <div className="flex items-center gap-3 text-[9px] text-zinc-600 pt-2 border-t border-zinc-900 mt-2">
                          <span>started: {new Date(sess.receivedAt).toISOString()}</span>
                          {sess.completedAt && <span>done: {new Date(sess.completedAt).toISOString()}</span>}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )
        )}

        {tab === "stats" && (
          <div className="p-4 space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-zinc-900/40 border border-zinc-800/50 rounded p-3">
                <div className="text-[9px] text-zinc-600 uppercase tracking-wider mb-2">HIT RATE OVER TIME</div>
                <div className="space-y-1">
                  {[60_000, 300_000, 3_600_000].map(window => {
                    const now = Date.now();
                    const count = hits.filter(h => now - h.ts < window).length;
                    const label = window === 60_000 ? "last 1m" : window === 300_000 ? "last 5m" : "last 1h";
                    return (
                      <div key={window} className="flex items-center justify-between">
                        <span className="text-zinc-600 text-[10px]">{label}</span>
                        <span className="text-red-400 font-bold">{count}</span>
                      </div>
                    );
                  })}
                </div>
              </div>

              <div className="bg-zinc-900/40 border border-zinc-800/50 rounded p-3">
                <div className="text-[9px] text-zinc-600 uppercase tracking-wider mb-2">TOP SOURCE IPs</div>
                <div className="space-y-1">
                  {Object.entries(
                    hits.reduce<Record<string, number>>((acc, h) => { acc[h.sourceIp] = (acc[h.sourceIp] ?? 0) + 1; return acc; }, {})
                  ).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([ip, cnt]) => (
                    <div key={ip} className="flex items-center justify-between">
                      <span className="text-cyan-600 text-[10px] font-mono">{ip}</span>
                      <span className="text-zinc-400">{cnt}</span>
                    </div>
                  ))}
                  {stats.uniqueIps === 0 && <span className="text-zinc-700 text-[10px]">no data yet</span>}
                </div>
              </div>
            </div>

            <div className="bg-zinc-900/40 border border-zinc-800/50 rounded p-3">
              <div className="text-[9px] text-zinc-600 uppercase tracking-wider mb-2">TOKENS</div>
              <div className="space-y-1.5 max-h-56 overflow-y-auto">
                {Object.entries(
                  hits.reduce<Record<string, number>>((acc, h) => { acc[h.token] = (acc[h.token] ?? 0) + 1; return acc; }, {})
                ).sort((a, b) => b[1] - a[1]).map(([tok, cnt]) => (
                  <div key={tok} className="flex items-center gap-2">
                    <span className="text-amber-600 font-mono text-[9px] bg-amber-950/30 px-1.5 py-0.5 rounded">{tok.slice(0, 16)}</span>
                    <div className="flex-1 h-1 bg-zinc-800 rounded overflow-hidden">
                      <div className="h-full bg-red-700 rounded" style={{ width: `${Math.min(100, (cnt / hits.length) * 100)}%` }} />
                    </div>
                    <span className="text-zinc-500 text-[9px] w-6 text-right">{cnt}</span>
                  </div>
                ))}
                {stats.total === 0 && <span className="text-zinc-700 text-[10px]">no callbacks yet</span>}
              </div>
            </div>

            <div className="bg-zinc-900/40 border border-zinc-800/50 rounded p-3">
              <div className="text-[9px] text-zinc-600 uppercase tracking-wider mb-2">METHOD BREAKDOWN</div>
              <div className="flex gap-4">
                {Object.entries(
                  hits.reduce<Record<string, number>>((acc, h) => { acc[h.method] = (acc[h.method] ?? 0) + 1; return acc; }, {})
                ).sort((a, b) => b[1] - a[1]).map(([method, cnt]) => (
                  <div key={method} className="flex flex-col items-center gap-1">
                    <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${methodBadge(method)}`}>{method}</span>
                    <span className="text-zinc-400 text-sm font-bold">{cnt}</span>
                  </div>
                ))}
                {stats.total === 0 && <span className="text-zinc-700 text-[10px]">no data yet</span>}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
