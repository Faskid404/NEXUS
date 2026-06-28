import React, { useState, useCallback, useRef, useEffect, useMemo } from "react";
import {
  decodeFrame, parseFramePayload, FrameType, FrameTypeName,
  deriveKey, hexToKey,
  HEADER_SIZE, HMAC_SIZE,
} from "../lib/c2-protocol";
import { withAuthToken } from "../lib/auth";

const API_URL = (import.meta.env as Record<string, string>)["VITE_API_URL"] ?? "";
function wsBase() {
  if (API_URL) { const u = new URL(API_URL); return `${u.protocol === "https:" ? "wss:" : "ws:"}//${u.host}`; }
  return `${location.protocol === "https:" ? "wss:" : "ws:"}//${location.host}`;
}

const TYPE_COLOR: Record<number, string> = {
  [FrameType.HEARTBEAT]: "text-zinc-500",
  [FrameType.CMD]:       "text-cyan-400",
  [FrameType.RESPONSE]:  "text-green-400",
  [FrameType.EXFIL]:     "text-red-400",
  [FrameType.AUTH]:      "text-yellow-400",
  [FrameType.PROXY]:     "text-purple-400",
  [FrameType.KILL]:      "text-red-600",
  [FrameType.UPDATE]:    "text-orange-400",
  [FrameType.ACK]:       "text-zinc-600",
  [FrameType.ERROR]:     "text-red-500",
};

function getByteColor(off: number, payLen: number, totalLen: number): string {
  if (off < 4)                                return "text-violet-400";
  if (off === 4)                              return "text-blue-400";
  if (off === 5)                              return "text-emerald-300";
  if (off < 10)                              return "text-green-400";
  if (off < 14)                              return "text-yellow-400";
  if (off < HEADER_SIZE + payLen)            return "text-cyan-300";
  if (off < HEADER_SIZE + payLen + HMAC_SIZE) return "text-orange-400";
  return "text-zinc-500";
}

function hexPad(n: number) { return n.toString(16).padStart(2, "0"); }

interface CapturedFrame {
  id:        string;
  ts:        number;
  relMs:     number;
  dir:       "rx" | "tx";
  type:      number;
  seq:       number;
  payLen:    number;
  totalLen:  number;
  hmacOk:    boolean;
  bytes:     Uint8Array;
  payload:   Uint8Array;
  parsed:    unknown;
  sessionId: string | null;
}

interface SessionStats {
  id:        string;
  frames:    number;
  bytes:     number;
  lastSeen:  number;
  types:     Record<string, number>;
}

const TYPE_ICONS: Record<number, string> = {
  [FrameType.HEARTBEAT]: "♥",
  [FrameType.CMD]:       "▶",
  [FrameType.RESPONSE]:  "◀",
  [FrameType.EXFIL]:     "⬆",
  [FrameType.AUTH]:      "🔑",
  [FrameType.PROXY]:     "↔",
  [FrameType.KILL]:      "✕",
  [FrameType.UPDATE]:    "↻",
  [FrameType.ACK]:       "✓",
  [FrameType.ERROR]:     "✗",
};

function HexDump({ frame }: { frame: CapturedFrame }) {
  const { bytes, payLen, totalLen } = frame;
  const rows: { off: number; chunk: number[] }[] = [];
  for (let off = 0; off < bytes.length; off += 16) {
    rows.push({ off, chunk: Array.from(bytes.slice(off, off + 16)) });
  }

  return (
    <div className="font-mono text-[9px] leading-relaxed select-text">
      {/* Legend */}
      <div className="flex items-center gap-3 mb-2 flex-wrap">
        {[
          ["MAGIC", "text-violet-400"], ["VER", "text-blue-400"], ["TYPE", "text-emerald-300"],
          ["SEQ", "text-green-400"], ["LEN", "text-yellow-400"],
          ["PAYLOAD(XOR)", "text-cyan-300"], ["HMAC-SHA256", "text-orange-400"],
        ].map(([l, c]) => (
          <span key={l} className="flex items-center gap-1">
            <span className={`${c} font-bold`}>██</span>
            <span className="text-zinc-600 text-[8px]">{l}</span>
          </span>
        ))}
      </div>

      <div className="space-y-0.5">
        {rows.map(({ off, chunk }) => (
          <div key={off} className="flex items-center gap-3">
            <span className="text-zinc-700 w-10 flex-shrink-0 select-none">{off.toString(16).padStart(8, "0")}</span>
            <div className="flex gap-1 flex-wrap flex-shrink-0 min-w-[18rem]">
              {chunk.map((b, i) => {
                const globalOff = off + i;
                const cls = getByteColor(globalOff, payLen, totalLen);
                return (
                  <span key={i} className={`${cls} tabular-nums`} title={`offset 0x${globalOff.toString(16)} = ${b}`}>
                    {hexPad(b)}
                  </span>
                );
              })}
            </div>
            <div className="flex-shrink-0">
              {chunk.map((b, i) => {
                const globalOff = off + i;
                const cls = getByteColor(globalOff, payLen, totalLen);
                const asc = b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "·";
                return <span key={i} className={`${cls} opacity-60`}>{asc}</span>;
              })}
            </div>
          </div>
        ))}
      </div>

      <div className="mt-2 pt-2 border-t border-white/[.04] text-[8px] text-zinc-700 flex gap-6">
        <span>total <span className="text-zinc-400">{totalLen}</span>B</span>
        <span>header <span className="text-zinc-400">{HEADER_SIZE}</span>B</span>
        <span>payload <span className="text-zinc-400">{payLen}</span>B (XOR-ciphered)</span>
        <span>HMAC <span className="text-zinc-400">{HMAC_SIZE}</span>B</span>
        <span className={frame.hmacOk ? "text-green-500" : "text-red-500 font-bold"}>
          {frame.hmacOk ? "HMAC ✓" : "HMAC ✗ TAMPERED"}
        </span>
      </div>
    </div>
  );
}

function JsonPane({ parsed }: { parsed: unknown }) {
  const text = JSON.stringify(parsed, null, 2);
  return (
    <pre className="text-[10px] text-green-400 font-mono whitespace-pre-wrap break-all leading-relaxed select-text">
      {text}
    </pre>
  );
}

function FrameRow({
  frame, selected, onClick,
}: {
  frame:    CapturedFrame;
  selected: boolean;
  onClick:  () => void;
}) {
  const typeName = FrameTypeName[frame.type] ?? "UNKNOWN";
  const tc       = TYPE_COLOR[frame.type] ?? "text-zinc-400";
  const icon     = TYPE_ICONS[frame.type] ?? "?";

  return (
    <button onClick={onClick}
      className={`w-full text-left flex items-center gap-2 px-3 py-1.5 border-b border-white/[.03] text-[9px] font-mono hover:bg-white/[.03] transition-all ${selected ? "bg-cyan-950/20 border-l-2 border-l-cyan-600" : "border-l-2 border-l-transparent"}`}>
      <span className="text-zinc-700 w-24 shrink-0">{new Date(frame.ts).toISOString().slice(11, 23)}</span>
      <span className={`text-[8px] shrink-0 w-4 ${frame.dir === "tx" ? "text-cyan-600" : "text-green-600"}`}>
        {frame.dir === "tx" ? "↑" : "↓"}
      </span>
      <span className={`${tc} font-bold w-20 shrink-0`}>{icon} {typeName}</span>
      <span className="text-zinc-700 w-8 shrink-0">#{frame.seq}</span>
      <span className="text-zinc-600 w-16 shrink-0">{frame.payLen}B</span>
      {!frame.hmacOk && <span className="text-red-600 font-bold shrink-0 animate-pulse">⚠HMAC</span>}
      <span className="text-zinc-700 shrink-0">{frame.relMs >= 0 ? `+${frame.relMs}ms` : ""}</span>
      {frame.sessionId && <span className="text-zinc-700 shrink-0 truncate max-w-24">{frame.sessionId.slice(0, 8)}</span>}
      <span className="text-zinc-800 truncate flex-1">{JSON.stringify(frame.parsed).slice(0, 60)}</span>
    </button>
  );
}

export default function C2TrafficSniffer() {
  const [wsUrl,      setWsUrl]      = useState(() => `${wsBase()}/api/ws/c2-sniffer`);
  const [passphrase, setPassphrase] = useState("ironworm-c2-key");
  const [customKey,  setCustomKey]  = useState("");
  const [useCustom,  setUseCustom]  = useState(false);
  const [connected,  setConnected]  = useState(false);
  const [paused,     setPaused]     = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const [showKey,    setShowKey]    = useState(false);

  const [frames,    setFrames]    = useState<CapturedFrame[]>([]);
  const [selected,  setSelected]  = useState<CapturedFrame | null>(null);
  const [filterSid, setFilterSid] = useState<string | null>(null);
  const [filterType,setFilterType]= useState<number | null>(null);
  const [sessions,  setSessions]  = useState<SessionStats[]>([]);
  const [hmacFails, setHmacFails] = useState(0);
  const [tab,       setTab]       = useState<"frames"|"hex"|"json"|"stats">("frames");

  // Offline analysis
  const [pasteHex,  setPasteHex]  = useState("");
  const [offlineResult, setOfflineResult] = useState<CapturedFrame | null>(null);
  const [offlineErr, setOfflineErr] = useState<string | null>(null);

  const wsRef      = useRef<WebSocket | null>(null);
  const keyRef     = useRef<Uint8Array>(deriveKey("ironworm-c2-key"));
  const pausedRef  = useRef(false);
  const frameCount = useRef(0);
  const capStart   = useRef<number>(0);
  const listRef    = useRef<HTMLDivElement>(null);

  useEffect(() => {
    keyRef.current = useCustom && customKey.length === 128
      ? hexToKey(customKey)
      : deriveKey(passphrase);
  }, [passphrase, customKey, useCustom]);

  // Keep pausedRef in sync so ws.onmessage always sees the latest value
  useEffect(() => { pausedRef.current = paused; }, [paused]);

  useEffect(() => {
    if (autoScroll && listRef.current && !paused) {
      listRef.current.scrollTop = listRef.current.scrollHeight;
    }
  }, [frames, autoScroll, paused]);

  const addFrame = useCallback((f: CapturedFrame) => {
    setFrames(p => [...p.slice(-2000), f]);
    if (!f.hmacOk) setHmacFails(n => n + 1);
    setSessions(p => {
      const sid = f.sessionId ?? "_unknown";
      const existing = p.find(s => s.id === sid);
      const typeName = FrameTypeName[f.type] ?? "UNKNOWN";
      if (existing) {
        return p.map(s => s.id === sid
          ? { ...s, frames: s.frames + 1, bytes: s.bytes + f.totalLen, lastSeen: f.ts, types: { ...s.types, [typeName]: (s.types[typeName] ?? 0) + 1 } }
          : s);
      }
      return [...p, { id: sid, frames: 1, bytes: f.totalLen, lastSeen: f.ts, types: { [typeName]: 1 } }];
    });
  }, []);

  const connect = useCallback(() => {
    if (wsRef.current) { wsRef.current.close(); wsRef.current = null; }
    capStart.current = Date.now();
    frameCount.current = 0;

    const ws = new WebSocket(withAuthToken(wsUrl));
    ws.binaryType = "arraybuffer";
    wsRef.current = ws;

    ws.onopen = () => { setConnected(true); };

    ws.onmessage = async (ev: MessageEvent) => {
      if (pausedRef.current) return;

      let raw: Uint8Array;
      let dir: "rx" | "tx" = "rx";

      if (ev.data instanceof ArrayBuffer) {
        raw = new Uint8Array(ev.data);
      } else if (typeof ev.data === "string") {
        // JSON envelope from relay: { dir, hex }
        try {
          const obj = JSON.parse(ev.data) as { dir?: string; hex?: string; session_id?: string };
          dir = (obj.dir ?? "rx") as "rx" | "tx";
          if (obj.hex) {
            raw = new Uint8Array(
              obj.hex.trim().split(/\s+/).filter(h => /^[0-9a-fA-F]{2}$/.test(h)).map(h => parseInt(h, 16))
            );
          } else return;
        } catch { return; }
      } else return;

      const frame = await decodeFrame(raw, keyRef.current);
      if (!frame) return;

      const parsed = parseFramePayload(frame.payload) as Record<string, unknown>;
      const sessionId = (parsed?.["session_id"] ?? parsed?.["token"] ?? null) as string | null;

      const cf: CapturedFrame = {
        id:        `f${++frameCount.current}`,
        ts:        Date.now(),
        relMs:     Date.now() - capStart.current,
        dir,
        type:      frame.type,
        seq:       frame.seq,
        payLen:    frame.payload.length,
        totalLen:  raw.length,
        hmacOk:    frame.hmacOk,
        bytes:     raw,
        payload:   frame.payload,
        parsed,
        sessionId,
      };
      addFrame(cf);
    };

    ws.onerror = () => {};
    ws.onclose = () => { setConnected(false); wsRef.current = null; };
  }, [wsUrl, addFrame]);

  const disconnect = useCallback(() => {
    wsRef.current?.close(1000);
    wsRef.current = null;
    setConnected(false);
  }, []);

  // Close WebSocket on unmount to avoid connection leaks
  useEffect(() => {
    return () => { wsRef.current?.close(1000); wsRef.current = null; };
  }, []);

  const clearCapture = useCallback(() => {
    setFrames([]);
    setSessions([]);
    setHmacFails(0);
    setSelected(null);
    frameCount.current = 0;
    capStart.current = Date.now();
  }, []);

  const exportCapture = useCallback(() => {
    const ndjson = frames.map(f => JSON.stringify({
      ts: f.ts, dir: f.dir, type: FrameTypeName[f.type],
      seq: f.seq, payLen: f.payLen, totalLen: f.totalLen,
      hmacOk: f.hmacOk, sessionId: f.sessionId, parsed: f.parsed,
      hex: Array.from(f.bytes).map(b => b.toString(16).padStart(2,"0")).join(" "),
    })).join("\n");
    const blob = new Blob([ndjson], { type: "application/x-ndjson" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
    a.download = `c2-capture-${Date.now()}.ndjson`; a.click(); URL.revokeObjectURL(a.href);
  }, [frames]);

  const analyzeOfflineHex = useCallback(async () => {
    setOfflineErr(null); setOfflineResult(null);
    const clean = pasteHex.replace(/[\s\n]/g, "");
    if (!clean || clean.length % 2 !== 0) { setOfflineErr("Invalid hex — must be even number of hex chars, spaces optional"); return; }
    try {
      const bytes = new Uint8Array(clean.length / 2);
      for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.slice(i*2, i*2+2), 16);
      const frame = await decodeFrame(bytes, keyRef.current);
      if (!frame) { setOfflineErr("Failed to decode — check key or frame format"); return; }
      const parsed = parseFramePayload(frame.payload);
      const sessionId = ((parsed as Record<string, unknown>)?.["session_id"] ?? null) as string | null;
      setOfflineResult({
        id: "offline", ts: Date.now(), relMs: 0, dir: "rx",
        type: frame.type, seq: frame.seq, payLen: frame.payload.length,
        totalLen: bytes.length, hmacOk: frame.hmacOk, bytes, payload: frame.payload,
        parsed, sessionId,
      });
    } catch (e) { setOfflineErr(String(e)); }
  }, [pasteHex]);

  const displayedFrames = useMemo(() => {
    return frames.filter(f =>
      (filterSid  === null || f.sessionId === filterSid) &&
      (filterType === null || f.type === filterType)
    );
  }, [frames, filterSid, filterType]);

  // Statistics
  const totalBytes  = useMemo(() => frames.reduce((a, f) => a + f.totalLen, 0), [frames]);
  const typeStats   = useMemo(() => {
    const m: Record<string, number> = {};
    for (const f of frames) { const n = FrameTypeName[f.type] ?? "UNK"; m[n] = (m[n] ?? 0) + 1; }
    return m;
  }, [frames]);
  const capDurationS = capStart.current > 0 ? ((Date.now() - capStart.current) / 1000).toFixed(1) : "0";

  return (
    <div className="flex flex-col h-full bg-[#050505] text-white font-mono overflow-hidden">

      {/* Header */}
      <div className="border-b border-cyan-900/30 px-4 py-2.5 bg-black/60 shrink-0">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-3">
            <div className={`w-2 h-2 rounded-full transition-colors ${connected ? "bg-cyan-500 animate-pulse" : "bg-zinc-700"}`} />
            <span className="text-cyan-400 font-bold tracking-[.2em] uppercase text-sm">C2 Traffic Sniffer</span>
            <span className="text-[9px] text-zinc-600 uppercase tracking-widest">XOR+HMAC-SHA256 Binary Frame Decoder</span>
          </div>
          <div className="flex items-center gap-4 text-[9px]">
            <span className="text-zinc-600">FRAMES <span className="text-white">{frames.length}</span></span>
            <span className="text-zinc-600">BYTES <span className="text-white">{totalBytes.toLocaleString()}</span></span>
            <span className="text-zinc-600">SESSIONS <span className="text-white">{sessions.length}</span></span>
            {hmacFails > 0 && <span className="text-red-500 font-bold animate-pulse">⚠ {hmacFails} HMAC FAIL{hmacFails !== 1 ? "S" : ""}</span>}
          </div>
        </div>

        {/* Controls bar */}
        <div className="flex items-center gap-2 flex-wrap">
          <input value={wsUrl} onChange={e => setWsUrl(e.target.value)}
            className="bg-black/60 border border-white/[.06] text-[10px] px-2 py-1 text-white focus:outline-none focus:border-cyan-900/60 w-64 placeholder-zinc-700"
            placeholder="ws://host/api/ws/c2-sniffer" />

          <div className="flex items-center gap-1">
            <button onClick={() => setUseCustom(false)} className={`text-[8px] px-2 py-1 border ${!useCustom ? "border-cyan-800 text-cyan-400" : "border-zinc-800 text-zinc-600"}`}>phrase</button>
            <button onClick={() => setUseCustom(true)}  className={`text-[8px] px-2 py-1 border ${useCustom  ? "border-cyan-800 text-cyan-400" : "border-zinc-800 text-zinc-600"}`}>hex</button>
            <input type={showKey ? "text" : "password"}
              value={useCustom ? customKey : passphrase}
              onChange={e => useCustom ? setCustomKey(e.target.value) : setPassphrase(e.target.value)}
              className="bg-black/60 border border-white/[.06] text-[10px] px-2 py-1 text-green-400 focus:outline-none w-36"
              placeholder={useCustom ? "128-char hex key" : "passphrase"} />
            <button onClick={() => setShowKey(s => !s)} className="text-[8px] px-1 text-zinc-700 hover:text-zinc-400">{showKey ? "hide" : "show"}</button>
          </div>

          <button onClick={connected ? disconnect : connect}
            className={`text-[9px] px-3 py-1.5 border font-bold uppercase tracking-widest transition-all ${connected ? "border-red-900/50 text-red-400 hover:border-red-700" : "border-cyan-800/50 text-cyan-400 bg-cyan-950/10 hover:border-cyan-600"}`}>
            {connected ? "■ Stop" : "▶ Capture"}
          </button>

          {frames.length > 0 && (
            <>
              <button onClick={() => setPaused(p => !p)}
                className={`text-[9px] px-3 py-1.5 border transition-all uppercase tracking-widest ${paused ? "border-yellow-800 text-yellow-400 bg-yellow-950/10" : "border-zinc-800 text-zinc-500 hover:text-zinc-300"}`}>
                {paused ? "▶ Resume" : "⏸ Pause"}
              </button>
              <button onClick={clearCapture} className="text-[9px] px-3 py-1.5 border border-zinc-800 text-zinc-600 hover:text-zinc-300 uppercase tracking-widest">CLR</button>
              <button onClick={exportCapture} className="text-[9px] px-3 py-1.5 border border-zinc-800 text-zinc-600 hover:text-zinc-300 uppercase tracking-widest">↓ NDJSON</button>
            </>
          )}

          <div className="ml-auto flex items-center gap-1">
            <button onClick={() => setAutoScroll(a => !a)} className={`text-[8px] px-2 py-1 border ${autoScroll ? "border-cyan-800 text-cyan-400" : "border-zinc-800 text-zinc-600"}`}>
              auto-scroll {autoScroll ? "on" : "off"}
            </button>
          </div>
        </div>
      </div>

      <div className="flex flex-1 min-h-0 overflow-hidden">

        {/* Left sidebar — sessions + type filters */}
        <div className="w-48 border-r border-white/[.04] flex flex-col bg-black/20 overflow-y-auto shrink-0">
          <div className="p-3 space-y-3">

            <div>
              <div className="text-[8px] text-zinc-600 uppercase tracking-widest mb-1.5">Session Filter</div>
              <button onClick={() => setFilterSid(null)}
                className={`block w-full text-left text-[9px] px-2 py-1.5 border mb-1 ${filterSid === null ? "border-cyan-800 text-cyan-400 bg-cyan-950/20" : "border-zinc-800 text-zinc-600 hover:text-zinc-400"}`}>
                All sessions ({sessions.length})
              </button>
              {sessions.map(s => (
                <button key={s.id} onClick={() => setFilterSid(sfs => sfs === s.id ? null : s.id)}
                  className={`block w-full text-left text-[9px] px-2 py-1.5 border mb-1 transition-all ${filterSid === s.id ? "border-cyan-800 bg-cyan-950/20 text-cyan-400" : "border-zinc-800 text-zinc-600 hover:text-zinc-400"}`}>
                  <div className="truncate">{s.id.slice(0, 10)}</div>
                  <div className="text-[8px] text-zinc-700">{s.frames}f · {s.bytes.toLocaleString()}B</div>
                </button>
              ))}
            </div>

            <div className="border-t border-white/[.04] pt-3">
              <div className="text-[8px] text-zinc-600 uppercase tracking-widest mb-1.5">Type Filter</div>
              <button onClick={() => setFilterType(null)}
                className={`block w-full text-left text-[9px] px-2 py-1 border mb-1 ${filterType === null ? "border-cyan-800 text-cyan-400" : "border-zinc-800 text-zinc-600 hover:text-zinc-400"}`}>
                All types
              </button>
              {Object.entries(FrameTypeName).map(([id, name]) => {
                const n = parseInt(id);
                const cnt = typeStats[name] ?? 0;
                return (
                  <button key={id} onClick={() => setFilterType(ft => ft === n ? null : n)}
                    className={`block w-full text-left text-[9px] px-2 py-1 border mb-0.5 transition-all ${filterType === n ? "border-cyan-800 text-cyan-400" : "border-zinc-800 text-zinc-700 hover:text-zinc-500"} ${cnt === 0 ? "opacity-40" : ""}`}>
                    <span className={TYPE_COLOR[n] ?? "text-zinc-500"}>{TYPE_ICONS[n] ?? "?"}</span>{" "}
                    {name} {cnt > 0 ? <span className="text-zinc-600">({cnt})</span> : ""}
                  </button>
                );
              })}
            </div>

            {/* Offline analysis */}
            <div className="border-t border-white/[.04] pt-3">
              <div className="text-[8px] text-zinc-600 uppercase tracking-widest mb-1.5">Offline Decode</div>
              <textarea value={pasteHex} onChange={e => setPasteHex(e.target.value)}
                className="w-full h-20 bg-black/60 border border-white/[.06] text-[9px] text-green-400 font-mono p-2 resize-none focus:outline-none placeholder-zinc-800"
                placeholder="49 52 4e 57 03 02..." />
              <button onClick={analyzeOfflineHex}
                className="w-full py-1.5 text-[9px] border border-cyan-800/50 text-cyan-400 uppercase tracking-widest mt-1 hover:bg-cyan-950/10">
                Decode
              </button>
              {offlineErr && <div className="text-[8px] text-red-400 mt-1 break-words">{offlineErr}</div>}
            </div>
          </div>
        </div>

        {/* Main pane */}
        <div className="flex-1 flex flex-col min-w-0 overflow-hidden">

          {/* Sub-tabs */}
          <div className="border-b border-white/[.04] px-4 py-1.5 flex items-center gap-1 shrink-0">
            {(["frames","hex","json","stats"] as const).map(t => (
              <button key={t} onClick={() => setTab(t)}
                className={`text-[9px] px-3 py-1.5 uppercase tracking-widest border transition-all ${tab === t ? "border-cyan-800 text-cyan-400 bg-cyan-950/10" : "border-zinc-800 text-zinc-600 hover:text-zinc-400"}`}>
                {t === "frames" ? `Frames (${displayedFrames.length})` : t.toUpperCase()}
              </button>
            ))}
            {selected && (
              <div className="ml-auto flex items-center gap-2 text-[8px] text-zinc-600">
                <span>Selected:</span>
                <span className={TYPE_COLOR[selected.type] ?? "text-zinc-400"}>{FrameTypeName[selected.type]}</span>
                <span>#{selected.seq}</span>
                <span>{selected.totalLen}B</span>
                <button onClick={() => setSelected(null)} className="text-zinc-700 hover:text-zinc-400 ml-1">✕</button>
              </div>
            )}
          </div>

          {/* FRAMES tab */}
          {tab === "frames" && (
            <div ref={listRef} className="flex-1 overflow-y-auto min-h-0">
              {displayedFrames.length === 0 && !connected && (
                <div className="flex flex-col items-center justify-center h-full text-zinc-700 gap-4">
                  <div className="text-5xl opacity-20">📡</div>
                  <p className="text-[10px] uppercase tracking-widest">Connect to a C2 relay to begin capture</p>
                  <div className="text-[9px] text-zinc-800 max-w-xs text-center space-y-1">
                    <p>Backend endpoint: <span className="text-zinc-600">/api/ws/c2-sniffer</span></p>
                    <p>Mirrors all binary C2 frames from both directions</p>
                    <p>Frame overhead: {HEADER_SIZE + HMAC_SIZE} bytes · XOR+HMAC-SHA256</p>
                    <p className="mt-2">Or paste hex bytes in the Offline Decode panel to analyze frames without a live connection</p>
                  </div>
                </div>
              )}
              {displayedFrames.length === 0 && connected && (
                <div className="flex items-center justify-center h-full text-zinc-700">
                  <div className="text-[9px] uppercase tracking-widest animate-pulse">● waiting for frames…</div>
                </div>
              )}
              {displayedFrames.map(f => (
                <FrameRow key={f.id} frame={f} selected={selected?.id === f.id}
                  onClick={() => setSelected(s => s?.id === f.id ? null : f)} />
              ))}
            </div>
          )}

          {/* HEX tab */}
          {tab === "hex" && (
            <div className="flex-1 overflow-y-auto p-4 min-h-0">
              {(offlineResult ?? selected) ? (
                <HexDump frame={(offlineResult ?? selected)!} />
              ) : (
                <div className="text-zinc-700 text-[9px] uppercase tracking-widest text-center py-8">
                  Select a frame in the Frames tab to view its hex dump
                </div>
              )}
            </div>
          )}

          {/* JSON tab */}
          {tab === "json" && (
            <div className="flex-1 overflow-y-auto p-4 min-h-0">
              {(offlineResult ?? selected) ? (
                <div className="space-y-4">
                  <div className="border border-zinc-800 p-3 bg-black/40">
                    <div className="text-[8px] text-zinc-600 uppercase tracking-widest mb-2">Frame Metadata</div>
                    <pre className="text-[10px] text-cyan-400 font-mono">{JSON.stringify({
                      type:      FrameTypeName[(offlineResult ?? selected)!.type],
                      seq:       (offlineResult ?? selected)!.seq,
                      payloadLen: (offlineResult ?? selected)!.payLen,
                      totalLen:  (offlineResult ?? selected)!.totalLen,
                      hmacOk:    (offlineResult ?? selected)!.hmacOk,
                      sessionId: (offlineResult ?? selected)!.sessionId,
                      direction: (offlineResult ?? selected)!.dir,
                    }, null, 2)}</pre>
                  </div>
                  <div className="border border-zinc-800 p-3 bg-black/40">
                    <div className="text-[8px] text-zinc-600 uppercase tracking-widest mb-2">Decrypted Payload</div>
                    <JsonPane parsed={(offlineResult ?? selected)!.parsed} />
                  </div>
                  <div className="border border-zinc-800 p-3 bg-black/40">
                    <div className="text-[8px] text-zinc-600 uppercase tracking-widest mb-2">Raw XOR-Ciphered Payload (pre-decryption)</div>
                    <pre className="text-[10px] text-orange-400 font-mono break-all">
                      {Array.from((offlineResult ?? selected)!.bytes.slice(HEADER_SIZE, HEADER_SIZE + (offlineResult ?? selected)!.payLen))
                        .map(b => b.toString(16).padStart(2,"0")).join(" ")}
                    </pre>
                  </div>
                </div>
              ) : (
                <div className="text-zinc-700 text-[9px] uppercase tracking-widest text-center py-8">
                  Select a frame to view decoded payload
                </div>
              )}
            </div>
          )}

          {/* STATS tab */}
          {tab === "stats" && (
            <div className="flex-1 overflow-y-auto p-4 min-h-0 space-y-4">
              <div className="grid grid-cols-4 gap-3">
                {[
                  ["Total Frames", String(frames.length), "text-white"],
                  ["Total Bytes", totalBytes.toLocaleString() + "B", "text-white"],
                  ["Sessions", String(sessions.length), "text-cyan-400"],
                  ["HMAC Failures", String(hmacFails), hmacFails > 0 ? "text-red-500" : "text-zinc-500"],
                ].map(([label, val, cls]) => (
                  <div key={label} className="border border-zinc-800 p-3 bg-black/20">
                    <div className="text-[8px] text-zinc-600 uppercase tracking-widest">{label}</div>
                    <div className={`text-lg font-bold mt-1 ${cls}`}>{val}</div>
                  </div>
                ))}
              </div>

              <div className="border border-zinc-800 p-3 bg-black/20">
                <div className="text-[8px] text-zinc-600 uppercase tracking-widest mb-3">Frame Type Breakdown</div>
                {Object.entries(typeStats).sort(([,a],[,b]) => b-a).map(([type, cnt]) => (
                  <div key={type} className="flex items-center gap-3 mb-1.5">
                    <div className="text-[9px] w-24 shrink-0 text-zinc-400">{type}</div>
                    <div className="flex-1 h-2 bg-zinc-900 overflow-hidden">
                      <div className="h-full bg-cyan-800 transition-all"
                        style={{ width: `${Math.round((cnt / frames.length) * 100)}%` }} />
                    </div>
                    <div className="text-[9px] text-zinc-500 w-16 text-right">{cnt} ({Math.round((cnt / frames.length)*100)}%)</div>
                  </div>
                ))}
              </div>

              <div className="border border-zinc-800 p-3 bg-black/20">
                <div className="text-[8px] text-zinc-600 uppercase tracking-widest mb-3">Session Details</div>
                {sessions.map(s => (
                  <div key={s.id} className="border-b border-zinc-900 pb-2 mb-2">
                    <div className="text-[9px] text-cyan-400 mb-1">{s.id}</div>
                    <div className="text-[8px] text-zinc-500">{s.frames} frames · {s.bytes.toLocaleString()} bytes · last seen {new Date(s.lastSeen).toISOString().slice(11,23)}</div>
                    <div className="flex flex-wrap gap-2 mt-1">
                      {Object.entries(s.types).map(([t, n]) => (
                        <span key={t} className="text-[8px] text-zinc-600">{t}:{n}</span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>

              <div className="border border-zinc-800 p-3 bg-black/20">
                <div className="text-[8px] text-zinc-600 uppercase tracking-widest mb-2">Protocol Reference</div>
                <pre className="text-[9px] text-zinc-500 font-mono leading-relaxed">{
`Frame: MAGIC(4) VER(1) TYPE(1) SEQ(4) LEN(4) | XOR-PAYLOAD(N) | HMAC-SHA256(32)
Total overhead: ${HEADER_SIZE + HMAC_SIZE}B per frame
XOR key: key[0..32]
HMAC key: key[32..64]
Key derivation: passphrase → deterministic 64-byte key via XOR-stretch
Type values: HB=0x01 CMD=0x02 RSP=0x03 EXFIL=0x04 AUTH=0x05
             PROXY=0x06 KILL=0x07 UPD=0x08 ACK=0x09 ERR=0x0a`}</pre>
              </div>
            </div>
          )}
        </div>

        {/* Right detail pane — shown when a frame is selected */}
        {selected && (tab === "frames") && (
          <div className="w-96 border-l border-white/[.04] flex flex-col bg-black/20 overflow-y-auto shrink-0">
            <div className="border-b border-white/[.04] px-4 py-3 bg-black/40 flex items-center justify-between shrink-0">
              <div>
                <span className={`${TYPE_COLOR[selected.type] ?? "text-zinc-400"} font-bold text-[11px]`}>
                  {TYPE_ICONS[selected.type]} {FrameTypeName[selected.type]}
                </span>
                <span className="text-zinc-600 text-[9px] ml-2">#{selected.seq} · {selected.totalLen}B</span>
              </div>
              <div className="flex items-center gap-2">
                <span className={`text-[8px] px-1.5 py-0.5 border font-bold ${selected.hmacOk ? "border-green-900 text-green-400" : "border-red-900 text-red-400 animate-pulse"}`}>
                  {selected.hmacOk ? "HMAC ✓" : "HMAC ✗"}
                </span>
                <button onClick={() => setSelected(null)} className="text-zinc-700 hover:text-zinc-400 text-xs">✕</button>
              </div>
            </div>
            <div className="p-4 space-y-4 flex-1">
              {/* Mini hex dump */}
              <div>
                <div className="text-[8px] text-zinc-600 uppercase tracking-widest mb-2">Hex Dump</div>
                <div className="bg-black/60 border border-zinc-800 p-3 max-h-64 overflow-y-auto">
                  <HexDump frame={selected} />
                </div>
              </div>
              {/* Decoded payload */}
              <div>
                <div className="text-[8px] text-zinc-600 uppercase tracking-widest mb-2">Decrypted Payload</div>
                <div className="bg-black/60 border border-zinc-800 p-3 max-h-48 overflow-y-auto">
                  <JsonPane parsed={selected.parsed} />
                </div>
              </div>
              <button onClick={() => {
                navigator.clipboard.writeText(
                  Array.from(selected.bytes).map(b => b.toString(16).padStart(2,"0")).join(" ")
                );
              }} className="w-full py-2 text-[9px] uppercase tracking-widest border border-zinc-800 hover:border-zinc-600 text-zinc-600 hover:text-zinc-300">
                Copy Raw Hex
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
