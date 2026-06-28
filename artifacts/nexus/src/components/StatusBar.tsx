import React, { useState, useEffect, useRef } from "react";
import { authHeaders } from "../lib/auth";

const API_URL = (import.meta.env as Record<string, string>)["VITE_API_URL"] ?? "";

interface StatusData {
  oobHits:      number;
  oobWithData:  number;
  c2Sessions:   number;
  c2Sniffers:   number;
  c2Operators:  number;
  wsActiveTotal: number;
  wsTotalEver:  number;
  uptimeMs:     number;
}

function fmtUptime(ms: number): string {
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${sec}s`;
  return `${sec}s`;
}

export default function StatusBar() {
  const [data,    setData]    = useState<StatusData | null>(null);
  const [online,  setOnline]  = useState(false);
  const [flash,   setFlash]   = useState(false);
  const prevHits = useRef(0);

  useEffect(() => {
    let cancelled = false;

    async function poll() {
      try {
        const r = await fetch(`${API_URL}/api/hub/status`, { headers: authHeaders() });
        if (cancelled) return;
        if (r.ok) {
          const d = await r.json() as StatusData;
          if (d.oobHits > prevHits.current) {
            setFlash(true);
            setTimeout(() => setFlash(false), 800);
          }
          prevHits.current = d.oobHits;
          setData(d);
          setOnline(true);
        } else {
          setOnline(false);
        }
      } catch {
        if (!cancelled) setOnline(false);
      }
    }

    void poll();
    const id = setInterval(poll, 4000);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  return (
    <div className={`flex items-center gap-0 px-3 py-0 bg-zinc-950 border-b font-mono text-[10px] shrink-0 h-7 transition-colors ${flash ? "border-red-700" : "border-zinc-900"}`}>
      <span className="text-red-500 font-black tracking-[.2em] text-[11px] uppercase pr-3 border-r border-zinc-800 mr-3">
        NEXUS
      </span>

      <div className="flex items-center gap-1.5 pr-3 border-r border-zinc-800 mr-3">
        <div className={`w-1.5 h-1.5 rounded-full ${online ? "bg-green-500 animate-pulse" : "bg-red-700"}`} />
        <span className={online ? "text-green-600" : "text-red-600"}>{online ? "ONLINE" : "OFFLINE"}</span>
      </div>

      {data ? (
        <>
          <div className="flex items-center gap-2 pr-3 border-r border-zinc-800 mr-3">
            <span className="text-zinc-600">OOB</span>
            <span className={`font-bold tabular-nums ${data.oobHits > 0 ? (flash ? "text-red-300" : "text-red-400") : "text-zinc-700"}`}>
              {data.oobHits}
            </span>
            {data.oobWithData > 0 && (
              <span className="text-[9px] text-amber-600">{data.oobWithData} w/data</span>
            )}
            {data.oobHits > 0 && <span className={`text-red-700 ${flash ? "animate-none" : "animate-pulse"}`}>●</span>}
          </div>

          <div className="flex items-center gap-2 pr-3 border-r border-zinc-800 mr-3">
            <span className="text-zinc-600">C2</span>
            <span className={`font-bold tabular-nums ${data.c2Sessions > 0 ? "text-purple-400" : "text-zinc-700"}`}>
              {data.c2Sessions}
            </span>
            <span className="text-zinc-700">sess</span>
            {data.c2Sniffers > 0 && (
              <span className="text-zinc-600">{data.c2Sniffers} sniff</span>
            )}
            {data.c2Operators > 0 && (
              <span className="text-cyan-700">{data.c2Operators} op</span>
            )}
          </div>

          <div className="flex items-center gap-2 pr-3 border-r border-zinc-800 mr-3">
            <span className="text-zinc-600">WS</span>
            <span className={`font-bold tabular-nums ${data.wsActiveTotal > 0 ? "text-cyan-500" : "text-zinc-700"}`}>
              {data.wsActiveTotal}
            </span>
            <span className="text-zinc-700">active</span>
            {data.wsTotalEver > 0 && (
              <span className="text-zinc-800">{data.wsTotalEver} ever</span>
            )}
          </div>

          <div className="ml-auto flex items-center gap-2 text-zinc-700">
            <span className="text-zinc-800">UP</span>
            <span className="text-zinc-600 tabular-nums">{fmtUptime(data.uptimeMs)}</span>
          </div>
        </>
      ) : (
        <span className="text-zinc-800 animate-pulse">loading stats…</span>
      )}
    </div>
  );
}
