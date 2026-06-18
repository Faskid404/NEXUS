import React, { useState, useEffect, useCallback } from "react";
import { authHeaders } from "../lib/auth";

interface ChainRun {
  id:             number;
  timestamp:      string;
  targetUrl:      string;
  injectParam:    string;
  httpMethod:     string;
  cmd:            string;
  confirmed:      boolean;
  confirmedMode:  string | null;
  confirmedVia:   string | null;
  exfilData:      string;
  elapsed:        number;
  modesRun:       number;
  totalModes:     number;
  oobToken:       string;
}

const API = import.meta.env.VITE_API_URL ?? "";

export default function ChainReplayPanel() {
  const [runs,         setRuns]         = useState<ChainRun[]>([]);
  const [loading,      setLoading]      = useState(false);
  const [selected,     setSelected]     = useState<ChainRun | null>(null);
  const [filter,       setFilter]       = useState<"all" | "confirmed" | "failed">("all");
  const [search,       setSearch]       = useState("");
  const [confirmClear, setConfirmClear] = useState(false);

  const fetchRuns = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch(`${API}/api/chainlog`, { headers: authHeaders() });
      if (r.ok) setRuns(await r.json() as ChainRun[]);
    } catch { /* network error */ }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { void fetchRuns(); }, [fetchRuns]);

  const handleClear = async () => {
    if (!confirmClear) { setConfirmClear(true); return; }
    setConfirmClear(false);
    await fetch(`${API}/api/chainlog`, { method: "DELETE", headers: authHeaders() });
    setRuns([]);
    setSelected(null);
  };

  const handleExport = () => {
    window.open(`${API}/api/chainlog/export`, "_blank");
  };

  const filtered = runs.filter(r => {
    if (filter === "confirmed" && !r.confirmed) return false;
    if (filter === "failed"    &&  r.confirmed) return false;
    if (search && !r.targetUrl.toLowerCase().includes(search.toLowerCase()) &&
        !(r.confirmedMode ?? "").toLowerCase().includes(search.toLowerCase()) &&
        !r.cmd.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const VIA_COLOR: Record<string, string> = {
    response_body: "text-lime-400",
    oob_callback:  "text-orange-400",
  };

  const MODE_COLOR: Record<string, string> = {
    classic:"text-lime-400", blind:"text-yellow-400", oob:"text-orange-400",
    quantum:"text-fuchsia-400", ifs:"text-cyan-400", concat:"text-blue-400",
    hex:"text-emerald-400", b64loop:"text-violet-400", env:"text-rose-400",
    heredoc:"text-amber-400", unicode:"text-sky-400", null:"text-zinc-400",
    wildcard:"text-teal-400", comment:"text-orange-300", double_enc:"text-pink-400",
    ssti:"text-red-500", log4shell:"text-orange-500", xxe:"text-purple-400",
    polyglot:"text-indigo-400", brace:"text-teal-300", process_sub:"text-violet-300",
    arith:"text-sky-300", ansi_c:"text-lime-300", rev:"text-pink-300",
    rev_shell:"text-red-600", cloud:"text-amber-400", container:"text-cyan-300",
  };

  return (
    <div className="flex h-full bg-black text-xs font-mono overflow-hidden">

      {/* Left: list */}
      <div className="w-80 flex flex-col border-r border-zinc-900 shrink-0">

        {/* toolbar */}
        <div className="flex items-center gap-1 p-2 border-b border-zinc-900 shrink-0">
          <span className="text-red-500 uppercase font-bold mr-1">REPLAYS</span>
          <span className="text-zinc-600 text-[10px]">{filtered.length}/{runs.length}</span>
          <div className="flex-1" />
          <button onClick={()=>void fetchRuns()}
            className="px-2 py-0.5 text-[10px] bg-zinc-900 text-zinc-400 hover:text-white uppercase border border-zinc-800 hover:border-zinc-600 transition-colors">
            ↻
          </button>
          <button onClick={handleExport}
            className="px-2 py-0.5 text-[10px] bg-zinc-900 text-zinc-400 hover:text-lime-400 uppercase border border-zinc-800 hover:border-lime-800 transition-colors">
            JSON
          </button>
          <button onClick={()=>void handleClear()}
            className={`px-2 py-0.5 text-[10px] bg-zinc-900 uppercase border transition-colors ${
              confirmClear
                ? "text-red-400 border-red-700 hover:bg-red-950/30"
                : "text-zinc-400 hover:text-red-400 border-zinc-800 hover:border-red-900"
            }`}>
            {confirmClear ? "SURE?" : "CLR"}
          </button>
        </div>

        {/* search */}
        <div className="p-2 border-b border-zinc-900 shrink-0">
          <input
            value={search} onChange={e => setSearch(e.target.value)}
            placeholder="search target / mode / cmd…"
            className="w-full bg-zinc-950 border border-zinc-800 px-2 py-1 text-[10px] text-zinc-300 placeholder-zinc-700 focus:outline-none focus:border-red-900"
          />
        </div>

        {/* filter pills */}
        <div className="flex gap-1 px-2 py-1 border-b border-zinc-900 shrink-0">
          {(["all","confirmed","failed"] as const).map(f => (
            <button key={f} onClick={() => setFilter(f)}
              className={`px-2 py-0.5 text-[10px] uppercase border transition-colors ${
                filter === f
                  ? f === "confirmed" ? "border-lime-700 text-lime-400 bg-lime-950"
                  : f === "failed"    ? "border-red-900 text-red-400 bg-red-950"
                  :                    "border-zinc-600 text-zinc-300 bg-zinc-900"
                  : "border-zinc-800 text-zinc-600 hover:text-zinc-400"
              }`}>
              {f}
            </button>
          ))}
        </div>

        {/* run list */}
        <div className="flex-1 overflow-y-auto min-h-0">
          {loading && (
            <div className="p-4 text-center text-zinc-600 text-[10px]">Loading…</div>
          )}
          {!loading && filtered.length === 0 && (
            <div className="p-4 text-center text-zinc-700 text-[10px]">
              {runs.length === 0 ? "No runs recorded yet.\nRun AUTOCHAIN to start logging." : "No matches."}
            </div>
          )}
          {filtered.map(run => (
            <button key={run.id} onClick={() => setSelected(run)}
              className={`w-full text-left px-3 py-2 border-b border-zinc-900 hover:bg-zinc-900/60 transition-colors ${
                selected?.id === run.id ? "bg-zinc-900" : ""
              }`}>
              <div className="flex items-center justify-between mb-0.5">
                <span className={`text-[10px] font-bold uppercase ${run.confirmed ? "text-lime-400" : "text-zinc-500"}`}>
                  {run.confirmed ? "✔ CONFIRMED" : "— NO HIT"}
                </span>
                <span className="text-[9px] text-zinc-700">
                  {new Date(run.timestamp).toLocaleTimeString()}
                </span>
              </div>
              <div className="text-[10px] text-zinc-400 truncate" title={run.targetUrl}>
                {run.targetUrl}
              </div>
              <div className="flex items-center gap-2 mt-0.5">
                <span className="text-[9px] text-zinc-600 uppercase">{run.httpMethod}</span>
                <span className="text-[9px] text-zinc-700">·</span>
                <span className="text-[9px] text-zinc-600">{run.injectParam}</span>
                {run.confirmedMode && (
                  <>
                    <span className="text-[9px] text-zinc-700">·</span>
                    <span className={`text-[9px] uppercase font-bold ${MODE_COLOR[run.confirmedMode] ?? "text-zinc-400"}`}>
                      {run.confirmedMode}
                    </span>
                  </>
                )}
                <span className="ml-auto text-[9px] text-zinc-700">{(run.elapsed / 1000).toFixed(1)}s</span>
              </div>
            </button>
          ))}
        </div>

      </div>

      {/* Right: detail */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {!selected ? (
          <div className="flex-1 flex items-center justify-center text-zinc-700 text-[11px] text-center">
            <div>
              <div className="text-2xl mb-2 opacity-20">⚡</div>
              <div>Select a run to inspect</div>
            </div>
          </div>
        ) : (
          <>
            {/* header */}
            <div className="border-b border-zinc-900 p-3 shrink-0 space-y-1">
              <div className="flex items-center gap-3">
                <span className={`text-sm font-bold uppercase ${selected.confirmed ? "text-lime-400" : "text-zinc-500"}`}>
                  {selected.confirmed ? "✔ EXECUTION CONFIRMED" : "— NO CONFIRMED EXECUTION"}
                </span>
                <button onClick={() => setSelected(null)} className="ml-auto text-zinc-700 hover:text-zinc-400 text-[10px]">✕</button>
              </div>
              <div className="text-zinc-400 break-all">{selected.targetUrl}</div>
              <div className="flex flex-wrap gap-4 text-[10px] text-zinc-600 mt-1">
                <span><span className="text-zinc-700">TIME </span>{new Date(selected.timestamp).toLocaleString()}</span>
                <span><span className="text-zinc-700">METHOD </span>{selected.httpMethod}</span>
                <span><span className="text-zinc-700">PARAM </span>{selected.injectParam}</span>
                <span><span className="text-zinc-700">MODES </span>{selected.modesRun}/{selected.totalModes}</span>
                <span><span className="text-zinc-700">ELAPSED </span>{selected.elapsed}ms</span>
                <span><span className="text-zinc-700">OOB-TOK </span>{selected.oobToken}</span>
              </div>
            </div>

            {/* body */}
            <div className="flex-1 overflow-y-auto p-3 space-y-4 min-h-0">

              {/* command */}
              <section>
                <div className="text-[10px] text-zinc-600 uppercase mb-1">Command</div>
                <pre className="bg-zinc-950 border border-zinc-900 p-2 text-[10px] text-zinc-300 whitespace-pre-wrap break-all">
                  {selected.cmd}
                </pre>
              </section>

              {/* confirmed mode / via */}
              {selected.confirmed && (
                <section>
                  <div className="text-[10px] text-zinc-600 uppercase mb-1">Confirmed Vector</div>
                  <div className="flex gap-6 border border-lime-900/40 bg-lime-950/20 p-3">
                    <div>
                      <div className="text-[10px] text-zinc-600 mb-0.5">MODE</div>
                      <span className={`text-sm font-bold uppercase ${MODE_COLOR[selected.confirmedMode ?? ""] ?? "text-lime-400"}`}>
                        {selected.confirmedMode ?? "—"}
                      </span>
                    </div>
                    <div>
                      <div className="text-[10px] text-zinc-600 mb-0.5">VIA</div>
                      <span className={`text-xs uppercase font-bold ${VIA_COLOR[selected.confirmedVia ?? ""] ?? "text-zinc-400"}`}>
                        {selected.confirmedVia ?? "—"}
                      </span>
                    </div>
                  </div>
                </section>
              )}

              {/* exfil data */}
              {selected.exfilData && (
                <section>
                  <div className="text-[10px] text-zinc-600 uppercase mb-1">Exfiltrated Data / Response</div>
                  <pre className="bg-zinc-950 border border-zinc-900 p-2 text-[10px] text-lime-300 whitespace-pre-wrap break-all max-h-64 overflow-y-auto">
                    {selected.exfilData}
                  </pre>
                </section>
              )}

              {/* export single */}
              <section>
                <button
                  onClick={() => {
                    const blob = new Blob([JSON.stringify(selected, null, 2)], { type: "application/json" });
                    const a    = document.createElement("a");
                    a.href     = URL.createObjectURL(blob);
                    a.download = `nexus_run_${selected.id}.json`;
                    a.click();
                    URL.revokeObjectURL(a.href);
                  }}
                  className="px-3 py-1.5 text-[10px] uppercase bg-zinc-900 border border-zinc-700 text-zinc-400 hover:text-lime-400 hover:border-lime-800 transition-colors">
                  ↓ Export this run as JSON
                </button>
              </section>

            </div>
          </>
        )}
      </div>

    </div>
  );
}
