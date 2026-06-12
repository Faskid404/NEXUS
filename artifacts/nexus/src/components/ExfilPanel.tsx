import React, { useState, useEffect, useCallback, useRef } from "react";

const API_URL = (import.meta.env as Record<string,string>)["VITE_API_URL"] ?? "";

interface ExfilPayload {
  id:        string;
  name:      string;
  category:  string;
  technique: "dns"|"http"|"https"|"icmp"|"smb";
  os:        "linux"|"windows"|"any";
  command:   string;
  notes:     string;
}

interface TokenInfo { token: string; cbUrl: string; payloads: Record<string,string>; }

const TECH_META: Record<string, { color: string; border: string; bg: string; label: string }> = {
  dns:   { color:"text-cyan-400",  border:"border-cyan-800",  bg:"bg-cyan-950/20",  label:"DNS"   },
  http:  { color:"text-orange-400",border:"border-orange-800",bg:"bg-orange-950/20",label:"HTTP"  },
  https: { color:"text-lime-400",  border:"border-lime-800",  bg:"bg-lime-950/20",  label:"HTTPS" },
  icmp:  { color:"text-purple-400",border:"border-purple-800",bg:"bg-purple-950/20",label:"ICMP"  },
  smb:   { color:"text-blue-400",  border:"border-blue-800",  bg:"bg-blue-950/20",  label:"SMB"   },
};

const OS_COLORS: Record<string,string> = {
  linux:   "text-lime-500",
  windows: "text-blue-400",
  any:     "text-zinc-400",
};

const CATEGORY_ORDER = [
  "Recon","Credentials","Secrets","Cloud","Container","Privilege Escalation",
  "Network","Windows","Mass",
];

export default function ExfilPanel() {
  const [tokenInfo,  setTokenInfo]  = useState<TokenInfo|null>(null);
  const [payloads,   setPayloads]   = useState<ExfilPayload[]>([]);
  const [loading,    setLoading]    = useState(false);
  const [tokenLoad,  setTokenLoad]  = useState(false);
  const [copied,     setCopied]     = useState<string|null>(null);
  const [filter,     setFilter]     = useState("");
  const [techFilter, setTechFilter] = useState<"all"|"dns"|"http">("all");
  const [osFilter,   setOsFilter]   = useState<"all"|"linux"|"windows">("all");
  const [catFilter,  setCatFilter]  = useState("all");
  const [expanded,   setExpanded]   = useState<string|null>(null);
  const [manualCb,   setManualCb]   = useState("");
  const [manualTok,  setManualTok]  = useState("");
  const [useManual,  setUseManual]  = useState(false);
  const filterRef = useRef<HTMLInputElement>(null);

  /* ── auto-fetch OOB token ─────────────────────────────────────────────── */
  const fetchToken = useCallback(async () => {
    setTokenLoad(true);
    try {
      const r = await fetch(`${API_URL}/api/oob/token`);
      if (r.ok) setTokenInfo(await r.json() as TokenInfo);
    } catch { /* offline */ }
    finally { setTokenLoad(false); }
  }, []);

  useEffect(() => { void fetchToken(); }, [fetchToken]);

  /* ── generate exfil payloads ─────────────────────────────────────────── */
  const generate = useCallback(async () => {
    const cb  = useManual ? manualCb  : (tokenInfo?.cbUrl  ?? "");
    const tok = useManual ? manualTok : (tokenInfo?.token   ?? "");
    if (!cb || !tok) return;
    setLoading(true);
    setPayloads([]);
    try {
      const params = new URLSearchParams({ cbUrl: cb, token: tok, technique: "all" });
      const r = await fetch(`${API_URL}/api/hub/exfil?${params}`);
      if (r.ok) {
        const d = await r.json() as { payloads: ExfilPayload[] };
        setPayloads(d.payloads ?? []);
      }
    } catch { /* offline */ }
    finally { setLoading(false); }
  }, [tokenInfo, manualCb, manualTok, useManual]);

  /* Auto-generate when token ready */
  useEffect(() => {
    if (tokenInfo && !useManual) void generate();
  }, [tokenInfo]); // eslint-disable-line

  const copy = useCallback((text: string, id: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(id);
      setTimeout(() => setCopied(c => c === id ? null : c), 2000);
    }).catch(() => {});
  }, []);

  /* ── filtering ────────────────────────────────────────────────────────── */
  const filtered = payloads.filter(p => {
    if (techFilter !== "all" && p.technique !== techFilter) return false;
    if (osFilter !== "all" && p.os !== osFilter && p.os !== "any") return false;
    if (catFilter !== "all" && p.category !== catFilter) return false;
    if (filter) {
      const q = filter.toLowerCase();
      return p.name.toLowerCase().includes(q) ||
             p.category.toLowerCase().includes(q) ||
             p.command.toLowerCase().includes(q) ||
             p.notes.toLowerCase().includes(q);
    }
    return true;
  });

  /* Group by category */
  const grouped: Record<string, ExfilPayload[]> = {};
  filtered.forEach(p => {
    if (!grouped[p.category]) grouped[p.category] = [];
    grouped[p.category]!.push(p);
  });
  const sortedCats = Object.keys(grouped).sort((a, b) => {
    const ai = CATEGORY_ORDER.indexOf(a), bi = CATEGORY_ORDER.indexOf(b);
    return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
  });

  const activeCb  = useManual ? manualCb  : (tokenInfo?.cbUrl  ?? "");
  const activeTok = useManual ? manualTok : (tokenInfo?.token   ?? "");

  const allCategories = [...new Set(payloads.map(p => p.category))];

  return (
    <div className="flex flex-col h-full bg-black text-zinc-300 font-mono text-xs overflow-hidden">

      {/* Header */}
      <div className="flex items-center gap-3 px-3 py-1.5 bg-zinc-950 border-b border-zinc-900 shrink-0 flex-wrap">
        <span className="text-red-500 font-bold uppercase tracking-widest text-[11px]">EXFIL</span>
        <span className="text-zinc-700 text-[10px]">DNS · HTTP · AWS · K8S · Cloud Metadata · Mass Exfil — OOB-linked</span>
        <div className="ml-auto flex items-center gap-2">
          {tokenLoad && <span className="text-[9px] text-zinc-600 animate-pulse">fetching OOB token…</span>}
          {tokenInfo && !useManual && (
            <span className="text-[9px] text-lime-700 border border-lime-900/40 px-2 py-0.5">
              ● OOB LIVE
            </span>
          )}
          <button onClick={fetchToken} disabled={tokenLoad}
            className="text-[10px] px-2 py-0.5 border border-zinc-800 text-zinc-600 hover:border-zinc-600 hover:text-zinc-400 disabled:opacity-40 uppercase">
            REFRESH TOKEN
          </button>
        </div>
      </div>

      <div className="flex flex-1 min-h-0 overflow-hidden">

        {/* ── Left: config panel ──────────────────────────────────────────── */}
        <div className="w-64 shrink-0 border-r border-zinc-900 flex flex-col overflow-y-auto">
          <div className="p-3 space-y-3">

            {/* OOB token display */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <span className="text-[9px] text-red-400 uppercase font-bold">Active OOB Callback</span>
                <button onClick={() => setUseManual(u => !u)}
                  className="text-[8px] text-zinc-700 hover:text-zinc-400 uppercase">
                  {useManual ? "USE AUTO" : "MANUAL"}
                </button>
              </div>

              {useManual ? (
                <div className="space-y-1.5">
                  <input value={manualCb} onChange={e => setManualCb(e.target.value)}
                    placeholder="https://your-oob-host/api/oob/cb"
                    className="w-full bg-zinc-900 border border-zinc-800 focus:border-red-800 text-zinc-200 px-2 py-1 text-[9px] outline-none placeholder:text-zinc-700"/>
                  <input value={manualTok} onChange={e => setManualTok(e.target.value)}
                    placeholder="token string"
                    className="w-full bg-zinc-900 border border-zinc-800 focus:border-red-800 text-zinc-200 px-2 py-1 text-[9px] outline-none placeholder:text-zinc-700"/>
                </div>
              ) : (
                <div className="border border-zinc-900 bg-zinc-950/60 px-2 py-2 space-y-1">
                  {tokenInfo ? (
                    <>
                      <div className="flex items-start justify-between gap-1">
                        <span className="text-[8px] text-zinc-600 shrink-0 mt-0.5">URL</span>
                        <span className="text-[9px] text-cyan-400 break-all text-right">{tokenInfo.cbUrl}</span>
                      </div>
                      <div className="flex items-center justify-between gap-1">
                        <span className="text-[8px] text-zinc-600 shrink-0">TOKEN</span>
                        <span className="text-[9px] text-lime-500 font-bold truncate">{tokenInfo.token.slice(0,24)}…</span>
                      </div>
                    </>
                  ) : (
                    <span className="text-[9px] text-zinc-700">
                      {tokenLoad ? "Connecting to OOB listener…" : "OOB listener offline — use manual"}
                    </span>
                  )}
                </div>
              )}
            </div>

            <button onClick={generate} disabled={loading || (!activeCb || !activeTok)}
              className="w-full py-2 bg-red-950/40 border border-red-800/50 text-red-400 text-[11px] uppercase tracking-widest hover:bg-red-900/50 hover:border-red-600 disabled:opacity-40 transition-colors font-bold">
              {loading ? "GENERATING…" : "▶ GENERATE EXFIL"}
            </button>

            {/* Filters */}
            {payloads.length > 0 && (
              <>
                <div>
                  <label className="text-[9px] text-zinc-600 uppercase block mb-1">Technique</label>
                  <div className="grid grid-cols-3 gap-1">
                    {(["all","dns","http"] as const).map(t => (
                      <button key={t} onClick={() => setTechFilter(t)}
                        className={`py-1 text-[9px] uppercase border transition-colors
                          ${techFilter === t ? "border-red-700 text-red-400 bg-red-950/20" : "border-zinc-800 text-zinc-600 hover:border-zinc-600"}`}>
                        {t}
                      </button>
                    ))}
                  </div>
                </div>

                <div>
                  <label className="text-[9px] text-zinc-600 uppercase block mb-1">OS</label>
                  <div className="grid grid-cols-3 gap-1">
                    {(["all","linux","windows"] as const).map(o => (
                      <button key={o} onClick={() => setOsFilter(o)}
                        className={`py-1 text-[9px] uppercase border transition-colors
                          ${osFilter === o ? "border-red-700 text-red-400 bg-red-950/20" : "border-zinc-800 text-zinc-600 hover:border-zinc-600"}`}>
                        {o}
                      </button>
                    ))}
                  </div>
                </div>

                <div>
                  <label className="text-[9px] text-zinc-600 uppercase block mb-1">Category</label>
                  <select value={catFilter} onChange={e => setCatFilter(e.target.value)}
                    className="w-full bg-zinc-900 border border-zinc-800 text-zinc-300 text-[10px] px-2 py-1 outline-none focus:border-zinc-600">
                    <option value="all">All Categories</option>
                    {allCategories.map(c => <option key={c} value={c}>{c}</option>)}
                  </select>
                </div>

                <div>
                  <input ref={filterRef} value={filter} onChange={e => setFilter(e.target.value)}
                    placeholder="Search commands…"
                    className="w-full bg-zinc-950 border border-zinc-800 focus:border-zinc-600 text-zinc-300 text-[10px] px-2 py-1 placeholder-zinc-700 outline-none"/>
                </div>

                {/* Stats */}
                <div className="border border-zinc-900 bg-zinc-950/50 p-2 grid grid-cols-2 gap-1">
                  {[
                    ["Total",    payloads.length,                                    "text-red-400"],
                    ["Filtered", filtered.length,                                    "text-zinc-300"],
                    ["DNS",      payloads.filter(p=>p.technique==="dns").length,     "text-cyan-400"],
                    ["HTTP/S",   payloads.filter(p=>p.technique.startsWith("http")).length, "text-orange-400"],
                    ["Linux",    payloads.filter(p=>p.os==="linux").length,          "text-lime-400"],
                    ["Windows",  payloads.filter(p=>p.os==="windows").length,        "text-blue-400"],
                  ].map(([l,v,c]) => (
                    <div key={l as string} className="text-center">
                      <div className={`text-sm font-bold ${c}`}>{v}</div>
                      <div className="text-[8px] text-zinc-700 uppercase">{l}</div>
                    </div>
                  ))}
                </div>

                {/* Copy all filtered */}
                <button onClick={() => copy(filtered.map(p=>p.command).join('\n\n'), "__all__")}
                  className="w-full py-1.5 border border-zinc-800 text-zinc-600 text-[9px] uppercase hover:border-zinc-600 hover:text-zinc-400 transition-colors">
                  {copied === "__all__" ? "✓ Copied All" : `Copy ${filtered.length} Commands`}
                </button>
              </>
            )}
          </div>
        </div>

        {/* ── Right: payload list ────────────────────────────────────────── */}
        <div className="flex-1 overflow-y-auto">
          {payloads.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-zinc-700 gap-3">
              <span className="text-4xl">⇅</span>
              <div className="text-center">
                <div className="text-[12px] mb-1">OOB-Linked Exfiltration Generator</div>
                <div className="text-[10px] text-zinc-800 space-y-0.5">
                  <div>DNS: /etc/passwd · /etc/shadow · ENV · AWS · K8s · Windows</div>
                  <div>HTTP: AWS IMDSv2 · GCP/Azure metadata · Docker socket · LSASS · Chrome</div>
                  <div>All commands bind to your live OOB callback token</div>
                </div>
              </div>
              {!activeCb && (
                <div className="text-[10px] text-red-800 border border-red-900/30 bg-red-950/10 px-3 py-2">
                  OOB listener offline — switch to Manual mode or start the OOB panel
                </div>
              )}
            </div>
          ) : (
            <div className="pb-4">
              {sortedCats.map(cat => (
                <div key={cat}>
                  {/* Category header */}
                  <div className="sticky top-0 z-10 px-4 py-1.5 bg-zinc-950/95 border-b border-zinc-900 flex items-center gap-2">
                    <span className="text-[9px] text-zinc-500 uppercase font-bold tracking-widest">{cat}</span>
                    <span className="text-[8px] text-zinc-800">{grouped[cat]!.length} payloads</span>
                  </div>

                  {grouped[cat]!.map(p => {
                    const tm = TECH_META[p.technique] ?? TECH_META["http"]!;
                    return (
                      <div key={p.id}
                        className="border-b border-zinc-900/60 hover:bg-zinc-950/60 transition-colors">

                        {/* Row header */}
                        <div className="flex items-center gap-2 px-4 pt-2.5 pb-1 cursor-pointer"
                          onClick={() => setExpanded(e => e === p.id ? null : p.id)}>
                          <span className={`text-[8px] px-1.5 py-0.5 border uppercase shrink-0 font-bold ${tm.border} ${tm.color} ${tm.bg}`}>
                            {tm.label}
                          </span>
                          <span className={`text-[8px] uppercase shrink-0 ${OS_COLORS[p.os] ?? "text-zinc-500"}`}>
                            {p.os}
                          </span>
                          <span className="text-zinc-200 text-[11px] font-bold">{p.name}</span>
                          <div className="ml-auto flex items-center gap-1.5 shrink-0">
                            <button
                              onClick={e => { e.stopPropagation(); copy(p.command, p.id); }}
                              className={`text-[9px] px-2 py-0.5 border transition-colors
                                ${copied === p.id
                                  ? "border-lime-700 text-lime-400 bg-lime-950/20"
                                  : "border-zinc-800 text-zinc-600 hover:border-red-800 hover:text-red-400"}`}>
                              {copied === p.id ? "✓ COPIED" : "COPY"}
                            </button>
                          </div>
                        </div>

                        {/* Command block */}
                        <div className="px-4 pb-2">
                          <pre
                            className={`text-[10px] whitespace-pre-wrap break-all px-3 py-2 border font-mono cursor-pointer transition-colors
                              ${p.technique === "dns"
                                ? "text-cyan-300 bg-cyan-950/10 border-cyan-900/30"
                                : "text-orange-300 bg-orange-950/10 border-orange-900/30"}`}
                            onClick={() => copy(p.command, p.id)}>
                            {p.command}
                          </pre>

                          {expanded === p.id && (
                            <div className="mt-1.5 text-[10px] text-zinc-500 border-l-2 border-zinc-800 pl-2 leading-5">
                              {p.notes}
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
