import React, { useState, useCallback, useRef, useEffect } from "react";

const API_URL = (import.meta.env as Record<string, string>)["VITE_API_URL"] ?? "";
const AUTH_KEY = "nxauth_v7";

interface IronWormResult {
  id: string;
  name: string;
  target: string;
  category: string;
  status: "success" | "failed" | "info";
  detail: string;
  artifacts: string[];
  steps: string[];
  severity: "critical" | "high" | "medium" | "info";
}

const SEV_COLORS: Record<string, string> = {
  critical: "text-red-400 border-red-900 bg-red-950/30",
  high:     "text-orange-400 border-orange-900 bg-orange-950/20",
  medium:   "text-yellow-400 border-yellow-900 bg-yellow-950/20",
  info:     "text-zinc-400 border-zinc-800 bg-zinc-900/30",
};
const STATUS_BADGE: Record<string, string> = {
  success: "bg-red-900/60 text-red-300 border border-red-800",
  failed:  "bg-zinc-900 text-zinc-500 border border-zinc-700",
  info:    "bg-blue-950/60 text-blue-300 border border-blue-900",
};

function CollapsibleArtifact({ text }: { text: string }) {
  const [open, setOpen] = useState(false);
  const title = text.split("\n")[0]?.slice(0, 64) ?? "Artifact";
  return (
    <div className="border border-zinc-800 bg-black/40 rounded">
      <button onClick={() => setOpen(o => !o)}
        className="w-full text-left px-3 py-2 text-[10px] text-zinc-400 hover:text-zinc-200 tracking-widest uppercase flex items-center gap-2">
        <span className="text-red-700">{open ? "▾" : "▸"}</span>{title}
      </button>
      {open && (
        <pre className="px-3 pb-3 text-[10px] text-green-400 font-mono whitespace-pre-wrap break-all leading-relaxed border-t border-zinc-800 max-h-80 overflow-y-auto">
          {text}
        </pre>
      )}
    </div>
  );
}

export default function IronWormPanel() {
  const [packageName,     setPackageName]     = useState("");
  const [githubOrg,       setGithubOrg]       = useState("");
  const [githubRepo,      setGithubRepo]       = useState("");
  const [depConfusionOrg, setDepConfusionOrg] = useState("");
  const [cbHost,          setCbHost]          = useState("");
  const [cbPort,          setCbPort]          = useState("9999");
  const [mode, setMode] = useState<"full"|"npm"|"pip"|"dep"|"github"|"payloads">("full");
  const [running,  setRunning]  = useState(false);
  const [results,  setResults]  = useState<IronWormResult[]>([]);
  const [selected, setSelected] = useState<IronWormResult | null>(null);
  const [log,      setLog]      = useState<string[]>([]);
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [log]);

  const run = useCallback(async () => {
    if (running) return;
    setRunning(true);
    setResults([]);
    setSelected(null);
    setLog(["[IronWorm] Supply chain attack module initiated..."]);
    const token = sessionStorage.getItem(AUTH_KEY) ?? "";
    try {
      const body: Record<string, string> = { mode };
      if (packageName)     body.packageName     = packageName;
      if (githubOrg)       body.githubOrg       = githubOrg;
      if (githubRepo)      body.githubRepo      = githubRepo;
      if (depConfusionOrg) body.depConfusionOrg = depConfusionOrg;
      if (cbHost)          body.cbHost          = cbHost;
      if (cbPort)          body.cbPort          = cbPort;
      const res = await fetch(`${API_URL}/api/weapons/ironworm`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json() as { results: IronWormResult[] };
      setResults(data.results ?? []);
      setLog(prev => [...prev, `[IronWorm] ${data.results?.length ?? 0} attack artifacts generated`]);
    } catch (err) {
      setLog(prev => [...prev, `[IronWorm] ERROR: ${err}`]);
    } finally {
      setRunning(false);
    }
  }, [running, mode, packageName, githubOrg, githubRepo, depConfusionOrg, cbHost, cbPort]);

  const criticalCount = results.filter(r => r.severity === "critical" && r.status === "success").length;
  const successCount  = results.filter(r => r.status === "success").length;

  return (
    <div className="flex flex-col h-full bg-[#080808] text-white font-mono select-none">
      {/* Header */}
      <div className="border-b border-red-900/30 px-6 py-4 bg-black/40">
        <div className="flex items-center gap-3 mb-1">
          <div className="w-2 h-2 rounded-full bg-red-600 animate-pulse" />
          <span className="text-red-400 font-bold tracking-[.25em] uppercase text-sm">IronWorm</span>
          <span className="text-[9px] text-zinc-600 tracking-widest uppercase">Supply Chain Attack Module</span>
        </div>
        <p className="text-[9px] text-zinc-700 tracking-widest uppercase">
          npm typosquatting · pip poisoning · dep confusion · GitHub Actions injection · CI/CD secrets harvest
        </p>
      </div>

      <div className="flex flex-1 min-h-0">
        {/* Left: config */}
        <div className="w-64 border-r border-white/[.05] flex flex-col bg-black/20 overflow-y-auto">
          <div className="p-4 space-y-3">
            <div>
              <label className="text-[9px] text-zinc-600 uppercase tracking-widest block mb-1.5">Attack Mode</label>
              {(["full","npm","pip","dep","github","payloads"] as const).map(m => (
                <button key={m} onClick={() => setMode(m)}
                  className={`block w-full text-left text-[10px] px-3 py-1.5 border mb-1 uppercase tracking-widest transition-all ${mode===m ? "border-red-800 bg-red-950/30 text-red-400" : "border-zinc-800 text-zinc-600 hover:text-zinc-400"}`}>
                  {m === "full" ? "Full Scan" : m === "npm" ? "npm Typosquat" : m === "pip" ? "pip Typosquat" : m === "dep" ? "Dep Confusion" : m === "github" ? "GitHub Actions" : "Payload Gen"}
                </button>
              ))}
            </div>

            <div className="border-t border-white/[.04] pt-3 space-y-2">
              {[
                ["Target Package", packageName, setPackageName, "lodash / requests"],
                ["GitHub Org",     githubOrg,   setGithubOrg,   "org-name"],
                ["GitHub Repo",    githubRepo,  setGithubRepo,  "repo-name"],
                ["Internal Org",   depConfusionOrg, setDepConfusionOrg, "acmecorp"],
                ["Callback Host",  cbHost,      setCbHost,       "LHOST"],
                ["Callback Port",  cbPort,      setCbPort,       "9999"],
              ].map(([label, val, setter, ph]) => (
                <React.Fragment key={label as string}>
                  <label className="text-[9px] text-zinc-600 uppercase tracking-widest block mt-2">{label as string}</label>
                  <input value={val as string} onChange={e => (setter as (v:string)=>void)(e.target.value)}
                    placeholder={ph as string}
                    className="w-full bg-black/60 border border-white/[.07] text-white text-[10px] px-3 py-1.5 focus:outline-none focus:border-red-900/60 placeholder-zinc-700 tracking-wide" />
                </React.Fragment>
              ))}
            </div>

            <button onClick={run} disabled={running}
              className="w-full py-2.5 text-[10px] font-bold uppercase tracking-[.3em] border transition-all mt-2 disabled:opacity-40"
              style={{ background:running?"transparent":"rgba(220,38,38,.15)", borderColor:running?"rgba(255,255,255,.07)":"rgba(220,38,38,.5)", color:running?"#52525b":"#f87171" }}>
              {running
                ? <span className="flex items-center justify-center gap-2"><span className="w-3 h-3 border border-red-500 border-t-transparent rounded-full inline-block animate-spin"/>Scanning…</span>
                : "Launch IronWorm"}
            </button>

            {results.length > 0 && (
              <div className="border border-zinc-800 bg-black/40 p-3 space-y-1 text-[9px] text-zinc-500">
                <div className="flex justify-between"><span>Total</span><span className="text-zinc-300">{results.length}</span></div>
                <div className="flex justify-between"><span>Successful</span><span className="text-orange-400">{successCount}</span></div>
                <div className="flex justify-between"><span>Critical</span><span className="text-red-400">{criticalCount}</span></div>
              </div>
            )}
          </div>
        </div>

        {/* Center: results */}
        <div className="flex-1 flex flex-col min-w-0">
          {log.length > 0 && (
            <div ref={logRef} className="border-b border-white/[.04] bg-black/60 px-4 py-2 text-[9px] text-green-700 font-mono h-14 overflow-y-auto">
              {log.map((l, i) => <div key={i}>{l}</div>)}
            </div>
          )}
          <div className="flex-1 overflow-y-auto p-4 space-y-2">
            {results.length === 0 && !running && (
              <div className="flex flex-col items-center justify-center h-full text-zinc-700">
                <div className="text-4xl mb-3 opacity-30">⛓</div>
                <p className="text-[10px] uppercase tracking-widest">Configure target and launch IronWorm</p>
                <p className="text-[9px] mt-1 text-zinc-800 tracking-wide">npm typosquat · pip poison · dep confusion · CI injection</p>
              </div>
            )}
            {results.map(r => (
              <button key={r.id} onClick={() => setSelected(s => s?.id === r.id ? null : r)}
                className={`w-full text-left border p-3 transition-all ${selected?.id === r.id ? "border-red-800 bg-red-950/20" : "border-zinc-800 bg-black/20 hover:border-zinc-600"}`}>
                <div className="flex items-start gap-3">
                  <div className={`mt-0.5 px-1.5 py-0.5 text-[8px] uppercase tracking-widest font-bold border flex-shrink-0 ${SEV_COLORS[r.severity]}`}>
                    {r.severity}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="text-[10px] text-white font-bold truncate">{r.name}</span>
                      <span className={`text-[8px] px-1.5 py-0.5 font-bold uppercase tracking-widest flex-shrink-0 ${STATUS_BADGE[r.status]}`}>{r.status}</span>
                    </div>
                    <div className="text-[9px] text-zinc-500 truncate">{r.category} · {r.target}</div>
                    <div className="text-[9px] text-zinc-400 mt-1 line-clamp-2">{r.detail}</div>
                  </div>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Right: detail */}
        {selected && (
          <div className="w-96 border-l border-white/[.05] flex flex-col bg-black/20 overflow-y-auto">
            <div className="border-b border-white/[.04] px-4 py-3 bg-black/40">
              <div className="flex items-center justify-between mb-1">
                <span className={`text-[8px] px-1.5 py-0.5 font-bold uppercase tracking-widest ${SEV_COLORS[selected.severity]}`}>{selected.severity}</span>
                <button onClick={() => setSelected(null)} className="text-zinc-700 hover:text-zinc-400 text-xs">✕</button>
              </div>
              <div className="text-[11px] text-white font-bold">{selected.name}</div>
              <div className="text-[9px] text-zinc-600 mt-0.5">{selected.category} · {selected.target}</div>
            </div>
            <div className="p-4 space-y-4 flex-1">
              <div>
                <div className="text-[9px] text-zinc-600 uppercase tracking-widest mb-1.5">Summary</div>
                <p className="text-[10px] text-zinc-300 leading-relaxed">{selected.detail}</p>
              </div>
              {selected.steps.length > 0 && (
                <div>
                  <div className="text-[9px] text-zinc-600 uppercase tracking-widest mb-1.5">Execution Log</div>
                  <div className="bg-black/60 border border-zinc-800 p-3 max-h-48 overflow-y-auto">
                    {selected.steps.map((s, i) => (
                      <div key={i} className={`text-[9px] font-mono leading-relaxed ${s.includes("[!]")||s.includes("FREE")?"text-red-400":s.includes("OCCUPIED")?"text-zinc-500":"text-zinc-400"}`}>{s}</div>
                    ))}
                  </div>
                </div>
              )}
              {selected.artifacts.length > 0 && (
                <div>
                  <div className="text-[9px] text-zinc-600 uppercase tracking-widest mb-1.5">Attack Artifacts ({selected.artifacts.length})</div>
                  <div className="space-y-2">{selected.artifacts.map((a, i) => <CollapsibleArtifact key={i} text={a} />)}</div>
                </div>
              )}
              <button onClick={() => navigator.clipboard.writeText(selected.artifacts.join("\n\n---\n\n"))}
                className="w-full py-2 text-[9px] uppercase tracking-widest border border-zinc-800 hover:border-zinc-600 text-zinc-600 hover:text-zinc-300 transition-all">
                Copy All Artifacts
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
