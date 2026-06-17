import React, { useState, useCallback, useRef, useEffect } from "react";

const API_URL = (import.meta.env as Record<string, string>)["VITE_API_URL"] ?? "";
const AUTH_KEY = "nxauth_v7";

const KILL_CHAIN_PHASES = [
  { id: "access",  label: "Initial Access",    icon: "⚡", baseColor: "text-red-400",    activeCls: "border-red-800    bg-red-950/20    text-red-400",    doneCls: "border-green-900 bg-green-950/20 text-green-400" },
  { id: "lpe",     label: "Priv Escalation",   icon: "⬆", baseColor: "text-orange-400", activeCls: "border-orange-800 bg-orange-950/20 text-orange-400", doneCls: "border-green-900 bg-green-950/20 text-green-400" },
  { id: "persist", label: "Persistence",        icon: "⚓", baseColor: "text-yellow-400", activeCls: "border-yellow-800 bg-yellow-950/20 text-yellow-400", doneCls: "border-green-900 bg-green-950/20 text-green-400" },
  { id: "lateral", label: "Lateral Movement",   icon: "↔", baseColor: "text-purple-400", activeCls: "border-purple-800 bg-purple-950/20 text-purple-400", doneCls: "border-green-900 bg-green-950/20 text-green-400" },
] as const;

const MODULES = [
  { id: "npm",      label: "npm Typosquat",     desc: "25+ variants · registry check · malicious package.json",  phase: "access"  },
  { id: "pip",      label: "PyPI Typosquat",    desc: "PyPI variant check · malicious setup.py",                 phase: "access"  },
  { id: "dep",      label: "Dep Confusion",     desc: "Internal org packages · public npm race · version 9999",  phase: "lpe"     },
  { id: "github",   label: "GH Actions Inject", desc: "pwn-request · pull_request_target · GITHUB_TOKEN steal", phase: "persist" },
  { id: "payloads", label: "Payload Generator", desc: "postinstall · setup.py · git hooks · Makefile · Docker",  phase: "lateral" },
] as const;

type ModuleId = typeof MODULES[number]["id"];
type ModuleStatus = "idle" | "running" | "done" | "failed";

interface ModuleState { status: ModuleStatus; count: number; free: number; }

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

function artifactLabel(text: string): string {
  if (text.includes('"name":') && text.includes('"scripts"')) return "package.json";
  if (text.includes("setup(") || text.includes("setup.py")) return "setup.py";
  if (text.includes("pull_request_target") || (text.includes("on:") && text.includes("uses:"))) return "workflow.yml";
  if (text.includes("FROM ") && text.includes("RUN ")) return "Dockerfile";
  if (text.includes("[Makefile]") || text.match(/^install:/m)) return "Makefile";
  if (text.includes("#!/") && text.includes("curl")) return "shell payload";
  return text.split("\n")[0]?.slice(0, 48) ?? "artifact";
}

function CollapsibleArtifact({ text }: { text: string }) {
  const [open, setOpen] = useState(false);
  const label = artifactLabel(text);
  const typeColor =
    label === "package.json" ? "text-yellow-400" :
    label === "setup.py"     ? "text-blue-400"   :
    label === "workflow.yml" ? "text-purple-400"  :
    label === "Dockerfile"   ? "text-cyan-400"    :
    label === "Makefile"     ? "text-orange-400"  :
    "text-green-400";
  return (
    <div className="border border-zinc-800 bg-black/40 rounded">
      <button onClick={() => setOpen(o => !o)}
        className="w-full text-left px-3 py-2 text-[10px] hover:bg-zinc-900/40 flex items-center gap-2 tracking-wide">
        <span className="text-red-700">{open ? "▾" : "▸"}</span>
        <span className={`font-bold uppercase tracking-widest ${typeColor}`}>{label}</span>
        {!open && <span className="text-zinc-700 text-[9px] truncate ml-1">{text.slice(0, 60)}</span>}
      </button>
      {open && (
        <pre className={`px-3 pb-3 text-[10px] ${typeColor} font-mono whitespace-pre-wrap break-all leading-relaxed border-t border-zinc-800 max-h-80 overflow-y-auto`}>
          {text}
        </pre>
      )}
    </div>
  );
}

function ModuleStatusIcon({ status }: { status: ModuleStatus }) {
  if (status === "running") return <span className="w-3 h-3 border border-red-500 border-t-transparent rounded-full inline-block animate-spin" />;
  if (status === "done")    return <span className="text-green-400 text-[10px]">✓</span>;
  if (status === "failed")  return <span className="text-red-500 text-[10px]">✗</span>;
  return <span className="text-zinc-700 text-[10px]">·</span>;
}

function LogLine({ line }: { line: string }) {
  const color =
    line.includes("FREE") || line.includes("[!]") || line.includes("VULN") ? "text-red-400" :
    line.includes("✓") || line.includes("SUCCESS") ? "text-green-400" :
    line.includes("OCCUPIED") || line.includes("TAKEN") ? "text-zinc-600" :
    line.includes("[npm]")     ? "text-yellow-300" :
    line.includes("[pip]")     ? "text-blue-300"   :
    line.includes("[dep]")     ? "text-orange-300" :
    line.includes("[github]")  ? "text-purple-300" :
    line.includes("[payload]") ? "text-cyan-300"   :
    line.includes("ERROR")     ? "text-red-500"    :
    line.includes("IronWorm")  ? "text-red-700"    :
    "text-zinc-500";
  return <div className={`text-[9px] font-mono leading-relaxed ${color}`}>{line}</div>;
}

function emptyModuleStates(): Record<ModuleId, ModuleState> {
  return {
    npm:      { status: "idle", count: 0, free: 0 },
    pip:      { status: "idle", count: 0, free: 0 },
    dep:      { status: "idle", count: 0, free: 0 },
    github:   { status: "idle", count: 0, free: 0 },
    payloads: { status: "idle", count: 0, free: 0 },
  };
}

export default function IronWormPanel() {
  const [packageName,     setPackageName]     = useState("");
  const [githubOrg,       setGithubOrg]       = useState("");
  const [githubRepo,      setGithubRepo]       = useState("");
  const [depConfusionOrg, setDepConfusionOrg] = useState("");
  const [cbHost,          setCbHost]          = useState("");
  const [cbPort,          setCbPort]          = useState("9999");
  const [mode,      setMode]      = useState<"full"|"npm"|"pip"|"dep"|"github"|"payloads">("full");
  const [running,   setRunning]   = useState(false);
  const [results,   setResults]   = useState<IronWormResult[]>([]);
  const [selected,  setSelected]  = useState<IronWormResult | null>(null);
  const [log,       setLog]       = useState<string[]>([]);
  const [modStates, setModStates] = useState<Record<ModuleId, ModuleState>>(emptyModuleStates);
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [log]);

  function deriveModuleStates(items: IronWormResult[]) {
    const next = emptyModuleStates();
    for (const r of items) {
      const cat = r.category.toLowerCase();
      const key: ModuleId =
        cat.includes("npm")                          ? "npm"      :
        cat.includes("pip") || cat.includes("pypi")  ? "pip"      :
        cat.includes("dep") || cat.includes("confus") ? "dep"     :
        cat.includes("github") || cat.includes("action") ? "github" :
        "payloads";
      const ms = next[key];
      ms.status = "done";
      ms.count++;
      if (r.status === "success") ms.free++;
    }
    setModStates(next);
  }

  const ts = () => new Date().toISOString().slice(11, 19);

  const run = useCallback(async () => {
    if (running) return;
    setRunning(true);
    setResults([]);
    setSelected(null);
    setModStates(emptyModuleStates());

    const modulesToRun = mode === "full" ? MODULES.map(m => m.id) : [mode];
    const initLog = [
      `[${ts()}] IronWorm supply chain attack module initiated`,
      `[${ts()}] mode=${mode}  package=${packageName || "(none)"}  C2=${cbHost || "(none)"}:${cbPort}`,
      ...modulesToRun.map(m => {
        const mod = MODULES.find(x => x.id === m)!;
        return `[${ts()}] [${m}] queued — ${mod.desc}`;
      }),
      `[${ts()}] Sending request to backend…`,
    ];
    setLog(initLog);

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
      const items = data.results ?? [];
      setResults(items);
      deriveModuleStates(items);

      const freeCount = items.filter(r => r.status === "success").length;
      const critCount = items.filter(r => r.severity === "critical" && r.status === "success").length;

      setLog(prev => [
        ...prev,
        `[${ts()}] Scan complete — ${items.length} artifact${items.length !== 1 ? "s" : ""} generated`,
        critCount > 0
          ? `[${ts()}] [!] ${freeCount} exploitable vectors found — ${critCount} CRITICAL`
          : `[${ts()}] ${freeCount} exploitable vectors found`,
        ...items.filter(r => r.status === "success").map(r =>
          `[${ts()}] [!] FREE SLOT → ${r.name}  (${r.severity})`
        ),
      ]);
    } catch (err) {
      setLog(prev => [...prev, `[${ts()}] ERROR: ${String(err)}`]);
    } finally {
      setRunning(false);
    }
  }, [running, mode, packageName, githubOrg, githubRepo, depConfusionOrg, cbHost, cbPort]);

  const totalFree    = Object.values(modStates).reduce((a, s) => a + s.free, 0);
  const criticalCount = results.filter(r => r.severity === "critical" && r.status === "success").length;
  const doneModCount  = Object.values(modStates).filter(s => s.status === "done").length;
  const phaseProgress = results.length > 0 ? Math.min(4, Math.ceil(doneModCount / MODULES.length * 4)) : 0;

  const fields: [string, string, (v: string) => void, string][] = [
    ["Target Package", packageName,     setPackageName,     "lodash / requests"],
    ["GitHub Org",     githubOrg,       setGithubOrg,       "org-name"],
    ["GitHub Repo",    githubRepo,      setGithubRepo,      "repo-name"],
    ["Internal Org",   depConfusionOrg, setDepConfusionOrg, "acmecorp"],
    ["Callback Host",  cbHost,          setCbHost,          "LHOST"],
    ["Callback Port",  cbPort,          setCbPort,          "9999"],
  ];

  return (
    <div className="flex flex-col h-full bg-[#080808] text-white font-mono select-none">

      {/* ── Header ── */}
      <div className="border-b border-red-900/30 px-6 py-3 bg-black/40 shrink-0">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-3">
            <div className="w-2 h-2 rounded-full bg-red-600 animate-pulse" />
            <span className="text-red-400 font-bold tracking-[.25em] uppercase text-sm">IronWorm</span>
            <span className="text-[9px] text-zinc-600 tracking-widest uppercase">Supply Chain Attack Module</span>
          </div>
          {results.length > 0 && (
            <div className="flex items-center gap-5 text-[9px]">
              <span className="text-zinc-600">TOTAL <span className="text-zinc-300">{results.length}</span></span>
              <span className="text-zinc-600">FREE  <span className="text-orange-400">{totalFree}</span></span>
              <span className="text-zinc-600">CRIT  <span className="text-red-400">{criticalCount}</span></span>
            </div>
          )}
        </div>

        {/* Kill-chain phase bar */}
        <div className="flex items-center gap-1">
          {KILL_CHAIN_PHASES.map((phase, i) => {
            const isDone   = phaseProgress > i;
            const isActive = running && phaseProgress === i;
            const cls = isDone ? phase.doneCls : isActive ? `${phase.activeCls} animate-pulse` : "border-zinc-900 text-zinc-700";
            return (
              <React.Fragment key={phase.id}>
                <div className={`flex items-center gap-1 px-2 py-1 border text-[9px] transition-all ${cls}`}>
                  <span>{phase.icon}</span>
                  <span className="uppercase tracking-wider hidden sm:inline">{phase.label}</span>
                </div>
                {i < KILL_CHAIN_PHASES.length - 1 && (
                  <span className={`text-[9px] ${isDone ? "text-green-700" : "text-zinc-800"}`}>→</span>
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>

      <div className="flex flex-1 min-h-0">

        {/* ── Left: Config + Module Tracker ── */}
        <div className="w-56 border-r border-white/[.05] flex flex-col bg-black/20 overflow-y-auto shrink-0">
          <div className="p-4 space-y-3">

            {/* Attack mode selector */}
            <div>
              <label className="text-[9px] text-zinc-600 uppercase tracking-widest block mb-1.5">Attack Mode</label>
              {(["full","npm","pip","dep","github","payloads"] as const).map(m => (
                <button key={m} onClick={() => setMode(m)}
                  className={`block w-full text-left text-[10px] px-3 py-1.5 border mb-1 uppercase tracking-widest transition-all ${mode === m ? "border-red-800 bg-red-950/30 text-red-400" : "border-zinc-800 text-zinc-600 hover:text-zinc-400"}`}>
                  {m === "full" ? "Full Scan" : m === "npm" ? "npm Typosquat" : m === "pip" ? "PyPI Typosquat" : m === "dep" ? "Dep Confusion" : m === "github" ? "GH Actions Inject" : "Payload Gen"}
                </button>
              ))}
            </div>

            {/* Input fields */}
            <div className="border-t border-white/[.04] pt-3 space-y-2">
              {fields.map(([label, val, setter, ph]) => (
                <React.Fragment key={label}>
                  <label className="text-[9px] text-zinc-600 uppercase tracking-widest block mt-2">{label}</label>
                  <input value={val} onChange={e => setter(e.target.value)} placeholder={ph}
                    className="w-full bg-black/60 border border-white/[.07] text-white text-[10px] px-3 py-1.5 focus:outline-none focus:border-red-900/60 placeholder-zinc-700 tracking-wide" />
                </React.Fragment>
              ))}
            </div>

            {/* Launch button */}
            <button onClick={run} disabled={running}
              className="w-full py-2.5 text-[10px] font-bold uppercase tracking-[.3em] border transition-all mt-2 disabled:opacity-40"
              style={{ background: running ? "transparent" : "rgba(220,38,38,.15)", borderColor: running ? "rgba(255,255,255,.07)" : "rgba(220,38,38,.5)", color: running ? "#52525b" : "#f87171" }}>
              {running
                ? <span className="flex items-center justify-center gap-2"><span className="w-3 h-3 border border-red-500 border-t-transparent rounded-full inline-block animate-spin"/>Scanning…</span>
                : "Launch IronWorm"}
            </button>

            {/* Module status tracker */}
            <div className="border border-zinc-900 bg-black/40 divide-y divide-zinc-900">
              <div className="px-3 py-1.5 text-[9px] text-zinc-600 uppercase tracking-widest">Module Status</div>
              {MODULES.map(mod => {
                const ms = modStates[mod.id];
                return (
                  <div key={mod.id} className="px-3 py-2 flex items-center justify-between gap-2">
                    <div className="min-w-0">
                      <div className="text-[9px] text-zinc-400 truncate">{mod.label}</div>
                      {ms.count > 0 && <div className="text-[8px] text-zinc-600">{ms.free}/{ms.count} free</div>}
                    </div>
                    <ModuleStatusIcon status={ms.status} />
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* ── Center: Streaming Log + Results ── */}
        <div className="flex-1 flex flex-col min-w-0">

          {/* Log panel */}
          <div
            ref={logRef}
            className="border-b border-white/[.04] bg-black/80 px-4 py-3 overflow-y-auto shrink-0 transition-all"
            style={{ height: results.length === 0 ? "100%" : "8rem" }}
          >
            {log.length === 0 && !running && (
              <div className="flex flex-col items-center justify-center h-full text-zinc-700 gap-3">
                <div className="text-4xl opacity-20">⛓</div>
                <p className="text-[10px] uppercase tracking-widest">Configure target and launch IronWorm</p>
                <p className="text-[9px] text-zinc-800 tracking-wide">npm typosquat · pip poison · dep confusion · CI injection</p>
              </div>
            )}
            {log.map((l, i) => <LogLine key={i} line={l} />)}
            {running && <div className="text-[9px] text-red-700 animate-pulse mt-1">● scanning…</div>}
          </div>

          {/* Results list */}
          {results.length > 0 && (
            <div className="flex-1 overflow-y-auto p-3 space-y-2">
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
                      {r.artifacts.length > 0 && (
                        <div className="text-[8px] text-zinc-600 mt-1">{r.artifacts.length} artifact{r.artifacts.length !== 1 ? "s" : ""}</div>
                      )}
                    </div>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* ── Right: Detail panel ── */}
        {selected && (
          <div className="w-96 border-l border-white/[.05] flex flex-col bg-black/20 overflow-y-auto shrink-0">
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
                      <div key={i} className={`text-[9px] font-mono leading-relaxed ${s.includes("[!]") || s.includes("FREE") ? "text-red-400" : s.includes("OCCUPIED") ? "text-zinc-500" : "text-zinc-400"}`}>{s}</div>
                    ))}
                  </div>
                </div>
              )}

              {selected.artifacts.length > 0 && (
                <div>
                  <div className="text-[9px] text-zinc-600 uppercase tracking-widest mb-1.5">Attack Artifacts ({selected.artifacts.length})</div>
                  <div className="space-y-2">
                    {selected.artifacts.map((a, i) => <CollapsibleArtifact key={i} text={a} />)}
                  </div>
                </div>
              )}

              <div className="flex gap-2 pt-1">
                <button onClick={() => navigator.clipboard.writeText(selected.artifacts.join("\n\n---\n\n"))}
                  className="flex-1 py-2 text-[9px] uppercase tracking-widest border border-zinc-800 hover:border-zinc-600 text-zinc-600 hover:text-zinc-300 transition-all">
                  Copy All Artifacts
                </button>
                <button onClick={() => navigator.clipboard.writeText(JSON.stringify(selected, null, 2))}
                  className="py-2 px-3 text-[9px] uppercase tracking-widest border border-zinc-800 hover:border-zinc-600 text-zinc-600 hover:text-zinc-300 transition-all">
                  JSON
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
