import React, { useState, useCallback, useEffect } from "react";

const API_URL = (import.meta.env as Record<string,string>)["VITE_API_URL"] ?? "";

interface InjLog    { id:number; timestamp:string; command:string; engine:string; mode:string; responseTime:number; }
interface ChainStep { step:number; service:string; port:number; action:string; result:string; status:string; elapsed:number; }
interface ChainRun  { id:string; target:string; startedAt:string; finishedAt?:string; steps:ChainStep[]; }
interface OobHit    { id:string; ts:number; type:string; method:string; sourceIp:string; data:string; token:string; }

function buildMarkdown(logs: InjLog[], chains: ChainRun[], oob: OobHit[], title: string): string {
  const date       = new Date().toUTCString();
  const succChains = chains.filter(c => c.steps.some(s => s.status === "success"));
  const modes      = [...new Set(logs.map(l => l.mode))];
  const avgRt      = logs.length ? Math.round(logs.reduce((s,l)=>s+l.responseTime,0)/logs.length) : 0;

  let md = `# ${title}\n\n**Generated:** ${date}  \n**Platform:** NEXUSFORGE v9.0.0\n\n---\n\n`;
  md += `## Executive Summary\n\n`;
  md += `| Metric | Value |\n|---|---|\n`;
  md += `| Total Injections | ${logs.length} |\n`;
  md += `| Exploit Chains | ${chains.length} |\n`;
  md += `| Confirmed Chains | ${succChains.length} |\n`;
  md += `| OOB Callbacks | ${oob.length} |\n`;
  md += `| Unique Modes | ${modes.length} |\n`;
  md += `| Avg Response Time | ${avgRt}ms |\n\n`;

  if (succChains.length) {
    md += `## Confirmed Attack Chains\n\n`;
    succChains.forEach(c => {
      md += `### Chain \`${c.id.slice(0,8)}\` — Target: ${c.target}\n`;
      md += `**Started:** ${c.startedAt}\n\n`;
      md += `| Step | Service | Port | Action | Status | Elapsed |\n|---|---|---|---|---|---|\n`;
      c.steps.forEach(s => {
        md += `| ${s.step} | ${s.service} | ${s.port||"—"} | ${s.action} | **${s.status.toUpperCase()}** | ${s.elapsed}ms |\n`;
      });
      md += `\n`;
    });
  }

  if (oob.length) {
    md += `## OOB Callback Log\n\n`;
    oob.slice(0, 30).forEach((h, i) => {
      md += `### Hit ${i+1} — ${new Date(h.ts).toISOString()}\n`;
      md += `- **Source IP:** \`${h.sourceIp}\`\n- **Method:** ${h.method}\n- **Token:** \`${h.token}\`\n`;
      if (h.data) md += `- **Exfiltrated:**\n\`\`\`\n${h.data.slice(0,400)}\n\`\`\`\n`;
      md += `\n`;
    });
  }

  if (logs.length) {
    md += `## Injection Log (${Math.min(logs.length,100)} of ${logs.length})\n\n`;
    md += `| # | Timestamp | Mode | Engine | Command | RT |\n|---|---|---|---|---|---|\n`;
    logs.slice(0,100).forEach(l => {
      md += `| ${l.id} | ${new Date(l.timestamp).toISOString()} | \`${l.mode}\` | ${l.engine} | \`${l.command.slice(0,40).replace(/`/g,"'")}\` | ${l.responseTime}ms |\n`;
    });
    if (logs.length > 100) md += `\n_...${logs.length-100} more entries omitted_\n`;
    md += `\n`;
  }

  if (modes.length) {
    md += `## Modes Exercised\n\n${modes.map(m=>`- \`${m}\``).join("\n")}\n\n`;
  }

  md += `---\n_NEXUSFORGE Security Assessment · Authorized Research Only_\n`;
  return md;
}

export default function ReportPanel() {
  const [logs,    setLogs]    = useState<InjLog[]>([]);
  const [chains,  setChains]  = useState<ChainRun[]>([]);
  const [oob,     setOob]     = useState<OobHit[]>([]);
  const [loading, setLoading] = useState(false);
  const [loaded,  setLoaded]  = useState(false);
  const [title,   setTitle]   = useState("NEXUSFORGE Security Assessment Report");
  const [copied,  setCopied]  = useState(false);

  const fetchAll = useCallback(async () => {
    setLoading(true);
    try {
      const [lr, cr, or_] = await Promise.all([
        fetch(`${API_URL}/api/logs?limit=500`),
        fetch(`${API_URL}/api/chainlog`),
        fetch(`${API_URL}/api/oob/hits`),
      ]);
      setLogs(lr.ok    ? await lr.json()  as InjLog[]   : []);
      setChains(cr.ok  ? await cr.json()  as ChainRun[] : []);
      const od = or_.ok ? await or_.json() as {hits?:OobHit[]}|OobHit[] : [];
      setOob(Array.isArray(od) ? od : (od as {hits?:OobHit[]}).hits ?? []);
      setLoaded(true);
    } catch { setLoaded(true); }
    setLoading(false);
  }, []);

  useEffect(() => { void fetchAll(); }, [fetchAll]);

  const markdown = buildMarkdown(logs, chains, oob, title);

  const dl = (content: string, name: string, type: string) => {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([content], {type}));
    a.download = name;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const succChains = chains.filter(c => c.steps.some(s => s.status === "success"));
  const avgRt      = logs.length ? Math.round(logs.reduce((s,l)=>s+l.responseTime,0)/logs.length) : 0;
  const modes      = [...new Set(logs.map(l => l.mode))];
  const modeCount: Record<string,number> = {};
  logs.forEach(l => { modeCount[l.mode] = (modeCount[l.mode]??0)+1; });

  return (
    <div className="flex flex-col h-full bg-black text-zinc-300 font-mono text-xs overflow-hidden">

      <div className="flex items-center gap-3 px-3 py-1.5 bg-zinc-950 border-b border-zinc-900 shrink-0">
        <span className="text-lime-500 font-bold uppercase tracking-widest text-[11px]">REPORT GENERATOR</span>
        <span className="text-zinc-700 text-[10px]">compile findings · export markdown / JSON</span>
        <div className="ml-auto">
          <button onClick={fetchAll} disabled={loading}
            className="text-[10px] px-2 py-0.5 border border-zinc-800 text-zinc-600 hover:border-zinc-600 hover:text-zinc-400 disabled:opacity-40 uppercase">
            {loading ? "LOADING…" : "REFRESH"}
          </button>
        </div>
      </div>

      <div className="flex flex-1 min-h-0 overflow-hidden">

        {/* Left panel */}
        <div className="w-72 shrink-0 border-r border-zinc-900 flex flex-col overflow-y-auto">
          <div className="p-3 space-y-3">
            <div className="text-[10px] text-lime-400 uppercase">Report Settings</div>

            <div>
              <label className="text-[9px] text-zinc-600 uppercase block mb-0.5">Report Title</label>
              <input value={title} onChange={e => setTitle(e.target.value)}
                className="w-full bg-zinc-900 border border-zinc-800 focus:border-lime-800 text-zinc-200 px-2 py-1 text-[10px] outline-none"/>
            </div>

            {/* Stats grid */}
            {loaded && (
              <div className="grid grid-cols-2 gap-1 border border-zinc-900 bg-zinc-950/50 p-2">
                {([
                  ["Injections",   logs.length,        "text-lime-400"],
                  ["Chains",       chains.length,       "text-cyan-400"],
                  ["Confirmed",    succChains.length,   "text-green-400"],
                  ["OOB Hits",     oob.length,          "text-orange-400"],
                  ["Modes Used",   modes.length,        "text-purple-400"],
                  ["Avg RT",       `${avgRt}ms`,        "text-yellow-400"],
                ] as [string,string|number,string][]).map(([label, val, col]) => (
                  <div key={label} className="text-center p-1.5 border border-zinc-900">
                    <div className={`text-base font-bold ${col}`}>{val}</div>
                    <div className="text-[8px] text-zinc-700 uppercase mt-0.5">{label}</div>
                  </div>
                ))}
              </div>
            )}

            {/* Export buttons */}
            <div className="space-y-1.5">
              <div className="text-[9px] text-zinc-600 uppercase">Export</div>
              <button onClick={() => dl(markdown, `nexus_report_${Date.now()}.md`, "text/markdown")}
                disabled={!loaded}
                className="w-full py-2 border border-lime-900/60 text-lime-500 text-[10px] uppercase tracking-wider hover:bg-lime-950/20 hover:border-lime-700 disabled:opacity-40 transition-colors">
                ↓ Download Markdown Report
              </button>
              <button onClick={() => dl(JSON.stringify({logs,chains,oob,generatedAt:new Date().toISOString()},null,2), `nexus_data_${Date.now()}.json`, "application/json")}
                disabled={!loaded}
                className="w-full py-2 border border-cyan-900/60 text-cyan-500 text-[10px] uppercase tracking-wider hover:bg-cyan-950/20 hover:border-cyan-700 disabled:opacity-40 transition-colors">
                ↓ Download JSON Data
              </button>
              <button onClick={() => { navigator.clipboard.writeText(markdown).then(()=>{setCopied(true);setTimeout(()=>setCopied(false),2000)}).catch(()=>{}); }}
                disabled={!loaded}
                className="w-full py-2 border border-zinc-800 text-zinc-500 text-[10px] uppercase tracking-wider hover:bg-zinc-900 disabled:opacity-40 transition-colors">
                {copied ? "✓ Copied to Clipboard" : "Copy Markdown"}
              </button>
            </div>

            {/* Top modes chart */}
            {logs.length > 0 && (
              <div>
                <div className="text-[9px] text-zinc-600 uppercase mb-1.5">Top Modes</div>
                {Object.entries(modeCount).sort((a,b)=>b[1]-a[1]).slice(0,8).map(([mode, count]) => (
                  <div key={mode} className="flex items-center gap-2 mb-1">
                    <div className="text-[9px] text-zinc-400 w-20 truncate uppercase">{mode}</div>
                    <div className="flex-1 h-1 bg-zinc-900 rounded overflow-hidden">
                      <div className="h-full bg-lime-700 rounded transition-all" style={{width:`${(count/logs.length)*100}%`}}/>
                    </div>
                    <div className="text-[9px] text-zinc-600 w-6 text-right">{count}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right: markdown preview */}
        <div className="flex-1 overflow-y-auto p-4">
          {!loaded
            ? <div className="flex items-center justify-center h-32 text-zinc-700">Loading assessment data…</div>
            : <pre className="text-[10px] text-zinc-400 whitespace-pre-wrap break-words leading-5">{markdown}</pre>
          }
        </div>
      </div>
    </div>
  );
}
