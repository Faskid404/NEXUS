import React, { useState, useCallback } from "react";

const API_URL = (import.meta.env as Record<string,string>)["VITE_API_URL"] ?? "";

interface PersistPayload {
  technique: string;
  category:  string;
  stealth:   number;
  command:   string;
  notes:     string;
}

const STEALTH_LABEL: Record<number, { label: string; color: string }> = {
  1: { label: "OBVIOUS",   color: "text-red-400" },
  2: { label: "LOW",       color: "text-orange-400" },
  3: { label: "MEDIUM",    color: "text-yellow-400" },
  4: { label: "HIGH",      color: "text-lime-400" },
  5: { label: "COVERT",    color: "text-emerald-400" },
};

export default function PersistencePanel() {
  const [lhost,    setLhost]    = useState("127.0.0.1");
  const [lport,    setLport]    = useState("4444");
  const [cmd,      setCmd]      = useState("id");
  const [os,       setOs]       = useState<"linux"|"windows">("linux");
  const [payloads, setPayloads] = useState<PersistPayload[]>([]);
  const [loading,  setLoading]  = useState(false);
  const [copied,   setCopied]   = useState<string|null>(null);
  const [expanded, setExpanded] = useState<string|null>(null);
  const [minStealth, setMinStealth] = useState(1);

  const generate = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ lhost, lport, cmd });
      const r = await fetch(`${API_URL}/api/hub/persist/${os}?${params}`);
      const d = await r.json() as { payloads: PersistPayload[] };
      setPayloads(d.payloads ?? []);
    } catch { /**/ }
    setLoading(false);
  }, [lhost, lport, cmd, os]);

  const copy = useCallback((text: string, id: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(id); setTimeout(() => setCopied(c => c === id ? null : c), 1800);
    }).catch(() => {});
  }, []);

  const filtered = payloads.filter(p => p.stealth >= minStealth);

  return (
    <div className="flex flex-col h-full bg-black text-zinc-300 font-mono text-xs overflow-hidden">

      {/* Header */}
      <div className="flex items-center gap-3 px-3 py-1.5 bg-zinc-950 border-b border-zinc-900 shrink-0">
        <span className="text-rose-500 font-bold uppercase tracking-widest text-[11px]">PERSISTENCE</span>
        <span className="text-zinc-700 text-[10px]">post-exploitation · cron · systemd · registry · WMI · fileless</span>
        <span className="ml-auto text-zinc-700 text-[10px]">{filtered.length} mechanisms</span>
      </div>

      <div className="flex flex-1 min-h-0 overflow-hidden">

        {/* Left: config */}
        <div className="w-64 shrink-0 border-r border-zinc-900 flex flex-col overflow-y-auto">
          <div className="p-3 space-y-2.5">
            <div className="text-[10px] text-rose-400 uppercase mb-1">Configuration</div>

            {/* OS toggle */}
            <div className="grid grid-cols-2 gap-1">
              {(["linux","windows"] as const).map(o => (
                <button key={o} onClick={() => { setOs(o); setPayloads([]); }}
                  className={`py-2 text-[10px] uppercase border font-bold transition-colors
                    ${os === o
                      ? o === "linux"
                        ? "border-lime-700 text-lime-400 bg-lime-950/20"
                        : "border-blue-700 text-blue-400 bg-blue-950/20"
                      : "border-zinc-800 text-zinc-600 hover:border-zinc-600 hover:text-zinc-400"}`}>
                  {o}
                </button>
              ))}
            </div>

            <div>
              <label className="text-[9px] text-zinc-600 uppercase block mb-0.5">Attacker LHOST</label>
              <input value={lhost} onChange={e => setLhost(e.target.value)}
                placeholder="10.10.14.5"
                className="w-full bg-zinc-900 border border-zinc-800 focus:border-rose-800 text-zinc-200 px-2 py-1 text-[10px] outline-none placeholder:text-zinc-700"/>
            </div>

            <div>
              <label className="text-[9px] text-zinc-600 uppercase block mb-0.5">LPORT</label>
              <input value={lport} onChange={e => setLport(e.target.value)}
                placeholder="4444" type="number"
                className="w-full bg-zinc-900 border border-zinc-800 focus:border-rose-800 text-zinc-200 px-2 py-1 text-[10px] outline-none"/>
            </div>

            <div>
              <label className="text-[9px] text-zinc-600 uppercase block mb-0.5">
                {os === "linux" ? "Command / Payload" : "Payload Path / Command"}
              </label>
              <input value={cmd} onChange={e => setCmd(e.target.value)}
                placeholder={os === "linux" ? "bash -i >& /dev/tcp/..." : "calc.exe"}
                className="w-full bg-zinc-900 border border-zinc-800 focus:border-rose-800 text-zinc-200 px-2 py-1 text-[10px] outline-none placeholder:text-zinc-700"/>
            </div>

            {/* Min stealth filter */}
            <div>
              <div className="flex justify-between items-center mb-1">
                <label className="text-[9px] text-zinc-600 uppercase">Min Stealth Level</label>
                <span className={`text-[9px] font-bold ${STEALTH_LABEL[minStealth]?.color}`}>
                  {STEALTH_LABEL[minStealth]?.label}
                </span>
              </div>
              <input type="range" min={1} max={5} value={minStealth} onChange={e => setMinStealth(+e.target.value)}
                className="w-full accent-rose-600"/>
              <div className="flex justify-between text-[8px] text-zinc-800 mt-0.5">
                <span>Obvious</span><span>Covert</span>
              </div>
            </div>

            <button onClick={generate} disabled={loading}
              className="w-full py-2 bg-rose-950/40 border border-rose-800/50 text-rose-400 text-[11px] uppercase tracking-widest hover:bg-rose-900/50 hover:text-rose-300 hover:border-rose-600 disabled:opacity-40 transition-colors font-bold">
              {loading ? "LOADING…" : "▶ GENERATE"}
            </button>

            {/* Stealth legend */}
            {payloads.length > 0 && (
              <div className="border border-zinc-900 bg-zinc-950/50 p-2 space-y-1">
                <div className="text-[9px] text-zinc-600 uppercase mb-1">Stealth Scale</div>
                {Object.entries(STEALTH_LABEL).map(([k, v]) => (
                  <div key={k} className="flex items-center gap-2">
                    <span className={`text-[9px] font-bold w-16 ${v.color}`}>{v.label}</span>
                    <div className="flex gap-0.5">
                      {Array.from({length:5},(_,i)=>(
                        <div key={i} className={`w-2 h-2 rounded-sm ${i < +k ? v.color.replace("text-","bg-") : "bg-zinc-900"}`}/>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right: persistence list */}
        <div className="flex-1 overflow-y-auto">
          {payloads.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-zinc-700 gap-2">
              <span className="text-3xl">⚡</span>
              <span className="text-[11px]">Generate persistence mechanisms for your target</span>
              <span className="text-[10px] text-zinc-800">cron · systemd · registry · WMI · SUID · LD_PRELOAD · and more</span>
            </div>
          ) : (
            <div className="divide-y divide-zinc-900">
              {filtered.map((p, i) => {
                const s   = STEALTH_LABEL[p.stealth]!;
                const key = `${i}`;
                return (
                  <div key={i}
                    onClick={() => setExpanded(e => e === key ? null : key)}
                    className="px-4 py-3 hover:bg-zinc-950 cursor-pointer transition-colors">

                    <div className="flex items-center gap-2 mb-1.5">
                      {/* Stealth dots */}
                      <div className="flex gap-0.5 shrink-0">
                        {Array.from({length:5},(_,di)=>(
                          <div key={di} className={`w-1.5 h-1.5 rounded-sm ${di < p.stealth ? s.color.replace("text-","bg-") : "bg-zinc-900"}`}/>
                        ))}
                      </div>
                      <span className={`text-[8px] uppercase font-bold ${s.color}`}>{s.label}</span>
                      <span className="text-zinc-200 text-[11px] font-bold ml-1">{p.technique}</span>
                      <button
                        onClick={e => { e.stopPropagation(); copy(p.command, key); }}
                        className="ml-auto text-[9px] text-zinc-600 hover:text-rose-400 border border-zinc-800 hover:border-rose-800 px-2 py-0.5 shrink-0 transition-colors">
                        {copied === key ? "✓ COPIED" : "COPY"}
                      </button>
                    </div>

                    <pre className="text-[10px] text-rose-300 whitespace-pre-wrap break-all bg-zinc-950/80 border border-zinc-900 px-3 py-2 font-mono">
                      {p.command}
                    </pre>

                    {expanded === key && (
                      <div className="mt-1.5 text-[10px] text-zinc-500 border-l-2 border-zinc-800 pl-2">
                        ℹ {p.notes}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
