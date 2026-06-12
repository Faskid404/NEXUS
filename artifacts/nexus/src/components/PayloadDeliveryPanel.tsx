import React, { useState, useCallback } from "react";

const API_URL = (import.meta.env as Record<string,string>)["VITE_API_URL"] ?? "";

interface DeliveryPayload { name: string; os: string; command: string; notes: string; }
interface DeliveryResponse { payloads: DeliveryPayload[]; }

const OS_OPTS = [
  { value: "linux",   label: "Linux",   color: "text-lime-400",   border: "border-lime-800",  bg: "bg-lime-950/20" },
  { value: "windows", label: "Windows", color: "text-blue-400",   border: "border-blue-800",  bg: "bg-blue-950/20" },
  { value: "any",     label: "Cross-OS",color: "text-purple-400", border: "border-purple-800",bg: "bg-purple-950/20" },
  { value: "all",     label: "All",     color: "text-zinc-300",   border: "border-zinc-700",  bg: "bg-zinc-900/30" },
];

export default function PayloadDeliveryPanel() {
  const [lhost,    setLhost]    = useState("127.0.0.1");
  const [lport,    setLport]    = useState("8080");
  const [urlPath,  setUrlPath]  = useState("shell.sh");
  const [os,       setOs]       = useState("linux");
  const [payloads, setPayloads] = useState<DeliveryPayload[]>([]);
  const [loading,  setLoading]  = useState(false);
  const [copied,   setCopied]   = useState<string|null>(null);
  const [filter,   setFilter]   = useState("");
  const [expanded, setExpanded] = useState<number|null>(null);

  const generate = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch(`${API_URL}/api/hub/deliver?lhost=${encodeURIComponent(lhost)}&lport=${encodeURIComponent(lport)}&path=${encodeURIComponent(urlPath)}&os=${os}`);
      const d = await r.json() as DeliveryResponse;
      setPayloads(d.payloads ?? []);
    } catch { /**/ }
    setLoading(false);
  }, [lhost, lport, urlPath, os]);

  const copy = useCallback((text: string, id: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(id); setTimeout(() => setCopied(c => c === id ? null : c), 1800);
    }).catch(() => {});
  }, []);

  const filtered = payloads.filter(p =>
    !filter ||
    p.name.toLowerCase().includes(filter.toLowerCase()) ||
    p.os.includes(filter.toLowerCase()) ||
    p.command.toLowerCase().includes(filter.toLowerCase())
  );

  const osInfo = OS_OPTS.find(o => o.value === os) ?? OS_OPTS[0]!;

  return (
    <div className="flex flex-col h-full bg-black text-zinc-300 font-mono text-xs overflow-hidden">

      {/* Header */}
      <div className="flex items-center gap-3 px-3 py-1.5 bg-zinc-950 border-b border-zinc-900 shrink-0">
        <span className="text-orange-500 font-bold uppercase tracking-widest text-[11px]">PAYLOAD DELIVERY</span>
        <span className="text-zinc-700 text-[10px]">dropper generation · LOLBIN chains · fileless techniques</span>
        <span className="ml-auto text-zinc-700 text-[10px]">{filtered.length} techniques</span>
      </div>

      <div className="flex flex-1 min-h-0 overflow-hidden">

        {/* Left: config */}
        <div className="w-64 shrink-0 border-r border-zinc-900 flex flex-col overflow-y-auto">
          <div className="p-3 space-y-2.5">
            <div className="text-[10px] text-orange-400 uppercase mb-1">Configuration</div>

            <div>
              <label className="text-[9px] text-zinc-600 uppercase block mb-0.5">Attacker Host / IP</label>
              <input value={lhost} onChange={e => setLhost(e.target.value)}
                placeholder="10.10.14.5"
                className="w-full bg-zinc-900 border border-zinc-800 focus:border-orange-800 text-zinc-200 px-2 py-1 text-[10px] outline-none placeholder:text-zinc-700"/>
            </div>

            <div>
              <label className="text-[9px] text-zinc-600 uppercase block mb-0.5">Listener Port</label>
              <input value={lport} onChange={e => setLport(e.target.value)}
                placeholder="8080" type="number"
                className="w-full bg-zinc-900 border border-zinc-800 focus:border-orange-800 text-zinc-200 px-2 py-1 text-[10px] outline-none"/>
            </div>

            <div>
              <label className="text-[9px] text-zinc-600 uppercase block mb-0.5">URL Path / Filename</label>
              <input value={urlPath} onChange={e => setUrlPath(e.target.value)}
                placeholder="shell.sh"
                className="w-full bg-zinc-900 border border-zinc-800 focus:border-orange-800 text-zinc-200 px-2 py-1 text-[10px] outline-none placeholder:text-zinc-700"/>
              <div className="text-[8px] text-zinc-700 mt-0.5">http://{"{lhost}"}:{"{lport}"}/{"{path}"}</div>
            </div>

            <div>
              <label className="text-[9px] text-zinc-600 uppercase block mb-1">Target OS</label>
              <div className="grid grid-cols-2 gap-1">
                {OS_OPTS.map(opt => (
                  <button key={opt.value} onClick={() => setOs(opt.value)}
                    className={`py-1.5 text-[9px] uppercase border transition-colors
                      ${os === opt.value ? `${opt.border} ${opt.color} ${opt.bg}` : "border-zinc-900 text-zinc-600 hover:border-zinc-700 hover:text-zinc-400"}`}>
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>

            <button onClick={generate} disabled={loading || !lhost.trim()}
              className="w-full py-2 bg-orange-950/40 border border-orange-800/50 text-orange-400 text-[11px] uppercase tracking-widest hover:bg-orange-900/50 hover:text-orange-300 hover:border-orange-600 disabled:opacity-40 transition-colors font-bold">
              {loading ? "GENERATING…" : "▶ GENERATE"}
            </button>

            {payloads.length > 0 && (
              <div>
                <input value={filter} onChange={e => setFilter(e.target.value)}
                  placeholder="Filter techniques…"
                  className="w-full bg-zinc-950 border border-zinc-800 focus:border-zinc-600 text-zinc-300 text-[10px] px-2 py-1 placeholder-zinc-700 outline-none"/>
              </div>
            )}

            {/* Listener hint */}
            <div className="border border-zinc-900 bg-zinc-950/50 p-2 space-y-1.5">
              <div className="text-[9px] text-zinc-500 uppercase mb-1">Quick Listeners</div>
              {[
                { label: "Python HTTP server",   cmd: `python3 -m http.server ${lport}` },
                { label: "nc listener (shell)",  cmd: `nc -lvnp ${lport}` },
                { label: "nc listener (reverse)",cmd: `rlwrap nc -lvnp ${lport}` },
              ].map(({ label, cmd }) => (
                <div key={label} className="flex items-center justify-between gap-1">
                  <span className="text-[8px] text-zinc-700 truncate">{label}</span>
                  <button onClick={() => copy(cmd, label)}
                    className="text-[8px] text-zinc-700 hover:text-orange-400 shrink-0">
                    {copied === label ? "✓" : "COPY"}
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right: payload list */}
        <div className="flex-1 overflow-y-auto">
          {payloads.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-zinc-700 gap-2">
              <span className="text-3xl">⬇</span>
              <span className="text-[11px]">Configure and generate delivery payloads</span>
              <span className="text-[10px] text-zinc-800">curl, wget, powershell, LOLBIN, fileless, and more</span>
            </div>
          ) : (
            <div className="divide-y divide-zinc-900">
              {filtered.map((p, i) => {
                const osMeta = OS_OPTS.find(o => o.value === p.os) ?? OS_OPTS[3]!;
                return (
                  <div key={i}
                    onClick={() => setExpanded(e => e === i ? null : i)}
                    className="px-4 py-3 hover:bg-zinc-950 cursor-pointer transition-colors">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`text-[9px] px-1.5 py-0.5 border ${osMeta.border} ${osMeta.color} ${osMeta.bg} uppercase shrink-0`}>
                        {p.os}
                      </span>
                      <span className="text-zinc-200 text-[11px] font-bold">{p.name}</span>
                      <button
                        onClick={e => { e.stopPropagation(); copy(p.command, `cmd${i}`); }}
                        className="ml-auto text-[9px] text-zinc-600 hover:text-orange-400 border border-zinc-800 hover:border-orange-800 px-2 py-0.5 shrink-0 transition-colors">
                        {copied === `cmd${i}` ? "✓ COPIED" : "COPY"}
                      </button>
                    </div>
                    <pre className="text-[10px] text-orange-300 whitespace-pre-wrap break-all bg-zinc-950/80 border border-zinc-900 px-3 py-2 mt-1.5 font-mono">
                      {p.command}
                    </pre>
                    {expanded === i && (
                      <div className="mt-1.5 text-[10px] text-zinc-500 border-l-2 border-zinc-800 pl-2">
                        {p.notes}
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
