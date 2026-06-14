import React, { useState, useRef, useEffect, useCallback } from "react";

const API = (p: string) => p;

interface EchoPayload  { id:string; name:string; category:string; protocol:string; os:string; stealth:number; command:string; notes:string; }
interface ShadowPayload { id:string; name:string; category:string; os:string; stealth:number; requires:string[]; command:string; notes:string; }
interface VeilPayload  { id:string; name:string; category:string; os:string; phase:string; stealth:number; command:string; notes:string; }
interface ChainMeta    { id:string; name:string; description:string; category:string; severity:string; steps:number; }

type SubTab = "ECHOVAULT" | "SHADOWFORGE" | "VEILRUNNER" | "CHAINREACTOR";
const SUB_TABS: SubTab[] = ["ECHOVAULT","SHADOWFORGE","VEILRUNNER","CHAINREACTOR"];

const VEIL_CATS = ["All","Anti-Forensics","EDR-Evasion","LOTL-Linux","Supply-Chain","CI-CD","Container-Escape","K8s-Abuse","Cloud-Pivot"];

const SEVERITY_COLOR: Record<string, string> = {
  critical: "text-red-500 border-red-900 bg-red-950/20",
  high:     "text-orange-400 border-orange-900 bg-orange-950/20",
  medium:   "text-yellow-400 border-yellow-900 bg-yellow-950/20",
};
const PROTOCOL_COLOR: Record<string, string> = {
  dns:"text-cyan-400", https:"text-green-400", http:"text-lime-400",
  icmp:"text-yellow-400", ws:"text-blue-400", cloud:"text-purple-400", stealth:"text-pink-400",
};
const OS_COLOR: Record<string, string> = {
  linux:"text-green-500", windows:"text-blue-400", any:"text-zinc-400",
};
const PHASE_COLOR: Record<string, string> = {
  pre:"text-cyan-400", during:"text-red-400", post:"text-orange-400",
};
const STEP_STATUS_COLOR: Record<string, string> = {
  success:"text-green-400", failed:"text-red-400", skipped:"text-zinc-500",
  info:"text-cyan-400", pending:"text-zinc-600",
};

function StealthBar({ val }: { val: number }) {
  return (
    <span className="flex gap-0.5 items-center">
      {[1,2,3,4,5].map(i => (
        <span key={i} className={`inline-block w-1.5 h-1.5 rounded-sm ${i<=val?"bg-red-500":"bg-zinc-800"}`}/>
      ))}
    </span>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => { void navigator.clipboard.writeText(text); setCopied(true); setTimeout(()=>setCopied(false),1500); }}
      className={`text-[9px] uppercase px-1.5 py-0.5 border rounded transition-colors ${copied?"border-green-700 text-green-400":"border-zinc-700 text-zinc-500 hover:text-red-400 hover:border-red-900"}`}
    >
      {copied ? "COPIED" : "COPY"}
    </button>
  );
}

function PayloadCard({ name, category, command, notes, extra }: {
  name:string; category:string; command:string; notes:string; extra?:React.ReactNode;
}) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className="border border-zinc-900 bg-black hover:border-zinc-700 transition-colors">
      <div className="flex items-center gap-2 px-2 py-1.5 cursor-pointer" onClick={()=>setExpanded(e=>!e)}>
        <span className="text-[9px] text-zinc-600 uppercase">{category}</span>
        <span className="text-[11px] text-zinc-200 flex-1">{name}</span>
        {extra}
        <CopyButton text={command} />
        <span className="text-zinc-600 text-[10px]">{expanded?"▲":"▼"}</span>
      </div>
      {expanded && (
        <div className="px-2 pb-2">
          <pre className="text-[10px] text-green-300 font-mono bg-zinc-950 border border-zinc-800 rounded p-2 overflow-x-auto whitespace-pre-wrap break-all">{command}</pre>
          <p className="text-[10px] text-zinc-500 mt-1">{notes}</p>
        </div>
      )}
    </div>
  );
}

function EchoVaultTab() {
  const [cbUrl,  setCbUrl]  = useState("http://oob.attacker.local");
  const [token,  setToken]  = useState("NEXUSTOKEN");
  const [proto,  setProto]  = useState("all");
  const [os,     setOs]     = useState("all");
  const [data,   setData]   = useState<EchoPayload[]>([]);
  const [loading,setLoading]= useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const q = new URLSearchParams({cbUrl, token, ...(proto!=="all"?{protocol:proto}:{}), ...(os!=="all"?{os}:{})});
      const r = await fetch(API(`/api/weapons/echoes?${q}`));
      const j = await r.json() as { payloads: EchoPayload[] };
      setData(j.payloads ?? []);
    } catch { setData([]); } finally { setLoading(false); }
  }, [cbUrl, token, proto, os]);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="flex flex-col gap-2 h-full">
      <div className="flex flex-wrap gap-2 items-end shrink-0">
        <div className="flex flex-col gap-0.5">
          <label className="text-[9px] text-zinc-600 uppercase">Callback URL</label>
          <input value={cbUrl} onChange={e=>setCbUrl(e.target.value)} className="bg-zinc-950 border border-zinc-800 text-[11px] text-zinc-200 px-2 py-1 w-56 font-mono" placeholder="http://oob.attacker.local"/>
        </div>
        <div className="flex flex-col gap-0.5">
          <label className="text-[9px] text-zinc-600 uppercase">Token / Tag</label>
          <input value={token} onChange={e=>setToken(e.target.value)} className="bg-zinc-950 border border-zinc-800 text-[11px] text-zinc-200 px-2 py-1 w-32 font-mono" placeholder="NEXUSTOKEN"/>
        </div>
        <div className="flex flex-col gap-0.5">
          <label className="text-[9px] text-zinc-600 uppercase">Protocol</label>
          <select value={proto} onChange={e=>setProto(e.target.value)} className="bg-zinc-950 border border-zinc-800 text-[11px] text-zinc-200 px-2 py-1">
            {["all","dns","http","https","icmp","ws","cloud","stealth"].map(v=><option key={v} value={v}>{v.toUpperCase()}</option>)}
          </select>
        </div>
        <div className="flex flex-col gap-0.5">
          <label className="text-[9px] text-zinc-600 uppercase">OS</label>
          <select value={os} onChange={e=>setOs(e.target.value)} className="bg-zinc-950 border border-zinc-800 text-[11px] text-zinc-200 px-2 py-1">
            {["all","linux","windows","any"].map(v=><option key={v} value={v}>{v.toUpperCase()}</option>)}
          </select>
        </div>
        <button onClick={()=>void load()} className="border border-red-900 text-red-500 text-[10px] uppercase px-3 py-1 hover:bg-red-950/30">
          {loading ? "LOADING…" : "LOAD"}
        </button>
        <span className="text-[10px] text-zinc-600 ml-auto">{data.length} payloads</span>
      </div>
      <div className="flex-1 overflow-y-auto space-y-1 min-h-0">
        {data.map(p => (
          <PayloadCard key={p.id} name={p.name} category={p.category} command={p.command} notes={p.notes}
            extra={
              <span className="flex gap-2 items-center">
                <span className={`text-[9px] uppercase ${PROTOCOL_COLOR[p.protocol]??"text-zinc-500"}`}>{p.protocol}</span>
                <span className={`text-[9px] uppercase ${OS_COLOR[p.os]??"text-zinc-500"}`}>{p.os}</span>
                <StealthBar val={p.stealth}/>
              </span>
            }
          />
        ))}
        {!loading && data.length===0 && <div className="text-[11px] text-zinc-600 text-center pt-10">No payloads match filters</div>}
      </div>
    </div>
  );
}

function ShadowForgeTab() {
  const [lhost,  setLhost]  = useState("10.10.10.1");
  const [lport,  setLport]  = useState("4444");
  const [os,     setOs]     = useState("all");
  const [cat,    setCat]    = useState("");
  const [data,   setData]   = useState<ShadowPayload[]>([]);
  const [loading,setLoading]= useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const q = new URLSearchParams({lhost, lport, ...(os!=="all"?{os}:{}), ...(cat?{cat}:{})});
      const r = await fetch(API(`/api/weapons/shadows?${q}`));
      const j = await r.json() as { payloads: ShadowPayload[] };
      setData(j.payloads ?? []);
    } catch { setData([]); } finally { setLoading(false); }
  }, [lhost, lport, os, cat]);

  useEffect(() => { void load(); }, [load]);

  const categories = ["","Fileless-Linux","Shellcode","Injection","Fileless-Windows","AMSI-Bypass","ETW-Bypass","LOLBAS"];

  return (
    <div className="flex flex-col gap-2 h-full">
      <div className="flex flex-wrap gap-2 items-end shrink-0">
        <div className="flex flex-col gap-0.5">
          <label className="text-[9px] text-zinc-600 uppercase">LHOST</label>
          <input value={lhost} onChange={e=>setLhost(e.target.value)} className="bg-zinc-950 border border-zinc-800 text-[11px] text-zinc-200 px-2 py-1 w-32 font-mono"/>
        </div>
        <div className="flex flex-col gap-0.5">
          <label className="text-[9px] text-zinc-600 uppercase">LPORT</label>
          <input value={lport} onChange={e=>setLport(e.target.value)} className="bg-zinc-950 border border-zinc-800 text-[11px] text-zinc-200 px-2 py-1 w-20 font-mono"/>
        </div>
        <div className="flex flex-col gap-0.5">
          <label className="text-[9px] text-zinc-600 uppercase">OS</label>
          <select value={os} onChange={e=>setOs(e.target.value)} className="bg-zinc-950 border border-zinc-800 text-[11px] text-zinc-200 px-2 py-1">
            {["all","linux","windows","any"].map(v=><option key={v} value={v}>{v.toUpperCase()}</option>)}
          </select>
        </div>
        <div className="flex flex-col gap-0.5">
          <label className="text-[9px] text-zinc-600 uppercase">Category</label>
          <select value={cat} onChange={e=>setCat(e.target.value)} className="bg-zinc-950 border border-zinc-800 text-[11px] text-zinc-200 px-2 py-1">
            {categories.map(v=><option key={v} value={v}>{v||"ALL"}</option>)}
          </select>
        </div>
        <button onClick={()=>void load()} className="border border-red-900 text-red-500 text-[10px] uppercase px-3 py-1 hover:bg-red-950/30">
          {loading?"LOADING…":"LOAD"}
        </button>
        <span className="text-[10px] text-zinc-600 ml-auto">{data.length} payloads</span>
      </div>
      <div className="flex-1 overflow-y-auto space-y-1 min-h-0">
        {data.map(p => (
          <PayloadCard key={p.id} name={p.name} category={p.category} command={p.command} notes={p.notes}
            extra={
              <span className="flex gap-2 items-center">
                <span className={`text-[9px] uppercase ${OS_COLOR[p.os]??"text-zinc-500"}`}>{p.os}</span>
                {p.requires.length>0 && <span className="text-[9px] text-zinc-600">{p.requires.join(",")}</span>}
                <StealthBar val={p.stealth}/>
              </span>
            }
          />
        ))}
        {!loading && data.length===0 && <div className="text-[11px] text-zinc-600 text-center pt-10">No payloads match filters</div>}
      </div>
    </div>
  );
}

function VeilRunnerTab() {
  const [lhost,  setLhost]  = useState("10.10.10.1");
  const [lport,  setLport]  = useState("4444");
  const [os,     setOs]     = useState("all");
  const [cat,    setCat]    = useState("All");
  const [phase,  setPhase]  = useState("all");
  const [data,   setData]   = useState<VeilPayload[]>([]);
  const [loading,setLoading]= useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const q = new URLSearchParams({
        lhost, lport,
        ...(os!=="all"?{os}:{}),
        ...(cat!=="All"?{cat}:{}),
        ...(phase!=="all"?{phase}:{}),
      });
      const r = await fetch(API(`/api/weapons/veils?${q}`));
      const j = await r.json() as { payloads: VeilPayload[] };
      setData(j.payloads ?? []);
    } catch { setData([]); } finally { setLoading(false); }
  }, [lhost, lport, os, cat, phase]);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="flex flex-col gap-2 h-full">
      <div className="flex flex-wrap gap-2 items-end shrink-0">
        <div className="flex flex-col gap-0.5">
          <label className="text-[9px] text-zinc-600 uppercase">LHOST</label>
          <input value={lhost} onChange={e=>setLhost(e.target.value)} className="bg-zinc-950 border border-zinc-800 text-[11px] text-zinc-200 px-2 py-1 w-32 font-mono"/>
        </div>
        <div className="flex flex-col gap-0.5">
          <label className="text-[9px] text-zinc-600 uppercase">LPORT</label>
          <input value={lport} onChange={e=>setLport(e.target.value)} className="bg-zinc-950 border border-zinc-800 text-[11px] text-zinc-200 px-2 py-1 w-20 font-mono"/>
        </div>
        <div className="flex flex-col gap-0.5">
          <label className="text-[9px] text-zinc-600 uppercase">Category</label>
          <select value={cat} onChange={e=>setCat(e.target.value)} className="bg-zinc-950 border border-zinc-800 text-[11px] text-zinc-200 px-2 py-1">
            {VEIL_CATS.map(v=><option key={v} value={v}>{v}</option>)}
          </select>
        </div>
        <div className="flex flex-col gap-0.5">
          <label className="text-[9px] text-zinc-600 uppercase">Phase</label>
          <select value={phase} onChange={e=>setPhase(e.target.value)} className="bg-zinc-950 border border-zinc-800 text-[11px] text-zinc-200 px-2 py-1">
            {["all","pre","during","post"].map(v=><option key={v} value={v}>{v.toUpperCase()}</option>)}
          </select>
        </div>
        <div className="flex flex-col gap-0.5">
          <label className="text-[9px] text-zinc-600 uppercase">OS</label>
          <select value={os} onChange={e=>setOs(e.target.value)} className="bg-zinc-950 border border-zinc-800 text-[11px] text-zinc-200 px-2 py-1">
            {["all","linux","windows","any"].map(v=><option key={v} value={v}>{v.toUpperCase()}</option>)}
          </select>
        </div>
        <button onClick={()=>void load()} className="border border-red-900 text-red-500 text-[10px] uppercase px-3 py-1 hover:bg-red-950/30">
          {loading?"LOADING…":"LOAD"}
        </button>
        <span className="text-[10px] text-zinc-600 ml-auto">{data.length} payloads</span>
      </div>
      <div className="flex-1 overflow-y-auto space-y-1 min-h-0">
        {data.map(p => (
          <PayloadCard key={p.id} name={p.name} category={p.category} command={p.command} notes={p.notes}
            extra={
              <span className="flex gap-2 items-center">
                <span className={`text-[9px] uppercase ${OS_COLOR[p.os]??"text-zinc-500"}`}>{p.os}</span>
                <span className={`text-[9px] uppercase ${PHASE_COLOR[p.phase]??"text-zinc-500"}`}>{p.phase}</span>
                <StealthBar val={p.stealth}/>
              </span>
            }
          />
        ))}
        {!loading && data.length===0 && <div className="text-[11px] text-zinc-600 text-center pt-10">No payloads match filters</div>}
      </div>
    </div>
  );
}

interface StepLog { stepId:string; name:string; status:string; output:string; elapsed:number; }

function ChainReactorTab() {
  const [chains,    setChains]    = useState<ChainMeta[]>([]);
  const [selectedId,setSelectedId]= useState<string>("");
  const [target,    setTarget]    = useState("10.10.10.1");
  const [lhost,     setLhost]     = useState("10.10.10.1");
  const [lport,     setLport]     = useState("4444");
  const [running,   setRunning]   = useState(false);
  const [logs,      setLogs]      = useState<StepLog[]>([]);
  const [summary,   setSummary]   = useState<string>("");
  const wsRef   = useRef<WebSocket|null>(null);
  const logsRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetch(API("/api/weapons/chains"))
      .then(r => r.json())
      .then((j: { chains: ChainMeta[] }) => {
        setChains(j.chains ?? []);
        if (j.chains?.length) setSelectedId(j.chains[0].id);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (logsRef.current) logsRef.current.scrollTop = logsRef.current.scrollHeight;
  }, [logs]);

  const selectedChain = chains.find(c => c.id === selectedId);

  const start = useCallback(() => {
    if (running || !selectedId) return;
    setRunning(true);
    setLogs([]);
    setSummary("");

    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${proto}//${window.location.host}/api/ws/chainreactor`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      ws.send(JSON.stringify({ chainId: selectedId, target, lhost, lport }));
    };

    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data as string) as Record<string,unknown>;
        const type = msg["type"] as string;
        if (type === "step_result") {
          const sl: StepLog = {
            stepId:  String(msg["stepId"]  ?? ""),
            name:    String(msg["name"]    ?? ""),
            status:  String(msg["status"]  ?? ""),
            output:  String(msg["output"]  ?? ""),
            elapsed: Number(msg["elapsed"] ?? 0),
          };
          setLogs(prev => [...prev, sl]);
        } else if (type === "step_start") {
          setLogs(prev => [...prev, {
            stepId:  String(msg["stepId"] ?? ""),
            name:    `▶ ${String(msg["name"] ?? "")}`,
            status:  "pending",
            output:  "",
            elapsed: 0,
          }]);
        } else if (type === "chain_end") {
          const ok  = Number(msg["succeeded"] ?? 0);
          const bad = Number(msg["failed"] ?? 0);
          setSummary(`Chain complete — ${ok} succeeded, ${bad} failed${msg["aborted"]?" (ABORTED)":""}`);
          setRunning(false);
        } else if (type === "error") {
          setSummary(`ERROR: ${String(msg["message"] ?? "")}`);
          setRunning(false);
        }
      } catch { /* parse error */ }
    };

    ws.onclose  = () => setRunning(false);
    ws.onerror  = () => { setSummary("WebSocket error"); setRunning(false); };
  }, [running, selectedId, target, lhost, lport]);

  const abort = useCallback(() => {
    wsRef.current?.send(JSON.stringify({ type: "abort" }));
    wsRef.current?.close();
    setRunning(false);
    setSummary("Aborted by user");
  }, []);

  return (
    <div className="flex flex-col gap-2 h-full">
      <div className="flex flex-wrap gap-2 items-end shrink-0">
        <div className="flex flex-col gap-0.5">
          <label className="text-[9px] text-zinc-600 uppercase">Kill Chain</label>
          <select value={selectedId} onChange={e=>setSelectedId(e.target.value)} className="bg-zinc-950 border border-zinc-800 text-[11px] text-zinc-200 px-2 py-1 w-64">
            {chains.map(c=><option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
        </div>
        <div className="flex flex-col gap-0.5">
          <label className="text-[9px] text-zinc-600 uppercase">TARGET</label>
          <input value={target} onChange={e=>setTarget(e.target.value)} className="bg-zinc-950 border border-zinc-800 text-[11px] text-zinc-200 px-2 py-1 w-36 font-mono"/>
        </div>
        <div className="flex flex-col gap-0.5">
          <label className="text-[9px] text-zinc-600 uppercase">LHOST</label>
          <input value={lhost} onChange={e=>setLhost(e.target.value)} className="bg-zinc-950 border border-zinc-800 text-[11px] text-zinc-200 px-2 py-1 w-32 font-mono"/>
        </div>
        <div className="flex flex-col gap-0.5">
          <label className="text-[9px] text-zinc-600 uppercase">LPORT</label>
          <input value={lport} onChange={e=>setLport(e.target.value)} className="bg-zinc-950 border border-zinc-800 text-[11px] text-zinc-200 px-2 py-1 w-20 font-mono"/>
        </div>
        {!running
          ? <button onClick={start} disabled={!selectedId} className="border border-red-900 text-red-500 text-[10px] uppercase px-3 py-1 hover:bg-red-950/30 disabled:opacity-40">
              ▶ FIRE CHAIN
            </button>
          : <button onClick={abort} className="border border-orange-800 text-orange-400 text-[10px] uppercase px-3 py-1 hover:bg-orange-950/30">
              ■ ABORT
            </button>
        }
      </div>

      {selectedChain && (
        <div className={`border px-2 py-1.5 rounded text-[10px] shrink-0 ${SEVERITY_COLOR[selectedChain.severity]??""}`}>
          <span className="font-bold uppercase mr-2">{selectedChain.severity}</span>
          <span className="text-zinc-300">{selectedChain.description}</span>
          <span className="text-zinc-500 ml-2">— {selectedChain.steps} steps</span>
        </div>
      )}

      <div ref={logsRef} className="flex-1 overflow-y-auto space-y-0.5 min-h-0 border border-zinc-900 bg-black p-1">
        {logs.length===0 && !running && (
          <div className="text-[11px] text-zinc-600 text-center pt-10">Select a kill chain and press FIRE CHAIN to begin real-time execution</div>
        )}
        {logs.map((l,i) => (
          <div key={i} className="flex gap-2 items-start font-mono text-[10px]">
            <span className={`w-14 shrink-0 uppercase ${STEP_STATUS_COLOR[l.status]??"text-zinc-400"}`}>{l.status}</span>
            <span className="text-zinc-400 w-40 shrink-0 truncate" title={l.name}>{l.name}</span>
            {l.elapsed>0 && <span className="text-zinc-700 w-12 shrink-0">{l.elapsed}ms</span>}
            {l.output && <span className="text-zinc-500 flex-1 truncate" title={l.output}>{l.output}</span>}
          </div>
        ))}
        {running && <div className="text-[10px] text-red-400 animate-pulse">● EXECUTING…</div>}
      </div>

      {summary && (
        <div className={`text-[11px] px-2 py-1 border rounded shrink-0 ${summary.includes("ERROR")||summary.includes("Aborted")?"border-orange-900 text-orange-400 bg-orange-950/10":"border-green-900 text-green-400 bg-green-950/10"}`}>
          {summary}
        </div>
      )}
    </div>
  );
}

export default function WeaponsPanel() {
  const [subTab, setSubTab] = useState<SubTab>("ECHOVAULT");

  const SUB_COLOR: Record<SubTab,string> = {
    ECHOVAULT:   "text-cyan-400   border-cyan-900",
    SHADOWFORGE: "text-purple-400 border-purple-900",
    VEILRUNNER:  "text-red-400    border-red-900",
    CHAINREACTOR:"text-orange-400 border-orange-900",
  };
  const SUB_DESC: Record<SubTab,string> = {
    ECHOVAULT:   "Covert Callback & Multi-Protocol Exfil Tunneler",
    SHADOWFORGE: "In-Memory Polymorphic Shellcode & Fileless Loader Arsenal",
    VEILRUNNER:  "EDR Evasion + LOTL + Supply Chain + Container + K8s + Cloud",
    CHAINREACTOR:"Real-Time Kill Chain Orchestrator — Live WebSocket Stream",
  };

  return (
    <div className="flex flex-col h-full bg-black">
      <div className="flex border-b border-zinc-900 shrink-0">
        {SUB_TABS.map(t => (
          <button
            key={t}
            onClick={() => setSubTab(t)}
            className={`px-3 py-1.5 text-[10px] uppercase font-mono border-b-2 transition-colors ${subTab===t?`${SUB_COLOR[t]} bg-zinc-950 border-b`:"border-transparent text-zinc-600 hover:text-zinc-400"}`}
          >
            {t}
          </button>
        ))}
        <div className="flex-1 flex items-center px-3">
          <span className="text-[9px] text-zinc-700">{SUB_DESC[subTab]}</span>
        </div>
      </div>
      <div className="flex-1 overflow-hidden p-2 min-h-0">
        {subTab === "ECHOVAULT"    && <EchoVaultTab />}
        {subTab === "SHADOWFORGE"  && <ShadowForgeTab />}
        {subTab === "VEILRUNNER"   && <VeilRunnerTab />}
        {subTab === "CHAINREACTOR" && <ChainReactorTab />}
      </div>
    </div>
  );
}
