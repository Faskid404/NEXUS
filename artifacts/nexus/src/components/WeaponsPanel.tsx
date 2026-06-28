import React, { useState, useRef, useEffect, useCallback } from "react";
import { authHeaders, withAuthToken } from "../lib/auth";

const API_URL = (import.meta.env as Record<string, string>)["VITE_API_URL"] ?? "";
const API = (p: string) => `${API_URL}${p}`;

function wsBase(): string {
  if (API_URL) {
    const u = new URL(API_URL);
    const proto = u.protocol === "https:" ? "wss:" : "ws:";
    return `${proto}//${u.host}/api/ws`;
  }
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}/api/ws`;
}

interface EchoPayload   { id:string; name:string; category:string; protocol:string; os:string; stealth:number; command:string; notes:string; }
interface ShadowPayload { id:string; name:string; category:string; os:string; stealth:number; requires:string[]; command:string; notes:string; }
interface VeilPayload   { id:string; name:string; category:string; os:string; phase:string; stealth:number; command:string; notes:string; }
interface ChainMeta     { id:string; name:string; description:string; category:string; severity:string; steps:number; }
interface C2Payload     { id:string; name:string; description:string; os:string; engine:string; command:string; }

type SubTab = "ECHOVAULT" | "SHADOWFORGE" | "VEILRUNNER" | "CHAINREACTOR" | "C2POLLER" | "PROBETARGET";
const SUB_TABS: SubTab[] = ["ECHOVAULT","SHADOWFORGE","VEILRUNNER","CHAINREACTOR","C2POLLER","PROBETARGET"];

const VEIL_CATS = ["All","Anti-Forensics","EDR-Evasion","LOTL-Linux","Supply-Chain","CI-CD","Container-Escape","K8s-Abuse","Cloud-Pivot","AppArmor-Bypass","Syscall-Bypass","Credential-Dump","Persistence"];

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

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5">
      <label className="text-[9px] text-zinc-600 uppercase">{label}</label>
      {children}
    </div>
  );
}

function Input({ value, onChange, w, placeholder, type="text" }: {
  value:string; onChange:(v:string)=>void; w?:string; placeholder?:string; type?:string;
}) {
  return (
    <input
      type={type} value={value} placeholder={placeholder}
      onChange={e=>onChange(e.target.value)}
      className={`bg-zinc-950 border border-zinc-800 text-[11px] text-zinc-200 px-2 py-1 font-mono ${w??"w-32"}`}
    />
  );
}

function Sel({ value, onChange, opts }: { value:string; onChange:(v:string)=>void; opts:{v:string;l?:string}[]; }) {
  return (
    <select value={value} onChange={e=>onChange(e.target.value)} className="bg-zinc-950 border border-zinc-800 text-[11px] text-zinc-200 px-2 py-1">
      {opts.map(o=><option key={o.v} value={o.v}>{o.l??o.v}</option>)}
    </select>
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
      const r = await fetch(API(`/api/weapons/echoes?${q}`), { headers: authHeaders() });
      const j = await r.json() as { payloads: EchoPayload[] };
      setData(j.payloads ?? []);
    } catch { setData([]); } finally { setLoading(false); }
  }, [cbUrl, token, proto, os]);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="flex flex-col gap-2 h-full">
      <div className="flex flex-wrap gap-2 items-end shrink-0">
        <Field label="Callback URL">
          <Input value={cbUrl} onChange={setCbUrl} w="w-56" placeholder="http://oob.attacker.local"/>
        </Field>
        <Field label="Token / Tag">
          <Input value={token} onChange={setToken} w="w-32" placeholder="NEXUSTOKEN"/>
        </Field>
        <Field label="Protocol">
          <Sel value={proto} onChange={setProto} opts={["all","dns","http","https","icmp","ws","cloud","stealth"].map(v=>({v,l:v.toUpperCase()}))}/>
        </Field>
        <Field label="OS">
          <Sel value={os} onChange={setOs} opts={["all","linux","windows","any"].map(v=>({v,l:v.toUpperCase()}))}/>
        </Field>
        <button onClick={()=>void load()} className="border border-cyan-900 text-cyan-500 text-[10px] uppercase px-3 py-1 hover:bg-cyan-950/30 self-end">
          {loading ? "LOADING…" : "LOAD"}
        </button>
        <span className="text-[10px] text-zinc-600 ml-auto self-end">{data.length} payloads</span>
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
      const r = await fetch(API(`/api/weapons/shadows?${q}`), { headers: authHeaders() });
      const j = await r.json() as { payloads: ShadowPayload[] };
      setData(j.payloads ?? []);
    } catch { setData([]); } finally { setLoading(false); }
  }, [lhost, lport, os, cat]);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="flex flex-col gap-2 h-full">
      <div className="flex flex-wrap gap-2 items-end shrink-0">
        <Field label="LHOST"><Input value={lhost} onChange={setLhost}/></Field>
        <Field label="LPORT"><Input value={lport} onChange={setLport} w="w-20"/></Field>
        <Field label="OS">
          <Sel value={os} onChange={setOs} opts={["all","linux","windows","any"].map(v=>({v,l:v.toUpperCase()}))}/>
        </Field>
        <Field label="Category">
          <Sel value={cat} onChange={setCat} opts={[
            {v:"",l:"ALL"},
            ...(["Fileless-Linux","Shellcode","Injection","Fileless-Windows","AMSI-Bypass","EDR-Bypass","Syscall-Bypass","Anti-Detection","Go-Dropper","LOLBAS"]
              .map(v=>({v})))
          ]}/>
        </Field>
        <button onClick={()=>void load()} className="border border-purple-900 text-purple-400 text-[10px] uppercase px-3 py-1 hover:bg-purple-950/30 self-end">
          {loading?"LOADING…":"LOAD"}
        </button>
        <span className="text-[10px] text-zinc-600 ml-auto self-end">{data.length} payloads</span>
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
      const r = await fetch(API(`/api/weapons/veils?${q}`), { headers: authHeaders() });
      const j = await r.json() as { payloads: VeilPayload[] };
      setData(j.payloads ?? []);
    } catch { setData([]); } finally { setLoading(false); }
  }, [lhost, lport, os, cat, phase]);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="flex flex-col gap-2 h-full">
      <div className="flex flex-wrap gap-2 items-end shrink-0">
        <Field label="LHOST"><Input value={lhost} onChange={setLhost}/></Field>
        <Field label="LPORT"><Input value={lport} onChange={setLport} w="w-20"/></Field>
        <Field label="Category">
          <Sel value={cat} onChange={setCat} opts={VEIL_CATS.map(v=>({v}))}/>
        </Field>
        <Field label="Phase">
          <Sel value={phase} onChange={setPhase} opts={["all","pre","during","post"].map(v=>({v,l:v.toUpperCase()}))}/>
        </Field>
        <Field label="OS">
          <Sel value={os} onChange={setOs} opts={["all","linux","windows","any"].map(v=>({v,l:v.toUpperCase()}))}/>
        </Field>
        <button onClick={()=>void load()} className="border border-red-900 text-red-400 text-[10px] uppercase px-3 py-1 hover:bg-red-950/30 self-end">
          {loading?"LOADING…":"LOAD"}
        </button>
        <span className="text-[10px] text-zinc-600 ml-auto self-end">{data.length} payloads</span>
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

interface StepLog { stepId:string; name:string; status:string; output:string; elapsed:number; stepIndex:number; }

const CHAIN_PHASES = [
  { label: "Initial Access",    icon: "⚡", color: "text-red-400    border-red-900/50"    },
  { label: "Priv Escalation",   icon: "⬆", color: "text-orange-400 border-orange-900/50" },
  { label: "Persistence",       icon: "⚓", color: "text-yellow-400 border-yellow-900/50" },
  { label: "Lateral Movement",  icon: "↔", color: "text-purple-400 border-purple-900/50" },
] as const;

function getPhase(stepIndex: number, totalSteps: number) {
  const bucket = Math.floor(stepIndex / Math.max(1, totalSteps) * 4);
  return CHAIN_PHASES[Math.min(3, bucket)]!;
}

function ChainReactorTab() {
  const [chains,    setChains]    = useState<ChainMeta[]>([]);
  const [selectedId,setSelectedId]= useState<string>("");
  const [target,    setTarget]    = useState("10.10.10.1");
  const [lhost,     setLhost]     = useState("10.10.10.1");
  const [lport,     setLport]     = useState("4444");
  const [running,   setRunning]   = useState(false);
  const [logs,      setLogs]      = useState<StepLog[]>([]);
  const [summary,   setSummary]   = useState<string>("");
  const wsRef         = useRef<WebSocket|null>(null);
  const logsRef       = useRef<HTMLDivElement>(null);
  const stepCounterRef = useRef(0);

  useEffect(() => {
    fetch(API("/api/weapons/chains"), { headers: authHeaders() })
      .then(r => r.json())
      .then((j: { chains: ChainMeta[] }) => {
        setChains(j.chains ?? []);
        if (j.chains?.length) setSelectedId(j.chains[0]!.id);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (logsRef.current) logsRef.current.scrollTop = logsRef.current.scrollHeight;
  }, [logs]);

  // Cleanup WebSocket on unmount to prevent memory leaks
  useEffect(() => {
    return () => {
      wsRef.current?.close();
      wsRef.current = null;
    };
  }, []);

  const selectedChain = chains.find(c => c.id === selectedId);

  const start = useCallback(() => {
    if (running || !selectedId) return;
    setRunning(true);
    setLogs([]);
    setSummary("");
    stepCounterRef.current = 0;
    if (wsRef.current && wsRef.current.readyState < WebSocket.CLOSING) {
      wsRef.current.close(1000, "restart");
    }
    const ws = new WebSocket(withAuthToken(`${wsBase()}/chainreactor`));
    wsRef.current = ws;
    ws.onopen = () => ws.send(JSON.stringify({ chainId: selectedId, target, lhost, lport }));
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data as string) as Record<string,unknown>;
        const type = msg["type"] as string;
        if (type==="step_result") {
          setLogs(prev => {
            const idx = prev.findIndex(l=>l.stepId===msg["stepId"] && l.status==="pending");
            const sl: StepLog = { stepId:String(msg["stepId"]??""), name:String(msg["name"]??""), status:String(msg["status"]??""), output:String(msg["output"]??""), elapsed:Number(msg["elapsed"]??0), stepIndex: idx >= 0 ? prev[idx]!.stepIndex : stepCounterRef.current };
            if (idx>=0) { const n=[...prev]; n[idx]=sl; return n; }
            return [...prev, sl];
          });
        } else if (type==="step_start") {
          const si = stepCounterRef.current++;
          setLogs(prev => [...prev, { stepId:String(msg["stepId"]??""), name:String(msg["name"]??""), status:"pending", output:"", elapsed:0, stepIndex: si }]);
        } else if (type==="chain_end") {
          setSummary(`Chain complete — ${String(msg["succeeded"]??0)} succeeded, ${String(msg["failed"]??0)} failed${msg["aborted"]?" [ABORTED]":""}`);
          setRunning(false);
        } else if (type==="error") {
          setSummary(`ERROR: ${String(msg["message"]??"")}`);
          setRunning(false);
        }
      } catch { /* ignore */ }
    };
    ws.onclose = () => { wsRef.current = null; setRunning(false); };
    ws.onerror = () => { setSummary("WebSocket connection error"); setRunning(false); };
  }, [running, selectedId, target, lhost, lport]);

  const abort = useCallback(() => {
    wsRef.current?.send(JSON.stringify({ type:"abort" }));
    wsRef.current?.close();
    setRunning(false); setSummary("Aborted by user");
  }, []);

  return (
    <div className="flex flex-col gap-2 h-full">
      <div className="flex flex-wrap gap-2 items-end shrink-0">
        <Field label="Kill Chain">
          <select value={selectedId} onChange={e=>setSelectedId(e.target.value)}
            className="bg-zinc-950 border border-zinc-800 text-[11px] text-zinc-200 px-2 py-1 w-72">
            {chains.map(c=><option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
        </Field>
        <Field label="TARGET"><Input value={target} onChange={setTarget} w="w-36"/></Field>
        <Field label="LHOST"><Input value={lhost} onChange={setLhost}/></Field>
        <Field label="LPORT"><Input value={lport} onChange={setLport} w="w-20"/></Field>
        {!running
          ? <button onClick={start} disabled={!selectedId} className="border border-orange-800 text-orange-400 text-[10px] uppercase px-3 py-1 hover:bg-orange-950/30 disabled:opacity-40 self-end">
              ▶ FIRE
            </button>
          : <button onClick={abort} className="border border-red-800 text-red-400 text-[10px] uppercase px-3 py-1 hover:bg-red-950/30 self-end animate-pulse">
              ■ ABORT
            </button>
        }
      </div>
      {selectedChain && (
        <div className={`border px-2 py-1.5 text-[10px] shrink-0 ${SEVERITY_COLOR[selectedChain.severity]??""}`}>
          <span className="font-bold uppercase mr-2">{selectedChain.severity}</span>
          <span className="text-zinc-300">{selectedChain.description}</span>
          <span className="text-zinc-500 ml-2">— {selectedChain.steps} steps</span>
        </div>
      )}
      <div ref={logsRef} className="flex-1 overflow-y-auto min-h-0 border border-zinc-900 bg-black p-1">
        {logs.length===0 && !running && (
          <div className="text-[11px] text-zinc-600 text-center pt-10">Select a kill chain and press FIRE to begin real-time execution</div>
        )}
        {(() => {
          const totalSteps = (selectedChain?.steps ?? logs.length) || 1;
          let lastPhaseLabel = "";
          const rows: React.ReactNode[] = [];
          for (let i = 0; i < logs.length; i++) {
            const l = logs[i]!;
            const phase = getPhase(l.stepIndex, totalSteps);
            if (phase.label !== lastPhaseLabel) {
              lastPhaseLabel = phase.label;
              rows.push(
                <div key={`ph-${phase.label}`} className={`flex items-center gap-2 mt-1.5 mb-0.5 px-1 border-t ${phase.color} pt-1`}>
                  <span className="text-[9px]">{phase.icon}</span>
                  <span className={`text-[8px] uppercase tracking-widest font-bold ${phase.color.split(" ")[0]}`}>{phase.label}</span>
                </div>
              );
            }
            rows.push(
              <div key={`log-${l.stepId}-${i}`} className="flex gap-2 items-start font-mono text-[10px] pl-1">
                <span className={`w-14 shrink-0 uppercase ${STEP_STATUS_COLOR[l.status]??"text-zinc-400"}`}>{l.status}</span>
                <span className="text-zinc-400 w-40 shrink-0 truncate" title={l.name}>{l.name}</span>
                {l.elapsed>0 && <span className="text-zinc-700 w-12 shrink-0">{l.elapsed}ms</span>}
                {l.output && <span className="text-zinc-500 flex-1 truncate" title={l.output}>{l.output}</span>}
              </div>
            );
          }
          return rows;
        })()}
        {running && <div className="text-[10px] text-orange-400 animate-pulse mt-1 pl-1">● EXECUTING CHAIN…</div>}
      </div>
      {summary && (
        <div className={`text-[11px] px-2 py-1 border shrink-0 ${summary.includes("ERROR")||summary.includes("Abort")?"border-orange-900 text-orange-400":"border-green-900 text-green-400"}`}>
          {summary}
        </div>
      )}
    </div>
  );
}

function C2PollerTab() {
  const [source,    setSource]    = useState("url");
  const [pollUrl,   setPollUrl]   = useState("https://gist.githubusercontent.com/USER/GIST_ID/raw/cmd.txt");
  const [reportUrl, setReportUrl] = useState("");
  const [pollInterval, setPollInterval] = useState("60");
  const [jitter,    setJitter]    = useState("30");
  const [maxRuns,   setMaxRuns]   = useState("9999");
  const [xorKey,    setXorKey]    = useState("78");
  const [killDate,  setKillDate]  = useState("");
  const [userAgent, setUserAgent] = useState("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
  const [os,        setOs]        = useState<"linux"|"windows">("linux");
  const [engine,    setEngine]    = useState("bash");
  const [data,      setData]      = useState<C2Payload[]>([]);
  const [loading,   setLoading]   = useState(false);
  const [encCmd,    setEncCmd]    = useState("id && hostname && whoami");
  const [encoded,   setEncoded]   = useState<string>("");
  const [encLoading,setEncLoading]= useState(false);

  const generate = useCallback(async () => {
    if (!pollUrl) return;
    setLoading(true);
    try {
      const r = await fetch(API("/api/weapons/c2"), {
        method:"POST",
        headers:{"Content-Type":"application/json",...authHeaders()},
        body: JSON.stringify({
          source, pollUrl, reportUrl: reportUrl||undefined,
          interval:Number(pollInterval), jitter:Number(jitter),
          maxRuns:Number(maxRuns), xorKey:Number(xorKey),
          killDate: killDate||undefined, userAgent, os, engine,
        }),
      });
      const j = await r.json() as { payloads: C2Payload[] };
      setData(j.payloads ?? []);
    } catch { setData([]); } finally { setLoading(false); }
  }, [source, pollUrl, reportUrl, pollInterval, jitter, maxRuns, xorKey, killDate, userAgent, os, engine]);

  const encodeCmd = useCallback(async () => {
    if (!encCmd) return;
    setEncLoading(true);
    try {
      const q = new URLSearchParams({ cmd:encCmd, xorKey });
      const r = await fetch(API(`/api/weapons/c2/encode?${q}`), { headers: authHeaders() });
      const j = await r.json() as { encoded: string };
      setEncoded(j.encoded ?? "");
    } catch { setEncoded("error"); } finally { setEncLoading(false); }
  }, [encCmd, xorKey]);

  return (
    <div className="flex flex-col gap-2 h-full">
      <div className="grid grid-cols-2 gap-x-4 gap-y-2 shrink-0">
        <div className="col-span-2">
          <div className="text-[9px] text-zinc-500 uppercase mb-1 border-b border-zinc-900 pb-0.5">Dead-Drop C2 Poller Configuration</div>
        </div>

        <Field label="Source / Backend">
          <Sel value={source} onChange={setSource} opts={[
            {v:"url",l:"Generic URL"},{v:"gist",l:"GitHub Gist"},{v:"pastebin",l:"Pastebin"},{v:"hastebin",l:"Hastebin"},{v:"rentry",l:"Rentry.co"},
          ]}/>
        </Field>
        <Field label="Target OS">
          <Sel value={os} onChange={v=>setOs(v as "linux"|"windows")} opts={[{v:"linux",l:"Linux"},{v:"windows",l:"Windows"}]}/>
        </Field>

        <Field label="Poll URL">
          <Input value={pollUrl} onChange={setPollUrl} w="w-full" placeholder="https://gist.githubusercontent.com/USER/GIST/raw/cmd.txt"/>
        </Field>
        <Field label="Report URL (optional)">
          <Input value={reportUrl} onChange={setReportUrl} w="w-full" placeholder="http://attacker.local/results (leave blank to skip)"/>
        </Field>

        <Field label="Poll Interval (sec)">
          <Input value={pollInterval} onChange={setPollInterval} w="w-24" type="number"/>
        </Field>
        <Field label="Jitter ± (sec)">
          <Input value={jitter} onChange={setJitter} w="w-24" type="number"/>
        </Field>

        <div className="col-span-2">
          {(() => {
            const iv = Math.max(1, Number(pollInterval) || 60);
            const jt = Math.max(0, Math.min(Number(jitter) || 0, iv - 1));
            const lo = iv - jt, hi = iv + jt;
            const pct = jt / (iv + jt) * 100;
            return (
              <div className="bg-zinc-950 border border-zinc-800 px-3 py-2 space-y-1">
                <div className="flex justify-between text-[9px] text-zinc-600">
                  <span>Beacon window</span>
                  <span className="text-zinc-400">{lo}s – {hi}s <span className="text-zinc-700">({(lo/60).toFixed(1)}m – {(hi/60).toFixed(1)}m)</span></span>
                </div>
                <div className="relative h-2 bg-zinc-900 rounded overflow-hidden">
                  <div className="absolute inset-y-0 bg-emerald-900/60" style={{ left: `${100-pct}%`, right: 0 }} />
                  <div className="absolute inset-y-0 bg-emerald-600/80" style={{ left: `${100-pct*0.5}%`, width: "2px" }} />
                  <div className="absolute inset-y-0 bg-emerald-900/60" style={{ left: 0, right: `${100-pct}%` }} />
                </div>
                <div className="text-[8px] text-zinc-700">Looks like normal browsing traffic — standard network monitors cannot distinguish C2 from user web activity</div>
              </div>
            );
          })()}
        </div>

        <Field label="Max Executions">
          <Input value={maxRuns} onChange={setMaxRuns} w="w-24" type="number"/>
        </Field>
        <Field label="XOR Key (0=none, 1-255)">
          <Input value={xorKey} onChange={setXorKey} w="w-24" type="number"/>
        </Field>

        <Field label="Kill Date (YYYY-MM-DD)">
          <div className="flex items-center gap-2">
            <Input value={killDate} onChange={setKillDate} w="w-36" placeholder="2026-12-31"/>
            {killDate && (() => {
              const d = Math.ceil((new Date(killDate).getTime() - Date.now()) / 86400000);
              return d > 0
                ? <span className={`text-[9px] font-mono ${d < 7 ? "text-red-400 animate-pulse" : d < 30 ? "text-orange-400" : "text-zinc-500"}`}>{d}d left</span>
                : <span className="text-[9px] font-mono text-red-600">EXPIRED</span>;
            })()}
          </div>
        </Field>
        <Field label="Exec Engine">
          <Sel value={engine} onChange={setEngine} opts={[{v:"bash"},{v:"sh"},{v:"python3"},{v:"powershell"}]}/>
        </Field>

        <div className="col-span-2">
          <Field label="User-Agent">
            <input value={userAgent} onChange={e=>setUserAgent(e.target.value)}
              className="bg-zinc-950 border border-zinc-800 text-[11px] text-zinc-200 px-2 py-1 font-mono w-full"/>
          </Field>
        </div>

        <div className="col-span-2 flex items-center gap-3">
          <button onClick={()=>void generate()} className="border border-emerald-800 text-emerald-400 text-[10px] uppercase px-3 py-1 hover:bg-emerald-950/30">
            {loading ? "GENERATING…" : "⚙ GENERATE PAYLOADS"}
          </button>
          {data.length>0 && <span className="text-[10px] text-zinc-500">{data.length} payloads generated</span>}
        </div>
      </div>

      <div className="border-t border-zinc-900 pt-2 shrink-0">
        <div className="text-[9px] text-zinc-500 uppercase mb-1">Command Encoder (XOR-encrypt command for dead-drop posting)</div>
        <div className="flex gap-2 items-center">
          <input value={encCmd} onChange={e=>setEncCmd(e.target.value)}
            placeholder="id && hostname && cat /etc/passwd"
            className="bg-zinc-950 border border-zinc-800 text-[11px] text-zinc-200 px-2 py-1 font-mono flex-1"/>
          <button onClick={()=>void encodeCmd()} className="border border-zinc-700 text-zinc-400 text-[10px] uppercase px-2 py-1 hover:text-red-400 hover:border-red-900 shrink-0">
            {encLoading?"…":"ENCODE"}
          </button>
        </div>
        {encoded && (
          <div className="flex items-center gap-2 mt-1">
            <code className="text-[10px] text-green-300 font-mono bg-zinc-950 border border-zinc-800 px-2 py-0.5 flex-1 truncate">{encoded}</code>
            <CopyButton text={encoded}/>
          </div>
        )}
        <p className="text-[9px] text-zinc-600 mt-0.5">Post this encoded string to your dead-drop URL. The poller will decode and execute it.</p>
      </div>

      <div className="flex-1 overflow-y-auto space-y-1 min-h-0">
        {data.length===0 && !loading && (
          <div className="text-[11px] text-zinc-600 text-center pt-6">Configure dead-drop settings above and press GENERATE PAYLOADS</div>
        )}
        {data.map(p => (
          <div key={p.id} className="border border-zinc-900 bg-black hover:border-zinc-700 transition-colors">
            <div className="flex items-center gap-2 px-2 py-1.5">
              <span className={`text-[9px] uppercase ${OS_COLOR[p.os]??"text-zinc-500"}`}>{p.os}</span>
              <span className="text-[9px] text-zinc-600 uppercase">{p.engine}</span>
              <span className="text-[11px] text-zinc-200 flex-1">{p.name}</span>
              <CopyButton text={p.command}/>
            </div>
            <div className="px-2 pb-2">
              <p className="text-[10px] text-zinc-500 mb-1">{p.description}</p>
              <pre className="text-[10px] text-green-300 font-mono bg-zinc-950 border border-zinc-800 rounded p-2 overflow-x-auto whitespace-pre-wrap break-all max-h-40">{p.command}</pre>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

interface ProbeEnv { server:string; language:string; framework:string; cms:string; waf:string|null; wafConfidence:string; cdn?:string; ip?:string; }
interface ProbeSvc { port:number; service:string; banner:string; version?:string; cveHints:string[]; }
interface ProbeDisc { paths:string[]; techs:string[]; }

function ProbeTargetTab() {
  const [url,       setUrl]       = useState("https://");
  const [scanPorts, setScanPorts] = useState(false);
  const [sshBrute,  setSshBrute]  = useState(false);
  const [running,   setRunning]   = useState(false);
  const [log,       setLog]       = useState<string[]>([]);
  const [env,       setEnv]       = useState<ProbeEnv|null>(null);
  const [svcs,      setSvcs]      = useState<ProbeSvc[]>([]);
  const [disc,      setDisc]      = useState<ProbeDisc|null>(null);
  const wsRef = useRef<WebSocket|null>(null);
  const logRef = useRef<HTMLDivElement|null>(null);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [log]);

  // Cleanup WebSocket on unmount to prevent memory leaks
  useEffect(() => {
    return () => {
      wsRef.current?.close();
      wsRef.current = null;
    };
  }, []);

  const stop = useCallback(() => {
    wsRef.current?.close();
    wsRef.current = null;
    setRunning(false);
  }, []);

  const probe = useCallback(() => {
    if (!url || running) return;
    setLog([]); setEnv(null); setSvcs([]); setDisc(null); setRunning(true);
    const ws = new WebSocket(withAuthToken(`${wsBase()}/probe`));
    wsRef.current = ws;
    ws.onopen = () => {
      ws.send(JSON.stringify({ url, scanPorts, sshBrute, ...authHeaders() }));
    };
    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data as string) as Record<string,unknown>;
        if (msg.type === "progress") {
          setLog(l => [...l, String(msg.message ?? "")]);
        } else if (msg.type === "result") {
          const r = msg.env as ProbeEnv;
          setEnv(r);
          setLog(l => [...l, `✓ Server: ${r.server||"?"} | Lang: ${r.language||"?"} | Framework: ${r.framework||"?"} | WAF: ${r.waf||"none"}`]);
        } else if (msg.type === "service_fingerprints") {
          const list = (msg.services as ProbeSvc[]) ?? [];
          setSvcs(list);
          setLog(l => [...l, `✓ ${list.length} service(s) fingerprinted`]);
        } else if (msg.type === "web_discovery") {
          const d = msg.discovery as ProbeDisc;
          setDisc(d);
          setLog(l => [...l, `✓ ${d.paths?.length??0} paths discovered`]);
        } else if (msg.type === "error") {
          setLog(l => [...l, `✗ ${String(msg.message)}`]);
        } else if (msg.type === "unreachable") {
          setLog(l => [...l, `✗ UNREACHABLE: ${String(msg.message)}`]);
        } else if (msg.type === "end") {
          setRunning(false);
        }
      } catch { }
    };
    ws.onerror = () => { setLog(l => [...l, "✗ WebSocket error"]); setRunning(false); };
    ws.onclose = () => { wsRef.current = null; setRunning(false); };
  }, [url, scanPorts, sshBrute, running]);

  const WAF_COLOR: Record<string,string> = {
    high:"text-red-400", medium:"text-orange-400", low:"text-yellow-400",
  };

  return (
    <div className="flex flex-col gap-2 h-full">
      <div className="flex flex-wrap gap-2 items-end shrink-0">
        <Field label="Target URL">
          <input value={url} onChange={e=>setUrl(e.target.value)}
            placeholder="https://target.example.com"
            className="bg-zinc-950 border border-zinc-800 text-[11px] text-zinc-200 px-2 py-1 font-mono w-72"/>
        </Field>
        <label className="flex items-center gap-1.5 text-[10px] text-zinc-400 cursor-pointer self-end pb-1">
          <input type="checkbox" checked={scanPorts} onChange={e=>setScanPorts(e.target.checked)} className="accent-red-500"/>
          TCP scan
        </label>
        <label className="flex items-center gap-1.5 text-[10px] text-zinc-400 cursor-pointer self-end pb-1">
          <input type="checkbox" checked={sshBrute} onChange={e=>setSshBrute(e.target.checked)} className="accent-red-500"/>
          SSH brute
        </label>
        <button onClick={()=> running ? stop() : void probe()}
          className={`border text-[10px] uppercase px-3 py-1 self-end transition-colors ${running?"border-red-900 text-red-500 hover:bg-red-950/30":"border-cyan-900 text-cyan-500 hover:bg-cyan-950/30"}`}>
          {running ? "■ STOP" : "▶ PROBE"}
        </button>
      </div>

      {env && (
        <div className="grid grid-cols-2 gap-1 shrink-0 border border-zinc-800 bg-zinc-950 p-2">
          {[
            ["Server",    env.server    || "—"],
            ["Language",  env.language  || "—"],
            ["Framework", env.framework || "—"],
            ["CMS",       (env as unknown as Record<string,string>)["cms"] || "—"],
            ["CDN",       env.cdn        || "—"],
            ["IP",        env.ip         || "—"],
          ].map(([k,v]) => (
            <div key={k} className="flex gap-1 items-baseline">
              <span className="text-[9px] text-zinc-600 uppercase w-16 shrink-0">{k}</span>
              <span className="text-[10px] text-cyan-300 font-mono truncate">{v}</span>
            </div>
          ))}
          {env.waf !== null && (
            <div className="col-span-2 flex gap-1 items-baseline">
              <span className="text-[9px] text-zinc-600 uppercase w-16 shrink-0">WAF</span>
              <span className={`text-[10px] font-mono ${WAF_COLOR[env.wafConfidence]??"text-zinc-400"}`}>
                {env.waf ?? "none"} <span className="text-zinc-600">({env.wafConfidence})</span>
              </span>
            </div>
          )}
        </div>
      )}

      {svcs.length > 0 && (
        <div className="shrink-0 border border-zinc-800 bg-zinc-950 px-2 py-1">
          <div className="text-[9px] text-zinc-600 uppercase mb-1">Open Services</div>
          <div className="space-y-0.5 max-h-24 overflow-y-auto">
            {svcs.map((s,i) => (
              <div key={i} className="flex gap-2 items-baseline text-[10px] font-mono">
                <span className="text-yellow-400 w-10 shrink-0">{s.port}</span>
                <span className="text-zinc-300 w-20 shrink-0">{s.service}</span>
                {s.version && <span className="text-zinc-500">{s.version}</span>}
                {s.cveHints.length > 0 && <span className="text-red-400 text-[9px]">{s.cveHints.slice(0,2).join(" ")}</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {disc && disc.paths.length > 0 && (
        <div className="shrink-0 border border-zinc-800 bg-zinc-950 px-2 py-1">
          <div className="text-[9px] text-zinc-600 uppercase mb-1">Discovered Paths ({disc.paths.length})</div>
          <div className="flex flex-wrap gap-1 max-h-16 overflow-y-auto">
            {disc.paths.slice(0,30).map((p,i) => (
              <span key={i} className="text-[9px] font-mono text-green-400 bg-zinc-900 px-1">{p}</span>
            ))}
          </div>
        </div>
      )}

      <div ref={logRef} className="flex-1 overflow-y-auto bg-zinc-950 border border-zinc-900 p-2 font-mono min-h-0">
        {log.length === 0 && !running && (
          <span className="text-[10px] text-zinc-700">Enter a target URL and press PROBE to fingerprint the stack.</span>
        )}
        {log.map((l,i) => (
          <div key={i} className={`text-[10px] leading-5 whitespace-pre-wrap ${l.startsWith("✓")?"text-green-400":l.startsWith("✗")?"text-red-400":"text-zinc-400"}`}>{l}</div>
        ))}
        {running && <div className="text-[10px] text-cyan-500 animate-pulse">● scanning…</div>}
      </div>
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
    C2POLLER:    "text-emerald-400 border-emerald-900",
    PROBETARGET: "text-yellow-400  border-yellow-900",
  };
  const SUB_DESC: Record<SubTab,string> = {
    ECHOVAULT:   "Domain-Fronting · DoH · SNI · HTTP Steganography · Cloud Dead-Drop",
    SHADOWFORGE: "Fileless · Indirect Syscalls · Sleep Obfuscation · Go Dropper · AMSI/ETW Chain",
    VEILRUNNER:  "eBPF Evasion · Falco Bypass · seccomp/AppArmor Bypass · LOTL · Container Escape · K8s/Cloud",
    CHAINREACTOR:"Real-Time Kill Chain Orchestrator — Log4Shell · Spring4Shell · MongoDB · YARN · C2 Deploy",
    C2POLLER:    "GitHub Gist / Pastebin Dead-Drop Poller — XOR Encrypted · Jitter · Persistent · Self-Destruct",
    PROBETARGET: "Live Target Fingerprint — Server · Language · Framework · WAF · CDN · TCP Services · Path Discovery",
  };

  return (
    <div className="flex flex-col h-full bg-black">
      <div className="flex border-b border-zinc-900 shrink-0 overflow-x-auto">
        {SUB_TABS.map(t => (
          <button
            key={t}
            onClick={() => setSubTab(t)}
            className={`px-3 py-1.5 text-[10px] uppercase font-mono border-b-2 transition-colors whitespace-nowrap ${subTab===t?`${SUB_COLOR[t]} bg-zinc-950`:"border-transparent text-zinc-600 hover:text-zinc-400"}`}
          >
            {t}
          </button>
        ))}
        <div className="flex-1 flex items-center px-3 min-w-0">
          <span className="text-[9px] text-zinc-700 truncate">{SUB_DESC[subTab]}</span>
        </div>
      </div>
      <div className="flex-1 overflow-hidden p-2 min-h-0">
        {subTab === "ECHOVAULT"    && <EchoVaultTab />}
        {subTab === "SHADOWFORGE"  && <ShadowForgeTab />}
        {subTab === "VEILRUNNER"   && <VeilRunnerTab />}
        {subTab === "CHAINREACTOR" && <ChainReactorTab />}
        {subTab === "C2POLLER"     && <C2PollerTab />}
        {subTab === "PROBETARGET"  && <ProbeTargetTab />}
      </div>
    </div>
  );
}
