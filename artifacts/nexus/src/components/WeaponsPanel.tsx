import React, { useState, useRef, useEffect, useCallback } from "react";

const API = (p: string) => p;

interface EchoPayload   { id:string; name:string; category:string; protocol:string; os:string; stealth:number; command:string; notes:string; }
interface ShadowPayload { id:string; name:string; category:string; os:string; stealth:number; requires:string[]; command:string; notes:string; }
interface VeilPayload   { id:string; name:string; category:string; os:string; phase:string; stealth:number; command:string; notes:string; }
interface ChainMeta     { id:string; name:string; description:string; category:string; severity:string; steps:number; }
interface C2Payload     { id:string; name:string; description:string; os:string; engine:string; command:string; }

type SubTab = "ECHOVAULT" | "SHADOWFORGE" | "VEILRUNNER" | "CHAINREACTOR" | "C2POLLER";
const SUB_TABS: SubTab[] = ["ECHOVAULT","SHADOWFORGE","VEILRUNNER","CHAINREACTOR","C2POLLER"];

const VEIL_CATS = ["All","Anti-Forensics","EDR-Evasion","LOTL-Linux","Supply-Chain","CI-CD","Container-Escape","K8s-Abuse","Cloud-Pivot","AppArmor-Bypass","Syscall-Bypass"];

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
      const r = await fetch(API(`/api/weapons/echoes?${q}`));
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
      const r = await fetch(API(`/api/weapons/shadows?${q}`));
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
      const r = await fetch(API(`/api/weapons/veils?${q}`));
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
        if (j.chains?.length) setSelectedId(j.chains[0]!.id);
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
    const ws = new WebSocket(`${proto}//${window.location.host}/api/ws/chainreactor`);
    wsRef.current = ws;
    ws.onopen = () => ws.send(JSON.stringify({ chainId: selectedId, target, lhost, lport }));
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data as string) as Record<string,unknown>;
        const type = msg["type"] as string;
        if (type==="step_result") {
          setLogs(prev => {
            const idx = prev.findIndex(l=>l.stepId===msg["stepId"] && l.status==="pending");
            const sl: StepLog = { stepId:String(msg["stepId"]??""), name:String(msg["name"]??""), status:String(msg["status"]??""), output:String(msg["output"]??""), elapsed:Number(msg["elapsed"]??0) };
            if (idx>=0) { const n=[...prev]; n[idx]=sl; return n; }
            return [...prev, sl];
          });
        } else if (type==="step_start") {
          setLogs(prev => [...prev, { stepId:String(msg["stepId"]??""), name:String(msg["name"]??""), status:"pending", output:"", elapsed:0 }]);
        } else if (type==="chain_end") {
          setSummary(`Chain complete — ${String(msg["succeeded"]??0)} succeeded, ${String(msg["failed"]??0)} failed${msg["aborted"]?" [ABORTED]":""}`);
          setRunning(false);
        } else if (type==="error") {
          setSummary(`ERROR: ${String(msg["message"]??"")}`);
          setRunning(false);
        }
      } catch { /* ignore */ }
    };
    ws.onclose = () => setRunning(false);
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
      <div ref={logsRef} className="flex-1 overflow-y-auto space-y-0.5 min-h-0 border border-zinc-900 bg-black p-1">
        {logs.length===0 && !running && (
          <div className="text-[11px] text-zinc-600 text-center pt-10">Select a kill chain and press FIRE to begin real-time execution</div>
        )}
        {logs.map((l,i) => (
          <div key={i} className="flex gap-2 items-start font-mono text-[10px]">
            <span className={`w-14 shrink-0 uppercase ${STEP_STATUS_COLOR[l.status]??"text-zinc-400"}`}>{l.status}</span>
            <span className="text-zinc-400 w-40 shrink-0 truncate" title={l.name}>{l.name}</span>
            {l.elapsed>0 && <span className="text-zinc-700 w-12 shrink-0">{l.elapsed}ms</span>}
            {l.output && <span className="text-zinc-500 flex-1 truncate" title={l.output}>{l.output}</span>}
          </div>
        ))}
        {running && <div className="text-[10px] text-orange-400 animate-pulse mt-1">● EXECUTING CHAIN…</div>}
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
  const [interval,  setInterval]  = useState("60");
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
        headers:{"Content-Type":"application/json"},
        body: JSON.stringify({
          source, pollUrl, reportUrl: reportUrl||undefined,
          interval:Number(interval), jitter:Number(jitter),
          maxRuns:Number(maxRuns), xorKey:Number(xorKey),
          killDate: killDate||undefined, userAgent, os, engine,
        }),
      });
      const j = await r.json() as { payloads: C2Payload[] };
      setData(j.payloads ?? []);
    } catch { setData([]); } finally { setLoading(false); }
  }, [source, pollUrl, reportUrl, interval, jitter, maxRuns, xorKey, killDate, userAgent, os, engine]);

  const encodeCmd = useCallback(async () => {
    if (!encCmd) return;
    setEncLoading(true);
    try {
      const q = new URLSearchParams({ cmd:encCmd, xorKey });
      const r = await fetch(API(`/api/weapons/c2/encode?${q}`));
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
          <Input value={interval} onChange={setInterval} w="w-24" type="number"/>
        </Field>
        <Field label="Jitter ± (sec)">
          <Input value={jitter} onChange={setJitter} w="w-24" type="number"/>
        </Field>

        <Field label="Max Executions">
          <Input value={maxRuns} onChange={setMaxRuns} w="w-24" type="number"/>
        </Field>
        <Field label="XOR Key (0=none, 1-255)">
          <Input value={xorKey} onChange={setXorKey} w="w-24" type="number"/>
        </Field>

        <Field label="Kill Date (YYYY-MM-DD)">
          <Input value={killDate} onChange={setKillDate} w="w-36" placeholder="2026-12-31"/>
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

export default function WeaponsPanel() {
  const [subTab, setSubTab] = useState<SubTab>("ECHOVAULT");

  const SUB_COLOR: Record<SubTab,string> = {
    ECHOVAULT:   "text-cyan-400   border-cyan-900",
    SHADOWFORGE: "text-purple-400 border-purple-900",
    VEILRUNNER:  "text-red-400    border-red-900",
    CHAINREACTOR:"text-orange-400 border-orange-900",
    C2POLLER:    "text-emerald-400 border-emerald-900",
  };
  const SUB_DESC: Record<SubTab,string> = {
    ECHOVAULT:   "Domain-Fronting · DoH · SNI · HTTP Steganography · Cloud Dead-Drop",
    SHADOWFORGE: "Fileless · Indirect Syscalls · Sleep Obfuscation · Go Dropper · AMSI/ETW Chain",
    VEILRUNNER:  "eBPF Evasion · Falco Bypass · seccomp/AppArmor Bypass · LOTL · Container Escape · K8s/Cloud",
    CHAINREACTOR:"Real-Time Kill Chain Orchestrator — Log4Shell · Spring4Shell · MongoDB · YARN · C2 Deploy",
    C2POLLER:    "GitHub Gist / Pastebin Dead-Drop Poller — XOR Encrypted · Jitter · Persistent · Self-Destruct",
  };

  return (
    <div className="flex flex-col h-full bg-black">
      <div className="flex border-b border-zinc-900 shrink-0 overflow-x-auto">
        {SUB_TABS.map(t => (
          <button
            key={t}
            onClick={() => setSubTab(t)}
            className={`px-3 py-1.5 text-[10px] uppercase font-mono border-b-2 transition-colors whitespace-nowrap ${subTab===t?`${SUB_COLOR[t]} bg-zinc-950 border-b`:"border-transparent text-zinc-600 hover:text-zinc-400"}`}
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
      </div>
    </div>
  );
}
