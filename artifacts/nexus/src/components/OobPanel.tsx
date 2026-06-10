import React, { useState, useEffect, useRef, useCallback } from "react";

  const API_URL = (import.meta.env as Record<string,string>)["VITE_API_URL"] ?? "";

  interface OobHit {
    id:string; ts:number; type:string; method:string; path:string; sourceIp:string;
    userAgent:string; headers:Record<string,string>; body:string;
    query:Record<string,string>; data:string; token:string; size:number;
  }
  interface TokenInfo { token:string; cbUrl:string; payloads:Record<string,string>; }

  function timeAgo(ts:number):string {
    const s=Math.floor((Date.now()-ts)/1000);
    if(s<2)return"just now"; if(s<60)return`${s}s ago`;
    if(s<3600)return`${Math.floor(s/60)}m ago`;
    return new Date(ts).toLocaleTimeString();
  }
  function tryDecode(raw:string):{text:string;decoded:boolean}{
    if(!raw)return{text:"",decoded:false};
    try{
      const dec=atob(raw.replace(/[ ]/g,"+"));
      if(/^[\x09\x0a\x0d\x20-\x7e]+$/.test(dec)&&dec.length>2)return{text:dec,decoded:true};
    }catch{/**/}
    return{text:raw,decoded:false};
  }
  const PAYLOAD_LABELS:Record<string,string>={
    wget_pixel:"wget Pixel",analytics_beacon:"Analytics Beacon",python3_urllib:"Python3 urllib",
    curl_font_fetch:"curl Font Fetch",curl_post_xhr:"curl POST XHR",bash_pipe_raw:"Bash Pipe",
    curl_exfil:"Full Exfil",perl_http:"Perl HTTP",python3_socket:"Python3 Socket",
  };

  export default function OobPanel(){
    const [hits,setHits]=useState<OobHit[]>([]);
    const [tokenInfo,setTokenInfo]=useState<TokenInfo|null>(null);
    const [connected,setConnected]=useState(false);
    const [expanded,setExpanded]=useState<string|null>(null);
    const [copied,setCopied]=useState<string|null>(null);
    const [filter,setFilter]=useState("");
    const [selPayload,setSelPayload]=useState("wget_pixel");
    const [loading,setLoading]=useState(false);
    const esRef=useRef<EventSource|null>(null);

    useEffect(()=>{
      const es=new EventSource(`${API_URL}/api/oob/stream`);
      esRef.current=es;
      es.onopen=()=>setConnected(true);
      es.onerror=()=>setConnected(false);
      es.addEventListener("hit",(e:MessageEvent)=>{
        try{setHits(p=>[JSON.parse(e.data),...p].slice(0,500));}catch{/**/}
      });
      es.addEventListener("cleared",()=>setHits([]));
      return()=>{es.close();setConnected(false);};
    },[]);

    const copy=useCallback((text:string,id:string)=>{
      navigator.clipboard.writeText(text).then(()=>{setCopied(id);setTimeout(()=>setCopied(c=>c===id?null:c),1800);}).catch(()=>{});
    },[]);

    const genToken=useCallback(async()=>{
      setLoading(true);
      try{const r=await fetch(`${API_URL}/api/oob/token`);setTokenInfo(await r.json());}catch{/**/}
      setLoading(false);
    },[]);

    const doClear=useCallback(async()=>{
      await fetch(`${API_URL}/api/oob/hits`,{method:"DELETE"}).catch(()=>{});setHits([]);
    },[]);

    useEffect(()=>{genToken();},[genToken]);

    const filtered=hits.filter(h=>!filter||h.token.includes(filter)||h.sourceIp.includes(filter)||
      h.data.toLowerCase().includes(filter.toLowerCase())||h.method.includes(filter.toUpperCase()));

    return(
      <div className="flex flex-col h-full bg-black text-zinc-300 font-mono text-xs overflow-hidden">
        <div className="flex items-center gap-3 px-3 py-1.5 bg-zinc-950 border-b border-zinc-900 shrink-0">
          <span className="text-red-500 font-bold uppercase tracking-widest text-[11px]">OOB Callback Listener</span>
          <div className="flex items-center gap-1.5">
            <div className={`w-1.5 h-1.5 rounded-full ${connected?"bg-green-500 animate-pulse":"bg-red-600"}`}/>
            <span className={`text-[10px] ${connected?"text-green-500":"text-red-500"}`}>{connected?"SSE LIVE":"DISCONNECTED"}</span>
          </div>
          <span className="ml-auto text-zinc-700 text-[10px]">{filtered.length} hits</span>
          <button onClick={doClear} className="text-[10px] text-zinc-600 hover:text-red-400 border border-zinc-800 px-2 py-0.5 hover:border-red-700">CLEAR</button>
        </div>
        <div className="flex flex-1 min-h-0 overflow-hidden">
          <div className="w-80 shrink-0 border-r border-zinc-900 flex flex-col overflow-hidden">
            <div className="p-3 border-b border-zinc-900 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-red-400 uppercase">Callback URL</span>
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
            <div className="px-3 py-2 border-b border-zinc-900">
              <input value={filter} onChange={e=>setFilter(e.target.value)} placeholder="Filter by token / IP / data…"
                className="w-full bg-zinc-950 border border-zinc-800 text-zinc-300 text-[10px] px-2 py-1 placeholder-zinc-700 focus:outline-none focus:border-zinc-600"/>
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
                      <span className={`text-[9px] px-1 border ${h.type==="oob"?"text-red-400 border-red-900":"text-blue-400 border-blue-900"}`}>{h.type.toUpperCase()}</span>
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
                              <span className="text-zinc-600">Data{decoded?" (base64 decoded)":""}</span>
                              <button onClick={e=>{e.stopPropagation();copy(dec,`d${h.id}`);}} className="text-zinc-600 hover:text-green-400">{copied===`d${h.id}`?"✓":"COPY"}</button>
                            </div>
                            <code className="text-green-400 break-all whitespace-pre-wrap">{dec.slice(0,300)}</code>
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
              ? <span>No OOB hits yet — fire a payload with OOB mode enabled</span>
              : <span className="text-zinc-700">Select a hit on the left to expand details</span>}
          </div>
        </div>
      </div>
    );
  }
  
