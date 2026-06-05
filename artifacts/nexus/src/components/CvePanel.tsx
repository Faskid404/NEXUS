import React, { useState, useRef, useEffect, useCallback } from "react";

  /* ═══════════════════════════════════════════════════════════════
     NEXUSFORGE — CVE Exploitation Panel  (2025 / 2026)
     SSH · FTP · HTTP — Probe · Exploit · Differential Analysis
     ═══════════════════════════════════════════════════════════════ */

  interface CveRecord {
    id:               string;
    title:            string;
    cvss:             number;
    type:             string;
    protocol:         "ssh"|"ftp"|"http"|"https"|"any";
    affectedProducts: string[];
    affectedVersions: string;
    patchedIn:        string;
    publishedDate:    string;
    references:       string[];
  }

  interface ProbeResult {
    vulnerable:   boolean | null;
    version:      string;
    banner:       string;
    evidence:     string;
    confidence:   string;
    responseTime: number;
  }

  interface DiffResult {
    method:         string;
    confirmed:      boolean;
    confidence:     string;
    payload:        string;
    timingDelta:    number;
    sizeDelta:      number;
    evidence:       string;
  }

  const API = "/api";
  const wsBase = (): string => {
    const loc = window.location;
    const proto = loc.protocol === "https:" ? "wss:" : "ws:";
    return proto + "//" + loc.host + "/api/ws";
  };

  function cvssColor(cvss: number): string {
    if (cvss >= 9) return "text-red-400";
    if (cvss >= 7) return "text-orange-400";
    if (cvss >= 4) return "text-yellow-400";
    return "text-green-400";
  }
  function cvssBar(cvss: number): string {
    const pct = Math.round((cvss / 10) * 100);
    let bg = "bg-green-500";
    if (cvss >= 9) bg = "bg-red-500";
    else if (cvss >= 7) bg = "bg-orange-500";
    else if (cvss >= 4) bg = "bg-yellow-500";
    return `<div class="h-1 ${bg} rounded" style="width:${pct}%"></div>`;
  }
  function typeBadge(type: string): string {
    const map: Record<string,string> = {
      rce: "bg-red-900/60 text-red-300 border-red-700",
      auth_bypass: "bg-purple-900/60 text-purple-300 border-purple-700",
      file_read: "bg-yellow-900/60 text-yellow-300 border-yellow-700",
      lpe: "bg-orange-900/60 text-orange-300 border-orange-700",
      ssrf: "bg-blue-900/60 text-blue-300 border-blue-700",
      mitm: "bg-fuchsia-900/60 text-fuchsia-300 border-fuchsia-700",
      dos: "bg-zinc-700/60 text-zinc-300 border-zinc-600",
    };
    return map[type] ?? "bg-zinc-800 text-zinc-400 border-zinc-600";
  }
  function protoIcon(proto: string): string {
    if (proto === "ssh") return "🔐";
    if (proto === "ftp") return "📁";
    if (proto === "http" || proto === "https") return "🌐";
    return "⚡";
  }

  // ── Shared small components ──────────────────────────────────────────
  function Label({ children }: { children: React.ReactNode }) {
    return <span className="text-[10px] text-zinc-500 uppercase tracking-widest">{children}</span>;
  }
  function Input({ className = "", ...props }: React.InputHTMLAttributes<HTMLInputElement>) {
    return (
      <input
        className={"bg-black border border-zinc-800 text-zinc-200 text-xs px-2 py-1 font-mono focus:outline-none focus:border-red-700 " + className}
        {...props}
      />
    );
  }
  function Btn({ children, className = "", ...props }: React.ButtonHTMLAttributes<HTMLButtonElement>) {
    return (
      <button
        className={"px-3 py-1 text-xs font-mono uppercase border transition-colors " + className}
        {...props}
      >
        {children}
      </button>
    );
  }

  // ── Main panel ───────────────────────────────────────────────────────
  export default function CvePanel() {
    const [cves, setCves]           = useState<CveRecord[]>([]);
    const [selected, setSelected]   = useState<CveRecord | null>(null);
    const [loading, setCveLoading]  = useState(true);

    // Target config
    const [targetUrl, setTargetUrl] = useState("");
    const [host, setHost]           = useState("");
    const [port, setPort]           = useState("");
    const [cmd, setCmd]             = useState("id && whoami && hostname");
    const [injectParam, setInjectParam] = useState("q");
    const [httpMethod, setHttpMethod]   = useState<"GET"|"POST">("GET");
    const [protectedPath, setProtectedPath] = useState("/admin");

    // Output & state
    const [output, setOutput]   = useState("");
    const [running, setRunning] = useState(false);
    const [probe, setProbe]     = useState<ProbeResult | null>(null);
    const [diffs, setDiffs]     = useState<DiffResult[]>([]);
    const [sessionId, setSessionId]   = useState("");
    const [shellReady, setShellReady] = useState(false);
    const [shellCmd, setShellCmd]     = useState("");
    const wsRef  = useRef<WebSocket | null>(null);
    const outRef = useRef<HTMLDivElement | null>(null);

    const append = useCallback((s: string) => {
      setOutput(p => (p + s).slice(-30_000));
      setTimeout(() => { outRef.current?.scrollTo({ top: 99999, behavior: "smooth" }); }, 30);
    }, []);

    // Load CVE list
    useEffect(() => {
      fetch(API + "/cve/list")
        .then(r => r.json())
        .then((data: CveRecord[]) => {
          setCves(data.sort((a,b) => b.cvss - a.cvss));
          setCveLoading(false);
        })
        .catch(() => setCveLoading(false));
    }, []);

    const stopWs = () => {
      wsRef.current?.close();
      wsRef.current = null;
      setRunning(false);
      setShellReady(false);
    };

    const handleShellSend = () => {
      if (!wsRef.current || wsRef.current.readyState !== 1 || !shellCmd.trim()) return;
      wsRef.current.send(JSON.stringify({ mode: "shell", cmd: shellCmd.trim() }));
      setShellCmd("");
    };

    function openWs(payload: object): WebSocket {
      stopWs();
      setOutput("");
      setProbe(null);
      setDiffs([]);
      setRunning(true);
      const ws = new WebSocket(wsBase() + "/cve");
      wsRef.current = ws;

      ws.onopen  = () => ws.send(JSON.stringify(payload));
      ws.onclose = () => setRunning(false);
      ws.onerror = () => { append("[WS ERROR]\n"); setRunning(false); };
      ws.onmessage = (e) => {
        const msg = JSON.parse(e.data) as Record<string,unknown>;
        switch (msg["type"]) {
          case "log":        append((msg["message"] as string) + "\n"); break;
          case "probeResult": setProbe(msg as unknown as ProbeResult); append(
            "\n[ PROBE RESULT ]\n" +
            "Vulnerable: " + (msg["vulnerable"] == null ? "UNKNOWN" : msg["vulnerable"] ? "YES ⚠" : "NO ✓") + "\n" +
            "Evidence:   " + String(msg["evidence"]) + "\n" +
            "Confidence: " + String(msg["confidence"]) + "\n" +
            "Banner:     " + String(msg["banner"] || "(none)") + "\n" +
            "Time:       " + String(msg["responseTime"] ?? msg["elapsed"] ?? 0) + "ms\n"
          ); break;
          case "exploitResult": append(
            "\n[ EXPLOIT RESULT ]\n" +
            "Success: " + String(msg["success"]) + "\n" +
            "Output:\n" + String(msg["output"] ?? "") + "\n"
          ); break;
          case "stepResult": append(
            "  HTTP " + String(msg["status"]) + " · " + String(msg["elapsed"]) + "ms" +
            (msg["output"] ? "\n" + String(msg["output"]).slice(0,800) : "") + "\n"
          ); break;
          case "diffResult": {
            const d = msg as unknown as DiffResult;
            setDiffs(p => [...p, d]);
            append(
              "  [" + d.method.toUpperCase() + "] " + (d.confirmed ? "CONFIRMED ✓" : "negative") +
              " Δt=" + d.timingDelta + "ms ΔB=" + d.sizeDelta + "  " + d.payload + "\n"
            );
            break;
          }
          case "sessionId": setSessionId(msg["sessionId"] as string); break;
          case "done":
            append("\n[ DONE ] confirmed=" + String(msg["confirmed"]) + " (" + String(msg["elapsed"]) + "ms)\n\n");
            if (msg["persistent"]) {
              setShellReady(true);
              setRunning(false); // exploit finished; shell input takes over
            }
            break;
          case "shellResult":
            append("\n$ " + String(msg["cmd"]) + "\n" + String(msg["output"] ?? "") + "\n");
            break;
          case "error":     append("\n[ ERROR ] " + String(msg["message"]) + "\n"); break;
        }
      };
      return ws;
    }

    // ── Action handlers ─────────────────────────────────────────────
    const handleSshProbe = () => {
      if (!host) { alert("Enter a host"); return; }
      append("Probing SSH " + host + ":" + (port || "22") + "...\n");
      openWs({ cveId: selected?.id ?? "CVE-2024-6387", mode: "ssh_probe", targetHost: host, targetPort: Number(port)||22 });
    };

    const handleFtpProbe = () => {
      if (!host) { alert("Enter a host"); return; }
      append("Probing FTP " + host + ":" + (port || "21") + "...\n");
      openWs({ cveId: "FTP-RECON", mode: "ftp_probe", targetHost: host, targetPort: Number(port)||21 });
    };

    const handleErlangExploit = () => {
      if (!host) { alert("Enter a host for Erlang/OTP exploit"); return; }
      append("CVE-2025-32433 → " + host + ":" + (port||"22") + "\n");
      openWs({ cveId: "CVE-2025-32433", mode: "erlang_ssh", targetHost: host, targetPort: Number(port)||22, cmd });
    };

    const handleHttpProbe = () => {
      if (!selected || !targetUrl) { alert("Select a CVE and enter a URL"); return; }
      append("HTTP probe " + selected.id + " → " + targetUrl + "\n");
      const opts: Record<string,string> = {};
      if (protectedPath) opts["path"] = protectedPath;
      openWs({ cveId: selected.id, mode: "probe", targetUrl, opts });
    };

    const handleExploit = () => {
      if (!selected || !targetUrl) { alert("Select a CVE and enter a URL"); return; }
      append("Exploit " + selected.id + " → " + targetUrl + "\n");
      openWs({ cveId: selected.id, mode: "exploit", targetUrl, cmd });
    };

    const handleDifferential = () => {
      if (!targetUrl || !injectParam) { alert("Enter target URL and parameter name"); return; }
      append("Differential analysis → " + targetUrl + " [param=" + injectParam + "]\n");
      openWs({ cveId: "DIFF", mode: "differential", targetUrl, injectParam, httpMethod });
    };

    // ── CVE protocol category ──────────────────────────────────────
    const isSSH  = selected?.protocol === "ssh";
    const isFTP  = selected?.protocol === "ftp";
    const isHTTP = selected?.protocol === "http" || selected?.protocol === "https";

    // ── Render ─────────────────────────────────────────────────────
    return (
      <div className="flex flex-col md:flex-row h-full min-h-0 bg-black text-zinc-300 font-mono text-xs overflow-hidden">

        {/* ── LEFT: CVE List ─────────────────────────────────────── */}
        <div className="w-full md:w-[340px] border-r border-zinc-800 flex flex-col shrink-0 overflow-hidden">
          <div className="px-3 py-2 border-b border-zinc-800 flex items-center justify-between">
            <span className="text-red-500 font-bold tracking-widest uppercase text-[11px]">CVE Database</span>
            <span className="text-zinc-600">{cves.length} entries</span>
          </div>
          <div className="overflow-y-auto flex-1 divide-y divide-zinc-900">
            {loading && <div className="p-4 text-zinc-600">Loading CVE registry...</div>}
            {cves.map(cve => (
              <button
                key={cve.id}
                onClick={() => setSelected(cve)}
                className={"w-full text-left px-3 py-2 hover:bg-zinc-950 transition-colors " + (selected?.id === cve.id ? "bg-zinc-900 border-l-2 border-red-600" : "border-l-2 border-transparent")}
              >
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-[10px]">{protoIcon(cve.protocol)}</span>
                  <span className="text-zinc-400 font-bold tracking-wide">{cve.id}</span>
                  <span className={"ml-auto font-bold " + cvssColor(cve.cvss)}>{cve.cvss.toFixed(1)}</span>
                </div>
                <div className="text-zinc-500 text-[10px] truncate leading-4">{cve.title}</div>
                <div className="flex items-center gap-1 mt-1 flex-wrap">
                  <span className={"border text-[9px] px-1 rounded " + typeBadge(cve.type)}>{cve.type.replace("_"," ").toUpperCase()}</span>
                  <span className="text-zinc-700 text-[9px]">{cve.publishedDate}</span>
                </div>
                <div className="mt-1 h-1 bg-zinc-900 rounded overflow-hidden">
                  <div
                    className={"h-1 rounded " + (cve.cvss >= 9 ? "bg-red-500" : cve.cvss >= 7 ? "bg-orange-500" : "bg-yellow-500")}
                    style={{ width: (cve.cvss * 10) + "%" }}
                  />
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* ── CENTRE: Configuration + Actions ───────────────────── */}
        <div className="flex-1 flex flex-col overflow-hidden min-w-0">
          {/* CVE detail header */}
          {selected ? (
            <div className="px-4 py-3 border-b border-zinc-800 shrink-0 bg-zinc-950">
              <div className="flex items-start gap-3 flex-wrap">
                <div className="flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-[10px]">{protoIcon(selected.protocol)}</span>
                    <span className="text-red-400 font-bold text-sm tracking-wide">{selected.id}</span>
                    <span className={"text-lg font-bold " + cvssColor(selected.cvss)}>CVSS {selected.cvss.toFixed(1)}</span>
                    <span className={"border text-[9px] px-1 rounded " + typeBadge(selected.type)}>{selected.type.replace("_"," ").toUpperCase()}</span>
                  </div>
                  <div className="text-zinc-300 text-[11px] mt-1 leading-5">{selected.title}</div>
                  <div className="text-zinc-600 text-[10px] mt-1">
                    <span className="text-zinc-500">Affected:</span> {selected.affectedVersions}
                    <span className="text-zinc-700 mx-2">·</span>
                    <span className="text-zinc-500">Patch:</span> {selected.patchedIn}
                  </div>
                  {selected.references.length > 0 && (
                    <div className="text-[10px] mt-1">
                      {selected.references.slice(0,2).map(r => (
                        <a key={r} href={r} target="_blank" rel="noreferrer" className="text-blue-600 hover:text-blue-400 mr-3 underline truncate block max-w-xs">{r}</a>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="px-4 py-4 border-b border-zinc-800 text-zinc-600 shrink-0">
              ← Select a CVE from the list to begin
            </div>
          )}

          {/* Config & actions */}
          <div className="px-4 py-3 border-b border-zinc-800 shrink-0 space-y-3">

            {/* SSH / FTP targets */}
            <div className="flex items-end gap-2 flex-wrap">
              <div className="flex flex-col gap-1">
                <Label>Host / IP</Label>
                <Input value={host} onChange={e => setHost(e.target.value)} placeholder="192.168.1.1" className="w-36"/>
              </div>
              <div className="flex flex-col gap-1">
                <Label>Port</Label>
                <Input value={port} onChange={e => setPort(e.target.value)} placeholder="auto" className="w-16"/>
              </div>
              <div className="flex flex-col gap-1">
                <Label>Command</Label>
                <Input value={cmd} onChange={e => setCmd(e.target.value)} className="w-56" placeholder="id && whoami"/>
              </div>
              {running
                ? <Btn onClick={stopWs} className="border-red-700 text-red-400 hover:bg-red-950/40 self-end">■ STOP</Btn>
                : <>
                    <Btn onClick={handleSshProbe} className="border-cyan-800 text-cyan-400 hover:bg-cyan-950/40 self-end">SSH PROBE</Btn>
                    <Btn onClick={handleFtpProbe} className="border-blue-800 text-blue-400 hover:bg-blue-950/40 self-end">FTP PROBE</Btn>
                    {selected?.id === "CVE-2025-32433" && (
                      <Btn onClick={handleErlangExploit} className="border-red-700 text-red-400 hover:bg-red-950/40 self-end">ERLANG RCE</Btn>
                    )}
                  </>
              }
            </div>

            {/* HTTP target */}
            <div className="flex items-end gap-2 flex-wrap">
              <div className="flex flex-col gap-1 flex-1">
                <Label>Target URL (HTTP/HTTPS)</Label>
                <Input value={targetUrl} onChange={e => setTargetUrl(e.target.value)} placeholder="https://target.example.com" className="w-full"/>
              </div>
              {(selected?.id === "CVE-2025-29927") && (
                <div className="flex flex-col gap-1">
                  <Label>Protected Path</Label>
                  <Input value={protectedPath} onChange={e => setProtectedPath(e.target.value)} className="w-28" placeholder="/admin"/>
                </div>
              )}
              {!running && (
                <>
                  <Btn onClick={handleHttpProbe} className="border-yellow-800 text-yellow-400 hover:bg-yellow-950/40 self-end">DETECT</Btn>
                  {isHTTP && <Btn onClick={handleExploit} className="border-red-700 text-red-400 hover:bg-red-950/40 self-end">EXPLOIT</Btn>}
                </>
              )}
            </div>

            {/* Differential analysis */}
            <div className="flex items-end gap-2 flex-wrap">
              <div className="flex flex-col gap-1">
                <Label>Inject Param</Label>
                <Input value={injectParam} onChange={e => setInjectParam(e.target.value)} className="w-24" placeholder="q"/>
              </div>
              <div className="flex flex-col gap-1">
                <Label>HTTP Method</Label>
                <select
                  value={httpMethod}
                  onChange={e => setHttpMethod(e.target.value as "GET"|"POST")}
                  className="bg-black border border-zinc-800 text-zinc-200 text-xs px-2 py-1 font-mono focus:outline-none focus:border-red-700"
                >
                  <option>GET</option>
                  <option>POST</option>
                </select>
              </div>
              {!running && (
                <Btn onClick={handleDifferential} className="border-fuchsia-800 text-fuchsia-400 hover:bg-fuchsia-950/40 self-end">∆ DIFFERENTIAL</Btn>
              )}
              {sessionId && <span className="text-zinc-600 self-end text-[10px]">session: {sessionId.slice(0,8)}</span>}
            </div>
          </div>

          {/* Diff results summary */}
          {diffs.length > 0 && (
            <div className="px-4 py-2 border-b border-zinc-800 shrink-0 flex flex-wrap gap-2">
              {diffs.filter(d => d.confirmed || d.confidence !== "low").map((d, i) => (
                <span key={i} className={"border text-[10px] px-2 py-0.5 rounded " + (d.confirmed ? "border-green-700 text-green-400" : "border-zinc-700 text-zinc-400")}>
                  {d.confirmed ? "✓" : "?"} {d.method.toUpperCase()} Δt={d.timingDelta}ms
                </span>
              ))}
            </div>
          )}

          {/* Persistent shell — shown after a confirmed exploit */}
          {shellReady && (
            <div className="px-4 py-2 border-b border-green-900/50 bg-green-950/10 shrink-0 flex items-center gap-2">
              <span className="text-green-500 text-[10px] font-bold shrink-0">SHELL ›</span>
              <input
                value={shellCmd}
                onChange={e => setShellCmd(e.target.value)}
                onKeyDown={e => { if (e.key === "Enter") handleShellSend(); }}
                className="flex-1 bg-transparent border-none text-green-400 text-xs font-mono focus:outline-none placeholder-green-900"
                placeholder="id && whoami && uname -a"
                autoFocus
              />
              <button onClick={handleShellSend}
                className="px-2 py-0.5 border border-green-800 text-green-500 text-[10px] uppercase hover:bg-green-950/50 shrink-0">
                EXEC
              </button>
              <button onClick={stopWs}
                className="px-2 py-0.5 border border-red-800 text-red-500 text-[10px] uppercase hover:bg-red-950/50 shrink-0">
                CLOSE
              </button>
            </div>
          )}

          {/* Output console */}
          <div
            ref={outRef}
            className="flex-1 overflow-y-auto bg-black px-4 py-3 leading-5 text-[11px] whitespace-pre-wrap break-all"
            style={{ fontFamily: "monospace" }}
          >
            {output
              ? output.split("\n").map((line, i) => {
                  const col = line.startsWith("[ CONFIRMED") || line.startsWith("✓ CONFIRMED")
                    ? "text-green-400"
                    : line.startsWith("[ ERROR")
                    ? "text-red-400"
                    : line.startsWith("[ PROBE")
                    ? "text-cyan-400"
                    : line.startsWith("[ EXPLOIT")
                    ? "text-orange-400"
                    : line.startsWith("[ DONE")
                    ? "text-lime-400"
                    : line.startsWith("  [TIMING") || line.startsWith("  [CONTENT")
                    ? "text-yellow-400"
                    : "text-zinc-400";
                  return <span key={i} className={col}>{line}\n</span>;
                })
              : <span className="text-zinc-700">Output will appear here. Select a CVE, configure a target, and run a probe or exploit.</span>
            }
            {running && <span className="text-red-500 animate-pulse">█</span>}
          </div>
        </div>
      </div>
    );
  }
  