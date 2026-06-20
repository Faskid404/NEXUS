const _counts = new Map<string, number>();
const _startMs = Date.now();
let _totalEver = 0;

export const WS_CHANNEL_META: ReadonlyArray<{ path: string; label: string; group: string }> = [
  { path: "/api/ws/exec",         label: "Stream Exec",      group: "CORE" },
  { path: "/api/ws/scan",         label: "Target Scanner",   group: "CORE" },
  { path: "/api/ws/chain",        label: "Exploit Chain",    group: "CORE" },
  { path: "/api/ws/probe",        label: "Probe Target",     group: "CORE" },
  { path: "/api/ws/autoexploit",  label: "Auto-Exploit",     group: "AUTO" },
  { path: "/api/ws/postexploit",  label: "Post-Exploit",     group: "AUTO" },
  { path: "/api/ws/cve",          label: "CVE Exploit",      group: "AUTO" },
  { path: "/api/ws/mutation",     label: "Mutation Scanner", group: "SCAN" },
  { path: "/api/ws/chainreactor", label: "Chain Reactor",    group: "SCAN" },
  { path: "/api/ws/c2",           label: "C2 Operator",      group: "C2"       },
  { path: "/api/ws/c2-implant",   label: "C2 Implant",       group: "C2"       },
  { path: "/api/ws/c2-sniffer",   label: "C2 Sniffer",       group: "C2"       },
  { path: "/api/ws/ironworm",     label: "IronWorm Scanner", group: "IRONWORM" },
];

export function incChannel(path: string): void {
  _counts.set(path, (_counts.get(path) ?? 0) + 1);
  _totalEver++;
}

export function decChannel(path: string): void {
  _counts.set(path, Math.max(0, (_counts.get(path) ?? 1) - 1));
}

export function getWsStats(): {
  uptimeMs:    number;
  totalEver:   number;
  activeTotal: number;
  channels:    Record<string, number>;
} {
  const channels: Record<string, number> = {};
  for (const { path } of WS_CHANNEL_META) {
    channels[path] = _counts.get(path) ?? 0;
  }
  return {
    uptimeMs:    Date.now() - _startMs,
    totalEver:   _totalEver,
    activeTotal: [..._counts.values()].reduce((a, b) => a + b, 0),
    channels,
  };
}
