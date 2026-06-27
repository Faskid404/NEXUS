import * as net from "net";
import * as http from "http";
import * as https from "https";
import { execSync } from "child_process";
import { existsSync, readFileSync } from "fs";
import { Pool } from "./pool.js";
import { withRetry, isTransient } from "./retry.js";

export function bannerGrab(host: string, port: number, ms = 2500, send?: Buffer): Promise<Buffer> {
  return new Promise((resolve) => {
    const s = new net.Socket();
    let data = Buffer.alloc(0);
    s.setTimeout(ms);
    s.once("connect", () => { if (send) s.write(send); });
    s.on("data", (c: Buffer) => { data = Buffer.concat([data, c]); if (data.length > 8192) s.destroy(); });
    s.once("timeout", () => { s.destroy(); resolve(data); });
    s.once("error",   () => { s.destroy(); resolve(data); });
    s.once("close",   () => resolve(data));
    s.connect(port, host);
  });
}

export function rawFetch(
  url: string,
  method: string,
  headers: Record<string, string>,
  body: string | null,
  timeoutMs: number,
): Promise<{ status: number; body: string; headers: Record<string, string> }> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const isHttps = u.protocol === "https:";
    const bodyBuf = body != null ? Buffer.from(body, "utf8") : null;
    const reqHeaders: Record<string, string> = {
      "User-Agent": "Mozilla/5.0 (compatible; NX-Scanner/1.0)",
      ...headers,
      ...(bodyBuf ? { "Content-Length": String(bodyBuf.length) } : {}),
    };
    const opts: https.RequestOptions = {
      hostname: u.hostname,
      port: u.port || (isHttps ? "443" : "80"),
      path: u.pathname + u.search,
      method: method.toUpperCase(),
      headers: reqHeaders,
      rejectUnauthorized: false,
      timeout: timeoutMs,
    };
    const proto = isHttps ? https : http;
    const req = proto.request(opts, (res) => {
      let d = "";
      let truncated = false;
      res.on("data", (c: Buffer) => { d += c.toString(); if (d.length > 131072) { truncated = true; res.destroy(); } });
      res.on("end", () => {
        const rh: Record<string, string> = {};
        for (const [k, v] of Object.entries(res.headers)) {
          if (v !== undefined) rh[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : v;
        }
        const body = d.slice(0, 131072) + (truncated ? "\n[...response truncated at 128 KB...]" : "");
        resolve({ status: res.statusCode ?? 0, body, headers: rh });
      });
    });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("timeout")); });
    if (bodyBuf) req.write(bodyBuf);
    req.end();
  });
}

export interface PortResult {
  port:    number;
  open:    boolean;
  banner:  string;
  latency: number;
  service: string;
  version?: string;
  cveHints: string[];
}

export interface AdaptiveScanOpts {
  timeoutMs?:    number;
  concurrency?:  number;
  jitterMs?:     number;
  retries?:      number;
  sendProbes?:   boolean;
  adaptiveDelay?: boolean;
}

const PROBE_PAYLOADS: Record<number, Buffer> = {
  21:    Buffer.from("USER anonymous\r\n"),
  22:    Buffer.from("SSH-2.0-OpenSSH_8.9p1\r\n"),
  25:    Buffer.from("EHLO nexus\r\n"),
  80:    Buffer.from("HEAD / HTTP/1.0\r\nHost: target\r\nConnection: close\r\n\r\n"),
  110:   Buffer.from("USER nx\r\n"),
  143:   Buffer.from("A001 CAPABILITY\r\n"),
  443:   Buffer.from("HEAD / HTTP/1.0\r\nHost: target\r\nConnection: close\r\n\r\n"),
  3306:  Buffer.from("\x0e\x00\x00\x01\x85\xa6\x0f\x00"),
  5432:  Buffer.from("\x00\x00\x00\x08\x04\xd2\x16\x2f"),
  6379:  Buffer.from("*1\r\n$4\r\nPING\r\n"),
  9200:  Buffer.from("GET / HTTP/1.0\r\nHost: target\r\nConnection: close\r\n\r\n"),
  11211: Buffer.from("version\r\n"),
  27017: Buffer.from("\x3a\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00"),
};

const SERVICE_MAP: Record<number, string> = {
  21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",111:"RPC",
  135:"MSRPC",139:"NetBIOS",143:"IMAP",161:"SNMP",389:"LDAP",443:"HTTPS",445:"SMB",
  465:"SMTPS",587:"SMTP-TLS",636:"LDAPS",873:"Rsync",993:"IMAPS",995:"POP3S",
  1080:"SOCKS",1433:"MSSQL",1521:"Oracle",2049:"NFS",2375:"Docker",2376:"DockerTLS",
  2379:"etcd",3000:"Node/Dev",3306:"MySQL",3389:"RDP",4444:"Metasploit",
  5000:"Flask/Dev",5432:"PostgreSQL",5601:"Kibana",5900:"VNC",5984:"CouchDB",
  5985:"WinRM",5986:"WinRMS",6379:"Redis",6443:"Kubernetes",7474:"Neo4j",
  8000:"HTTP-Alt",8080:"HTTP-Proxy",8443:"HTTPS-Alt",8888:"Jupyter",
  9000:"SonarQube",9090:"Prometheus",9200:"Elasticsearch",9300:"ES-Cluster",
  10250:"Kubelet",11211:"Memcached",15672:"RabbitMQ",27017:"MongoDB",50070:"Hadoop",
};

const VERSION_SIGS: Array<{ re: RegExp; svc: string }> = [
  { re: /OpenSSH[_ ](\S+)/,                  svc: "SSH"           },
  { re: /220.*vsftpd[_ ]?(\S+)/i,             svc: "FTP"           },
  { re: /220.*FileZilla[_ ](\S+)/i,           svc: "FTP"           },
  { re: /\+OK.*Dovecot[_ ](\S+)/i,            svc: "POP3"          },
  { re: /\* OK.*Dovecot[_ ](\S+)/i,           svc: "IMAP"          },
  { re: /Redis[_ ](\S+)/i,                    svc: "Redis"         },
  { re: /Memcached[_ ](\S+)/i,                svc: "Memcached"     },
  { re: /Apache[/ ](\S+)/i,                   svc: "HTTP-Apache"   },
  { re: /nginx[/ ](\S+)/i,                    svc: "HTTP-nginx"    },
  { re: /Microsoft-IIS[/ ](\S+)/i,            svc: "HTTP-IIS"      },
  { re: /MySQL.*V?(\d+\.\d+\.\d+)/,           svc: "MySQL"         },
  { re: /PostgreSQL.*?(\d+\.\d+)/i,           svc: "PostgreSQL"    },
  { re: /MongoDB.*?(\d+\.\d+\.\d+)/i,         svc: "MongoDB"       },
  { re: /Elasticsearch[/ ](\S+)/i,            svc: "Elasticsearch" },
  { re: /RabbitMQ[_ ](\S+)/i,                 svc: "RabbitMQ"      },
  { re: /PONG/i,                               svc: "Redis"         },
];

const CVE_MAP: Record<string, string[]> = {
  "SSH":           ["CVE-2023-38408 (ssh-agent RCE)", "CVE-2018-15473 (username enum)"],
  "Redis":         ["CVE-2022-0543 (Lua sandbox escape)", "CVE-2023-41056 (integer overflow)"],
  "MySQL":         ["CVE-2021-27928 (wsrep command injection)"],
  "Elasticsearch": ["CVE-2021-22145 (log4j RCE via logged input)", "CVE-2015-1427 (Groovy sandbox escape)"],
  "HTTP-Apache":   ["CVE-2021-41773 (path traversal)", "CVE-2021-42013 (RCE)"],
  "MongoDB":       ["CVE-2021-20328 (auth bypass pre-5.0)"],
  "Docker":        ["CVE-2019-5736 (runc escape)", "CVE-2024-21626 (runc WORKDIR escape)"],
  "Kubernetes":    ["CVE-2018-1002105 (API server privilege escalation)"],
  "Jupyter":       ["Unauthenticated RCE — execute arbitrary code if no token set"],
  "etcd":          ["CVE-2018-16886 (client cert bypass)"],
  "CouchDB":       ["CVE-2017-12636 (query server RCE)"],
  "Memcached":     ["CVE-2022-48571 (NULL dereference)", "Often exposed with no auth"],
  "RabbitMQ":      ["CVE-2023-46118 (HTTP API DoS)", "Default creds: guest:guest"],
};

function fingerprintBanner(banner: string, port: number): { service: string; version?: string; cveHints: string[] } {
  let service = SERVICE_MAP[port] ?? "Unknown";
  let version: string | undefined;

  for (const sig of VERSION_SIGS) {
    const m = banner.match(sig.re);
    if (m) {
      service = sig.svc;
      version = m[1];
      break;
    }
  }

  const cveHints = CVE_MAP[service] ?? [];
  return { service, version, cveHints };
}

const BANNER_CACHE = new Map<string, { data: Buffer; ts: number }>();
const CACHE_TTL    = 120_000;

async function cachedBannerGrab(host: string, port: number, ms: number, probe?: Buffer): Promise<Buffer> {
  const key = `${host}:${port}`;
  const hit = BANNER_CACHE.get(key);
  if (hit && Date.now() - hit.ts < CACHE_TTL) return hit.data;
  const data = await bannerGrab(host, port, ms, probe);
  if (data.length > 0) BANNER_CACHE.set(key, { data, ts: Date.now() });
  return data;
}

export async function adaptiveScan(
  host: string,
  ports: number[],
  opts: AdaptiveScanOpts = {},
): Promise<PortResult[]> {
  const {
    timeoutMs    = 2500,
    concurrency  = 64,
    jitterMs     = 80,
    retries      = 1,
    sendProbes   = true,
    adaptiveDelay = true,
  } = opts;

  const pool      = new Pool(concurrency);
  let   dynDelay  = 0;

  const results: PortResult[] = await pool.map(ports, async (port) => {
    if (jitterMs > 0) {
      const cap = adaptiveDelay ? Math.max(jitterMs, dynDelay) : jitterMs;
      await new Promise(r => setTimeout(r, Math.random() * cap));
    }

    const probe = sendProbes ? PROBE_PAYLOADS[port] : undefined;
    const t0    = Date.now();

    const raw = await withRetry(
      () => cachedBannerGrab(host, port, timeoutMs, probe),
      { attempts: retries + 1, baseMs: 200, retryIf: isTransient },
    );

    const latency = Date.now() - t0;
    const open    = raw.length > 0;
    const bannerStr = raw.toString("utf8").replace(/[\x00-\x08\x0b-\x1f\x7f]/g, "").trim().slice(0, 512);

    if (open && adaptiveDelay) dynDelay = Math.min(dynDelay + 10, 300);

    const fp = fingerprintBanner(bannerStr, port);
    return { port, open, banner: bannerStr, latency, ...fp };
  });

  return results.sort((a, b) => a.port - b.port);
}

export function parseKnownHosts(): string[] {
  const paths = [
    `${process.env["HOME"] ?? "/root"}/.ssh/known_hosts`,
    "/root/.ssh/known_hosts",
    "/etc/ssh/ssh_known_hosts",
  ];
  const hosts = new Set<string>();
  for (const p of paths) {
    if (!existsSync(p)) continue;
    try {
      for (const line of readFileSync(p, "utf8").split("\n")) {
        const part = line.trim().split(/\s+/)[0];
        if (!part || part.startsWith("#") || part.startsWith("|")) continue;
        for (const t of part.split(",")) {
          const h = t.startsWith("[") ? t.replace(/^\[|\]:\d+$/g, "") : t;
          if (h) hosts.add(h.trim());
        }
      }
    } catch { continue; }
  }
  return [...hosts];
}

export function parseProcNetTcp(): string[] {
  const hosts = new Set<string>();
  for (const file of ["/proc/net/tcp", "/proc/net/tcp6"]) {
    if (!existsSync(file)) continue;
    try {
      for (const line of readFileSync(file, "utf8").split("\n").slice(1)) {
        const parts = line.trim().split(/\s+/);
        if (parts.length < 3 || !parts[2] || parts[2] === "00000000:0000") continue;
        const addrHex = parts[2].split(":")[0];
        if (!addrHex || addrHex === "00000000") continue;
        const b = Buffer.from(addrHex, "hex").reverse();
        const ip = `${b[0]}.${b[1]}.${b[2]}.${b[3]}`;
        if (!ip.startsWith("0.") && !ip.startsWith("127.")) hosts.add(ip);
      }
    } catch { continue; }
  }
  return [...hosts];
}

export function discoverLocalHosts(): string[] {
  const hosts = new Set<string>();
  try {
    const out = execSync("arp -n 2>/dev/null || ip neigh 2>/dev/null", { timeout: 3000 }).toString();
    for (const m of out.matchAll(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g)) {
      if (m[1] && !m[1].startsWith("127.")) hosts.add(m[1]);
    }
  } catch { }
  for (const h of parseKnownHosts()) hosts.add(h);
  for (const h of parseProcNetTcp())  hosts.add(h);
  return [...hosts];
}

export interface ScanSummary {
  host:       string;
  openPorts:  number;
  results:    PortResult[];
  discovered: string[];
  elapsed:    number;
}

const TOP_PORTS = [
  21,22,23,25,53,80,110,135,139,143,389,443,445,465,587,
  636,873,993,995,1080,1433,1521,2049,2375,2376,2379,3000,
  3306,3389,4444,5000,5432,5601,5900,5984,5985,5986,6379,
  6443,7474,8000,8080,8443,8888,9000,9090,9200,9300,10250,
  11211,15672,27017,50070,
];

export async function fullScan(
  host: string,
  ports?: number[],
  opts: AdaptiveScanOpts = {},
): Promise<ScanSummary> {
  const t0      = Date.now();
  const results = await adaptiveScan(host, ports ?? TOP_PORTS, opts);
  return {
    host,
    openPorts:  results.filter(r => r.open).length,
    results,
    discovered: discoverLocalHosts(),
    elapsed:    Date.now() - t0,
  };
}

export interface StealthScanOpts {
  ports?:         number[];
  timeoutMs?:     number;
  jitterMinMs?:   number;
  jitterMaxMs?:   number;
  concurrency?:   number;
  decoyRatio?: number;
}

export interface PrioritizedHost {
  host:     string;
  priority: number;
  source:   "known_hosts" | "arp" | "proc_net" | "cidr";
}

export function buildPrioritizedHostList(cidrHosts: string[]): PrioritizedHost[] {
  const result = new Map<string, PrioritizedHost>();

  const addHost = (host: string, source: PrioritizedHost["source"], priority: number) => {
    const existing = result.get(host);
    if (!existing || priority > existing.priority) {
      result.set(host, { host, priority, source });
    }
  };

  for (const h of parseKnownHosts()) addHost(h, "known_hosts", 3);

  try {
    const arpOut = execSync("arp -n 2>/dev/null || ip neigh 2>/dev/null", { timeout: 3000 }).toString();
    for (const m of arpOut.matchAll(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g)) {
      if (m[1] && !m[1].startsWith("127.")) addHost(m[1], "arp", 2);
    }
  } catch { }

  for (const h of parseProcNetTcp()) addHost(h, "proc_net", 2);

  for (const h of cidrHosts) {
    if (!result.has(h)) addHost(h, "cidr", 1);
  }

  return [...result.values()].sort((a, b) => b.priority - a.priority);
}

export async function scanStealthy(
  hosts: string[],
  opts: StealthScanOpts = {},
): Promise<Map<string, PortResult[]>> {
  const {
    ports       = TOP_PORTS,
    timeoutMs   = 4000,
    jitterMinMs = 30_000,
    jitterMaxMs = 300_000,
    concurrency = 2,
    decoyRatio  = 0.12,
  } = opts;

  const results = new Map<string, PortResult[]>();
  const allHosts = [...hosts];

  const injectDecoys = (list: string[]): string[] => {
    if (decoyRatio <= 0) return list;
    const decoyCount = Math.ceil(list.length * decoyRatio);
    const decoys = Array.from({ length: decoyCount }, () => {
      const n = Math.floor(Math.random() * 0xffffff);
      return `10.${(n >> 16) & 0xff}.${(n >> 8) & 0xff}.${n & 0xff}`;
    });
    const out = [...list];
    for (const d of decoys) {
      const pos = Math.floor(Math.random() * (out.length + 1));
      out.splice(pos, 0, d);
    }
    return out;
  };

  const shuffledWithDecoys = injectDecoys(allHosts);
  let i = 0;

  while (i < shuffledWithDecoys.length) {
    const batch = shuffledWithDecoys.slice(i, i + concurrency);
    i += concurrency;

    await Promise.all(batch.map(async (host) => {
      const jitter = jitterMinMs + Math.random() * (jitterMaxMs - jitterMinMs);
      await new Promise<void>(r => setTimeout(r, jitter));

      try {
        const portResults = await adaptiveScan(host, ports, {
          timeoutMs,
          concurrency: 4,
          jitterMs:    2000 + Math.random() * 4000,
          retries:     0,
          adaptiveDelay: true,
        });
        const open = portResults.filter(p => p.open);
        if (open.length > 0) results.set(host, open);
      } catch { }
    }));
  }

  return results;
}
