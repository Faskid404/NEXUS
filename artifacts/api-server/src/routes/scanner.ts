import { Router, type IRouter, type Request, type Response } from "express";
import * as net from "net";
import * as https from "https";
import * as http from "http";
import { createLogger } from "../lib/logger.js";

const log = createLogger("scanner");
const router: IRouter = Router();

/* ── Service map ─────────────────────────────────────────────────────*/
const SERVICE_MAP = new Map<number, string>([
  [21, "FTP"],        [22, "SSH"],         [23, "Telnet"],     [25, "SMTP"],
  [53, "DNS"],        [80, "HTTP"],        [110, "POP3"],      [111, "RPC"],
  [135, "MSRPC"],    [139, "NetBIOS"],    [143, "IMAP"],      [443, "HTTPS"],
  [445, "SMB"],       [587, "SMTP-TLS"],   [993, "IMAPS"],     [995, "POP3S"],
  [1080, "SOCKS"],   [1433, "MSSQL"],     [1521, "Oracle"],   [2049, "NFS"],
  [2181, "Zookeeper"],[2375, "Docker"],   [2376, "DockerTLS"],[3000, "Node/Dev"],
  [3306, "MySQL"],    [3389, "RDP"],       [4444, "Metasploit"],[5000, "Flask"],
  [5432, "PostgreSQL"],[5601, "Kibana"],  [5900, "VNC"],       [6379, "Redis"],
  [6443, "Kubernetes"],[7474, "Neo4j"],   [8000, "HTTP-Alt"],  [8080, "HTTP-Proxy"],
  [8443, "HTTPS-Alt"],[8888, "Jupyter"],  [9000, "SonarQube"], [9090, "Prometheus"],
  [9200, "Elasticsearch"],[9300, "ES-Cluster"],[9418, "Git"],  [10250, "Kubelet"],
  [11211, "Memcached"],[15672, "RabbitMQ"],[27017, "MongoDB"], [27018, "Mongo-Shard"],
  [50070, "Hadoop"],  [5984, "CouchDB"],  [6000, "X11"],       [389, "LDAP"],
  [636, "LDAPS"],     [8161, "ActiveMQ"], [9090, "Prometheus"],[6666, "IRC"],
  [873, "Rsync"],     [1194, "OpenVPN"],  [1883, "MQTT"],      [4369, "Erlang-EPM"],
  [5555, "ADB"],      [6881, "BitTorrent"],[9418, "Git"],      [27443, "Mongo-TLS"],
]);

const HTTP_PORTS  = new Set([80, 3000, 5000, 5601, 7474, 8000, 8080, 8161, 8888, 9000, 9090, 15672, 50070]);
const HTTPS_PORTS = new Set([443, 2376, 6443, 8443, 10250]);

/* ── CVE hints per service ────────────────────────────────────────── */
const CVE_HINTS: Record<string, string[]> = {
  FTP:           ["CVE-2015-3306 (ProFTPD RCE)", "CVE-2011-2523 (vsftpd backdoor)"],
  SSH:           ["CVE-2023-38408 (OpenSSH agent forwarding RCE)", "CVE-2024-6387 (regreSSHion — OpenSSH race condition)"],
  Telnet:        ["Cleartext credentials — brute-forceable"],
  SMTP:          ["CVE-2020-7247 (OpenSMTPD RCE)", "Open relay check recommended"],
  DNS:           ["CVE-2020-1350 (SIGRed — Windows DNS)", "Zone transfer exposure"],
  HTTP:          ["Enumerate paths; check for CVE-2021-41773 (Apache path traversal)"],
  HTTPS:         ["Check TLS version; CVE-2014-0160 (Heartbleed)", "CVE-2022-0778 (OpenSSL DoS)"],
  MSSQL:         ["CVE-2020-0618 (SQL Server RCE)", "xp_cmdshell check"],
  MySQL:         ["CVE-2012-2122 (auth bypass)", "Check for remote root login"],
  PostgreSQL:    ["CVE-2019-9193 (COPY TO/FROM PROGRAM RCE with SUPERUSER)"],
  Redis:         ["CVE-2022-0543 (Lua sandbox escape)", "No-auth exposure — common"],
  MongoDB:       ["CVE-2013-1892 (remote code execution)", "Unauthenticated access check"],
  Elasticsearch: ["CVE-2015-1427 (Groovy sandbox bypass RCE)", "CVE-2021-22145 (info leak)"],
  Docker:        ["CVE-2019-5736 (runc breakout)", "Unauthenticated API — full container compromise"],
  Kubernetes:    ["CVE-2018-1002105 (API server privilege escalation)"],
  Kubelet:       ["CVE-2018-1002105 — anonymous API often enabled; exec API exposure"],
  RDP:           ["CVE-2019-0708 (BlueKeep — no-auth RCE)", "CVE-2019-1182 (DejaBlue)"],
  SMB:           ["CVE-2017-0144 (EternalBlue / WannaCry)", "CVE-2020-0796 (SMBGhost)"],
  VNC:           ["CVE-2006-2369 (auth bypass)", "Weak/no password common"],
  Jenkins:       ["CVE-2024-23897 (arbitrary file read)", "CVE-2019-1003000 (sandbox bypass)"],
  Jupyter:       ["No-auth notebook execution — common misconfig"],
  Prometheus:    ["Unauthenticated metrics scrape — can expose env vars/secrets"],
  Zookeeper:     ["CVE-2019-0201 (SASL admin bypass)"],
  MQTT:          ["Unauthenticated message broker — common in IoT"],
  Erlang:        ["CVE-2011-0766 (weak cookie auth — trivial RCE)"],
};

/* ── OS fingerprinting hints from open services ──────────────────── */
function guessOs(openPorts: number[], banners: Record<number, string>): string {
  const portSet = new Set(openPorts);
  // Windows signals
  if (portSet.has(3389) || portSet.has(135) || portSet.has(445) || portSet.has(139)) return "Windows";
  // Linux signals
  if (portSet.has(22)) {
    const sshBanner = banners[22] ?? "";
    if (sshBanner.toLowerCase().includes("ubuntu"))  return "Linux (Ubuntu)";
    if (sshBanner.toLowerCase().includes("debian"))  return "Linux (Debian)";
    if (sshBanner.toLowerCase().includes("centos"))  return "Linux (CentOS)";
    if (sshBanner.toLowerCase().includes("alpine"))  return "Linux (Alpine)";
    return "Linux";
  }
  if (portSet.has(111) || portSet.has(2049)) return "Linux/Unix (NFS/RPC)";
  if (portSet.has(5432)) return "Likely Linux (PostgreSQL)";
  return "Unknown";
}

/* ── HTTP banner probe ────────────────────────────────────────────── */
function httpBannerProbe(host: string, port: number, useHttps: boolean, timeoutMs: number): Promise<string> {
  return new Promise((resolve) => {
    const mod = useHttps ? https : http;
    let settled = false;
    const settle = (val: string) => { if (!settled) { settled = true; resolve(val); } };
    const timer = setTimeout(() => settle(""), timeoutMs);
    try {
      const req = mod.request(
        {
          hostname: host, port, path: "/", method: "HEAD", timeout: timeoutMs,
          rejectUnauthorized: false,
          headers: {
            "User-Agent": "Mozilla/5.0 (compatible; NEXUSFORGE/11.0)",
            "Connection":  "close",
          },
        },
        (res) => {
          clearTimeout(timer);
          const server  = String(res.headers["server"]        ?? "");
          const powered = String(res.headers["x-powered-by"]  ?? "");
          const via     = String(res.headers["via"]            ?? "");
          const status  = `HTTP ${res.statusCode}`;
          settle([status, server, powered, via].filter(Boolean).join(" | ").trim().slice(0, 150));
          res.resume();
        },
      );
      req.on("error",   () => { clearTimeout(timer); settle(""); });
      req.on("timeout", () => { req.destroy(); clearTimeout(timer); settle(""); });
      req.end();
    } catch { clearTimeout(timer); settle(""); }
  });
}

/* ── TCP banner probe ────────────────────────────────────────────── */
function tcpBannerProbe(host: string, port: number, timeoutMs: number): Promise<{ open: boolean; banner: string }> {
  return new Promise((resolve) => {
    const sock   = new net.Socket();
    let   banner  = "";
    let   settled = false;
    const settle  = (open: boolean) => { if (settled) return; settled = true; sock.destroy(); resolve({ open, banner: banner.replace(/[\r\n]+$/, "").trim().slice(0, 200) }); };
    const timer   = setTimeout(() => settle(false), timeoutMs);
    sock.once("connect", () => {
      clearTimeout(timer);
      const wait = setTimeout(() => settle(true), Math.min(timeoutMs / 3, 800));
      sock.once("data", (d) => { clearTimeout(wait); banner = d.toString("utf8", 0, 300); settle(true); });
    });
    sock.once("error",   () => { clearTimeout(timer); settle(false); });
    sock.once("timeout", () => settle(false));
    sock.setTimeout(timeoutMs);
    try { sock.connect(port, host); } catch { clearTimeout(timer); settle(false); }
  });
}

/* ── Single port scan ─────────────────────────────────────────────── */
async function scanPort(
  host: string, port: number, timeoutMs: number,
): Promise<{ port: number; open: boolean; service: string; banner: string; cveHints: string[] }> {
  const service  = SERVICE_MAP.get(port) ?? "Unknown";
  const isHttp   = HTTP_PORTS.has(port);
  const isHttps  = HTTPS_PORTS.has(port);

  const { open, banner } = await tcpBannerProbe(host, port, timeoutMs);
  if (!open) return { port, open: false, service, banner: "", cveHints: [] };

  let enrichedBanner = banner;
  if (isHttp || isHttps) {
    const httpB = await httpBannerProbe(host, port, isHttps, timeoutMs);
    if (httpB) enrichedBanner = httpB;
  }

  // CVE hints based on service name
  const cveHints = CVE_HINTS[service] ?? [];
  // Additional hints from banner content
  const bl = enrichedBanner.toLowerCase();
  if (bl.includes("apache/2.2")) cveHints.push("Apache 2.2 — multiple high CVEs; upgrade to 2.4+");
  if (bl.includes("openssh_6") || bl.includes("openssh_5")) cveHints.push("OpenSSH < 7 — CVE-2016-6210 (user enum)");
  if (bl.includes("iis/6.0"))   cveHints.push("IIS 6.0 — CVE-2017-7269 (WebDAV buffer overflow)");
  if (bl.includes("jenkins"))   cveHints.push("Jenkins — CVE-2024-23897 (arbitrary file read)");
  if (bl.includes("struts"))    cveHints.push("Apache Struts — CVE-2017-5638 (OGNL injection, Equifax)");
  if (bl.includes("tomcat"))    cveHints.push("Tomcat — CVE-2020-1938 (GhostCat — AJP file read)");
  if (bl.includes("log4j") || bl.includes("log4"))  cveHints.push("Log4j detected — CVE-2021-44228 (Log4Shell)");
  if (bl.includes("spring"))    cveHints.push("Spring Framework — CVE-2022-22965 (Spring4Shell)");

  return { port, open: true, service, banner: enrichedBanner, cveHints };
}

/* ── Concurrent batch scanner ─────────────────────────────────────── */
async function scanPortsConcurrent(
  host: string, ports: number[], timeoutMs: number, concurrency = 50,
): Promise<{ port: number; open: boolean; service: string; banner: string; cveHints: string[] }[]> {
  const results: { port: number; open: boolean; service: string; banner: string; cveHints: string[] }[] = [];
  const q = [...ports];

  async function worker(): Promise<void> {
    while (q.length > 0) {
      const p = q.shift()!;
      results.push(await scanPort(host, p, timeoutMs));
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, ports.length) }, () => worker());
  await Promise.all(workers);
  return results.sort((a, b) => a.port - b.port);
}

/* ── Quick scan: top-25 most exploitable ports ─────────────────────── */
const QUICK_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 1521,
  2375, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017, 50070];

/* ── Routes ────────────────────────────────────────────────────────── */

/** POST /scanner/scan — full configurable scan */
router.post("/scanner/scan", async (req: Request, res: Response) => {
  const {
    host,
    ports       = [],
    timeout     = 1500,
    concurrency = 50,
  } = req.body as { host?: string; ports?: number[]; timeout?: number; concurrency?: number };

  if (!host || typeof host !== "string") {
    res.status(400).json({ error: "host is required" });
    return;
  }

  const sanitisedHost = host.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  const portList      = Array.isArray(ports) && ports.length > 0
    ? ports.slice(0, 10_000).map(Number).filter(n => n > 0 && n < 65536)
    : QUICK_PORTS;
  const timeoutMs     = Math.min(Math.max(Number(timeout) || 1500, 200), 10_000);
  const concurrencyN  = Math.min(Math.max(Number(concurrency) || 50, 1), 200);

  log.info({ host: sanitisedHost, portCount: portList.length, timeoutMs, concurrencyN }, "scan started");
  const start   = Date.now();
  const results = await scanPortsConcurrent(sanitisedHost, portList, timeoutMs, concurrencyN);
  const elapsed = Date.now() - start;

  const open = results.filter(r => r.open);
  log.info({ host: sanitisedHost, open: open.length, elapsed }, "scan completed");

  const bannerMap: Record<number, string> = {};
  for (const r of open) bannerMap[r.port] = r.banner;

  res.json({
    host:        sanitisedHost,
    portsScanned: portList.length,
    openPorts:   open.length,
    elapsed,
    os:          guessOs(open.map(r => r.port), bannerMap),
    results:     open,
    allResults:  results,
  });
});

/** POST /scanner/quick — fast top-25 scan */
router.post("/scanner/quick", async (req: Request, res: Response) => {
  const { host, timeout = 1200 } = req.body as { host?: string; timeout?: number };
  if (!host) { res.status(400).json({ error: "host required" }); return; }
  const sanitisedHost = (host as string).trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  const timeoutMs     = Math.min(Math.max(Number(timeout) || 1200, 200), 5_000);

  const results = await scanPortsConcurrent(sanitisedHost, QUICK_PORTS, timeoutMs, 25);
  const open    = results.filter(r => r.open);
  const bannerMap: Record<number, string> = {};
  for (const r of open) bannerMap[r.port] = r.banner;

  res.json({
    host: sanitisedHost, mode: "quick",
    openPorts: open.length,
    os: guessOs(open.map(r => r.port), bannerMap),
    results: open,
  });
});

/** GET /scanner/services — list known port→service mappings */
router.get("/scanner/services", (_req: Request, res: Response) => {
  res.json(Object.fromEntries(SERVICE_MAP));
});

export default router;
