import { Router, type IRouter, type Request, type Response } from "express";
import * as net from "net";
import * as https from "https";
import * as http from "http";

const router: IRouter = Router();

const SERVICE_MAP = new Map<number, string>([
  [21, "FTP"],       [22, "SSH"],       [23, "Telnet"],    [25, "SMTP"],
  [53, "DNS"],       [80, "HTTP"],      [110, "POP3"],     [111, "RPC"],
  [135, "MSRPC"],   [139, "NetBIOS"],  [143, "IMAP"],     [443, "HTTPS"],
  [445, "SMB"],      [587, "SMTP-TLS"], [993, "IMAPS"],    [995, "POP3S"],
  [1080, "SOCKS"],  [1433, "MSSQL"],   [1521, "Oracle"],  [2049, "NFS"],
  [2375, "Docker"],  [2376, "DockerTLS"],[3000, "Node/Dev"],[3306, "MySQL"],
  [3389, "RDP"],     [4444, "Metasploit"],[5000, "Flask"], [5432, "PostgreSQL"],
  [5601, "Kibana"],  [5900, "VNC"],     [6379, "Redis"],   [6443, "Kubernetes"],
  [7474, "Neo4j"],   [8000, "HTTP-Alt"],[8080, "HTTP-Proxy"],[8443, "HTTPS-Alt"],
  [8888, "Jupyter"], [9000, "SonarQube"],[9200, "Elasticsearch"],[9300, "ES-Cluster"],
  [9418, "Git"],     [10250, "Kubelet"],[11211, "Memcached"],[15672, "RabbitMQ"],
  [27017, "MongoDB"],[27018, "Mongo-Shard"],[50070, "Hadoop"],
  [5984, "CouchDB"], [6000, "X11"],     [389, "LDAP"],     [636, "LDAPS"],
  [8161, "ActiveMQ"],[9090, "Prometheus"],[2181, "Zookeeper"],
]);

const HTTP_PORTS  = new Set([80, 3000, 5000, 5601, 7474, 8000, 8080, 8161, 8888, 9000, 9090, 15672, 50070]);
const HTTPS_PORTS = new Set([443, 2376, 6443, 8443, 10250]);

function httpBannerProbe(host: string, port: number, useHttps: boolean, timeoutMs: number): Promise<string> {
  return new Promise((resolve) => {
    const mod = useHttps ? https : http;
    let settled = false;
    const settle = (val: string) => { if (!settled) { settled = true; resolve(val); } };

    const timer = setTimeout(() => settle(""), timeoutMs);

    try {
      const req = mod.request(
        {
          hostname: host,
          port,
          path: "/",
          method: "HEAD",
          timeout: timeoutMs,
          rejectUnauthorized: false,
          headers: {
            "User-Agent": "Mozilla/5.0 (compatible; NEXUSFORGE/7.0)",
            "Connection":  "close",
          },
        },
        (res) => {
          clearTimeout(timer);
          const server  = res.headers["server"]        ?? "";
          const powered = res.headers["x-powered-by"]  ?? "";
          const via     = res.headers["via"]            ?? "";
          const status  = `HTTP ${res.statusCode}`;
          const parts   = [status, server, powered, via].map(String).filter(Boolean);
          settle(parts.join(" | ").trim().slice(0, 120));
          res.resume();
        },
      );
      req.on("error", () => { clearTimeout(timer); settle(""); });
      req.on("timeout", () => { req.destroy(); clearTimeout(timer); settle(""); });
      req.end();
    } catch {
      clearTimeout(timer);
      settle("");
    }
  });
}

function tcpBannerProbe(host: string, port: number, timeoutMs: number): Promise<{ open: boolean; banner: string }> {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let banner   = "";
    let settled  = false;

    const settle = (open: boolean) => {
      if (settled) return;
      settled = true;
      sock.destroy();
      resolve({ open, banner: banner.trim().slice(0, 120) });
    };

    const hardTimer = setTimeout(() => settle(false), timeoutMs + 200);

    sock.setTimeout(timeoutMs);
    sock.on("connect", () => {
      clearTimeout(hardTimer);
      setTimeout(() => settle(true), Math.min(300, timeoutMs / 3));
    });
    sock.on("data", (d: Buffer) => {
      banner += d.toString("utf8").replace(/[\x00-\x1f\x7f-\x9f]/g, " ");
    });
    sock.on("timeout", () => { clearTimeout(hardTimer); settle(false); });
    sock.on("error",   () => { clearTimeout(hardTimer); settle(false); });
    sock.on("close",   () => { clearTimeout(hardTimer); if (!settled) settle(false); });

    try {
      sock.connect(port, host);
    } catch {
      clearTimeout(hardTimer);
      settle(false);
    }
  });
}

async function probePort(
  host: string,
  port: number,
  timeoutMs: number,
): Promise<{ open: boolean; banner: string }> {
  const tcp = await tcpBannerProbe(host, port, timeoutMs);
  if (!tcp.open) return tcp;

  if (tcp.banner) return tcp;

  if (HTTP_PORTS.has(port)) {
    const httpBanner = await httpBannerProbe(host, port, false, Math.min(timeoutMs, 3000));
    if (httpBanner) return { open: true, banner: httpBanner };
  } else if (HTTPS_PORTS.has(port)) {
    const httpsBanner = await httpBannerProbe(host, port, true, Math.min(timeoutMs, 3000));
    if (httpsBanner) return { open: true, banner: httpsBanner };
  }

  return tcp;
}

router.post("/hub/scan", async (req: Request, res: Response) => {
  const {
    target,
    ports,
    timeout: rawTimeout = 1200,
    concurrency = 25,
  } = req.body as {
    target?: string;
    ports?: number[];
    timeout?: number;
    concurrency?: number;
  };

  if (!target || typeof target !== "string" || !target.trim()) {
    res.status(400).json({ error: "target is required" });
    return;
  }

  const host      = target.trim();
  const timeoutMs = Math.max(400, Math.min(Number(rawTimeout), 5000));
  const c         = Math.max(1, Math.min(Number(concurrency), 50));

  const portList: number[] =
    Array.isArray(ports) && ports.length > 0
      ? ports.map(Number).filter((p) => p > 0 && p < 65536)
      : Array.from(SERVICE_MAP.keys());

  const results: { port: number; open: boolean; service: string; banner: string }[] = [];

  for (let i = 0; i < portList.length; i += c) {
    const batch = portList.slice(i, i + c);
    const batchRes = await Promise.all(
      batch.map(async (port) => {
        const { open, banner } = await probePort(host, port, timeoutMs);
        return { port, open, service: SERVICE_MAP.get(port) ?? "unknown", banner };
      }),
    );
    results.push(...batchRes);
  }

  results.sort((a, b) => Number(b.open) - Number(a.open) || a.port - b.port);

  res.json({
    target: host,
    results,
    total:  results.length,
    open:   results.filter((r) => r.open).length,
  });
});

export default router;
