import * as net from "net";
import type { WebSocket } from "ws";
import { logger } from "../lib/logger.js";

interface ScanRequest {
  target: string;
  ports?: number[];
  timeout?: number;
  concurrency?: number;
}

interface PortResultMsg {
  type: "portResult";
  port: number;
  open: boolean;
  service: string;
  banner: string;
  scanned: number;
  total: number;
  openCount: number;
}

const SERVICE_MAP = new Map<number, string>([
  [21, "FTP"],        [22, "SSH"],        [23, "Telnet"],     [25, "SMTP"],
  [53, "DNS"],        [80, "HTTP"],       [110, "POP3"],      [111, "RPC"],
  [119, "NNTP"],      [135, "MSRPC"],     [139, "NetBIOS"],   [143, "IMAP"],
  [161, "SNMP"],      [194, "IRC"],       [389, "LDAP"],      [443, "HTTPS"],
  [445, "SMB"],       [465, "SMTPS"],     [587, "SMTP-TLS"],  [636, "LDAPS"],
  [873, "Rsync"],     [993, "IMAPS"],     [995, "POP3S"],     [1080, "SOCKS"],
  [1194, "OpenVPN"],  [1433, "MSSQL"],    [1521, "Oracle"],   [1723, "PPTP"],
  [2049, "NFS"],      [2375, "Docker"],   [2376, "DockerTLS"],[2379, "etcd"],
  [3000, "Node/Dev"], [3306, "MySQL"],    [3389, "RDP"],      [4444, "Metasploit"],
  [5000, "Flask/Dev"],[5432, "PostgreSQL"],[5601, "Kibana"],  [5900, "VNC"],
  [5984, "CouchDB"],  [5985, "WinRM"],    [5986, "WinRMS"],   [6379, "Redis"],
  [6443, "Kubernetes"],[7474, "Neo4j"],   [8000, "HTTP-Alt"], [8080, "HTTP-Proxy"],
  [8443, "HTTPS-Alt"],[8888, "Jupyter"],  [9000, "SonarQube"],[9090, "Prometheus"],
  [9200, "Elasticsearch"],[9300, "ES-Cluster"],[9418, "Git"],
  [10250, "Kubelet"], [11211, "Memcached"],[15672, "RabbitMQ"],
  [27017, "MongoDB"], [27018, "Mongo-Shard"],[50070, "Hadoop"],
]);

const HTTP_PORTS  = new Set([80,8000,8001,8008,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8180,3000,3001,4000,5000,9000,9090,10000]);
const HTTPS_PORTS = new Set([443,8443,4443,8444,9443,10443]);
const TEXT_BANNER_PORTS = new Set([21,22,25,110,111,143,389,587,636,993,995,6379,5984,27017]);

function grabBanner(
  host: string,
  port: number,
  timeoutMs: number,
): Promise<{ open: boolean; banner: string }> {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let data = "";
    let connected = false;
    let settled = false;

    const finish = (open: boolean) => {
      if (settled) return;
      settled = true;
      try { sock.destroy(); } catch { /* ignore */ }
      const cleaned = data
        .replace(/\r\n/g, "\n")
        .replace(/[\x00-\x08\x0b-\x1f\x7f-\x9f]/g, "")
        .trim()
        .split("\n")[0]
        ?.slice(0, 120) ?? "";
      resolve({ open, banner: cleaned });
    };

    const hardTimer = setTimeout(() => finish(connected), timeoutMs + 400);

    sock.setTimeout(timeoutMs);

    sock.on("connect", () => {
      connected = true;
      clearTimeout(hardTimer);

      if (HTTPS_PORTS.has(port)) {
        finish(true);
        return;
      }
      if (HTTP_PORTS.has(port)) {
        sock.write(`HEAD / HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`);
        setTimeout(() => finish(true), Math.min(600, timeoutMs / 2));
        return;
      }
      if (TEXT_BANNER_PORTS.has(port)) {
        setTimeout(() => finish(true), Math.min(500, timeoutMs / 2));
        return;
      }
      setTimeout(() => finish(true), Math.min(300, timeoutMs / 3));
    });

    sock.on("data", (chunk: Buffer) => {
      data += chunk.toString("utf8").slice(0, 300);
    });

    sock.on("timeout", () => { clearTimeout(hardTimer); finish(connected); });
    sock.on("error",   () => { clearTimeout(hardTimer); finish(false); });
    sock.on("close",   () => { clearTimeout(hardTimer); finish(connected); });

    try {
      sock.connect(port, host);
    } catch {
      clearTimeout(hardTimer);
      finish(false);
    }
  });
}

function parseHint(port: number, banner: string): string {
  if (!banner) return "";
  if (banner.startsWith("SSH-")) return banner.slice(0, 80);
  if (banner.startsWith("220") || banner.startsWith("+OK") || banner.startsWith("-ERR")) {
    return banner.split("\n")[0]?.trim().slice(0, 80) ?? "";
  }
  const bl = banner.toLowerCase();
  if (bl.includes("http/")) {
    const server = banner.match(/server:\s*([^\r\n]+)/i)?.[1]?.trim() ?? "";
    const status = banner.split("\n")[0]?.trim() ?? "";
    return server ? `${status} · ${server}` : status;
  }
  return banner.split("\n")[0]?.trim().slice(0, 100) ?? "";
}

export function handleScanTarget(ws: WebSocket): void {
  ws.once("message", (raw) => {
    let req: ScanRequest;
    try {
      req = JSON.parse(raw.toString()) as ScanRequest;
    } catch {
      ws.send(JSON.stringify({ type: "error", message: "invalid JSON" }));
      ws.close();
      return;
    }

    const {
      target = "",
      ports,
      timeout: rawTimeout = 1200,
      concurrency: rawConcurrency = 30,
    } = req;

    const safeTarget = target.trim().replace(/[^a-zA-Z0-9.\-_:[\]]/g, "");
    if (!safeTarget) {
      ws.send(JSON.stringify({ type: "error", message: "invalid or empty target" }));
      ws.close();
      return;
    }

    const timeoutMs = Math.max(400, Math.min(Number(rawTimeout), 5000));
    const concurrency = Math.max(1, Math.min(Number(rawConcurrency), 50));
    const portList: number[] =
      Array.isArray(ports) && ports.length > 0
        ? ports.map(Number).filter((p) => p > 0 && p < 65536)
        : Array.from(SERVICE_MAP.keys());

    logger.info({ target: safeTarget, ports: portList.length, timeout: timeoutMs }, "ws/scan start");

    const send = (obj: unknown): void => {
      if (ws.readyState === 1) ws.send(JSON.stringify(obj));
    };

    let aborted = false;
    ws.on("close", () => { aborted = true; });

    const startTime = Date.now();

    send({ type: "start", target: safeTarget, total: portList.length });

    let scanned = 0;
    let openCount = 0;
    let idx = 0;

    const probe = async (): Promise<void> => {
      while (!aborted && idx < portList.length) {
        const port = portList[idx++]!;

        const { open, banner } = await grabBanner(safeTarget, port, timeoutMs);
        if (aborted) break;

        scanned++;
        if (open) openCount++;

        const msg: PortResultMsg = {
          type: "portResult",
          port,
          open,
          service: SERVICE_MAP.get(port) ?? "unknown",
          banner: parseHint(port, banner),
          scanned,
          total: portList.length,
          openCount,
        };
        send(msg);
      }
    };

    const workers = Array.from(
      { length: Math.min(concurrency, portList.length) },
      () => probe(),
    );

    Promise.all(workers)
      .then(() => {
        if (!aborted) {
          send({
            type: "end",
            target: safeTarget,
            total: portList.length,
            open: openCount,
            elapsed: Date.now() - startTime,
          });
        }
        ws.close();
      })
      .catch(() => {
        ws.close();
      });
  });
}
