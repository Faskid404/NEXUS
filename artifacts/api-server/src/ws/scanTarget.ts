import type { WebSocket } from "ws";
import { logger } from "../lib/logger.js";
import { ScanRequestSchema } from "../lib/schemas.js";
import { adaptiveScan, discoverLocalHosts } from "../lib/scanner.js";

const SERVICE_MAP = new Map<number, string>([
  [21,"FTP"],[22,"SSH"],[23,"Telnet"],[25,"SMTP"],[53,"DNS"],[80,"HTTP"],
  [110,"POP3"],[111,"RPC"],[119,"NNTP"],[135,"MSRPC"],[139,"NetBIOS"],[143,"IMAP"],
  [161,"SNMP"],[194,"IRC"],[389,"LDAP"],[443,"HTTPS"],[445,"SMB"],[465,"SMTPS"],
  [587,"SMTP-TLS"],[636,"LDAPS"],[873,"Rsync"],[993,"IMAPS"],[995,"POP3S"],
  [1080,"SOCKS"],[1194,"OpenVPN"],[1433,"MSSQL"],[1521,"Oracle"],[1723,"PPTP"],
  [2049,"NFS"],[2375,"Docker"],[2376,"DockerTLS"],[2379,"etcd"],
  [3000,"Node/Dev"],[3306,"MySQL"],[3389,"RDP"],[4444,"Metasploit"],
  [5000,"Flask/Dev"],[5432,"PostgreSQL"],[5601,"Kibana"],[5900,"VNC"],
  [5984,"CouchDB"],[5985,"WinRM"],[5986,"WinRMS"],[6379,"Redis"],
  [6443,"Kubernetes"],[7474,"Neo4j"],[8000,"HTTP-Alt"],[8080,"HTTP-Proxy"],
  [8443,"HTTPS-Alt"],[8888,"Jupyter"],[9000,"SonarQube"],[9090,"Prometheus"],
  [9200,"Elasticsearch"],[9300,"ES-Cluster"],[9418,"Git"],
  [10250,"Kubelet"],[11211,"Memcached"],[15672,"RabbitMQ"],
  [27017,"MongoDB"],[27018,"Mongo-Shard"],[50070,"Hadoop"],
]);

const DEFAULT_PORTS = [...SERVICE_MAP.keys()];

function wsend(ws: WebSocket, obj: unknown): void {
  if (ws.readyState === 1) {
    try { ws.send(JSON.stringify(obj)); } catch { }
  }
}

export function handleScanTarget(ws: WebSocket): void {
  ws.once("message", (raw) => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw.toString());
    } catch {
      wsend(ws, { type: "error", message: "invalid JSON" });
      ws.close();
      return;
    }

    const result = ScanRequestSchema.safeParse(parsed);
    if (!result.success) {
      wsend(ws, { type: "error", message: "validation failed", issues: result.error.issues });
      ws.close();
      return;
    }

    const { target, ports, timeout: rawTimeout = 1200, concurrency: rawConcurrency = 30, adaptive = true, jitter = 80 } = result.data;

    const safeTarget = target.trim().replace(/[^a-zA-Z0-9.\-_:[\]]/g, "");
    if (!safeTarget) {
      wsend(ws, { type: "error", message: "invalid target" });
      ws.close();
      return;
    }

    const timeoutMs    = Math.max(400, Math.min(rawTimeout ?? 1200, 8000));
    const concurrency  = Math.max(1, Math.min(rawConcurrency ?? 30, 128));
    const portList     = (Array.isArray(ports) && ports.length > 0)
      ? ports.filter((p): p is number => typeof p === "number" && p > 0 && p < 65536)
      : DEFAULT_PORTS;

    logger.info({ target: safeTarget, ports: portList.length, timeout: timeoutMs }, "ws/scan start");

    let aborted = false;
    ws.on("close", () => { aborted = true; });

    const t0 = Date.now();
    wsend(ws, { type: "start", target: safeTarget, total: portList.length });

    let scanned   = 0;
    let openCount = 0;

    adaptiveScan(safeTarget, portList, {
      timeoutMs,
      concurrency,
      jitterMs:     jitter,
      adaptiveDelay: adaptive,
      sendProbes:   true,
      retries:      1,
    }).then(results => {
      for (const r of results) {
        if (aborted) break;
        scanned++;
        if (r.open) openCount++;
        wsend(ws, {
          type:     "portResult",
          port:     r.port,
          open:     r.open,
          service:  r.service,
          version:  r.version,
          banner:   r.banner,
          latency:  r.latency,
          cveHints: r.cveHints,
          scanned,
          total:    portList.length,
          openCount,
        });
      }

      if (!aborted) {
        const discovered = discoverLocalHosts();
        wsend(ws, {
          type:       "end",
          target:     safeTarget,
          total:      portList.length,
          open:       openCount,
          elapsed:    Date.now() - t0,
          discovered,
        });
        ws.close();
      }
    }).catch((err: unknown) => {
      if (!aborted) {
        wsend(ws, { type: "error", message: (err as Error).message ?? String(err) });
        ws.close();
      }
    });
  });
}
