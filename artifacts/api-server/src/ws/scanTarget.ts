import { spawn } from "child_process";
import type { WebSocket } from "ws";
import { logger } from "../lib/logger.js";

interface ScanRequest {
  target: string;
  mode?: "common" | "web" | "full";
}

const PORT_SETS: Record<string, number[]> = {
  common: [
    21, 22, 23, 25, 53, 80, 110, 111, 119, 135, 139, 143, 161, 194, 389, 443,
    445, 465, 587, 636, 993, 995, 1080, 1194, 1433, 1521, 1723, 2049, 2375,
    2376, 3000, 3306, 3389, 4444, 5000, 5432, 5900, 5985, 6379, 8080, 8443,
    8888, 9090, 9200, 9300, 10250, 27017, 27018, 50070,
  ],
  web: [
    80, 443, 3000, 3001, 4000, 4200, 4443, 5000, 5001, 7000, 8000, 8001,
    8008, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090,
    8180, 8443, 8444, 8888, 9000, 9090, 9091, 9200, 9443, 10000, 10443,
  ],
  full: Array.from({ length: 1024 }, (_, i) => i + 1),
};

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

    const { target = "", mode = "common" } = req;

    if (!target.trim()) {
      ws.send(JSON.stringify({ type: "error", message: "target required" }));
      ws.close();
      return;
    }

    const safeTarget = target.replace(/[^a-zA-Z0-9.\-_:]/g, "");
    if (!safeTarget) {
      ws.send(JSON.stringify({ type: "error", message: "invalid target" }));
      ws.close();
      return;
    }

    logger.info({ target: safeTarget, mode }, "ws/scan");

    const send = (obj: unknown) => {
      if (ws.readyState === 1) ws.send(JSON.stringify(obj));
    };

    const ports = PORT_SETS[mode] ?? PORT_SETS["common"]!;

    send({ type: "data", chunk: `[NEXUSFORGE SCAN] Target ......... ${safeTarget}\n` });
    send({ type: "data", chunk: `[NEXUSFORGE SCAN] Mode ........... ${mode.toUpperCase()} (${ports.length} ports)\n` });
    send({ type: "data", chunk: `[NEXUSFORGE SCAN] Method ......... bash /dev/tcp — 30 concurrent\n` });
    send({ type: "data", chunk: `─────────────────────────────────────────────────────\n\n` });

    const openPorts: number[] = [];
    let completed = 0;
    let aborted = false;
    let idx = 0;
    const CONCURRENCY = 30;
    const start = Date.now();

    ws.on("close", () => { aborted = true; });

    const probe = () => {
      if (aborted) return;
      if (idx >= ports.length) return;
      const port = ports[idx++]!;

      const child = spawn("bash", [
        "-c",
        `(timeout 1 bash -c "(echo >/dev/tcp/${safeTarget}/${port}) 2>/dev/null" 2>/dev/null && echo OPEN) || true`,
      ]);

      let out = "";
      child.stdout.on("data", (d: Buffer) => { out += d.toString(); });

      const finish = () => {
        if (aborted) return;
        if (out.includes("OPEN")) {
          openPorts.push(port);
          send({ type: "data", chunk: `[OPEN]  ${String(port).padEnd(6)} tcp\n` });
        }
        completed++;
        probe();
        if (completed === ports.length) {
          const elapsed = Date.now() - start;
          openPorts.sort((a, b) => a - b);
          send({ type: "data", chunk: `\n─────────────────────────────────────────────────────\n` });
          send({ type: "data", chunk: `[SCAN COMPLETE] ${elapsed}ms | ${openPorts.length} open port(s) on ${safeTarget}\n` });
          if (openPorts.length > 0) {
            send({ type: "data", chunk: `[OPEN PORTS]    ${openPorts.join(", ")}\n` });
          } else {
            send({ type: "data", chunk: `[RESULT]        No open ports found (host may be down or filtered)\n` });
          }
          send({ type: "end", code: 0, openPorts });
          ws.close();
        }
      };

      child.on("close", finish);
      child.on("error", finish);
    };

    for (let i = 0; i < Math.min(CONCURRENCY, ports.length); i++) {
      probe();
    }
  });
}
