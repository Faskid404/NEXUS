import { spawn } from "child_process";
import * as net from "net";
import type { WebSocket } from "ws";
import { logger } from "../lib/logger.js";

interface ScanRequest {
  target: string;
  mode?: "common" | "web" | "full";
}

const PORT_SETS: Record<string, number[]> = {
  common: [
    21, 22, 23, 25, 53, 80, 110, 111, 119, 135, 139, 143, 161, 194, 389, 443,
    445, 465, 587, 636, 873, 993, 995, 1080, 1194, 1433, 1521, 1723, 2049,
    2375, 2376, 2379, 3000, 3306, 3389, 4444, 5000, 5432, 5900, 5985, 5986,
    6379, 6443, 8080, 8443, 8888, 9090, 9200, 9300, 10250, 27017, 27018, 50070,
  ],
  web: [
    80, 443, 3000, 3001, 4000, 4200, 4443, 5000, 5001, 7000, 8000, 8001, 8008,
    8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8180,
    8443, 8444, 8888, 9000, 9090, 9091, 9200, 9443, 10000, 10443,
  ],
  full: Array.from({ length: 1024 }, (_, i) => i + 1),
};

const HTTP_PORTS  = new Set([80, 8080, 8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8180, 3000, 3001, 4000, 5000, 9000, 9090, 10000]);
const HTTPS_PORTS = new Set([443, 8443, 4443, 8444, 9443, 10443]);
const SSH_PORTS   = new Set([22, 2222]);
const FTP_PORTS   = new Set([21]);
const SMTP_PORTS  = new Set([25, 587, 465]);

function grabBanner(host: string, port: number, timeoutMs = 2500): Promise<string> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let data = "";
    let settled = false;

    const finish = (result: string) => {
      if (settled) return;
      settled = true;
      try { socket.destroy(); } catch { /* ignore */ }
      const clean = result
        .replace(/\r\n/g, "\n")
        .replace(/\r/g, "\n")
        .replace(/[\x00-\x08\x0b-\x1f\x7f-\x9f]/g, "")
        .trim()
        .slice(0, 280);
      resolve(clean);
    };

    socket.setTimeout(timeoutMs);

    socket.on("connect", () => {
      if (HTTP_PORTS.has(port)) {
        socket.write(
          `HEAD / HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n`
        );
      } else if (HTTPS_PORTS.has(port)) {
        finish("[TLS — use curl/openssl for banner]");
        return;
      }
    });

    socket.on("data", (chunk) => {
      data += chunk.toString("utf8", 0, 512);
      const isText = SSH_PORTS.has(port) || FTP_PORTS.has(port) || SMTP_PORTS.has(port);
      if (data.length >= 512 || (isText && data.includes("\n"))) {
        finish(data);
      }
    });

    socket.on("timeout", () => finish(data));
    socket.on("close",   () => finish(data));
    socket.on("error",   () => finish(data || ""));

    socket.connect(port, host);
  });
}

function parseServiceHint(port: number, banner: string): string {
  if (!banner) return "no banner";

  if (banner.startsWith("SSH-")) {
    return banner.split("\n")[0]?.trim() ?? banner.slice(0, 80);
  }

  const bl = banner.toLowerCase();

  if (bl.startsWith("http/") || bl.startsWith("head /")) {
    const statusLine = banner.split("\n")[0]?.trim() ?? "";
    const serverLine = banner.match(/server:\s*([^\r\n]+)/i)?.[1]?.trim() ?? "";
    const poweredBy  = banner.match(/x-powered-by:\s*([^\r\n]+)/i)?.[1]?.trim() ?? "";
    const parts = [statusLine];
    if (serverLine) parts.push(`Server: ${serverLine}`);
    if (poweredBy)  parts.push(`X-Powered-By: ${poweredBy}`);
    return parts.join(" | ").slice(0, 140);
  }

  if (banner.startsWith("220")) {
    return banner.split("\n")[0]?.trim() ?? banner.slice(0, 80);
  }

  if (banner.startsWith("230") || banner.startsWith("+OK") || banner.startsWith("-ERR")) {
    return banner.split("\n")[0]?.trim() ?? banner.slice(0, 80);
  }

  if (banner.includes("TLS")) {
    return "[TLS — use curl/openssl for banner]";
  }

  const first = banner.split("\n")[0]?.trim() ?? "";
  return first.slice(0, 100) || "connected (no banner)";
}

async function grabBanners(
  host: string,
  ports: number[],
  send: (obj: unknown) => void
): Promise<void> {
  send({ type: "data", chunk: `\n[BANNER GRAB] Service detection on ${ports.length} port(s)...\n` });
  for (const port of ports) {
    const banner = await grabBanner(host, port, 2500);
    const hint   = parseServiceHint(port, banner);
    const portStr = String(port).padEnd(5);
    const svcHint = hint || "no banner";
    send({ type: "data", chunk: `[${portStr} tcp] ${svcHint}\n` });
  }
  send({ type: "data", chunk: `[BANNER GRAB] Complete.\n` });
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
    const start = Date.now();

    send({ type: "data", chunk: `[NEXUSFORGE SCAN] Target ......... ${safeTarget}\n` });
    send({ type: "data", chunk: `[NEXUSFORGE SCAN] Mode ........... ${mode.toUpperCase()} (${ports.length} ports)\n` });
    send({ type: "data", chunk: `[NEXUSFORGE SCAN] Method ......... bash /dev/tcp | 30 concurrent\n` });
    send({ type: "data", chunk: `─────────────────────────────────────────────────────\n\n` });

    const openPorts: number[] = [];
    let completed  = 0;
    let aborted    = false;
    let idx        = 0;
    const CONCURRENCY = 30;

    ws.on("close", () => { aborted = true; });

    const probe = () => {
      if (aborted || idx >= ports.length) return;
      const port = ports[idx++]!;

      const child = spawn("bash", [
        "-c",
        `(timeout 1 bash -c "(echo >/dev/tcp/${safeTarget}/${port}) 2>/dev/null" 2>/dev/null && echo OPEN) || true`,
      ]);

      let out = "";
      child.stdout.on("data", (d: Buffer) => { out += d.toString(); });

      const onDone = () => {
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
            void grabBanners(safeTarget, openPorts, send).then(() => {
              send({ type: "end", code: 0, openPorts });
              ws.close();
            });
          } else {
            send({ type: "data", chunk: `[RESULT]        No open ports found — host may be down or filtered\n` });
            send({ type: "end", code: 0, openPorts: [] });
            ws.close();
          }
        }
      };

      child.on("close", onDone);
      child.on("error", onDone);
    };

    for (let i = 0; i < Math.min(CONCURRENCY, ports.length); i++) probe();
  });
}
