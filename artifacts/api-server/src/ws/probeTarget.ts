import type { WebSocket } from "ws";
import { probeTargetEnvironment, probeNetworkServices, probeWebDiscovery } from "../lib/targetProbe.js";
import { isSelfTarget } from "../lib/bypassEngine.js";
import { logger } from "../lib/logger.js";

const DEFAULT_PROBE_PORTS = [21, 22, 25, 80, 443, 445, 1433, 2375, 3306, 3389, 5432, 5900, 5984, 5985, 6379, 8080, 8443, 9200, 11211, 27017];

function send(ws: WebSocket, obj: unknown): void {
  if (ws.readyState === 1) {
    try { ws.send(JSON.stringify(obj)); } catch { /* connection closed mid-send */ }
  }
}

export function handleProbeTarget(ws: WebSocket): void {
  ws.once("message", (raw) => {
    let req: { url?: string; scanPorts?: boolean; ports?: number[] };
    try {
      req = JSON.parse(raw.toString()) as { url?: string; scanPorts?: boolean; ports?: number[] };
    } catch {
      send(ws, { type: "error", message: "invalid JSON" });
      ws.close();
      return;
    }

    const url        = (req.url ?? "").trim();
    const scanPorts  = req.scanPorts !== false;
    const portList   = Array.isArray(req.ports) && req.ports.length > 0
      ? req.ports.map(Number).filter((p) => p > 0 && p < 65536)
      : DEFAULT_PROBE_PORTS;

    if (!url) {
      send(ws, { type: "error", message: "url is required" });
      ws.close();
      return;
    }

    let parsed: URL;
    try { parsed = new URL(url); } catch {
      send(ws, { type: "error", message: `invalid URL: ${url}` });
      ws.close();
      return;
    }

    if (isSelfTarget(url)) {
      send(ws, { type: "error", message: "Self-targeting is disabled. Set an external target URL." });
      ws.close();
      return;
    }

    logger.info({ url, scanPorts }, "ws/probe start");

    send(ws, { type: "progress", message: `Probing HTTP environment: ${url}` });

    probeTargetEnvironment(url, 10000)
      .then(async (env) => {
        if (!env.reachable) {
          send(ws, { type: "error", message: `Target unreachable: ${url}` });
          ws.close();
          return;
        }

        send(ws, {
          type:    "result",
          env,
          summary: [
            `Status    : HTTP ${env.statusCode}  (${env.responseTime}ms)`,
            `OS        : ${env.os.toUpperCase()} [${env.osConfidence} confidence]`,
            `Server    : ${env.server      || "unknown"}`,
            `Language  : ${env.language    || "unknown"}`,
            `Framework : ${env.framework   || "unknown"}`,
            `CMS       : ${env.cms         || "none detected"}`,
            `WAF       : ${env.waf         ? `${env.waf} [${env.wafConfidence} confidence]` : "none detected"}`,
            `Body      : ${env.bodyLength} bytes`,
            env.redirectUrl ? `Redirect  : ${env.redirectUrl}` : "",
            "",
            "── Injection Hints ──",
            ...env.injectHints.map(h => `  ${h}`),
            "",
            "── Notable Headers ──",
            ...Object.entries(env.headers)
              .filter(([k]) => ["server","x-powered-by","x-aspnet-version","x-runtime","via","x-frame-options","content-security-policy","strict-transport-security","x-generator"].includes(k))
              .map(([k, v]) => `  ${k}: ${v}`),
            "",
            "── Cookies ──",
            ...env.cookies.slice(0, 6).map(c => `  ${c.split(";")[0]}`),
          ].filter(Boolean).join("\n"),
        });

        send(ws, { type: "progress", message: `Running web path discovery on ${url}` });

        try {
          const webDisc = await probeWebDiscovery(url, 8000);
          send(ws, { type: "web_discovery", discovery: webDisc });

          const discLines: string[] = ["── Web Discovery ──"];
          if (webDisc.gitExposed)   discLines.push("  [!] /.git/HEAD exposed — full source code recoverable via git-dumper");
          if (webDisc.phpinfo)      discLines.push("  [!] phpinfo() exposed — reveals config, paths, loaded modules");
          if (webDisc.dirListing)   discLines.push("  [!] Directory listing enabled");
          for (const p of webDisc.adminPanels) discLines.push(`  [+] Admin panel ${p.path} (HTTP ${p.status})`);
          for (const f of webDisc.sensitiveFiles) discLines.push(`  [!] Sensitive file ${f.path} is public (HTTP ${f.status})`);
          if (webDisc.robotsTxt) {
            const disallowed = webDisc.robotsTxt.split("\n").filter(l => /^Disallow:/i.test(l)).slice(0, 8).map(l => l.trim());
            if (disallowed.length) discLines.push("  Robots.txt disallowed paths:", ...disallowed.map(l => `    ${l}`));
          }
          if (discLines.length > 1) {
            send(ws, { type: "progress", message: discLines.join("\n") });
          }
        } catch {
          /* web discovery failure is non-fatal */
        }

        if (scanPorts) {
          send(ws, { type: "progress", message: `Fingerprinting ${portList.length} TCP services on ${parsed.hostname}` });
          try {
            const services = await probeNetworkServices(parsed.hostname, portList, 2500);
            send(ws, { type: "service_fingerprints", host: parsed.hostname, services });

            const svcLines = ["── Service Fingerprints ──"];
            for (const s of services) {
              const line = `  ${String(s.port).padEnd(6)} ${s.service.padEnd(16)} ${s.version || ""}`.trimEnd();
              svcLines.push(line);
              for (const h of s.vulnHints) svcLines.push(`           [!] ${h}`);
            }
            if (services.length) send(ws, { type: "progress", message: svcLines.join("\n") });
          } catch {
            /* service scan failure is non-fatal */
          }
        }

        send(ws, { type: "end" });
        ws.close();
      })
      .catch((err: unknown) => {
        send(ws, { type: "error", message: (err as Error).message ?? String(err) });
        ws.close();
      });
  });
}
