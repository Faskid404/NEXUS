import * as net from "net";
import * as http from "http";
import * as https from "https";

export function bannerGrab(host: string, port: number, ms = 2500, send?: Buffer): Promise<Buffer> {
  return new Promise((resolve) => {
    const s = new net.Socket();
    let data = Buffer.alloc(0);
    s.setTimeout(ms);
    s.once("connect", () => { if (send) s.write(send); });
    s.on("data", (c: Buffer) => { data = Buffer.concat([data, c]); if (data.length > 4096) s.destroy(); });
    s.once("timeout", () => { s.destroy(); resolve(data); });
    s.once("error",   () => { s.destroy(); resolve(data); });
    s.once("close",   () => resolve(data));
    s.connect(port, host);
  });
}

export function rawFetch(
  url: string,
  method: string,
  headers: Record<string, string>,
  body: string | null,
  timeoutMs: number,
): Promise<{ status: number; body: string; headers: Record<string, string> }> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const isHttps = u.protocol === "https:";
    const bodyBuf = body != null ? Buffer.from(body, "utf8") : null;
    const reqHeaders: Record<string, string> = {
      "User-Agent": "Mozilla/5.0 (compatible; NX-Scanner/1.0)",
      ...headers,
      ...(bodyBuf ? { "Content-Length": String(bodyBuf.length) } : {}),
    };
    const opts: https.RequestOptions = {
      hostname: u.hostname,
      port: u.port || (isHttps ? "443" : "80"),
      path: u.pathname + u.search,
      method: method.toUpperCase(),
      headers: reqHeaders,
      rejectUnauthorized: false,
      timeout: timeoutMs,
    };
    const proto = isHttps ? https : http;
    const req = proto.request(opts, (res) => {
      let data = "";
      res.on("data", (c: Buffer) => { data += c.toString(); });
      res.on("end", () => {
        const resHeaders: Record<string, string> = {};
        for (const [k, v] of Object.entries(res.headers)) {
          if (v !== undefined) resHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : v;
        }
        resolve({ status: res.statusCode ?? 0, body: data.slice(0, 65536), headers: resHeaders });
      });
    });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("timeout")); });
    if (bodyBuf) req.write(bodyBuf);
    req.end();
  });
}
