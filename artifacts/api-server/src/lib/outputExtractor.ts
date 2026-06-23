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

export const NEXUS_MARKER = "===NEXUS_OUTPUT_END===";

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

  return null;
}

/* ── Verification payload ───────────────────────────────────── */
export const VERIFY_PAYLOAD =
  `id && whoami && uname -a && hostname && echo '${NEXUS_MARKER}'`;
