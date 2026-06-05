/* ════════════════════════════════════════════════════════════════════
     NEXUSFORGE — Differential Analysis Engine
     Detects injection without signatures — timing, size, and content deltas.
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
    method:         "timing" | "size" | "content" | "status" | "none";
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

  const TIMING_PAYLOADS = [
    "1; sleep 2",
    "1 || sleep 2",
    "1 | sleep 2 #",
    "1; ping -c 2 127.0.0.1",
    "1 AND sleep(2)-- -",
    "1; timeout 2 cmd.exe",
    "1; Start-Sleep -Seconds 2",
  ];
  const SIZE_PAYLOADS = [
    "1 | echo NX_MARKER_OK",
    "1; echo NX_MARKER_OK",
    "1 || echo NX_MARKER_OK",
    "1' AND '1'='1",
    '1" AND "1"="1',
  ];

  export async function runDifferentialAnalysis(cfg: DiffConfig): Promise<DiffResult[]> {
    const results: DiffResult[] = [];

    // Baseline — two benign values averaged
    const [b1, b2] = await Promise.all([req(cfg, "hello"), req(cfg, "test123")]);
    const baselineMs   = Math.round((b1.elapsed + b2.elapsed) / 2);
    const baselineSize = Math.round((b1.size + b2.size) / 2);
    const baselineSt   = b1.status;
    logger.info({ baselineMs, baselineSize, baselineSt }, "differential: baseline");

    // Timing tests
    for (const payload of TIMING_PAYLOADS) {
      const t = await req(cfg, payload);
      const delta = t.elapsed - baselineMs;
      if (delta >= TIMING_THRESH) {
        results.push({
          method: "timing", confirmed: true, confidence: "high", payload,
          baselineMs, testMs: t.elapsed, timingDelta: delta,
          baselineSize, testSize: t.size, sizeDelta: t.size - baselineSize,
          baselineStatus: baselineSt, testStatus: t.status,
          evidence: "Timing delta " + delta + "ms (baseline " + baselineMs + "ms) — sleep injection confirmed",
        });
        break;
      } else if (delta > 800) {
        results.push({
          method: "timing", confirmed: false, confidence: "medium", payload,
          baselineMs, testMs: t.elapsed, timingDelta: delta,
          baselineSize, testSize: t.size, sizeDelta: t.size - baselineSize,
          baselineStatus: baselineSt, testStatus: t.status,
          evidence: "Suspicious timing delta " + delta + "ms — may indicate injection",
        });
      }
    }

    // Content/size tests
    for (const payload of SIZE_PAYLOADS) {
      const t = await req(cfg, payload);
      const hasMarker = t.body.includes("NX_MARKER_OK");
      const delta     = t.size - baselineSize;
      if (hasMarker) {
        results.push({
          method: "content", confirmed: true, confidence: "high", payload,
          baselineMs, testMs: t.elapsed, timingDelta: t.elapsed - baselineMs,
          baselineSize, testSize: t.size, sizeDelta: delta,
          baselineStatus: baselineSt, testStatus: t.status,
          evidence: "Output marker NX_MARKER_OK present in response — injection confirmed",
        });
        break;
      } else if (Math.abs(delta) >= SIZE_THRESH) {
        results.push({
          method: "size", confirmed: false, confidence: "low", payload,
          baselineMs, testMs: t.elapsed, timingDelta: t.elapsed - baselineMs,
          baselineSize, testSize: t.size, sizeDelta: delta,
          baselineStatus: baselineSt, testStatus: t.status,
          evidence: "Response size changed by " + delta + " bytes — potential injection",
        });
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
  