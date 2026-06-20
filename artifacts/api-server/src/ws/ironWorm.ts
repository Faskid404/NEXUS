import type { WebSocket } from "ws";
import { ironWormScan, type IronWormOptions, type IronWormResult } from "../lib/ironWorm.js";
import { logger } from "../lib/logger.js";
import { IronWormScanRequestSchema } from "../lib/schemas.js";

interface IronWormRequest extends IronWormOptions {
  mode?: "typosquat" | "dep_confusion" | "github" | "full" | "payloads";
}

function send(ws: WebSocket, obj: unknown): void {
  if (ws.readyState === 1) {
    try { ws.send(JSON.stringify(obj)); } catch { /* closing */ }
  }
}

function sendLog(ws: WebSocket, level: "info" | "warn" | "error" | "success", msg: string): void {
  send(ws, { type: "log", level, msg, ts: new Date().toISOString() });
}

function sendResult(ws: WebSocket, result: IronWormResult, index: number): void {
  send(ws, { type: "result", result, index });
}

function sendProgress(ws: WebSocket, done: number, total: number, label: string): void {
  send(ws, { type: "progress", done, total, pct: total > 0 ? Math.round((done / total) * 100) : 0, label });
}

export function handleIronWormScan(ws: WebSocket): void {
  ws.once("message", (raw) => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw.toString());
    } catch {
      send(ws, { type: "error", message: "Invalid JSON payload" });
      ws.close();
      return;
    }

    const validation = IronWormScanRequestSchema.safeParse(parsed);
    if (!validation.success) {
      send(ws, { type: "error", message: "validation failed", issues: validation.error.issues });
      ws.close();
      return;
    }

    const req = validation.data;
    const {
      packageName,
      githubOrg,
      githubRepo,
      depConfusionOrg,
      cbHost     = "LHOST",
      cbPort     = "9999",
      propagate  = false,
      targetCidr = "",
    } = req;

    logger.info(
      { packageName, githubOrg, depConfusionOrg, cbHost, propagate },
      "ws/ironworm scan started",
    );

    sendLog(ws, "info", `IronWorm scan started — cb=${cbHost}:${cbPort}`);

    if (packageName)     sendLog(ws, "info", `Package targets: ${packageName}`);
    if (githubOrg)       sendLog(ws, "info", `GitHub org: ${githubOrg}/${githubRepo ?? "*"}`);
    if (depConfusionOrg) sendLog(ws, "info", `Dep-confusion org: ${depConfusionOrg}`);
    if (propagate)       sendLog(ws, "warn", `Network propagation ENABLED — CIDR: ${targetCidr || "auto-detect"}`);

    sendProgress(ws, 0, 1, "Initialising scan engine…");

    const startMs = Date.now();
    let resultIdx = 0;

    ironWormScan({
      packageName:     packageName?.trim()     || undefined,
      githubOrg:       githubOrg?.trim()       || undefined,
      githubRepo:      githubRepo?.trim()       || undefined,
      depConfusionOrg: depConfusionOrg?.trim() || undefined,
      cbHost:          (cbHost ?? "").trim()  || "LHOST",
      cbPort:          String(cbPort ?? "9999").trim() || "9999",
      propagate,
      targetCidr:      targetCidr?.trim() || undefined,
    })
      .then((results) => {
        const total = results.length;
        sendProgress(ws, total, total, `Scan complete — ${total} result${total !== 1 ? "s" : ""}`);

        for (const result of results) {
          sendResult(ws, result, resultIdx++);

          const lvl =
            result.severity === "critical" ? "error" :
            result.severity === "high"     ? "warn"  :
            result.status   === "success"  ? "success" : "info";

          sendLog(ws, lvl,
            `[${result.category.toUpperCase()}] ${result.name} — ${result.detail}`,
          );
        }

        const elapsed = Date.now() - startMs;
        const critCount = results.filter(r => r.severity === "critical").length;
        const successCount = results.filter(r => r.status === "success").length;

        sendLog(ws, critCount > 0 ? "error" : "success",
          `Scan done in ${(elapsed / 1000).toFixed(1)}s — ${successCount}/${total} exploitable, ${critCount} critical`,
        );

        send(ws, {
          type:    "done",
          elapsed,
          total,
          critical: critCount,
          success:  successCount,
        });

        ws.close();
      })
      .catch((err: unknown) => {
        const msg = (err as Error).message ?? String(err);
        logger.error({ err }, "ws/ironworm scan error");
        sendLog(ws, "error", `Scan error: ${msg}`);
        send(ws, { type: "error", message: msg });
        ws.close();
      });
  });
}
