import { Router, type IRouter, type Request, type Response } from "express";
import { readLogs, clearLogs, getLogStats } from "../lib/injectionLogger.js";

const router: IRouter = Router();

/* ── GET /logs — paginated log fetch with optional filters ──────────── */
router.get("/logs", async (req: Request, res: Response) => {
  const limit  = Math.min(Number(req.query["limit"]  ?? 200), 500);
  const offset = Number(req.query["offset"] ?? 0);
  const mode   = (req.query["mode"]   as string | undefined)?.toLowerCase();
  const engine = (req.query["engine"] as string | undefined)?.toLowerCase();
  const since  = req.query["since"]  ? Number(req.query["since"])  : undefined;
  const until  = req.query["until"]  ? Number(req.query["until"])  : undefined;

  let logs = await readLogs(500, 0); // fetch broader set for filtering

  if (mode)   logs = logs.filter(l => l.mode?.toLowerCase()   === mode);
  if (engine) logs = logs.filter(l => l.engine?.toLowerCase() === engine);
  if (since)  logs = logs.filter(l => new Date(l.timestamp).getTime() >= since);
  if (until)  logs = logs.filter(l => new Date(l.timestamp).getTime() <= until);
  const paged  = logs.slice(offset, offset + limit);

  res.json(paged);
});

/* ── DELETE /logs — clear all logs ─────────────────────────────────── */
router.delete("/logs", async (_req: Request, res: Response) => {
  try {
    await clearLogs();
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Could not clear logs" });
  }
});

/* ── GET /logs/stats — aggregate statistics ─────────────────────────── */
router.get("/logs/stats", async (_req: Request, res: Response) => {
  try {
    const stats = await getLogStats();
    res.json(stats);
  } catch {
    res.status(500).json({ error: "Could not fetch stats" });
  }
});

/* ── GET /logs/export.ndjson — newline-delimited JSON export ─────────── */
router.get("/logs/export.ndjson", async (_req: Request, res: Response) => {
  const logs = await readLogs(10_000, 0);
  res.setHeader("Content-Type", "application/x-ndjson");
  res.setHeader("Content-Disposition", `attachment; filename="nexus-logs-${Date.now()}.ndjson"`);
  for (const entry of logs) {
    res.write(JSON.stringify(entry) + "\n");
  }
  res.end();
});

/* ── GET /logs/export.csv — CSV export ─────────────────────────────── */
router.get("/logs/export.csv", async (_req: Request, res: Response) => {
  const logs = await readLogs(10_000, 0);
  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", `attachment; filename="nexus-logs-${Date.now()}.csv"`);
  const header = "id,timestamp,command,engine,mode,responseTime\n";
  res.write(header);
  for (const l of logs) {
    const row = [
      l.id,
      l.timestamp,
      `"${String(l.command ?? "").replace(/"/g, '""')}"`,
      l.engine ?? "",
      l.mode   ?? "",
      l.responseTime ?? 0,
    ].join(",") + "\n";
    res.write(row);
  }
  res.end();
});

export default router;
