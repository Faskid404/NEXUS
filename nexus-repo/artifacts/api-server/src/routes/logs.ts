import { Router, type IRouter, type Request, type Response } from "express";
import { readLogs, clearLogs } from "../lib/injectionLogger.js";

const router: IRouter = Router();

router.get("/logs", async (req: Request, res: Response) => {
  const limit = Math.min(Number(req.query["limit"] ?? 200), 500);
  const offset = Number(req.query["offset"] ?? 0);
  const logs = await readLogs(limit, offset);
  res.json(logs);
});

router.delete("/logs", async (_req: Request, res: Response) => {
  try {
    await clearLogs();
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Could not clear logs" });
  }
});

export default router;
