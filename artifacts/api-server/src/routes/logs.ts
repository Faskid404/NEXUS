import { Router, type IRouter, type Request, type Response } from "express";
import { readLogs, clearLogs } from "../lib/injectionLogger.js";

const router: IRouter = Router();

router.get("/logs", (_req: Request, res: Response) => {
  res.json(readLogs());
});

router.delete("/logs", (_req: Request, res: Response) => {
  try {
    clearLogs();
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Could not clear logs" });
  }
});

export default router;
