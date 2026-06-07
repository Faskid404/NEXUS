import { Router, type IRouter, type Request, type Response } from "express";
import { getChainRuns, clearChainRuns } from "../lib/chainLog.js";

const router: IRouter = Router();

router.get("/chainlog", async (_req: Request, res: Response) => {
  res.json(await getChainRuns());
});

router.delete("/chainlog", async (_req: Request, res: Response) => {
  try {
    await clearChainRuns();
    res.json({ ok: true });
  } catch (err: unknown) {
    res.status(500).json({ ok: false, error: (err as Error).message });
  }
});

router.get("/chainlog/export", async (_req: Request, res: Response) => {
  const runs = await getChainRuns();
  res.setHeader("Content-Type", "application/json");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename="nexus_chainlog_${Date.now()}.json"`,
  );
  res.send(JSON.stringify(runs, null, 2));
});

export default router;
