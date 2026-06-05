import { Router, type IRouter, type Request, type Response } from "express";
import { getChainRuns, clearChainRuns } from "../lib/chainLog.js";

const router: IRouter = Router();

router.get("/chainlog", (_req: Request, res: Response) => {
  res.json(getChainRuns());
});

router.delete("/chainlog", (_req: Request, res: Response) => {
  clearChainRuns();
  res.json({ ok: true });
});

router.get("/chainlog/export", (_req: Request, res: Response) => {
  const runs = getChainRuns();
  res.setHeader("Content-Type", "application/json");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename="nexus_chainlog_${Date.now()}.json"`,
  );
  res.send(JSON.stringify(runs, null, 2));
});

export default router;
