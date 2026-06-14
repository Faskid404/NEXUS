import { Router, type IRouter, type Request, type Response } from "express";
import {
  CVE_DB, detectCve, buildExploitSteps,
  probeSsh, probeFtp, exploitErlangSsh,
} from "../lib/cveExploits2025.js";
import { runDifferentialAnalysis } from "../lib/differentialAnalysis.js";
import { listSessions, deleteSession } from "../lib/sessionManager.js";

const router: IRouter = Router();

router.get("/cve/list", (_req: Request, res: Response) => {
  res.json(CVE_DB.map(c => ({
    id: c.id, title: c.title, cvss: c.cvss, type: c.type,
    protocol: c.protocol, affectedProducts: c.affectedProducts,
    affectedVersions: c.affectedVersions, patchedIn: c.patchedIn,
    publishedDate: c.publishedDate, references: c.references,
  })));
});

router.get("/cve/:id", (req: Request, res: Response) => {
  const cve = CVE_DB.find(c => c.id === req.params["id"]);
  if (!cve) { res.status(404).json({ error: "CVE not found" }); return; }
  res.json(cve);
});

router.post("/cve/probe/http", async (req: Request, res: Response) => {
  const { cveId, targetUrl, opts } = req.body as {
    cveId?: string; targetUrl?: string; opts?: Record<string,string>;
  };
  if (!cveId || !targetUrl) { res.status(400).json({ error: "cveId and targetUrl required" }); return; }
  try {
    const result = await detectCve(cveId, targetUrl, opts ?? {});
    res.json(result);
  } catch (err) { res.status(500).json({ error: (err as Error).message }); }
});

router.post("/cve/probe/ssh", async (req: Request, res: Response) => {
  const { host, port } = req.body as { host?: string; port?: number };
  if (!host) { res.status(400).json({ error: "host required" }); return; }
  try { res.json(await probeSsh(host, port ?? 22)); }
  catch (err) { res.status(500).json({ error: (err as Error).message }); }
});

router.post("/cve/probe/ftp", async (req: Request, res: Response) => {
  const { host, port } = req.body as { host?: string; port?: number };
  if (!host) { res.status(400).json({ error: "host required" }); return; }
  try { res.json(await probeFtp(host, port ?? 21)); }
  catch (err) { res.status(500).json({ error: (err as Error).message }); }
});

router.post("/cve/exploit/steps", (req: Request, res: Response) => {
  const { cveId, cmd, opts } = req.body as {
    cveId?: string; cmd?: string; opts?: Record<string,string>;
  };
  if (!cveId) { res.status(400).json({ error: "cveId required" }); return; }
  res.json({ cveId, steps: buildExploitSteps(cveId, cmd ?? "id", opts ?? {}) });
});

router.post("/cve/exploit/erlang-ssh", async (req: Request, res: Response) => {
  const { host, port, cmd } = req.body as { host?: string; port?: number; cmd?: string };
  if (!host) { res.status(400).json({ error: "host required" }); return; }
  try { res.json(await exploitErlangSsh(host, port ?? 22, cmd ?? "id && whoami && hostname")); }
  catch (err) { res.status(500).json({ error: (err as Error).message }); }
});

router.post("/cve/differential", async (req: Request, res: Response) => {
  const { targetUrl, injectParam, httpMethod, customHeaders } = req.body as {
    targetUrl?: string; injectParam?: string;
    httpMethod?: "GET"|"POST"; customHeaders?: Record<string,string>;
  };
  if (!targetUrl || !injectParam) {
    res.status(400).json({ error: "targetUrl and injectParam required" }); return;
  }
  try {
    const results = await runDifferentialAnalysis({
      targetUrl, injectParam, httpMethod: httpMethod ?? "GET", customHeaders,
    });
    res.json(results);
  } catch (err) { res.status(500).json({ error: (err as Error).message }); }
});

router.get("/cve/sessions/list", (_req: Request, res: Response) => {
  res.json(listSessions());
});

router.delete("/cve/sessions/:id", (req: Request, res: Response) => {
  const id = Array.isArray(req.params["id"]) ? req.params["id"][0]! : req.params["id"]!;
  deleteSession(id);
  res.json({ ok: true });
});

export default router;
