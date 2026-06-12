import { Router, type Request, type Response } from "express";
import { buildHttpExfil, buildDnsExfil } from "../lib/exfilEngine.js";

const router = Router();

/* GET /api/hub/exfil?cbUrl=...&token=...&technique=http|dns|all */
router.get("/hub/exfil", (req: Request, res: Response) => {
  const {
    cbUrl     = "",
    token     = "",
    technique = "all",
    category  = "",
  } = req.query as Record<string, string>;

  if (!cbUrl || !token) {
    res.status(400).json({ error: "cbUrl and token are required" });
    return;
  }

  const http = technique === "dns" ? [] : buildHttpExfil(cbUrl, token);
  const dns  = technique === "http" ? [] : buildDnsExfil(cbUrl, token);

  let payloads = [...http, ...dns];
  if (category) {
    payloads = payloads.filter(p => p.category.toLowerCase() === category.toLowerCase());
  }

  res.json({ cbUrl, token, count: payloads.length, payloads });
});

export default router;
