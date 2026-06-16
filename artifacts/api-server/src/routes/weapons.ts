import { Router, type Request, type Response } from "express";
import { buildAllEchoPayloads }   from "../lib/echoVault.js";
import { buildAllShadowPayloads } from "../lib/shadowForge.js";
import { buildAllVeilPayloads }   from "../lib/veilRunner.js";
import { KILL_CHAINS }            from "../lib/chainReactor.js";
import { buildC2PollerBundle, buildGistCommandEncoder } from "../lib/c2Poller.js";
import type { C2PollerConfig }    from "../lib/c2Poller.js";

import { ironWormScan } from "../lib/ironWorm.js";

const router = Router();

/* ── GET /api/weapons/echoes ────────────────────────────────────────── */
router.get("/api/weapons/echoes", (req, res) => {
  const cbUrl = String(req.query["cbUrl"]  ?? "http://oob.nexusforge.local");
  const token = String(req.query["token"]  ?? "NEXUSTOKEN");
  const proto = req.query["protocol"] as string | undefined;
  const os    = req.query["os"]       as string | undefined;

  let payloads = buildAllEchoPayloads(cbUrl, token);
  if (proto) payloads = payloads.filter(p => p.protocol === proto);
  if (os && os !== "all") payloads = payloads.filter(p => p.os === os || p.os === "any");

  res.json({ payloads, total: payloads.length });
});

/* ── GET /api/weapons/shadows ───────────────────────────────────────── */
router.get("/api/weapons/shadows", (req, res) => {
  const lhost = String(req.query["lhost"] ?? "127.0.0.1");
  const lport = String(req.query["lport"] ?? "4444");
  const os    = req.query["os"]  as string | undefined;
  const cat   = req.query["cat"] as string | undefined;

  let payloads = buildAllShadowPayloads(lhost, lport);
  if (os && os !== "all") payloads = payloads.filter(p => p.os === os || (p.os as string) === "any");
  if (cat) payloads = payloads.filter(p => p.category.toLowerCase().includes(cat.toLowerCase()));

  res.json({ payloads, total: payloads.length });
});

/* ── GET /api/weapons/veils ─────────────────────────────────────────── */
router.get("/api/weapons/veils", (req, res) => {
  const lhost = String(req.query["lhost"] ?? "127.0.0.1");
  const lport = String(req.query["lport"] ?? "4444");
  const os    = req.query["os"]    as string | undefined;
  const cat   = req.query["cat"]   as string | undefined;
  const phase = req.query["phase"] as string | undefined;

  let payloads = buildAllVeilPayloads(lhost, lport);
  if (os && os !== "all") payloads = payloads.filter(p => p.os === os || (p.os as string) === "any");
  if (cat)   payloads = payloads.filter(p => p.category.toLowerCase().includes(cat.toLowerCase()));
  if (phase) payloads = payloads.filter(p => p.phase === phase);

  res.json({ payloads, total: payloads.length });
});

/* ── GET /api/weapons/chains ────────────────────────────────────────── */
router.get("/api/weapons/chains", (_req, res) => {
  res.json({
    chains: KILL_CHAINS.map(c => ({
      id:          c.id,
      name:        c.name,
      description: c.description,
      category:    c.category,
      severity:    c.severity,
      steps:       c.steps.length,
    })),
    total: KILL_CHAINS.length,
  });
});

/* ── POST /api/weapons/c2 ───────────────────────────────────────────── */
router.post("/api/weapons/c2", (req, res) => {
  const b = req.body as Partial<C2PollerConfig>;
  if (!b.pollUrl) { res.status(400).json({ error: "pollUrl is required" }); return; }
  const cfg: C2PollerConfig = {
    source:    (b.source as C2PollerConfig["source"]) ?? "url",
    pollUrl:   b.pollUrl,
    reportUrl: b.reportUrl,
    interval:  Number(b.interval ?? 60),
    jitter:    Number(b.jitter   ?? 30),
    engine:    (b.engine as C2PollerConfig["engine"]) ?? "bash",
    maxRuns:   Number(b.maxRuns  ?? 9999),
    xorKey:    Number(b.xorKey   ?? 0x4e),
    killDate:  b.killDate,
    userAgent: b.userAgent ?? "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    os:        (b.os as C2PollerConfig["os"]) ?? "linux",
  };
  const payloads = buildC2PollerBundle(cfg);
  res.json({ payloads, total: payloads.length, config: cfg });
});

/* ── GET /api/weapons/c2/encode ─────────────────────────────────────── */
router.get("/api/weapons/c2/encode", (req, res) => {
  const cmd    = String(req.query["cmd"]    ?? "id");
  const xorKey = Number(req.query["xorKey"] ?? 0x4e);
  if (xorKey < 0 || xorKey > 255) { res.status(400).json({ error: "xorKey must be 0-255" }); return; }
  res.json({ encoded: buildGistCommandEncoder(cmd, xorKey), cmd, xorKey });
});

/* ── GET /api/weapons/stats ─────────────────────────────────────────── */
router.get("/api/weapons/stats", (req: Request, res: Response) => {
  const lhost  = String(req.query["lhost"] ?? "127.0.0.1");
  const lport  = String(req.query["lport"] ?? "4444");
  const cbUrl  = String(req.query["cbUrl"] ?? "http://oob.nexusforge.local");
  const token  = String(req.query["token"] ?? "NEXUSTOKEN");

  const shadows  = buildAllShadowPayloads(lhost, lport);
  const veils    = buildAllVeilPayloads(lhost, lport);
  const echoes   = buildAllEchoPayloads(cbUrl, token);

  // Count by category
  const shadowCats:  Record<string, number> = {};
  const veilCats:    Record<string, number> = {};
  for (const p of shadows) { shadowCats[p.category]  = (shadowCats[p.category]  ?? 0) + 1; }
  for (const p of veils)   { veilCats[p.category]    = (veilCats[p.category]    ?? 0) + 1; }

  const echoProtos: Record<string, number> = {};
  for (const p of echoes) { echoProtos[p.protocol] = (echoProtos[p.protocol] ?? 0) + 1; }

  res.json({
    totals: {
      shadows:    shadows.length,
      veils:      veils.length,
      echoes:     echoes.length,
      killChains: KILL_CHAINS.length,
    },
    shadowCategories: shadowCats,
    veilCategories:   veilCats,
    echoProtocols:    echoProtos,
  });
});

/* ── GET /api/weapons/search ─────────────────────────────────────────── */
router.get("/api/weapons/search", (req: Request, res: Response) => {
  const q     = ((req.query["q"] as string | undefined) ?? "").toLowerCase();
  const lhost = String(req.query["lhost"] ?? "127.0.0.1");
  const lport = String(req.query["lport"] ?? "4444");
  const cbUrl = String(req.query["cbUrl"] ?? "http://oob.nexusforge.local");
  const token = String(req.query["token"] ?? "NEXUSTOKEN");

  if (!q || q.length < 2) {
    res.status(400).json({ error: "q (search query) must be at least 2 characters" });
    return;
  }

  const shadows  = buildAllShadowPayloads(lhost, lport).filter(
    p => p.name.toLowerCase().includes(q) || p.payload.toLowerCase().includes(q) || p.category.toLowerCase().includes(q),
  );
  const veils    = buildAllVeilPayloads(lhost, lport).filter(
    p => p.name.toLowerCase().includes(q) || p.payload.toLowerCase().includes(q) || p.category.toLowerCase().includes(q),
  );
  const echoes   = buildAllEchoPayloads(cbUrl, token).filter(
    p => p.name.toLowerCase().includes(q) || p.payload.toLowerCase().includes(q),
  );

  res.json({
    query:   q,
    results: {
      shadows:  shadows.slice(0, 50),
      veils:    veils.slice(0, 50),
      echoes:   echoes.slice(0, 50),
    },
    totals: { shadows: shadows.length, veils: veils.length, echoes: echoes.length },
  });
});

/* ── GET /api/weapons/categories ────────────────────────────────────── */
router.get("/api/weapons/categories", (req: Request, res: Response) => {
  const lhost = String(req.query["lhost"] ?? "127.0.0.1");
  const lport = String(req.query["lport"] ?? "4444");

  const shadows    = buildAllShadowPayloads(lhost, lport);
  const veils      = buildAllVeilPayloads(lhost, lport);
  const shadowCats = [...new Set(shadows.map(p => p.category))].sort();
  const veilCats   = [...new Set(veils.map(p => p.category))].sort();
  const veilPhases = [...new Set(veils.map(p => p.phase))].sort();

  res.json({
    shadow: { categories: shadowCats },
    veil:   { categories: veilCats, phases: veilPhases },
    chains: { categories: [...new Set(KILL_CHAINS.map(c => c.category))].sort() },
  });
});

/* ── POST /api/weapons/ironworm ─────────────────────────────────────── */
router.post("/api/weapons/ironworm", async (req, res) => {
  const { mode, packageName, githubOrg, githubRepo, depConfusionOrg, cbHost, cbPort } = req.body as Record<string,string|undefined>;
  try {
    const results = await ironWormScan({
      packageName:     packageName?.trim()      || undefined,
      githubOrg:       githubOrg?.trim()        || undefined,
      githubRepo:      githubRepo?.trim()        || undefined,
      depConfusionOrg: depConfusionOrg?.trim()  || undefined,
      cbHost:          cbHost?.trim()            || "LHOST",
      cbPort:          cbPort?.trim()            || "9999",
    });
    res.json({ ok:true, results });
  } catch (err) {
    req.log.error({ err }, "IronWorm scan failed");
    res.status(500).json({ ok:false, error:String(err) });
  }
});

export default router;
