import { Router } from "express";
import { buildAllEchoPayloads }   from "../lib/echoVault.js";
import { buildAllShadowPayloads } from "../lib/shadowForge.js";
import { buildAllVeilPayloads }   from "../lib/veilRunner.js";
import { KILL_CHAINS }            from "../lib/chainReactor.js";

const router = Router();

router.get("/api/weapons/echoes", (req, res) => {
  const cbUrl = String(req.query["cbUrl"]  ?? "http://oob.nexusforge.local");
  const token = String(req.query["token"]  ?? "NEXUSTOKEN");
  const proto = req.query["protocol"] as string | undefined;
  const os    = req.query["os"]       as string | undefined;

  let payloads = buildAllEchoPayloads(cbUrl, token);
  if (proto) payloads = payloads.filter(p => p.protocol === proto);
  if (os && os !== "any") payloads = payloads.filter(p => p.os === os || p.os === "any");

  res.json({ payloads, total: payloads.length });
});

router.get("/api/weapons/shadows", (req, res) => {
  const lhost = String(req.query["lhost"] ?? "127.0.0.1");
  const lport = String(req.query["lport"] ?? "4444");
  const os    = req.query["os"]      as string | undefined;
  const cat   = req.query["cat"]     as string | undefined;

  let payloads = buildAllShadowPayloads(lhost, lport);
  if (os && os !== "any") payloads = payloads.filter(p => p.os === os || p.os === "any");
  if (cat) payloads = payloads.filter(p => p.category.toLowerCase().includes(cat.toLowerCase()));

  res.json({ payloads, total: payloads.length });
});

router.get("/api/weapons/veils", (req, res) => {
  const lhost = String(req.query["lhost"] ?? "127.0.0.1");
  const lport = String(req.query["lport"] ?? "4444");
  const os    = req.query["os"]      as string | undefined;
  const cat   = req.query["cat"]     as string | undefined;
  const phase = req.query["phase"]   as string | undefined;

  let payloads = buildAllVeilPayloads(lhost, lport);
  if (os && os !== "any") payloads = payloads.filter(p => p.os === os || p.os === "any");
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

export default router;
