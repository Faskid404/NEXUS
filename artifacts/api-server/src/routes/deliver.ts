import { Router, type Request, type Response } from "express";
import {
  buildLinuxPersistence,
  buildWindowsPersistence,
  buildDeliveryPayloads,
} from "../lib/persistenceEngine.js";

const router = Router();

/* GET /api/hub/deliver — generate payload delivery commands */
router.get("/hub/deliver", (req: Request, res: Response) => {
  const {
    lhost   = "127.0.0.1",
    lport   = "4444",
    path: p = "payload",
    os      = "linux",
  } = req.query as Record<string, string>;

  const all      = buildDeliveryPayloads(lhost, lport, p);
  const filtered = os === "all"
    ? all
    : all.filter(x => x.os === os || x.os === "any");

  res.json({ lhost, lport, path: p, os, payloads: filtered });
});

/* GET /api/hub/persist/linux — Linux persistence payloads */
router.get("/hub/persist/linux", (req: Request, res: Response) => {
  const {
    lhost = "127.0.0.1",
    lport = "4444",
    cmd   = "id",
  } = req.query as Record<string, string>;
  res.json({ lhost, lport, cmd, payloads: buildLinuxPersistence(lhost, lport, cmd) });
});

/* GET /api/hub/persist/windows — Windows persistence payloads */
router.get("/hub/persist/windows", (req: Request, res: Response) => {
  const {
    lhost = "127.0.0.1",
    lport = "4444",
    cmd   = "calc.exe",
  } = req.query as Record<string, string>;
  res.json({ lhost, lport, cmd, payloads: buildWindowsPersistence(lhost, lport, cmd) });
});

export default router;
